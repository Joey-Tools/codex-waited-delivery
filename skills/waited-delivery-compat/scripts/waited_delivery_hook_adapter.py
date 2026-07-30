#!/usr/bin/env python3

"""Explicit-only hook compatibility for historical waited-delivery runs."""

from __future__ import annotations

import argparse
import copy
import contextlib
import ctypes
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import select
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback
import uuid
from collections.abc import Iterator
from typing import Literal, NamedTuple, TypedDict, cast


BRIDGE_PATH = pathlib.Path(__file__).resolve().with_name("waited_delivery_bridge.py")
RUNNER_PATH = BRIDGE_PATH.with_name("waited_delivery_runner.py")
INDEX_SCHEMA_VERSION = 3
INDEX_FILE_NAME = "index.json"
INDEX_LOCK_FILE_NAME = "index.lock"
INDEX_MAX_BYTES = 4 * 1024 * 1024
INDEX_DIRECTORY_MODE = 0o700
INDEX_FILE_MODE = 0o600
UNTRUSTED_WRITE_MASK = stat.S_IWGRP | stat.S_IWOTH
CURRENT_THREAD_ENV = "CODEX_THREAD_ID"
HOOK_DEBUG_ENV = "WAITED_DELIVERY_HOOK_DEBUG"
HOOK_COMMANDS = {"user-prompt-submit-hook", "stop-hook"}
HOOK_ENABLE_FLAG = "--enable-compat-hook"
NON_HOOK_COMMANDS = {
    "prepare-active-run",
    "recover-active-run",
    "attach-child-active-run",
    "finish-child-active-run",
    "reconcile-active-run",
    "show-index",
}
HOOK_LOG_MAX_BYTES_ENV = "WAITED_DELIVERY_HOOK_LOG_MAX_BYTES"
HOOK_LOG_UNCOMPRESSED_SLOTS_ENV = "WAITED_DELIVERY_HOOK_LOG_UNCOMPRESSED_SLOTS"
HOOK_LOG_RETENTION_DAYS_ENV = "WAITED_DELIVERY_HOOK_LOG_RETENTION_DAYS"
HOOK_LOG_BASE_NAME = "waited-delivery-hooks"
HOOK_LOG_MAX_BYTES = 1024 * 1024
HOOK_LOG_UNCOMPRESSED_SLOTS = 3
HOOK_LOG_RETENTION_DAYS = 7
HOOK_LOG_PRUNE_INTERVAL = dt.timedelta(days=1)
TERMINAL_PHASE_STATUSES = {
    "passed",
    "failed",
    "blocked",
    "unavailable",
    "decision_point",
}
CHILD_TERMINAL_STATUSES = {"completed", "failed", "interrupted"}
RECOVERABLE_PREPARATION_STATUSES = {"preparing", "recovery_required"}
CLEANUP_PENDING_STATUS = "cleanup_pending"
CLEANUP_COMPLETE_STATUS = "cleanup_complete"
PREPARATION_STATUSES = RECOVERABLE_PREPARATION_STATUSES | {
    CLEANUP_PENDING_STATUS,
    CLEANUP_COMPLETE_STATUS,
}
PREPARATION_REASON_MAX_CHARS = 512
RUNS_DIR_NAME = "waited-delivery"
RUN_DIRECTORY_MODE = 0o700
LEGACY_RUN_DIRECTORY_MODE = 0o755
STATE_MAX_BYTES = 4 * 1024 * 1024
RUNNER_PREPARATION_SCHEMA_VERSIONS = {4, 5}
PROMPT_REFRESH_SCHEMA_VERSION = 3
SOURCE_FRAME_MAGIC = b"WDLPIPE1"
SOURCE_FRAME_HEADER_BYTES = 8 + 8 + 32 + 8 + 32
SOURCE_PIPE_BOOTSTRAP = """\
import hashlib
import sys

MAX_SOURCE_BYTES = 4 * 1024 * 1024

def read_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(min(64 * 1024, remaining))
        if not chunk:
            raise SystemExit("truncated waited-delivery source frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

stream = sys.stdin.buffer
if read_exact(stream, 8) != b"WDLPIPE1":
    raise SystemExit("invalid waited-delivery source frame")
bridge_size = int.from_bytes(read_exact(stream, 8), "big")
bridge_sha256 = read_exact(stream, 32).hex()
runner_size = int.from_bytes(read_exact(stream, 8), "big")
runner_sha256 = read_exact(stream, 32).hex()
if (
    bridge_size <= 0
    or bridge_size > MAX_SOURCE_BYTES
    or runner_size <= 0
    or runner_size > MAX_SOURCE_BYTES
):
    raise SystemExit("waited-delivery source frame size is outside the bound")
bridge_source = read_exact(stream, bridge_size)
runner_source = read_exact(stream, runner_size)
if stream.read(1):
    raise SystemExit("waited-delivery source frame has trailing bytes")
if hashlib.sha256(bridge_source).hexdigest() != bridge_sha256:
    raise SystemExit("waited-delivery bridge source digest mismatch")
if hashlib.sha256(runner_source).hexdigest() != runner_sha256:
    raise SystemExit("waited-delivery runner source digest mismatch")
bridge_path = sys.argv[1]
runner_path = sys.argv[2]
bridge_args = sys.argv[3:]
sys.argv[:] = [bridge_path, *bridge_args]
bridge_globals = {
    "__name__": "__main__",
    "__file__": bridge_path,
    "__package__": None,
    "__cached__": None,
    "_WAITED_DELIVERY_BOUND_BRIDGE_SOURCE": bridge_source,
    "_WAITED_DELIVERY_BOUND_RUNNER_SOURCE": runner_source,
    "_WAITED_DELIVERY_BOUND_RUNNER_PATH": runner_path,
}
exec(compile(bridge_source, bridge_path, "exec"), bridge_globals)
"""
REFRESH_TIMEOUT_SECONDS = 7.0
REFRESH_CLEANUP_TIMEOUT_SECONDS = 2.0
REFRESH_CAPTURE_MAX_BYTES = 256 * 1024
REFRESH_DRAIN_CHUNK_BYTES = 64 * 1024
REFRESH_POLL_INTERVAL_SECONDS = 0.02
REFRESH_PROC_GROUP_SCAN_MAX_ENTRIES = 131_072
REFRESH_PROC_GROUP_SCAN_TIMEOUT_SECONDS = 0.25

LinuxRefreshProcessGroupState = Literal[
    "live",
    "zombie-only",
    "no-members",
    "unknown",
]
RunEntryPresence = Literal["absent", "present"]
LeaseEntryPresence = Literal["absent", "present"]


class UserError(RuntimeError):
    pass


class RunSafetyError(UserError):
    pass


class RunDirectoryIdentity(NamedTuple):
    device: int
    inode: int
    uid: int
    gid: int
    mode: int


class StopArtifactVersion(NamedTuple):
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int
    sha256: str


class IndexFileVersion(NamedTuple):
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int
    sha256: str


class StopArtifactRead(NamedTuple):
    content: bytes
    version: StopArtifactVersion


class RefreshedPrompts(NamedTuple):
    child_prompt: pathlib.Path
    child_version: StopArtifactVersion
    parent_prompt: pathlib.Path
    parent_version: StopArtifactVersion


class LaunchArtifactSource(NamedTuple):
    source_path: pathlib.Path
    source_version: StopArtifactVersion
    content: bytes


class RefreshLaunchSources(NamedTuple):
    bridge: LaunchArtifactSource
    runner: LaunchArtifactSource


class PreparationReservation(NamedTuple):
    session_id: str
    preparation_id: str
    run_id: str
    run_dir: str
    lease_path: str
    started_at: str


class SessionRecord(TypedDict):
    session_id: str
    cwd: str
    transcript_path: str | None
    permission_mode: str | None
    last_prompt: str | None
    run_dir: str | None
    status: str
    updated_at: str | None
    preparation_id: str | None
    preparation_run_id: str | None
    preparation_lease_path: str | None
    preparation_started_at: str | None
    preparation_reason: str | None


class AdapterIndex(TypedDict):
    schema_version: int
    latest_session_id: str | None
    updated_at: str | None
    sessions: dict[str, SessionRecord]


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _validate_component_name(name: str, *, label: str) -> None:
    if not name or name in {".", ".."} or pathlib.PurePath(name).name != name:
        raise UserError(f"{label} must be one path component: {name!r}")


def _shell_command(args: list[str]) -> str:
    return " ".join(shlex.quote(arg) for arg in args)


def _run(
    cmd: list[str],
    *,
    cwd: pathlib.Path | None = None,
    pass_fds: tuple[int, ...] = (),
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        pass_fds=pass_fds,
    )


class _RefreshCaptureLimitExceeded(Exception):
    pass


class _DeferredRefreshTermination(BaseException):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


class _RefreshSignalTransaction:
    """Defer one terminal signal until refresh has no live group members."""

    def __init__(self) -> None:
        self._entry_mask: set[int] = set()
        self._managed_signals: tuple[int, ...] = ()
        self._previous_handlers: dict[int, object] = {}
        self._pending_signal: int | None = None
        self._raised = False

    def _record(self, signum: int, _frame: object) -> None:
        if self._pending_signal is None:
            self._pending_signal = signum

    @staticmethod
    def _signal_runtime() -> tuple[object, object, object]:
        pthread_sigmask = getattr(signal, "pthread_sigmask", None)
        sigpending = getattr(signal, "sigpending", None)
        sigwait = getattr(signal, "sigwait", None)
        if (
            os.name != "posix"
            or not callable(pthread_sigmask)
            or not callable(sigpending)
            or not callable(sigwait)
        ):
            raise UserError(
                "prompt refresh signal supervision requires POSIX "
                "pthread_sigmask, sigpending, and sigwait"
            )
        return pthread_sigmask, sigpending, sigwait

    @staticmethod
    def _candidate_signals() -> tuple[int, ...]:
        return tuple(
            int(signum)
            for signum in (
                signal.SIGHUP,
                signal.SIGTERM,
                signal.SIGQUIT,
            )
        )

    def __enter__(self) -> _RefreshSignalTransaction:
        pthread_sigmask, _sigpending, _sigwait = self._signal_runtime()
        candidates = self._candidate_signals()
        try:
            self._entry_mask = {
                int(value)
                for value in pthread_sigmask(signal.SIG_BLOCK, set(candidates))
            }
        except (OSError, ValueError) as error:
            raise UserError(
                f"cannot block prompt refresh supervision signals: {error}"
            ) from error
        try:
            for signum in candidates:
                previous = signal.getsignal(signum)
                if previous == signal.SIG_IGN or signum in self._entry_mask:
                    continue
                self._previous_handlers[signum] = previous
                signal.signal(signum, self._record)
            self._managed_signals = tuple(self._previous_handlers)
        except BaseException:
            for signum, previous in reversed(tuple(self._previous_handlers.items())):
                signal.signal(signum, previous)
            pthread_sigmask(signal.SIG_SETMASK, self._entry_mask)
            raise
        try:
            pthread_sigmask(signal.SIG_SETMASK, self._entry_mask)
        except (OSError, ValueError) as error:
            for signum, previous in reversed(tuple(self._previous_handlers.items())):
                signal.signal(signum, previous)
            raise UserError(
                f"cannot restore prompt refresh entry signal mask: {error}"
            ) from error
        return self

    def raise_if_pending(self) -> None:
        if self._pending_signal is None or self._raised:
            return
        self._raised = True
        raise _DeferredRefreshTermination(self._pending_signal)

    @property
    def pending_signal(self) -> int | None:
        return self._pending_signal

    def _capture_pending_masked(
        self,
        sigpending: object,
        sigwait: object,
    ) -> None:
        assert callable(sigpending)
        assert callable(sigwait)
        managed = set(self._managed_signals)
        while True:
            try:
                pending = {int(value) for value in sigpending()} & managed
            except OSError as error:
                raise UserError(
                    f"cannot inspect pending prompt refresh signals: {error}"
                ) from error
            if not pending:
                return
            try:
                signum = int(sigwait(pending))
            except (OSError, ValueError) as error:
                raise UserError(
                    f"cannot consume pending prompt refresh signal: {error}"
                ) from error
            if signum not in pending:
                raise UserError("prompt refresh sigwait returned an unrequested signal")
            self._record(signum, None)

    def __exit__(
        self,
        _exc_type: object,
        exc: BaseException | None,
        _traceback: object,
    ) -> bool:
        pthread_sigmask, sigpending, sigwait = self._signal_runtime()
        try:
            terminal_mask = {
                int(value)
                for value in pthread_sigmask(
                    signal.SIG_BLOCK,
                    set(self._managed_signals),
                )
            }
        except (OSError, ValueError) as error:
            raise UserError(
                f"cannot block prompt refresh signals during cleanup: {error}"
            ) from error
        try:
            self._capture_pending_masked(sigpending, sigwait)
            for signum, previous in reversed(tuple(self._previous_handlers.items())):
                signal.signal(signum, previous)
            self._previous_handlers.clear()
            self._capture_pending_masked(sigpending, sigwait)
            signum = self._pending_signal
            if signum is not None:
                if exc is not None and not isinstance(
                    exc,
                    _DeferredRefreshTermination,
                ):
                    print(
                        "note: prompt refresh cleanup raised "
                        f"{type(exc).__name__}: {exc}; propagating "
                        f"{signal.Signals(signum).name}",
                        file=sys.stderr,
                        flush=True,
                    )
                signal.raise_signal(signum)
        finally:
            try:
                pthread_sigmask(signal.SIG_SETMASK, terminal_mask)
            except (OSError, ValueError) as error:
                raise UserError(
                    f"cannot restore prompt refresh terminal signal mask: {error}"
                ) from error
        return isinstance(exc, _DeferredRefreshTermination)


class _UnreapedLeaderObserver:
    """Observe one session leader without releasing its PID/PGID identity."""

    def __init__(self, pid: int, *, platform: str | None = None) -> None:
        if pid <= 0:
            raise UserError("process leader pid must be positive")
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise UserError(
                "process supervision requires the default SIGCHLD disposition"
            )
        self.pid = pid
        self.platform = sys.platform if platform is None else platform
        self._exited = False
        self._reaped = False
        self._kqueue: object | None = None
        if self.platform == "darwin":
            required = (
                "kqueue",
                "kevent",
                "KQ_FILTER_PROC",
                "KQ_NOTE_EXIT",
                "KQ_EV_ADD",
                "KQ_EV_ENABLE",
                "KQ_EV_ONESHOT",
            )
            if any(not hasattr(select, name) for name in required):
                raise UserError(
                    "Darwin process supervision requires kqueue NOTE_EXIT"
                )
            kqueue: object | None = None
            try:
                kqueue = select.kqueue()
                event = select.kevent(
                    pid,
                    filter=select.KQ_FILTER_PROC,
                    flags=(
                        select.KQ_EV_ADD
                        | select.KQ_EV_ENABLE
                        | select.KQ_EV_ONESHOT
                    ),
                    fflags=select.KQ_NOTE_EXIT,
                )
                observed = kqueue.control([event], 1, 0)
            except OSError as error:
                if kqueue is not None:
                    try:
                        kqueue.close()  # type: ignore[attr-defined]
                    except OSError:
                        pass
                raise UserError(
                    "cannot bind Darwin process-exit observation"
                ) from error
            self._kqueue = kqueue
            self._accept_kqueue_events(observed)
        elif self.platform.startswith("linux"):
            if not callable(getattr(os, "waitid", None)):
                raise UserError("Linux process supervision requires waitid")
        else:
            raise UserError(
                f"process supervision is unsupported on platform {self.platform}"
            )

    def _accept_kqueue_events(self, events: list[object]) -> None:
        for event in events:
            if (
                getattr(event, "ident", None) != self.pid
                or not (getattr(event, "fflags", 0) & select.KQ_NOTE_EXIT)
            ):
                raise UserError(
                    "Darwin process-exit observation returned an unrelated event"
                )
            self._exited = True

    def exited(self) -> bool:
        if self._reaped:
            raise UserError("process leader was already reaped")
        if self._exited:
            return True
        if self.platform == "darwin":
            assert self._kqueue is not None
            try:
                events = self._kqueue.control(None, 1, 0)  # type: ignore[attr-defined]
            except OSError as error:
                raise UserError(
                    "cannot inspect Darwin process-exit observation"
                ) from error
            self._accept_kqueue_events(events)
            return self._exited
        waitid = getattr(os, "waitid")
        try:
            result = waitid(
                os.P_PID,
                self.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError as error:
            raise UserError(
                "process leader was reaped outside its supervisor"
            ) from error
        except OSError as error:
            raise UserError("cannot observe process leader without reaping") from error
        if result is None:
            return False
        if result.si_pid != self.pid:
            raise UserError("waitid returned an unrelated process leader")
        self._exited = True
        return True

    def signal_group(self, signum: int) -> None:
        if self._reaped:
            raise UserError("refusing to signal a process group after leader reap")
        try:
            os.killpg(self.pid, signum)
        except ProcessLookupError:
            pass

    def reap(self, process: subprocess.Popen[bytes]) -> int:
        if process.pid != self.pid:
            raise UserError("process leader identity changed before reap")
        if not self.exited():
            raise UserError("cannot reap a process leader before observed exit")
        returncode = process.wait()
        self._reaped = True
        self.close()
        return returncode

    def close(self) -> None:
        if self._kqueue is None:
            return
        kqueue = self._kqueue
        self._kqueue = None
        try:
            kqueue.close()  # type: ignore[attr-defined]
        except OSError:
            pass


class _DarwinProcBSDInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def _darwin_refresh_process_group_state(
    pgid: int,
    *,
    max_entries: int = REFRESH_PROC_GROUP_SCAN_MAX_ENTRIES,
) -> LinuxRefreshProcessGroupState:
    if max_entries <= 0:
        return "unknown"
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_group = libproc.proc_listpgrppids
        list_group.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        list_group.restype = ctypes.c_int
        pid_info = libproc.proc_pidinfo
        pid_info.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        pid_info.restype = ctypes.c_int
        pid_array = (ctypes.c_int * max_entries)()
        count = list_group(
            pgid,
            pid_array,
            ctypes.sizeof(pid_array),
        )
    except (AttributeError, OSError, ValueError):
        return "unknown"
    if count < 0 or count >= max_entries:
        return "unknown"
    saw_zombie = False
    for pid in pid_array[:count]:
        if pid <= 0:
            return "unknown"
        info = _DarwinProcBSDInfo()
        try:
            size = pid_info(
                pid,
                3,
                0,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
        except (OSError, ValueError):
            return "unknown"
        if size == 0:
            continue
        if (
            size != ctypes.sizeof(info)
            or info.pbi_pid != pid
            or info.pbi_pgid != pgid
        ):
            return "unknown"
        if info.pbi_status != 5:
            return "live"
        saw_zombie = True
    if saw_zombie:
        return "zombie-only"
    return "no-members"


def _parse_linux_proc_stat(raw: bytes) -> tuple[str, int] | None:
    closing_parenthesis = raw.rfind(b")")
    if closing_parenthesis <= 0:
        return None
    fields = raw[closing_parenthesis + 1 :].split()
    if len(fields) < 3 or len(fields[0]) != 1:
        return None
    try:
        process_group = int(fields[2])
    except ValueError:
        return None
    state_value = fields[0][0]
    if state_value > 0x7F:
        return None
    return chr(state_value), process_group


def _linux_refresh_process_group_state(
    pgid: int,
    *,
    proc_root: pathlib.Path = pathlib.Path("/proc"),
    deadline: float | None = None,
    max_entries: int = REFRESH_PROC_GROUP_SCAN_MAX_ENTRIES,
) -> LinuxRefreshProcessGroupState:
    if deadline is None:
        deadline = time.monotonic() + REFRESH_PROC_GROUP_SCAN_TIMEOUT_SECONDS
    if max_entries <= 0:
        return "unknown"
    saw_zombie = False
    entry_count = 0
    try:
        with os.scandir(proc_root) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > max_entries or time.monotonic() >= deadline:
                    return "unknown"
                if not entry.name.isdecimal():
                    continue
                try:
                    raw = (pathlib.Path(entry.path) / "stat").read_bytes()
                except FileNotFoundError:
                    continue
                parsed = _parse_linux_proc_stat(raw)
                if parsed is None:
                    return "unknown"
                state, process_group = parsed
                if process_group != pgid:
                    continue
                if state != "Z":
                    return "live"
                saw_zombie = True
    except OSError:
        return "unknown"
    if saw_zombie:
        return "zombie-only"
    return "no-members"


def _refresh_process_group_has_live_members(
    pgid: int,
    *,
    proc_root: pathlib.Path = pathlib.Path("/proc"),
    platform: str = sys.platform,
    deadline: float | None = None,
) -> bool:
    if platform == "darwin":
        return _darwin_refresh_process_group_state(pgid) not in {
            "zombie-only",
            "no-members",
        }
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    if not platform.startswith("linux"):
        return True
    state = _linux_refresh_process_group_state(
        pgid,
        proc_root=proc_root,
        deadline=deadline,
    )
    if state == "zombie-only":
        return False
    if state != "no-members":
        return True
    # The group may have disappeared during the scan. Only a second ESRCH proves
    # absence; unreadable, ambiguous, or still-addressable states remain live.
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_refresh_process_group(observer: _UnreapedLeaderObserver) -> None:
    observer.signal_group(signal.SIGKILL)


def _drain_refresh_output_once(
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    timeout: float,
    capture: bool,
    max_capture_bytes: int,
) -> None:
    for key, _mask in selector.select(timeout):
        try:
            chunk = os.read(key.fd, REFRESH_DRAIN_CHUNK_BYTES)
        except BlockingIOError:
            continue
        if not chunk:
            selector.unregister(key.fd)
            continue
        if not capture:
            continue
        retained = sum(len(value) for value in captures.values())
        if retained + len(chunk) > max_capture_bytes:
            raise _RefreshCaptureLimitExceeded
        captures[cast(str, key.data)].extend(chunk)


def _service_refresh_io_once(
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    input_bytes: bytes,
    input_offset: int,
    timeout: float,
    max_capture_bytes: int,
) -> tuple[int, bool]:
    input_rejected = False
    for key, mask in selector.select(timeout):
        if key.data == "stdin":
            if not (mask & selectors.EVENT_WRITE):
                continue
            try:
                written = os.write(
                    key.fd,
                    input_bytes[
                        input_offset : input_offset + REFRESH_DRAIN_CHUNK_BYTES
                    ],
                )
            except (BrokenPipeError, ConnectionResetError):
                written = 0
                input_rejected = True
            except BlockingIOError:
                continue
            if written > 0:
                input_offset += written
            if input_rejected or input_offset == len(input_bytes):
                selector.unregister(key.fd)
                cast(object, key.fileobj).close()  # type: ignore[attr-defined]
            continue
        try:
            chunk = os.read(key.fd, REFRESH_DRAIN_CHUNK_BYTES)
        except BlockingIOError:
            continue
        if not chunk:
            selector.unregister(key.fd)
            continue
        retained = sum(len(value) for value in captures.values())
        if retained + len(chunk) > max_capture_bytes:
            raise _RefreshCaptureLimitExceeded
        captures[cast(str, key.data)].extend(chunk)
    return input_offset, input_rejected


def _close_refresh_input(
    selector: selectors.BaseSelector,
    stream: object | None,
) -> None:
    if stream is None:
        return
    fileno = getattr(stream, "fileno", None)
    close = getattr(stream, "close", None)
    if callable(fileno):
        try:
            selector.unregister(fileno())
        except (KeyError, ValueError, OSError):
            pass
    if callable(close):
        try:
            close()
        except OSError:
            pass


def _cleanup_refresh_process(
    process: subprocess.Popen[bytes],
    observer: _UnreapedLeaderObserver,
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    cleanup_timeout: float,
    max_capture_bytes: int,
) -> None:
    _kill_refresh_process_group(observer)
    deadline = time.monotonic() + cleanup_timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        _drain_refresh_output_once(
            selector,
            captures,
            timeout=min(REFRESH_POLL_INTERVAL_SECONDS, max(0.0, remaining)),
            capture=False,
            max_capture_bytes=max_capture_bytes,
        )
        if (
            observer.exited()
            and not _refresh_process_group_has_live_members(
                process.pid,
                deadline=deadline,
            )
            and not selector.get_map()
        ):
            observer.reap(process)
            return
    reasons: list[str] = []
    leader_exited = observer.exited()
    group_has_live_members = _refresh_process_group_has_live_members(process.pid)
    if not leader_exited:
        reasons.append("failed to reap prompt refresh process")
    if group_has_live_members:
        reasons.append("failed to eliminate live prompt refresh process-group members")
    if selector.get_map():
        reasons.append("failed to drain prompt refresh process pipes")
    if leader_exited:
        observer.reap(process)
    raise UserError("; ".join(reasons) or "prompt refresh cleanup timed out")


def _run_bounded_refresh_process(
    command: list[str],
    *,
    pass_fds: tuple[int, ...],
    env: dict[str, str],
    input_bytes: bytes | None = None,
    timeout: float = REFRESH_TIMEOUT_SECONDS,
    cleanup_timeout: float = REFRESH_CLEANUP_TIMEOUT_SECONDS,
    max_capture_bytes: int = REFRESH_CAPTURE_MAX_BYTES,
) -> subprocess.CompletedProcess[str]:
    if not command or not all(isinstance(argument, str) for argument in command):
        raise UserError("prompt refresh command must be a nonempty argv")
    if any(not isinstance(file_fd, int) or file_fd < 0 for file_fd in pass_fds):
        raise UserError("prompt refresh pass_fds must be nonnegative integers")
    if input_bytes is not None and not isinstance(input_bytes, bytes):
        raise UserError("prompt refresh input must be bytes")
    if input_bytes is not None and len(input_bytes) > (
        SOURCE_FRAME_HEADER_BYTES + 2 * STATE_MAX_BYTES
    ):
        raise UserError("prompt refresh input exceeds the source-frame byte bound")
    if timeout <= 0 or cleanup_timeout <= 0 or max_capture_bytes <= 0:
        raise UserError("prompt refresh process bounds must be positive")
    signal_transaction = _RefreshSignalTransaction()
    completed: subprocess.CompletedProcess[str] | None = None
    with signal_transaction:
        completed = _run_bounded_refresh_process_supervised(
            command,
            pass_fds=pass_fds,
            env=env,
            input_bytes=input_bytes,
            timeout=timeout,
            cleanup_timeout=cleanup_timeout,
            max_capture_bytes=max_capture_bytes,
            signal_transaction=signal_transaction,
        )
    if signal_transaction.pending_signal is not None:
        signum = signal_transaction.pending_signal
        return subprocess.CompletedProcess(
            command,
            128 + signum,
            stdout="" if completed is None else completed.stdout,
            stderr=(
                "BLOCKED: prompt refresh interrupted by "
                f"{signal.Signals(signum).name} after process-group cleanup\n"
            ),
        )
    if completed is None:
        raise UserError("prompt refresh process completed without a result")
    return completed


def _run_bounded_refresh_process_supervised(
    command: list[str],
    *,
    pass_fds: tuple[int, ...],
    env: dict[str, str],
    input_bytes: bytes | None,
    timeout: float,
    cleanup_timeout: float,
    max_capture_bytes: int,
    signal_transaction: _RefreshSignalTransaction,
) -> subprocess.CompletedProcess[str]:
    try:
        selector = selectors.DefaultSelector()
    except OSError as error:
        raise UserError(
            f"cannot initialize prompt refresh selector: {error}"
        ) from error
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    failure: tuple[int, str] | None = None
    cleanup_complete = False
    try:
        signal_transaction.raise_if_pending()
        try:
            process = subprocess.Popen(
                command,
                stdin=(
                    subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=pass_fds,
                env=env,
                start_new_session=True,
            )
        except OSError as error:
            raise UserError(f"cannot start prompt refresh: {error}") from error
        try:
            observer = _UnreapedLeaderObserver(process.pid)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        try:
            if process.stdout is None or process.stderr is None:
                raise UserError("prompt refresh process pipes were not created")
            for name, stream in (
                ("stdout", process.stdout),
                ("stderr", process.stderr),
            ):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream.fileno(), selectors.EVENT_READ, name)
            input_offset = 0
            input_rejected = False
            if input_bytes is not None:
                if process.stdin is None:
                    raise UserError("prompt refresh input pipe was not created")
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(
                    process.stdin,
                    selectors.EVENT_WRITE,
                    "stdin",
                )
            signal_transaction.raise_if_pending()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                signal_transaction.raise_if_pending()
                remaining = deadline - time.monotonic()
                try:
                    input_offset, rejected_now = _service_refresh_io_once(
                        selector,
                        captures,
                        input_bytes=b"" if input_bytes is None else input_bytes,
                        input_offset=input_offset,
                        timeout=min(
                            REFRESH_POLL_INTERVAL_SECONDS,
                            max(0.0, remaining),
                        ),
                        max_capture_bytes=max_capture_bytes,
                    )
                    input_rejected = input_rejected or rejected_now
                except _RefreshCaptureLimitExceeded:
                    failure = (
                        125,
                        "BLOCKED: prompt refresh output exceeded "
                        f"{max_capture_bytes} bytes",
                    )
                    break
                if (
                    input_bytes is not None
                    and input_rejected
                    and input_offset != len(input_bytes)
                ):
                    failure = (
                        126,
                        "BLOCKED: prompt refresh rejected its source frame before "
                        "the complete payload was delivered",
                    )
                    break
                signal_transaction.raise_if_pending()
                if not observer.exited():
                    continue
                if input_bytes is not None and input_offset != len(input_bytes):
                    failure = (
                        126,
                        "BLOCKED: prompt refresh rejected its source frame before "
                        "the complete payload was delivered",
                    )
                    break
                if _refresh_process_group_has_live_members(
                    process.pid,
                    deadline=deadline,
                ):
                    failure = (
                        126,
                        "BLOCKED: prompt refresh left a live descendant in its "
                        "process group",
                    )
                    break
                if not selector.get_map():
                    break
            else:
                failure = (
                    124,
                    f"BLOCKED: prompt refresh exceeded {timeout:g} second hard timeout",
                )

            if failure is not None:
                _close_refresh_input(selector, process.stdin)
                _cleanup_refresh_process(
                    process,
                    observer,
                    selector,
                    captures,
                    cleanup_timeout=cleanup_timeout,
                    max_capture_bytes=max_capture_bytes,
                )
                cleanup_complete = True
                returncode, reason = failure
                stderr = captures["stderr"].decode("utf-8", errors="replace")
                if stderr and not stderr.endswith("\n"):
                    stderr += "\n"
                stderr += reason + "\n"
                return subprocess.CompletedProcess(
                    command,
                    returncode,
                    stdout=captures["stdout"].decode("utf-8", errors="replace"),
                    stderr=stderr,
                )

            returncode = observer.reap(process)
            cleanup_complete = True
            return subprocess.CompletedProcess(
                command,
                returncode,
                stdout=captures["stdout"].decode("utf-8", errors="replace"),
                stderr=captures["stderr"].decode("utf-8", errors="replace"),
            )
        except BaseException:
            if not cleanup_complete:
                _close_refresh_input(selector, process.stdin)
                _cleanup_refresh_process(
                    process,
                    observer,
                    selector,
                    captures,
                    cleanup_timeout=cleanup_timeout,
                    max_capture_bytes=max_capture_bytes,
                )
            raise
        finally:
            observer.close()
            _close_refresh_input(selector, process.stdin)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
    finally:
        selector.close()


def _bridge_json_payload(
    completed: subprocess.CompletedProcess[str],
) -> dict[str, object]:
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise UserError(stderr)
    stdout = completed.stdout.strip()
    if not stdout:
        raise UserError("bridge command did not return JSON output")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise UserError(f"invalid bridge JSON output: {error}") from error
    if not isinstance(payload, dict):
        raise UserError("bridge JSON output must be an object")
    return cast(dict[str, object], payload)


def _run_bridge_json(*args: str) -> dict[str, object]:
    with _verified_refresh_launch_sources() as sources:
        return _bridge_json_payload(
            _run_bound_bridge_process(
                sources,
                *args,
            )
        )


def _run_bridge_json_with_lease(
    lease_fd: int,
    *args: str,
) -> dict[str, object]:
    if lease_fd < 0:
        raise RunSafetyError("preparation lease fd must be nonnegative")
    with _verified_refresh_launch_sources() as sources:
        return _bridge_json_payload(
            _run_bound_bridge_process(
                sources,
                *args,
                "--preparation-lease-fd",
                str(lease_fd),
                pass_fds=(lease_fd,),
            ),
        )


def _run_bridge_passthrough(*args: str) -> int:
    with _verified_refresh_launch_sources() as sources:
        completed = _run_bound_bridge_process(
            sources,
            *args,
        )
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.returncode != 0 and completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    return completed.returncode


def _resolve_repo_root(path_str: str, *, strict: bool) -> pathlib.Path | None:
    candidate = pathlib.Path(path_str).resolve()
    completed = _run(
        ["git", "-C", str(candidate), "rev-parse", "--show-toplevel"],
    )
    if completed.returncode != 0:
        if strict:
            stderr = completed.stderr.strip() or "not a git repository"
            raise UserError(stderr)
        return None
    return pathlib.Path(completed.stdout.strip()).resolve()


def _adapter_dir(repo_root: pathlib.Path) -> pathlib.Path:
    return repo_root / ".codex-tmp" / "waited-delivery-hook-adapter"


def _index_path(repo_root: pathlib.Path) -> pathlib.Path:
    return _adapter_dir(repo_root) / INDEX_FILE_NAME


def _index_template() -> AdapterIndex:
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "latest_session_id": None,
        "updated_at": None,
        "sessions": {},
    }


def _decode_index(content: bytes, path: pathlib.Path) -> AdapterIndex:
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise UserError(f"invalid adapter index: {path}: {error}") from error
    payload = json.loads(decoded)
    if not isinstance(payload, dict):
        raise UserError(f"invalid adapter index: {path}")
    schema_version = payload.get("schema_version", 1)
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in {1, 2, INDEX_SCHEMA_VERSION}
    ):
        raise UserError(f"unsupported adapter index schema: {path}")
    payload["schema_version"] = INDEX_SCHEMA_VERSION
    payload.setdefault("latest_session_id", None)
    payload.setdefault("updated_at", None)
    raw_sessions = payload.setdefault("sessions", {})
    if not isinstance(raw_sessions, dict):
        raise UserError(f"invalid adapter sessions: {path}")
    sessions = cast(dict[str, object], raw_sessions)
    for session_id, raw_record in list(sessions.items()):
        if not isinstance(raw_record, dict):
            raise UserError(f"invalid adapter session record: {session_id}")
        raw_record.setdefault("session_id", session_id)
        raw_record.setdefault("cwd", "")
        raw_record.setdefault("transcript_path", None)
        raw_record.setdefault("permission_mode", None)
        raw_record.setdefault("last_prompt", None)
        raw_record.setdefault("run_dir", None)
        raw_record.setdefault("status", "observed")
        raw_record.setdefault("updated_at", None)
        raw_record.setdefault("preparation_id", None)
        raw_record.setdefault("preparation_run_id", None)
        raw_record.setdefault("preparation_lease_path", None)
        raw_record.setdefault("preparation_started_at", None)
        raw_record.setdefault("preparation_reason", None)
    return cast(AdapterIndex, payload)


def _canonical_index_snapshot(index: AdapterIndex) -> str:
    return json.dumps(index, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _serialize_index_for_commit(
    index: AdapterIndex,
    *,
    transaction_time: str,
    context: str,
) -> bytes:
    candidate = copy.deepcopy(index)
    candidate["updated_at"] = transaction_time
    content = (
        json.dumps(candidate, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(content) > INDEX_MAX_BYTES:
        raise RunSafetyError(
            f"{context} exceeds the adapter index byte limit before index "
            f"publication ({len(content)} > {INDEX_MAX_BYTES} bytes); "
            "the existing index remains unchanged. Remove or shorten stale session "
            "metadata and retry."
        )
    projected = copy.deepcopy(candidate)
    for raw_record in projected["sessions"].values():
        if raw_record.get("status") not in PREPARATION_STATUSES:
            continue
        raw_record["status"] = "recovery_required"
        raw_record["preparation_reason"] = "x" * PREPARATION_REASON_MAX_CHARS
    projected_content = (
        json.dumps(projected, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(projected_content) > INDEX_MAX_BYTES:
        raise RunSafetyError(
            f"{context} would consume reserved preparation recovery capacity "
            f"({len(projected_content)} > {INDEX_MAX_BYTES} projected bytes); "
            "the existing index remains unchanged. Remove or shorten stale session "
            "metadata and retry."
        )
    return content


def _open_or_create_directory_at(
    parent_fd: int,
    name: str,
    *,
    mode: int,
    owner_private: bool,
) -> int:
    created = False
    previous_umask = os.umask(0)
    try:
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
    finally:
        os.umask(previous_umask)
    try:
        directory_fd = _open_directory_at(parent_fd, name)
    except OSError as error:
        raise RunSafetyError(
            f"adapter index directory cannot be opened without following links: {name}"
        ) from error
    try:
        descriptor_stat = os.fstat(directory_fd)
        named_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(descriptor_stat.st_mode)
            or not stat.S_ISDIR(named_stat.st_mode)
            or not _same_object(descriptor_stat, named_stat)
        ):
            raise RunSafetyError(f"adapter index directory identity mismatch: {name}")
        _require_owned_nonwritable_directory(
            directory_fd,
            label=f"adapter index directory {name}",
        )
        if owner_private:
            if created or stat.S_IMODE(descriptor_stat.st_mode) != mode:
                os.fchmod(directory_fd, mode)
            descriptor_after = os.fstat(directory_fd)
            named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(descriptor_after.st_mode)
                or not stat.S_ISDIR(named_after.st_mode)
                or not _same_object(descriptor_stat, descriptor_after)
                or not _same_object(descriptor_after, named_after)
                or descriptor_after.st_uid != os.geteuid()
                or stat.S_IMODE(descriptor_after.st_mode) != mode
            ):
                raise RunSafetyError(
                    f"adapter index directory is not owner-private: {name}"
                )
            _require_no_extended_acl(
                directory_fd,
                label=f"adapter index directory {name}",
            )
        try:
            os.fsync(parent_fd)
        except OSError as error:
            raise RunSafetyError(
                f"adapter index directory entry cannot be persisted: {name}"
            ) from error
        named_durable = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor_durable = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(named_durable.st_mode)
            or not stat.S_ISDIR(descriptor_durable.st_mode)
            or not _same_object(descriptor_stat, descriptor_durable)
            or not _same_object(descriptor_durable, named_durable)
            or (
                descriptor_durable.st_uid,
                descriptor_durable.st_gid,
                stat.S_IMODE(descriptor_durable.st_mode),
            )
            != (
                named_durable.st_uid,
                named_durable.st_gid,
                stat.S_IMODE(named_durable.st_mode),
            )
        ):
            raise RunSafetyError(
                f"adapter index directory changed while persisting its entry: {name}"
            )
        _require_owned_nonwritable_directory(
            directory_fd,
            label=f"adapter index directory {name}",
        )
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def _open_index_directories(
    repo_root: pathlib.Path,
) -> tuple[int, int, int]:
    repo_fd: int | None = None
    codex_tmp_fd: int | None = None
    adapter_fd: int | None = None
    try:
        repo_fd = _open_absolute_directory(repo_root)
        _require_owned_nonwritable_directory(
            repo_fd,
            label="repository root",
        )
        codex_tmp_fd = _open_or_create_directory_at(
            repo_fd,
            ".codex-tmp",
            mode=INDEX_DIRECTORY_MODE,
            owner_private=False,
        )
        adapter_fd = _open_or_create_directory_at(
            codex_tmp_fd,
            "waited-delivery-hook-adapter",
            mode=INDEX_DIRECTORY_MODE,
            owner_private=True,
        )
        return repo_fd, codex_tmp_fd, adapter_fd
    except Exception:
        if adapter_fd is not None:
            os.close(adapter_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        if repo_fd is not None:
            os.close(repo_fd)
        raise


def _revalidate_index_directories(
    repo_fd: int,
    codex_tmp_fd: int,
    adapter_fd: int,
) -> None:
    _require_owned_nonwritable_directory(
        repo_fd,
        label="repository root",
    )
    _bound_directory_identity(
        repo_fd,
        ".codex-tmp",
        codex_tmp_fd,
        label="adapter .codex-tmp parent",
    )
    _bound_directory_identity(
        codex_tmp_fd,
        "waited-delivery-hook-adapter",
        adapter_fd,
        label="adapter index directory",
    )
    codex_tmp_stat = os.fstat(codex_tmp_fd)
    named_codex_tmp = os.stat(
        ".codex-tmp",
        dir_fd=repo_fd,
        follow_symlinks=False,
    )
    adapter_stat = os.fstat(adapter_fd)
    named_adapter = os.stat(
        "waited-delivery-hook-adapter",
        dir_fd=codex_tmp_fd,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISDIR(codex_tmp_stat.st_mode)
        or not stat.S_ISDIR(named_codex_tmp.st_mode)
        or not _same_object(codex_tmp_stat, named_codex_tmp)
        or not stat.S_ISDIR(adapter_stat.st_mode)
        or not stat.S_ISDIR(named_adapter.st_mode)
        or not _same_object(adapter_stat, named_adapter)
        or adapter_stat.st_uid != os.geteuid()
        or stat.S_IMODE(adapter_stat.st_mode) != INDEX_DIRECTORY_MODE
    ):
        raise RunSafetyError(
            "adapter index directory identity or access policy changed"
        )


def _open_index_lock(adapter_fd: int) -> int:
    created = False
    create_flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        lock_fd = os.open(
            INDEX_LOCK_FILE_NAME,
            create_flags,
            INDEX_FILE_MODE,
            dir_fd=adapter_fd,
        )
        created = True
    except FileExistsError:
        try:
            lock_fd = os.open(
                INDEX_LOCK_FILE_NAME,
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=adapter_fd,
            )
        except OSError as error:
            raise RunSafetyError(
                "adapter index lock cannot be opened without following links"
            ) from error
    except OSError as error:
        raise RunSafetyError("adapter index lock cannot be created safely") from error
    try:
        if created:
            os.fchmod(lock_fd, INDEX_FILE_MODE)
        _revalidate_index_lock(adapter_fd, lock_fd)
        return lock_fd
    except Exception:
        os.close(lock_fd)
        raise


def _revalidate_index_lock(adapter_fd: int, lock_fd: int) -> None:
    descriptor_stat = os.fstat(lock_fd)
    named_stat = os.stat(
        INDEX_LOCK_FILE_NAME,
        dir_fd=adapter_fd,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(descriptor_stat.st_mode)
        or not stat.S_ISREG(named_stat.st_mode)
        or not _same_object(descriptor_stat, named_stat)
        or descriptor_stat.st_uid != os.geteuid()
        or stat.S_IMODE(descriptor_stat.st_mode) != INDEX_FILE_MODE
        or (
            descriptor_stat.st_uid,
            descriptor_stat.st_gid,
            stat.S_IMODE(descriptor_stat.st_mode),
        )
        != (
            named_stat.st_uid,
            named_stat.st_gid,
            stat.S_IMODE(named_stat.st_mode),
        )
    ):
        raise RunSafetyError("adapter index lock identity or access policy mismatch")
    _require_no_extended_acl(lock_fd, label="adapter index lock")


def _pread_index_bytes(file_fd: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while True:
        chunk = os.pread(
            file_fd,
            min(65536, INDEX_MAX_BYTES + 1 - offset),
            offset,
        )
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
        if offset > INDEX_MAX_BYTES:
            raise RunSafetyError("adapter index exceeds byte limit")
    return b"".join(chunks)


def _read_index_bytes_at(
    adapter_fd: int,
) -> tuple[bytes, IndexFileVersion] | None:
    try:
        file_fd = os.open(
            INDEX_FILE_NAME,
            _regular_open_flags(),
            dir_fd=adapter_fd,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RunSafetyError(
            "adapter index cannot be opened without following links"
        ) from error
    try:
        before = os.fstat(file_fd)
        named_before = os.stat(
            INDEX_FILE_NAME,
            dir_fd=adapter_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named_before.st_mode)
            or not _same_object(before, named_before)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > INDEX_MAX_BYTES
        ):
            raise RunSafetyError(
                "adapter index must be an owned, non-writable-by-others regular file"
            )
        _require_no_extended_acl(file_fd, label="adapter index")
        first_content = _pread_index_bytes(file_fd)
        middle = os.fstat(file_fd)
        second_content = _pread_index_bytes(file_fd)
        after = os.fstat(file_fd)
        named_after = os.stat(
            INDEX_FILE_NAME,
            dir_fd=adapter_fd,
            follow_symlinks=False,
        )
        expected_access = (
            before.st_uid,
            before.st_gid,
            stat.S_IMODE(before.st_mode),
        )
        observed_stats = (before, named_before, middle, after, named_after)
        if (
            any(not stat.S_ISREG(value.st_mode) for value in observed_stats)
            or any(not _same_object(before, value) for value in observed_stats[1:])
            or any(value.st_size != before.st_size for value in observed_stats[1:])
            or any(
                (
                    value.st_uid,
                    value.st_gid,
                    stat.S_IMODE(value.st_mode),
                )
                != expected_access
                for value in observed_stats[1:]
            )
            or len(first_content) != before.st_size
            or first_content != second_content
        ):
            raise RunSafetyError(
                "adapter index identity, access policy, size, or content changed "
                "while read"
            )
        _require_no_extended_acl(file_fd, label="adapter index")
        return (
            second_content,
            IndexFileVersion(
                device=after.st_dev,
                inode=after.st_ino,
                uid=after.st_uid,
                gid=after.st_gid,
                mode=stat.S_IMODE(after.st_mode),
                size=after.st_size,
                sha256=hashlib.sha256(second_content).hexdigest(),
            ),
        )
    except RunSafetyError:
        raise
    except OSError as error:
        raise RunSafetyError("adapter index cannot be read stably") from error
    finally:
        os.close(file_fd)


def _write_all(file_fd: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(file_fd, content[offset:])
        if written <= 0:
            raise RunSafetyError("adapter index temporary file write made no progress")
        offset += written


def _atomic_save_index_at(
    adapter_fd: int,
    index: AdapterIndex,
    expected_version: IndexFileVersion | None,
    *,
    transaction_time: str | None = None,
    context: str = "adapter index update",
) -> IndexFileVersion:
    current = _read_index_bytes_at(adapter_fd)
    current_version = None if current is None else current[1]
    if current_version != expected_version:
        raise RunSafetyError("adapter index changed outside the locked transaction")
    commit_time = transaction_time or _utc_now()
    content = _serialize_index_for_commit(
        index,
        transaction_time=commit_time,
        context=context,
    )
    index["updated_at"] = commit_time
    temporary_name = f".{INDEX_FILE_NAME}.{uuid.uuid4().hex}.tmp"
    temporary_fd: int | None = None
    temporary_visible = False
    replaced = False
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            INDEX_FILE_MODE,
            dir_fd=adapter_fd,
        )
        temporary_visible = True
        os.fchmod(temporary_fd, INDEX_FILE_MODE)
        _write_all(temporary_fd, content)
        os.fsync(temporary_fd)
        temporary_stat = os.fstat(temporary_fd)
        named_temporary = os.stat(
            temporary_name,
            dir_fd=adapter_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(temporary_stat.st_mode)
            or not stat.S_ISREG(named_temporary.st_mode)
            or not _same_object(temporary_stat, named_temporary)
            or temporary_stat.st_uid != os.geteuid()
            or stat.S_IMODE(temporary_stat.st_mode) != INDEX_FILE_MODE
            or temporary_stat.st_size != len(content)
            or _pread_index_bytes(temporary_fd) != content
        ):
            raise RunSafetyError(
                "adapter index temporary file failed identity, access, or "
                "content validation"
            )
        _require_no_extended_acl(
            temporary_fd,
            label="adapter index temporary file",
        )
        current = _read_index_bytes_at(adapter_fd)
        current_version = None if current is None else current[1]
        if current_version != expected_version:
            raise RunSafetyError("adapter index changed before atomic replacement")
        os.replace(
            temporary_name,
            INDEX_FILE_NAME,
            src_dir_fd=adapter_fd,
            dst_dir_fd=adapter_fd,
        )
        temporary_visible = False
        replaced = True
        os.fsync(adapter_fd)
        saved = _read_index_bytes_at(adapter_fd)
        if (
            saved is None
            or saved[0] != content
            or saved[1].uid != os.geteuid()
            or saved[1].mode != INDEX_FILE_MODE
        ):
            raise RunSafetyError(
                "adapter index atomic replacement could not be verified"
            )
        return saved[1]
    except RunSafetyError:
        raise
    except OSError as error:
        operation = "commit" if replaced else "prepare"
        raise RunSafetyError(
            f"adapter index atomic {operation} failed: {error}"
        ) from error
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary_visible:
            try:
                os.unlink(temporary_name, dir_fd=adapter_fd)
            except FileNotFoundError:
                pass


@contextlib.contextmanager
def _index_transaction(
    repo_root: pathlib.Path,
    *,
    write: bool,
    commit_time: str | None = None,
    context: str = "adapter index update",
) -> Iterator[AdapterIndex]:
    repo_fd: int | None = None
    codex_tmp_fd: int | None = None
    adapter_fd: int | None = None
    lock_fd: int | None = None
    locked = False
    try:
        repo_fd, codex_tmp_fd, adapter_fd = _open_index_directories(repo_root)
        lock_fd = _open_index_lock(adapter_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
        locked = True
        _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
        _revalidate_index_lock(adapter_fd, lock_fd)
        loaded = _read_index_bytes_at(adapter_fd)
        if loaded is None:
            index = _index_template()
            expected_version = None
        else:
            content, expected_version = loaded
            index = _decode_index(content, _index_path(repo_root))
        original_snapshot = _canonical_index_snapshot(index)
        yield index
        if write and _canonical_index_snapshot(index) != original_snapshot:
            _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
            _revalidate_index_lock(adapter_fd, lock_fd)
            _atomic_save_index_at(
                adapter_fd,
                index,
                expected_version,
                transaction_time=commit_time,
                context=context,
            )
            _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
            _revalidate_index_lock(adapter_fd, lock_fd)
    finally:
        if lock_fd is not None:
            if locked:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        if adapter_fd is not None:
            os.close(adapter_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        if repo_fd is not None:
            os.close(repo_fd)


def _success_hook_response() -> int:
    print("{}")
    return 0


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(value, 0)


def _hook_log_dir() -> pathlib.Path:
    return pathlib.Path.home() / ".codex" / "log"


def _hook_log_path() -> pathlib.Path:
    return _hook_log_dir() / f"{HOOK_LOG_BASE_NAME}.jsonl"


def _hook_log_slot_path(slot: int) -> pathlib.Path:
    return _hook_log_dir() / f"{HOOK_LOG_BASE_NAME}.{slot}.jsonl"


def _hook_log_archive_path(ts: str) -> pathlib.Path:
    return _hook_log_dir() / f"{HOOK_LOG_BASE_NAME}-{ts}.jsonl.zst"


def _hook_log_lock_path() -> pathlib.Path:
    return _hook_log_dir() / f"{HOOK_LOG_BASE_NAME}.lock"


def _hook_log_prune_stamp_path() -> pathlib.Path:
    return _hook_log_dir() / f"{HOOK_LOG_BASE_NAME}.prune-stamp"


def _hook_archive_glob() -> str:
    return f"{HOOK_LOG_BASE_NAME}-*.jsonl.zst"


def _hook_archive_fallback_glob() -> str:
    return f"{HOOK_LOG_BASE_NAME}-*.jsonl"


def _hook_archive_label(path: pathlib.Path) -> str:
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{ts}-{uuid.uuid4().hex[:12]}-{path.stem}"


def _compress_hook_log(path: pathlib.Path) -> None:
    zstd = shutil.which("zstd")
    archive = _hook_log_archive_path(_hook_archive_label(path))
    if zstd is None:
        archive = archive.with_suffix("")
        path.replace(archive)
        return
    completed = subprocess.run(
        [zstd, "-q", "-f", str(path), "-o", str(archive)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode == 0:
        path.unlink(missing_ok=True)
        return
    archive = archive.with_suffix("")
    path.replace(archive)


def _prune_hook_archives_unlocked(*, now: dt.datetime | None = None) -> None:
    retention_days = _int_env(HOOK_LOG_RETENTION_DAYS_ENV, HOOK_LOG_RETENTION_DAYS)
    current_time = now or dt.datetime.now(dt.timezone.utc)
    cutoff = current_time - dt.timedelta(days=retention_days)
    for pattern in (_hook_archive_glob(), _hook_archive_fallback_glob()):
        for path in _hook_log_dir().glob(pattern):
            modified = dt.datetime.fromtimestamp(
                path.stat().st_mtime, tz=dt.timezone.utc
            )
            if modified < cutoff:
                path.unlink(missing_ok=True)


def _prune_hook_archives_if_due_unlocked() -> None:
    current_time = dt.datetime.now(dt.timezone.utc)
    stamp_path = _hook_log_prune_stamp_path()
    if stamp_path.exists():
        last_prune = dt.datetime.fromtimestamp(
            stamp_path.stat().st_mtime, tz=dt.timezone.utc
        )
        if current_time - last_prune < HOOK_LOG_PRUNE_INTERVAL:
            return
    _prune_hook_archives_unlocked(now=current_time)
    stamp_path.touch()


def _rotate_hook_logs_unlocked() -> None:
    total_slots = max(
        _int_env(HOOK_LOG_UNCOMPRESSED_SLOTS_ENV, HOOK_LOG_UNCOMPRESSED_SLOTS), 1
    )
    active_path = _hook_log_path()
    rotated_slots = total_slots - 1
    if rotated_slots == 0:
        if active_path.exists():
            _compress_hook_log(active_path)
        return
    tail_path = _hook_log_slot_path(rotated_slots)
    if tail_path.exists():
        _compress_hook_log(tail_path)
    for slot in range(rotated_slots - 1, 0, -1):
        source = _hook_log_slot_path(slot)
        if source.exists():
            source.replace(_hook_log_slot_path(slot + 1))
    if active_path.exists():
        active_path.replace(_hook_log_slot_path(1))


def _append_hook_log(entry: dict[str, object]) -> None:
    log_dir = _hook_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    lock_path = _hook_log_lock_path()
    with lock_path.open("a", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            active_path = _hook_log_path()
            encoded = json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
            encoded_bytes = encoded.encode("utf-8")
            max_bytes = _hook_log_max_bytes()
            if (
                active_path.exists()
                and active_path.stat().st_size + len(encoded_bytes) > max_bytes
            ):
                _rotate_hook_logs_unlocked()
            with active_path.open("ab") as handle:
                handle.write(encoded_bytes)
            _prune_hook_archives_if_due_unlocked()
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _preview_text(value: object, *, limit: int = 240) -> str | None:
    """Retain the legacy formatter for import compatibility.

    Hook diagnostics intentionally no longer call this helper.
    """
    if not isinstance(value, str):
        return None
    preview = value.replace("\n", "\\n")
    if len(preview) > limit:
        return preview[: limit - 3] + "..."
    return preview


def _hook_log_event(error: Exception) -> dict[str, object]:
    payload: dict[str, object] = {}
    hook_payload = getattr(error, "hook_payload", None)
    if isinstance(hook_payload, dict):
        payload = cast(dict[str, object], hook_payload)
    traceback_text = ""
    if not isinstance(error, UserError):
        traceback_text = traceback.format_exc()
    return {
        "ts": _utc_now(),
        "hook_command": getattr(error, "hook_command", None),
        "session_id": payload.get("session_id"),
        "cwd": payload.get("cwd"),
        "transcript_path": payload.get("transcript_path"),
        "permission_mode": payload.get("permission_mode"),
        "stop_hook_active": payload.get("stop_hook_active"),
        "prompt_preview": None,
        "assistant_preview": None,
        "error_type": type(error).__name__,
        "error_message": str(error),
        "traceback_tail": traceback_text[-4000:] if traceback_text else None,
    }


def _record_hook_failure(error: Exception) -> dict[str, object]:
    event = _hook_log_event(error)
    try:
        _append_hook_log(event)
    except Exception as log_error:
        if os.environ.get(HOOK_DEBUG_ENV):
            try:
                print(
                    f"waited-delivery hook diagnostics write failed: {log_error}",
                    file=sys.stderr,
                )
            except Exception:
                pass
    return event


def _fail_open_hook_response(error: Exception) -> int:
    event = _record_hook_failure(error)
    if os.environ.get(HOOK_DEBUG_ENV):
        try:
            print(
                f"waited-delivery hook fail-open ({event['hook_command']}): {error}",
                file=sys.stderr,
            )
        except Exception:
            pass
    return _success_hook_response()


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _regular_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _open_absolute_directory(path: pathlib.Path) -> int:
    if not path.is_absolute():
        raise RunSafetyError("repository root must be absolute")
    current_fd = os.open("/", _directory_open_flags())
    try:
        for component in path.parts[1:]:
            next_fd = os.open(
                component,
                _directory_open_flags(),
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _open_directory_at(parent_fd: int, name: str) -> int:
    return os.open(name, _directory_open_flags(), dir_fd=parent_fd)


def _descriptor_has_extended_acl(file_fd: int, *, label: str) -> bool:
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        acl_get_fd_np = libc.acl_get_fd_np
        acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        acl_get_fd_np.restype = ctypes.c_void_p
        acl_free = libc.acl_free
        acl_free.argtypes = [ctypes.c_void_p]
        acl_free.restype = ctypes.c_int
        ctypes.set_errno(0)
        acl = acl_get_fd_np(file_fd, 0x00000100)
        if not acl:
            error_number = ctypes.get_errno()
            if error_number in {
                errno.ENOENT,
                getattr(errno, "ENODATA", errno.ENOENT),
                errno.ENOTSUP,
                getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
            }:
                return False
            raise RunSafetyError(f"{label} extended ACL cannot be inspected safely")
        if acl_free(acl) != 0:
            raise RunSafetyError(f"{label} extended ACL inspection cleanup failed")
        return True
    if sys.platform.startswith("linux"):
        getxattr = getattr(os, "getxattr", None)
        if getxattr is None:
            raise RunSafetyError(
                f"{label} POSIX ACL inspection is unavailable on this runtime"
            )
        for attribute in (
            "system.posix_acl_access",
            "system.posix_acl_default",
        ):
            try:
                getxattr(file_fd, attribute)
            except OSError as error:
                if error.errno in {
                    getattr(errno, "ENODATA", -1),
                    getattr(errno, "ENOATTR", -1),
                    errno.ENOTSUP,
                    getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
                }:
                    continue
                raise RunSafetyError(
                    f"{label} POSIX ACL cannot be inspected safely"
                ) from error
            except (TypeError, ValueError) as error:
                raise RunSafetyError(
                    f"{label} POSIX ACL cannot be inspected descriptor-relatively"
                ) from error
            return True
        return False
    raise RunSafetyError(
        f"{label} ACL inspection is unsupported on platform {sys.platform}"
    )


def _require_no_extended_acl(file_fd: int, *, label: str) -> None:
    if _descriptor_has_extended_acl(file_fd, label=label):
        raise RunSafetyError(f"{label} must not carry a named or extended ACL")


def _require_owned_nonwritable_directory(
    directory_fd: int,
    *,
    label: str,
) -> RunDirectoryIdentity:
    try:
        directory_stat = os.fstat(directory_fd)
    except OSError as error:
        raise RunSafetyError(f"{label} cannot be inspected safely") from error
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise RunSafetyError(f"{label} must be a directory")
    identity = _run_directory_identity(directory_stat)
    if identity.uid != os.geteuid():
        raise RunSafetyError(f"{label} must be owned by the current user")
    if identity.mode & UNTRUSTED_WRITE_MASK:
        raise RunSafetyError(
            f"{label} must not be writable by group or other users"
        )
    _require_no_extended_acl(directory_fd, label=label)
    return identity


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _bound_directory_identity(
    parent_fd: int,
    name: str,
    directory_fd: int,
    *,
    label: str,
) -> RunDirectoryIdentity:
    try:
        descriptor_stat = os.fstat(directory_fd)
        named_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise RunSafetyError(f"{label} directory binding cannot be restated") from error
    if (
        not stat.S_ISDIR(descriptor_stat.st_mode)
        or not stat.S_ISDIR(named_stat.st_mode)
        or not _same_object(descriptor_stat, named_stat)
    ):
        raise RunSafetyError(f"{label} directory binding changed")
    descriptor_identity = _require_owned_nonwritable_directory(
        directory_fd,
        label=label,
    )
    if descriptor_identity != _run_directory_identity(named_stat):
        raise RunSafetyError(f"{label} directory access identity changed")
    return descriptor_identity


def _revalidate_bound_directory(
    parent_fd: int,
    name: str,
    directory_fd: int,
    expected: RunDirectoryIdentity,
    *,
    label: str,
) -> None:
    if (
        _bound_directory_identity(
            parent_fd,
            name,
            directory_fd,
            label=label,
        )
        != expected
    ):
        raise RunSafetyError(f"{label} directory identity changed")


def _run_directory_identity(file_stat: os.stat_result) -> RunDirectoryIdentity:
    return RunDirectoryIdentity(
        device=file_stat.st_dev,
        inode=file_stat.st_ino,
        uid=file_stat.st_uid,
        gid=file_stat.st_gid,
        mode=stat.S_IMODE(file_stat.st_mode),
    )


def _harden_legacy_run_directory(
    run_fd: int,
    identity: RunDirectoryIdentity,
) -> RunDirectoryIdentity:
    if identity.uid != os.geteuid():
        raise RunSafetyError("active run directory must be owned by the current user")
    if identity.mode == RUN_DIRECTORY_MODE:
        return identity
    if identity.mode != LEGACY_RUN_DIRECTORY_MODE:
        raise RunSafetyError(
            "active run directory must use mode 0700 or owned legacy mode 0755"
        )
    try:
        os.fchmod(run_fd, RUN_DIRECTORY_MODE)
        hardened = _run_directory_identity(os.fstat(run_fd))
    except OSError as error:
        raise RunSafetyError(
            "cannot tighten owned legacy active run directory to mode 0700"
        ) from error
    if (
        hardened.device,
        hardened.inode,
        hardened.uid,
        hardened.gid,
    ) != (
        identity.device,
        identity.inode,
        identity.uid,
        identity.gid,
    ) or hardened.mode != RUN_DIRECTORY_MODE:
        raise RunSafetyError(
            "active run directory object or access identity changed while "
            "tightening legacy mode"
        )
    return hardened


def _open_stop_run_directory(repo_root: pathlib.Path, run_name: str) -> int:
    try:
        repo_fd = _open_absolute_directory(repo_root)
    except OSError as error:
        raise RunSafetyError(
            "repository path contains a symlink, non-directory, or missing component"
        ) from error
    codex_tmp_fd: int | None = None
    runs_fd: int | None = None
    try:
        _require_owned_nonwritable_directory(
            repo_fd,
            label="repository root",
        )
        codex_tmp_fd = _open_directory_at(repo_fd, ".codex-tmp")
        _bound_directory_identity(
            repo_fd,
            ".codex-tmp",
            codex_tmp_fd,
            label="run .codex-tmp parent",
        )
        runs_fd = _open_directory_at(codex_tmp_fd, RUNS_DIR_NAME)
        _bound_directory_identity(
            codex_tmp_fd,
            RUNS_DIR_NAME,
            runs_fd,
            label="waited-delivery parent",
        )
        run_fd = _open_directory_at(runs_fd, run_name)
        try:
            _bound_directory_identity(
                runs_fd,
                run_name,
                run_fd,
                label="active run",
            )
        except Exception:
            os.close(run_fd)
            raise
        return run_fd
    except OSError as error:
        raise RunSafetyError(
            "active run path contains a symlink, non-directory, or missing component"
        ) from error
    finally:
        if runs_fd is not None:
            os.close(runs_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        os.close(repo_fd)


def _read_stop_regular_artifact(
    run_fd: int,
    name: str,
    *,
    max_bytes: int,
) -> StopArtifactRead:
    try:
        file_fd = os.open(name, _regular_open_flags(), dir_fd=run_fd)
    except OSError as error:
        raise RunSafetyError(
            f"active run artifact cannot be opened without following links: {name}"
        ) from error
    try:
        before = os.fstat(file_fd)
        try:
            named_before = os.stat(
                name,
                dir_fd=run_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise RunSafetyError(
                f"active run artifact cannot be restated without following links: {name}"
            ) from error
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named_before.st_mode)
            or not _same_object(before, named_before)
        ):
            raise RunSafetyError(f"active run artifact must be a regular file: {name}")
        if before.st_uid != os.geteuid() or named_before.st_uid != os.geteuid():
            raise RunSafetyError(
                f"active run artifact must be owned by the current user: {name}"
            )
        if (
            stat.S_IMODE(before.st_mode) & UNTRUSTED_WRITE_MASK
            or stat.S_IMODE(named_before.st_mode) & UNTRUSTED_WRITE_MASK
        ):
            raise RunSafetyError(
                "active run artifact must not be writable by group or other "
                f"users: {name}"
            )
        _require_no_extended_acl(file_fd, label=f"active run artifact {name}")
        if before.st_size > max_bytes:
            raise RunSafetyError(f"active run artifact exceeds byte limit: {name}")
        expected_access = (
            before.st_uid,
            before.st_gid,
            stat.S_IMODE(before.st_mode),
        )

        def read_bounded() -> bytes:
            chunks: list[bytes] = []
            retained = 0
            while True:
                chunk = os.read(file_fd, min(65536, max_bytes + 1 - retained))
                if not chunk:
                    break
                chunks.append(chunk)
                retained += len(chunk)
                if retained > max_bytes:
                    raise RunSafetyError(
                        f"active run artifact exceeds byte limit: {name}"
                    )
            return b"".join(chunks)

        first_content = read_bounded()
        middle = os.fstat(file_fd)
        os.lseek(file_fd, 0, os.SEEK_SET)
        second_content = read_bounded()
        after = os.fstat(file_fd)
        try:
            named_after = os.stat(
                name,
                dir_fd=run_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise RunSafetyError(
                f"active run artifact cannot be restated without following links: {name}"
            ) from error
        stable_stats = (before, named_before, middle, after, named_after)
        if (
            any(not stat.S_ISREG(value.st_mode) for value in stable_stats)
            or any(not _same_object(before, value) for value in stable_stats[1:])
            or any(value.st_size != before.st_size for value in stable_stats[1:])
            or any(
                (
                    value.st_uid,
                    value.st_gid,
                    stat.S_IMODE(value.st_mode),
                )
                != expected_access
                for value in stable_stats[1:]
            )
            or len(first_content) != before.st_size
            or len(second_content) != before.st_size
            or hashlib.sha256(first_content).digest()
            != hashlib.sha256(second_content).digest()
            or first_content != second_content
        ):
            raise RunSafetyError(
                f"active run artifact identity, access, size, or content changed "
                f"while read: {name}"
            )
        _require_no_extended_acl(file_fd, label=f"active run artifact {name}")
        return StopArtifactRead(
            content=second_content,
            version=StopArtifactVersion(
                device=after.st_dev,
                inode=after.st_ino,
                uid=after.st_uid,
                gid=after.st_gid,
                mode=stat.S_IMODE(after.st_mode),
                size=after.st_size,
                sha256=hashlib.sha256(second_content).hexdigest(),
            ),
        )
    except RunSafetyError:
        raise
    except OSError as error:
        raise RunSafetyError(
            f"active run artifact cannot be read stably: {name}"
        ) from error
    finally:
        os.close(file_fd)


def _read_stop_regular_file(
    run_fd: int,
    name: str,
    *,
    max_bytes: int,
) -> bytes:
    return _read_stop_regular_artifact(
        run_fd,
        name,
        max_bytes=max_bytes,
    ).content


def _read_stop_absolute_regular_artifact(
    path: pathlib.Path,
    *,
    max_bytes: int,
) -> StopArtifactRead:
    if not path.is_absolute() or not path.name:
        raise RunSafetyError("absolute artifact path is required")
    try:
        parent_fd = _open_absolute_directory(path.parent)
    except OSError as error:
        raise RunSafetyError(
            f"absolute artifact parent cannot be opened without following links: {path}"
        ) from error
    try:
        _require_owned_nonwritable_directory(
            parent_fd,
            label=f"absolute artifact parent {path.parent}",
        )
        return _read_stop_regular_artifact(
            parent_fd,
            path.name,
            max_bytes=max_bytes,
        )
    finally:
        os.close(parent_fd)


@contextlib.contextmanager
def _verified_refresh_launch_sources() -> Iterator[RefreshLaunchSources]:
    bound_bridge = _read_stop_absolute_regular_artifact(
        BRIDGE_PATH,
        max_bytes=STATE_MAX_BYTES,
    )
    bound_runner = _read_stop_absolute_regular_artifact(
        RUNNER_PATH,
        max_bytes=STATE_MAX_BYTES,
    )
    yield RefreshLaunchSources(
        bridge=LaunchArtifactSource(
            source_path=BRIDGE_PATH,
            source_version=bound_bridge.version,
            content=bound_bridge.content,
        ),
        runner=LaunchArtifactSource(
            source_path=RUNNER_PATH,
            source_version=bound_runner.version,
            content=bound_runner.content,
        ),
    )


def _validate_launch_artifact_version(
    name: str,
    actual: StopArtifactVersion,
    expected: StopArtifactVersion,
) -> None:
    if (actual.device, actual.inode) != (expected.device, expected.inode):
        raise RunSafetyError(
            f"compatibility launch source was replaced before process start: {name}"
        )
    if (actual.uid, actual.gid, actual.mode) != (
        expected.uid,
        expected.gid,
        expected.mode,
    ):
        raise RunSafetyError(
            f"compatibility launch source access policy changed before process "
            f"start: {name}"
        )
    if actual.size != expected.size or actual.sha256 != expected.sha256:
        raise RunSafetyError(
            f"compatibility launch source content changed before process start: {name}"
        )


def _revalidate_refresh_launch_sources(
    sources: RefreshLaunchSources,
) -> None:
    for name, source in (
        ("waited_delivery_bridge.py", sources.bridge),
        ("waited_delivery_runner.py", sources.runner),
    ):
        current = _read_stop_absolute_regular_artifact(
            source.source_path,
            max_bytes=STATE_MAX_BYTES,
        )
        _validate_launch_artifact_version(
            name,
            current.version,
            source.source_version,
        )


def _refresh_source_frame(sources: RefreshLaunchSources) -> bytes:
    bridge_content = sources.bridge.content
    runner_content = sources.runner.content
    if (
        not bridge_content
        or len(bridge_content) > STATE_MAX_BYTES
        or not runner_content
        or len(runner_content) > STATE_MAX_BYTES
    ):
        raise RunSafetyError(
            "compatibility launch source is outside the source-frame byte bound"
        )
    return b"".join(
        (
            SOURCE_FRAME_MAGIC,
            len(bridge_content).to_bytes(8, "big"),
            hashlib.sha256(bridge_content).digest(),
            len(runner_content).to_bytes(8, "big"),
            hashlib.sha256(runner_content).digest(),
            bridge_content,
            runner_content,
        )
    )


def _isolated_python_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("PYTHON") and name != "__PYVENV_LAUNCHER__"
    }


def _expected_version_args(
    prefix: str,
    version: StopArtifactVersion,
) -> list[str]:
    return [
        f"--expected-{prefix}-dev",
        str(version.device),
        f"--expected-{prefix}-ino",
        str(version.inode),
        f"--expected-{prefix}-uid",
        str(version.uid),
        f"--expected-{prefix}-gid",
        str(version.gid),
        f"--expected-{prefix}-mode",
        str(version.mode),
        f"--expected-{prefix}-size",
        str(version.size),
        f"--expected-{prefix}-sha256",
        version.sha256,
    ]


def _run_refresh_bridge_json(
    sources: RefreshLaunchSources,
    *args: str,
) -> dict[str, object]:
    completed = _run_bound_bridge_process(
        sources,
        "refresh-prompts-live",
        "--published-bridge-path",
        str(BRIDGE_PATH),
        "--published-runner-path",
        str(RUNNER_PATH),
        *_expected_version_args(
            "bridge",
            sources.bridge.source_version,
        ),
        *_expected_version_args(
            "runner",
            sources.runner.source_version,
        ),
        *args,
    )
    return _bridge_json_payload(completed)


def _run_bound_bridge_process(
    sources: RefreshLaunchSources,
    *args: str,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess[str]:
    _revalidate_refresh_launch_sources(sources)
    command = [
        sys.executable,
        "-I",
        "-B",
        "-S",
        "-c",
        SOURCE_PIPE_BOOTSTRAP,
        str(BRIDGE_PATH),
        str(RUNNER_PATH),
        *args,
    ]
    return _run_bounded_refresh_process(
        command,
        pass_fds=pass_fds,
        env=_isolated_python_environment(),
        input_bytes=_refresh_source_frame(sources),
    )


def _stop_artifact_version_from_payload(
    payload: dict[str, object],
    field: str,
) -> StopArtifactVersion:
    raw_version = payload.get(field)
    if not isinstance(raw_version, dict):
        raise RunSafetyError(f"refresh-prompts-live did not return {field}")
    version = cast(dict[str, object], raw_version)
    integer_fields = ("device", "inode", "uid", "gid", "mode", "size")
    integer_values = tuple(version.get(name) for name in integer_fields)
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in integer_values
    ):
        raise RunSafetyError(
            f"refresh-prompts-live returned an invalid {field} identity"
        )
    sha256 = version.get("sha256")
    if (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise RunSafetyError(f"refresh-prompts-live returned an invalid {field} digest")
    return StopArtifactVersion(
        device=cast(int, integer_values[0]),
        inode=cast(int, integer_values[1]),
        uid=cast(int, integer_values[2]),
        gid=cast(int, integer_values[3]),
        mode=cast(int, integer_values[4]),
        size=cast(int, integer_values[5]),
        sha256=sha256,
    )


def _validate_expected_stop_artifact(
    name: str,
    actual: StopArtifactVersion,
    expected: StopArtifactVersion,
) -> None:
    if (actual.device, actual.inode) != (expected.device, expected.inode):
        raise RunSafetyError(
            f"active run artifact was replaced after prompt refresh: {name}"
        )
    if (actual.uid, actual.gid, actual.mode) != (
        expected.uid,
        expected.gid,
        expected.mode,
    ):
        raise RunSafetyError(
            f"active run artifact access policy changed after prompt refresh: {name}"
        )
    if actual.size != expected.size or actual.sha256 != expected.sha256:
        raise RunSafetyError(
            f"active run artifact content changed after prompt refresh: {name}"
        )


def _validate_stop_run_state_descriptor(
    repo_root: pathlib.Path,
    run_dir: pathlib.Path,
    run_fd: int,
    *,
    expected_identity: RunDirectoryIdentity | None = None,
    expected_prompt_versions: dict[str, StopArtifactVersion] | None = None,
) -> tuple[dict[str, object], RunDirectoryIdentity]:
    pinned = os.fstat(run_fd)
    if not stat.S_ISDIR(pinned.st_mode):
        raise RunSafetyError("active run path must end in a directory")
    _require_no_extended_acl(run_fd, label="active run directory")
    pinned_identity = _run_directory_identity(pinned)
    if expected_identity is not None:
        if (
            pinned_identity.device,
            pinned_identity.inode,
        ) != (
            expected_identity.device,
            expected_identity.inode,
        ):
            raise RunSafetyError(
                "active run directory object changed during validation"
            )
        if pinned_identity != expected_identity:
            raise RunSafetyError(
                "active run directory access identity changed during validation"
            )
    else:
        pinned_identity = _harden_legacy_run_directory(run_fd, pinned_identity)
    if (
        pinned_identity.uid != os.geteuid()
        or pinned_identity.mode != RUN_DIRECTORY_MODE
    ):
        raise RunSafetyError(
            "active run directory must be owned by the current user with mode 0700"
        )
    try:
        payload = json.loads(
            _read_stop_regular_file(
                run_fd,
                "state.json",
                max_bytes=STATE_MAX_BYTES,
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunSafetyError("active run state.json is invalid") from error
    if not isinstance(payload, dict):
        raise RunSafetyError("active run state.json must contain an object")
    if payload.get("repo_root") != str(repo_root):
        raise RunSafetyError(
            "active run state repo_root does not exactly match the current repository"
        )
    prompt_names = ("child-prompt.md", "parent-prompt.md")
    if expected_prompt_versions is not None and set(expected_prompt_versions) != set(
        prompt_names
    ):
        raise RunSafetyError(
            "prompt refresh did not return complete child and parent versions"
        )
    for prompt_name in prompt_names:
        prompt = _read_stop_regular_artifact(
            run_fd,
            prompt_name,
            max_bytes=STATE_MAX_BYTES,
        )
        if expected_prompt_versions is not None:
            _validate_expected_stop_artifact(
                prompt_name,
                prompt.version,
                expected_prompt_versions[prompt_name],
            )
    current_fd = _open_stop_run_directory(repo_root, run_dir.name)
    try:
        current = os.fstat(current_fd)
        current_identity = _run_directory_identity(current)
        if not stat.S_ISDIR(current.st_mode) or current_identity != pinned_identity:
            raise RunSafetyError(
                "active run directory was replaced or its access identity "
                "changed during validation"
            )
    finally:
        os.close(current_fd)
    _require_no_extended_acl(run_fd, label="active run directory")
    return cast(dict[str, object], payload), pinned_identity


def _load_stop_run_state(
    repo_root: pathlib.Path,
    run_dir_str: str,
) -> tuple[
    pathlib.Path,
    dict[str, object],
    RunDirectoryIdentity,
    int,
]:
    run_dir = pathlib.Path(run_dir_str)
    if not run_dir.is_absolute():
        raise RunSafetyError("active run_dir must be absolute")
    expected_runs_root = repo_root / ".codex-tmp" / RUNS_DIR_NAME
    if (
        run_dir.parent != expected_runs_root
        or not run_dir.name
        or run_dir.name in {".", ".."}
        or pathlib.PurePath(run_dir.name).name != run_dir.name
    ):
        raise RunSafetyError(
            "active run_dir is outside the current repository waited-delivery root"
        )
    run_fd = _open_stop_run_directory(repo_root, run_dir.name)
    try:
        state, run_identity = _validate_stop_run_state_descriptor(
            repo_root,
            run_dir,
            run_fd,
        )
    except Exception:
        os.close(run_fd)
        raise
    return run_dir, state, run_identity, run_fd


def _refresh_recovery_prompts(
    run_dir: pathlib.Path,
    repo_root: pathlib.Path,
    run_identity: RunDirectoryIdentity,
) -> RefreshedPrompts:
    with _verified_refresh_launch_sources() as sources:
        payload = _run_refresh_bridge_json(
            sources,
            "--run-dir",
            str(run_dir),
            "--expected-repo-root",
            str(repo_root),
            "--expected-run-dev",
            str(run_identity.device),
            "--expected-run-ino",
            str(run_identity.inode),
            "--expected-run-uid",
            str(run_identity.uid),
            "--expected-run-gid",
            str(run_identity.gid),
            "--expected-run-mode",
            str(run_identity.mode),
        )
        if payload.get("refresh_schema_version") != PROMPT_REFRESH_SCHEMA_VERSION:
            raise RunSafetyError(
                "refresh-prompts-live returned an unsupported refresh schema"
            )
        if payload.get("python_isolated") is not True:
            raise RunSafetyError(
                "refresh-prompts-live did not attest isolated Python execution"
            )
        for field in ("bridge_source_transport", "runner_source_transport"):
            if payload.get(field) != "anonymous-pipe-memory":
                raise RunSafetyError(
                    f"refresh-prompts-live did not attest anonymous in-memory {field}"
                )
        for field in ("bridge_source_reopenable", "runner_source_reopenable"):
            if payload.get(field) is not False:
                raise RunSafetyError(
                    f"refresh-prompts-live did not attest non-reopenable {field}"
                )
        expected_paths = {
            "runner_path": RUNNER_PATH,
            "compiled_bridge_path": BRIDGE_PATH,
            "compiled_runner_path": RUNNER_PATH,
            "child_prompt": run_dir / "child-prompt.md",
            "parent_prompt": run_dir / "parent-prompt.md",
        }
        for field, expected_path in expected_paths.items():
            value = payload.get(field)
            if not isinstance(value, str) or not value:
                raise RunSafetyError(f"refresh-prompts-live did not return {field}")
            if pathlib.Path(value) != expected_path:
                raise RunSafetyError(
                    f"refresh-prompts-live returned unexpected {field}: {value}"
                )
        bridge_version = _stop_artifact_version_from_payload(
            payload,
            "bridge_version",
        )
        runner_version = _stop_artifact_version_from_payload(
            payload,
            "runner_version",
        )
        child_version = _stop_artifact_version_from_payload(
            payload,
            "child_prompt_version",
        )
        parent_version = _stop_artifact_version_from_payload(
            payload,
            "parent_prompt_version",
        )
        _validate_launch_artifact_version(
            "waited_delivery_bridge.py bound source",
            bridge_version,
            sources.bridge.source_version,
        )
        _validate_launch_artifact_version(
            "waited_delivery_runner.py bound source",
            runner_version,
            sources.runner.source_version,
        )
        returned_identity_values = (
            payload.get("run_dev"),
            payload.get("run_ino"),
            payload.get("run_uid"),
            payload.get("run_gid"),
            payload.get("run_mode"),
        )
        if not all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in returned_identity_values
        ):
            raise RunSafetyError(
                "refresh-prompts-live did not return a complete run access identity"
            )
        returned_identity = RunDirectoryIdentity(
            device=cast(int, returned_identity_values[0]),
            inode=cast(int, returned_identity_values[1]),
            uid=cast(int, returned_identity_values[2]),
            gid=cast(int, returned_identity_values[3]),
            mode=cast(int, returned_identity_values[4]),
        )
        if returned_identity != run_identity:
            raise RunSafetyError(
                "refresh-prompts-live returned an unexpected run directory identity"
            )
        return RefreshedPrompts(
            child_prompt=expected_paths["child_prompt"],
            child_version=child_version,
            parent_prompt=expected_paths["parent_prompt"],
            parent_version=parent_version,
        )


def _state_orchestration(state: dict[str, object]) -> dict[str, object]:
    orchestration = state.get("orchestration")
    if isinstance(orchestration, dict):
        return cast(dict[str, object], orchestration)
    return {}


def _state_phase_statuses(state: dict[str, object]) -> list[str]:
    phases = state.get("phases")
    if not isinstance(phases, dict):
        return []
    statuses: list[str] = []
    for raw_phase in phases.values():
        if not isinstance(raw_phase, dict):
            return []
        status = raw_phase.get("status")
        if not isinstance(status, str):
            return []
        statuses.append(status)
    return statuses


def _run_is_terminal(state: dict[str, object]) -> bool:
    overall_status = state.get("overall_status")
    orchestration = _state_orchestration(state)
    child_status = orchestration.get("child_status")
    child_session_id = orchestration.get("child_session_id")
    phases = state.get("phases")
    internal_review = (
        phases.get("internal_review") if isinstance(phases, dict) else None
    )
    phase_statuses = _state_phase_statuses(state)
    return (
        isinstance(overall_status, str)
        and overall_status != "pending"
        and child_status in CHILD_TERMINAL_STATUSES
        and isinstance(child_session_id, str)
        and bool(child_session_id.strip())
        and isinstance(internal_review, dict)
        and internal_review.get("status") in TERMINAL_PHASE_STATUSES
        and bool(phase_statuses)
        and all(status in TERMINAL_PHASE_STATUSES for status in phase_statuses)
    )


def _selector_label(value: str | None, *, label: str) -> str | None:
    if value:
        return f"{label}={value}"
    return None


def _current_thread_session_id() -> str | None:
    value = os.environ.get(CURRENT_THREAD_ENV)
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return normalized


def _record_preview(record: SessionRecord) -> str:
    parts = [record["session_id"]]
    if record["transcript_path"]:
        parts.append(f"transcript={record['transcript_path']}")
    if record["last_prompt"]:
        preview = record["last_prompt"].replace("\n", "\\n")
        if len(preview) > 80:
            preview = preview[:77] + "..."
        parts.append(f"prompt={preview}")
    return " | ".join(parts)


def _select_unique_record(
    candidates: list[SessionRecord], *, reason: str, repo_root: pathlib.Path
) -> SessionRecord:
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise UserError(
            "no observed Codex session matches the requested selector; "
            f"inspect `{_index_path(repo_root)}` with `show-index` to choose the correct session"
        )
    preview = "\n".join(f"- {_record_preview(record)}" for record in candidates[:5])
    if len(candidates) > 5:
        preview += f"\n- ... ({len(candidates) - 5} more)"
    raise UserError(
        f"ambiguous session selection ({reason}); pass --session-id explicitly.\n{preview}"
    )


def _resolve_session_record(
    index: AdapterIndex,
    *,
    repo_root: pathlib.Path,
    session_id: str | None = None,
    run_dir: str | None = None,
    transcript_path: str | None = None,
    prompt_text: str | None = None,
    host_session_id: str | None = None,
) -> SessionRecord:
    sessions = index["sessions"]
    if session_id:
        record = sessions.get(session_id)
        if record is None:
            raise UserError(f"unknown session id: {session_id}")
        if run_dir and record["run_dir"] != run_dir:
            raise UserError(
                f"session {session_id} does not own run_dir={run_dir}; "
                f"current run_dir={record['run_dir'] or 'none'}"
            )
        return record
    if run_dir:
        for record in sessions.values():
            if record["run_dir"] == run_dir:
                return record
        raise UserError(
            "no observed Codex session currently owns "
            f"run_dir={run_dir}; inspect `{_index_path(repo_root)}` with `show-index` "
            "to choose the correct session"
        )
    candidates = list(sessions.values())
    if transcript_path:
        matches = [
            record
            for record in candidates
            if record["transcript_path"] == transcript_path
        ]
        return _select_unique_record(
            matches,
            reason=f"transcript_path={transcript_path}",
            repo_root=repo_root,
        )
    if prompt_text:
        matches = [
            record for record in candidates if record["last_prompt"] == prompt_text
        ]
        return _select_unique_record(
            matches,
            reason="prompt_text matched multiple observed sessions",
            repo_root=repo_root,
        )
    if host_session_id:
        record = sessions.get(host_session_id)
        if record is None:
            raise UserError(
                "current Codex thread is not recorded for this repo; "
                f"{CURRENT_THREAD_ENV}={host_session_id}. Ensure the UserPromptSubmit "
                "hook ran for this session, or pass --session-id / --transcript-path / "
                f"--prompt-text explicitly. Inspect `{_index_path(repo_root)}` with "
                "`show-index` if needed."
            )
        return record
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        latest_session_id = index.get("latest_session_id")
        latest_hint = _selector_label(latest_session_id, label="latest_session_id")
        reason = "multiple observed sessions for this repo"
        if latest_hint:
            reason = f"{reason}; {latest_hint}"
        return _select_unique_record(
            candidates,
            reason=reason,
            repo_root=repo_root,
        )
    raise UserError(
        "no observed Codex session metadata for this repo; ensure the UserPromptSubmit hook ran first"
    )


def _update_session_observation(
    index: AdapterIndex,
    *,
    session_id: str,
    cwd: str,
    transcript_path: str | None,
    permission_mode: str | None,
    prompt: str | None,
) -> SessionRecord:
    existing = index["sessions"].get(session_id)
    run_dir = existing["run_dir"] if existing else None
    if existing and existing["status"] in PREPARATION_STATUSES:
        status = existing["status"]
    else:
        status = "active" if existing and existing["run_dir"] else "observed"
    record: SessionRecord = {
        "session_id": session_id,
        "cwd": cwd,
        "transcript_path": transcript_path,
        "permission_mode": permission_mode,
        "last_prompt": prompt,
        "run_dir": run_dir,
        "status": status,
        "updated_at": _utc_now(),
        "preparation_id": existing.get("preparation_id") if existing else None,
        "preparation_run_id": (
            existing.get("preparation_run_id") if existing else None
        ),
        "preparation_lease_path": (
            existing.get("preparation_lease_path") if existing else None
        ),
        "preparation_started_at": (
            existing.get("preparation_started_at") if existing else None
        ),
        "preparation_reason": (
            existing.get("preparation_reason") if existing else None
        ),
    }
    index["sessions"][session_id] = record
    index["latest_session_id"] = session_id
    return record


def _bounded_preparation_reason(reason: str) -> str:
    sanitized = "".join(
        character
        if 0x20 <= ord(character) <= 0x7E and character not in {'"', "\\"}
        else "?"
        for character in reason
    )
    if len(sanitized) <= PREPARATION_REASON_MAX_CHARS:
        return sanitized
    digest = hashlib.sha256(sanitized.encode("ascii")).hexdigest()
    suffix = f"... [bytes={len(sanitized)} sha256={digest}]"
    retained = PREPARATION_REASON_MAX_CHARS - len(suffix)
    return sanitized[:retained] + suffix


def _preparation_recovery_argv(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> list[str]:
    return [
        sys.executable,
        str(pathlib.Path(__file__).resolve()),
        "recover-active-run",
        "--repo",
        str(repo_root),
        "--session-id",
        reservation.session_id,
        "--preparation-id",
        reservation.preparation_id,
    ]


def _preparation_recovery_message(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
    *,
    reason: str,
) -> str:
    return (
        f"{reason} Preparation {reservation.preparation_id} remains recorded at "
        f"{reservation.run_dir}. Recover it with: "
        f"{_shell_command(_preparation_recovery_argv(repo_root, reservation))}"
    )


def _reservation_from_record(record: SessionRecord) -> PreparationReservation:
    preparation_id = record.get("preparation_id")
    run_id = record.get("preparation_run_id")
    run_dir = record.get("run_dir")
    lease_path = record.get("preparation_lease_path")
    started_at = record.get("preparation_started_at")
    if not all(
        isinstance(value, str) and bool(value)
        for value in (preparation_id, run_id, run_dir, lease_path, started_at)
    ):
        raise RunSafetyError(
            f"session {record['session_id']} has an incomplete preparation reservation"
        )
    return PreparationReservation(
        session_id=record["session_id"],
        preparation_id=cast(str, preparation_id),
        run_id=cast(str, run_id),
        run_dir=cast(str, run_dir),
        lease_path=cast(str, lease_path),
        started_at=cast(str, started_at),
    )


def _require_exact_reservation(
    record: SessionRecord,
    reservation: PreparationReservation,
    *,
    allow_active: bool,
) -> None:
    allowed_statuses = set(PREPARATION_STATUSES)
    if allow_active:
        allowed_statuses.add("active")
    if (
        record["status"] not in allowed_statuses
        or record["session_id"] != reservation.session_id
        or record.get("preparation_id") != reservation.preparation_id
        or record.get("preparation_run_id") != reservation.run_id
        or record.get("preparation_lease_path") != reservation.lease_path
        or record.get("preparation_started_at") != reservation.started_at
        or record.get("run_dir") != reservation.run_dir
    ):
        raise RunSafetyError(
            "preparation reservation changed before the requested transition"
        )


def _mark_preparation_cleanup_complete(
    record: SessionRecord,
    *,
    updated_at: str,
) -> None:
    record["status"] = CLEANUP_COMPLETE_STATUS
    record["updated_at"] = updated_at
    record["preparation_reason"] = (
        "descriptor-proven run and lease absence committed; this exact cleanup "
        "tombstone may be retried or superseded by a new preparation"
    )


def _mark_preparation_recovery(
    record: SessionRecord,
    *,
    reason: str,
    updated_at: str,
) -> None:
    if record["status"] in {
        CLEANUP_PENDING_STATUS,
        CLEANUP_COMPLETE_STATUS,
    }:
        raise RunSafetyError("cleanup reservation cannot return to recovery_required")
    record["status"] = "recovery_required"
    record["updated_at"] = updated_at
    record["preparation_reason"] = _bounded_preparation_reason(reason)


def _mark_preparation_cleanup_pending(
    record: SessionRecord,
    *,
    reason: str,
    updated_at: str,
) -> None:
    record["status"] = CLEANUP_PENDING_STATUS
    record["updated_at"] = updated_at
    record["preparation_reason"] = _bounded_preparation_reason(reason)


def _activate_preparation(
    record: SessionRecord,
    *,
    updated_at: str,
) -> None:
    if record["status"] not in RECOVERABLE_PREPARATION_STATUSES | {"active"}:
        raise RunSafetyError("cleanup reservation cannot be activated")
    record["status"] = "active"
    record["updated_at"] = updated_at
    record["preparation_reason"] = None


def _clear_preparation_metadata(record: SessionRecord) -> None:
    record["preparation_id"] = None
    record["preparation_run_id"] = None
    record["preparation_lease_path"] = None
    record["preparation_started_at"] = None
    record["preparation_reason"] = None


def _complete_session_record(
    record: SessionRecord,
    *,
    updated_at: str,
) -> None:
    record["run_dir"] = None
    record["status"] = "completed"
    record["updated_at"] = updated_at
    _clear_preparation_metadata(record)


def _require_active_record(record: SessionRecord) -> None:
    if record["status"] != "active":
        raise UserError(
            f"session {record['session_id']} is {record['status']}; "
            "recover or finish its preparation before mutating the run"
        )


def _reservation_run_path(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> pathlib.Path:
    _validate_component_name(reservation.run_id, label="reserved run id")
    expected = repo_root / ".codex-tmp" / RUNS_DIR_NAME / reservation.run_id
    if pathlib.Path(reservation.run_dir) != expected:
        raise RunSafetyError(
            "preparation reservation run_dir does not match its repository and run id"
        )
    return expected


def _preparation_lease_name(preparation_id: str) -> str:
    _validate_component_name(preparation_id, label="preparation id")
    return f"prepare-{preparation_id}.lease"


def _preparation_lease_path(
    repo_root: pathlib.Path,
    preparation_id: str,
) -> pathlib.Path:
    return _adapter_dir(repo_root) / _preparation_lease_name(preparation_id)


def _preparation_lease_content(
    reservation: PreparationReservation,
) -> bytes:
    return (
        json.dumps(
            {
                "preparation_id": reservation.preparation_id,
                "run_dir": reservation.run_dir,
                "run_id": reservation.run_id,
                "schema_version": 1,
                "session_id": reservation.session_id,
                "started_at": reservation.started_at,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _validate_preparation_lease_fd(
    adapter_fd: int,
    lease_fd: int,
    reservation: PreparationReservation,
) -> None:
    name = _preparation_lease_name(reservation.preparation_id)
    expected_content = _preparation_lease_content(reservation)
    try:
        descriptor_stat = os.fstat(lease_fd)
        named_stat = os.stat(name, dir_fd=adapter_fd, follow_symlinks=False)
        content = os.pread(lease_fd, len(expected_content) + 1, 0)
    except OSError as error:
        raise RunSafetyError(
            "preparation lease cannot be revalidated through its descriptor"
        ) from error
    if (
        not stat.S_ISREG(descriptor_stat.st_mode)
        or not stat.S_ISREG(named_stat.st_mode)
        or not _same_object(descriptor_stat, named_stat)
        or descriptor_stat.st_uid != os.geteuid()
        or descriptor_stat.st_gid != named_stat.st_gid
        or stat.S_IMODE(descriptor_stat.st_mode) != INDEX_FILE_MODE
        or stat.S_IMODE(named_stat.st_mode) != INDEX_FILE_MODE
        or descriptor_stat.st_size != len(expected_content)
        or named_stat.st_size != len(expected_content)
        or content != expected_content
    ):
        raise RunSafetyError(
            "preparation lease identity, access policy, or content changed"
        )
    _require_no_extended_acl(lease_fd, label="preparation lease")


def _create_preparation_lease(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> int:
    expected_path = _preparation_lease_path(
        repo_root,
        reservation.preparation_id,
    )
    if pathlib.Path(reservation.lease_path) != expected_path:
        raise RunSafetyError(
            "preparation reservation lease path does not match its transaction id"
        )
    repo_fd: int | None = None
    codex_tmp_fd: int | None = None
    adapter_fd: int | None = None
    lease_fd: int | None = None
    lease_visible = False
    try:
        repo_fd, codex_tmp_fd, adapter_fd = _open_index_directories(repo_root)
        name = _preparation_lease_name(reservation.preparation_id)
        try:
            lease_fd = os.open(
                name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                INDEX_FILE_MODE,
                dir_fd=adapter_fd,
            )
        except OSError as error:
            raise RunSafetyError(
                "preparation lease cannot be created safely"
            ) from error
        lease_visible = True
        os.fchmod(lease_fd, INDEX_FILE_MODE)
        _write_all(lease_fd, _preparation_lease_content(reservation))
        os.fsync(lease_fd)
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
        _validate_preparation_lease_fd(adapter_fd, lease_fd, reservation)
        os.fsync(adapter_fd)
        lease_visible = False
        result = lease_fd
        lease_fd = None
        return result
    except Exception:
        if lease_visible and adapter_fd is not None and lease_fd is not None:
            try:
                _validate_preparation_lease_fd(adapter_fd, lease_fd, reservation)
                os.unlink(
                    _preparation_lease_name(reservation.preparation_id),
                    dir_fd=adapter_fd,
                )
                os.fsync(adapter_fd)
            except Exception:
                pass
        raise
    finally:
        if lease_fd is not None:
            os.close(lease_fd)
        if adapter_fd is not None:
            os.close(adapter_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        if repo_fd is not None:
            os.close(repo_fd)


def _acquire_preparation_lease(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> int:
    expected_path = _preparation_lease_path(
        repo_root,
        reservation.preparation_id,
    )
    if pathlib.Path(reservation.lease_path) != expected_path:
        raise RunSafetyError(
            "preparation reservation lease path does not match its transaction id"
        )
    repo_fd: int | None = None
    codex_tmp_fd: int | None = None
    adapter_fd: int | None = None
    lease_fd: int | None = None
    try:
        repo_fd, codex_tmp_fd, adapter_fd = _open_index_directories(repo_root)
        try:
            lease_fd = os.open(
                _preparation_lease_name(reservation.preparation_id),
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=adapter_fd,
            )
        except OSError as error:
            raise RunSafetyError(
                "preparation lease is missing or cannot be opened safely; "
                "writer quiescence is unproven"
            ) from error
        _validate_preparation_lease_fd(adapter_fd, lease_fd, reservation)
        try:
            fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RunSafetyError(
                "preparation lease is still held; the bridge or runner may still "
                "be creating the reserved run"
            ) from error
        _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
        _validate_preparation_lease_fd(adapter_fd, lease_fd, reservation)
        result = lease_fd
        lease_fd = None
        return result
    finally:
        if lease_fd is not None:
            os.close(lease_fd)
        if adapter_fd is not None:
            os.close(adapter_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        if repo_fd is not None:
            os.close(repo_fd)


def _remove_preparation_lease(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
    lease_fd: int,
) -> None:
    repo_fd: int | None = None
    codex_tmp_fd: int | None = None
    adapter_fd: int | None = None
    try:
        repo_fd, codex_tmp_fd, adapter_fd = _open_index_directories(repo_root)
        _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
        _validate_preparation_lease_fd(adapter_fd, lease_fd, reservation)
        os.unlink(
            _preparation_lease_name(reservation.preparation_id),
            dir_fd=adapter_fd,
        )
        os.fsync(adapter_fd)
        try:
            os.stat(
                _preparation_lease_name(reservation.preparation_id),
                dir_fd=adapter_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise RunSafetyError("preparation lease removal could not be verified")
        _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
    except OSError as error:
        raise RunSafetyError("preparation lease removal failed") from error
    finally:
        if adapter_fd is not None:
            os.close(adapter_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        if repo_fd is not None:
            os.close(repo_fd)


def _preparation_lease_entry_presence(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> LeaseEntryPresence:
    expected_path = _preparation_lease_path(
        repo_root,
        reservation.preparation_id,
    )
    if pathlib.Path(reservation.lease_path) != expected_path:
        raise RunSafetyError(
            "preparation reservation lease path does not match its transaction id"
        )
    repo_fd: int | None = None
    codex_tmp_fd: int | None = None
    adapter_fd: int | None = None
    try:
        repo_fd, codex_tmp_fd, adapter_fd = _open_index_directories(repo_root)
        _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
        try:
            os.stat(
                _preparation_lease_name(reservation.preparation_id),
                dir_fd=adapter_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            presence: LeaseEntryPresence = "absent"
        except OSError as error:
            raise RunSafetyError(
                "preparation lease presence cannot be inspected safely"
            ) from error
        else:
            presence = "present"
        _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
        return presence
    finally:
        if adapter_fd is not None:
            os.close(adapter_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        if repo_fd is not None:
            os.close(repo_fd)


def _fsync_preparation_lease_absence(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> None:
    expected_path = _preparation_lease_path(
        repo_root,
        reservation.preparation_id,
    )
    if pathlib.Path(reservation.lease_path) != expected_path:
        raise RunSafetyError(
            "preparation reservation lease path does not match its transaction id"
        )
    repo_fd: int | None = None
    codex_tmp_fd: int | None = None
    adapter_fd: int | None = None
    lease_name = _preparation_lease_name(reservation.preparation_id)
    try:
        repo_fd, codex_tmp_fd, adapter_fd = _open_index_directories(repo_root)
        _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
        try:
            os.stat(
                lease_name,
                dir_fd=adapter_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise RunSafetyError(
                "preparation lease absence cannot be inspected safely"
            ) from error
        else:
            raise RunSafetyError(
                "preparation lease is still present before cleanup final CAS"
            )
        os.fsync(adapter_fd)
        try:
            os.stat(
                lease_name,
                dir_fd=adapter_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise RunSafetyError(
                "preparation lease absence cannot be revalidated safely"
            ) from error
        else:
            raise RunSafetyError(
                "preparation lease reappeared before cleanup final CAS"
            )
        _revalidate_index_directories(repo_fd, codex_tmp_fd, adapter_fd)
    except OSError as error:
        raise RunSafetyError(
            "preparation lease parent durability cannot be established"
        ) from error
    finally:
        if adapter_fd is not None:
            os.close(adapter_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        if repo_fd is not None:
            os.close(repo_fd)


def _require_cleanup_complete_absence(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> None:
    _fsync_preparation_lease_absence(repo_root, reservation)
    if _expected_run_entry_presence(repo_root, reservation) != "absent":
        raise RunSafetyError(
            "cleanup-complete tombstone no longer has a descriptor-proven "
            "absent reserved run entry"
        )


def _retire_inherited_preparation_lease(lease_fd: int) -> None:
    """Close one local inherited-lease reference without retrying ambiguity."""

    os.close(lease_fd)


def _expected_run_entry_presence(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> RunEntryPresence:
    """Prove point-in-time absence or conservatively report possible presence."""

    _reservation_run_path(repo_root, reservation)
    repo_fd: int | None = None
    codex_tmp_fd: int | None = None
    runs_fd: int | None = None
    try:
        try:
            repo_fd = _open_absolute_directory(repo_root)
            _require_owned_nonwritable_directory(
                repo_fd,
                label="repository root",
            )
            codex_tmp_fd = _open_directory_at(repo_fd, ".codex-tmp")
        except OSError as error:
            raise RunSafetyError(
                "preparation run parent path cannot be opened without following links"
            ) from error
        codex_tmp_identity = _bound_directory_identity(
            repo_fd,
            ".codex-tmp",
            codex_tmp_fd,
            label="preparation .codex-tmp",
        )
        try:
            runs_fd = _open_directory_at(codex_tmp_fd, RUNS_DIR_NAME)
        except FileNotFoundError:
            _revalidate_bound_directory(
                repo_fd,
                ".codex-tmp",
                codex_tmp_fd,
                codex_tmp_identity,
                label="preparation .codex-tmp",
            )
            try:
                os.stat(
                    RUNS_DIR_NAME,
                    dir_fd=codex_tmp_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return "absent"
            except OSError as error:
                raise RunSafetyError(
                    "preparation runs root absence cannot be revalidated"
                ) from error
            raise RunSafetyError(
                "preparation runs root appeared during absence validation"
            )
        except OSError as error:
            raise RunSafetyError(
                "preparation runs root cannot be opened without following links"
            ) from error
        runs_identity = _bound_directory_identity(
            codex_tmp_fd,
            RUNS_DIR_NAME,
            runs_fd,
            label="preparation runs root",
        )
        try:
            os.stat(
                reservation.run_id,
                dir_fd=runs_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            _revalidate_bound_directory(
                codex_tmp_fd,
                RUNS_DIR_NAME,
                runs_fd,
                runs_identity,
                label="preparation runs root",
            )
            _revalidate_bound_directory(
                repo_fd,
                ".codex-tmp",
                codex_tmp_fd,
                codex_tmp_identity,
                label="preparation .codex-tmp",
            )
            try:
                os.stat(
                    reservation.run_id,
                    dir_fd=runs_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return "absent"
            except OSError as error:
                raise RunSafetyError(
                    "reserved run entry absence cannot be revalidated"
                ) from error
            raise RunSafetyError(
                "reserved run entry appeared during absence validation"
            )
        except OSError as error:
            raise RunSafetyError(
                "reserved run entry presence cannot be determined"
            ) from error
        _revalidate_bound_directory(
            codex_tmp_fd,
            RUNS_DIR_NAME,
            runs_fd,
            runs_identity,
            label="preparation runs root",
        )
        _revalidate_bound_directory(
            repo_fd,
            ".codex-tmp",
            codex_tmp_fd,
            codex_tmp_identity,
            label="preparation .codex-tmp",
        )
        return "present"
    finally:
        if runs_fd is not None:
            os.close(runs_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        if repo_fd is not None:
            os.close(repo_fd)


def _require_reserved_state_attestation(
    run_dir: pathlib.Path,
    state: dict[str, object],
    reservation: PreparationReservation,
) -> None:
    if run_dir != pathlib.Path(reservation.run_dir):
        raise RunSafetyError("reserved run resolved to an unexpected repository path")
    if state.get("schema_version") not in RUNNER_PREPARATION_SCHEMA_VERSIONS:
        raise RunSafetyError(
            "reserved run state does not use the preparation-aware schema"
        )
    if state.get("run_id") != reservation.run_id:
        raise RunSafetyError(
            "reserved run state does not attest the preparation run id"
        )
    if state.get("preparation_id") != reservation.preparation_id:
        raise RunSafetyError(
            "reserved run state does not attest the preparation transaction"
        )
    orchestration = _state_orchestration(state)
    if orchestration.get("parent_session_id") != reservation.session_id:
        raise RunSafetyError(
            "reserved run state does not attest the preparation session"
        )


def _validate_reserved_run_state(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> tuple[
    pathlib.Path,
    dict[str, object],
    RunDirectoryIdentity,
    int,
]:
    run_dir = _reservation_run_path(repo_root, reservation)
    loaded_run_dir, state, run_identity, run_fd = _load_stop_run_state(
        repo_root,
        reservation.run_dir,
    )
    try:
        if loaded_run_dir != run_dir:
            raise RunSafetyError(
                "reserved run resolved to an unexpected repository path"
            )
        _require_reserved_state_attestation(loaded_run_dir, state, reservation)
    except Exception:
        os.close(run_fd)
        raise
    return loaded_run_dir, state, run_identity, run_fd


def _build_stop_continuation_prompt(
    repo_root: pathlib.Path,
    run_dir: pathlib.Path,
    state: dict[str, object],
    *,
    child_prompt: pathlib.Path | None = None,
    parent_prompt: pathlib.Path | None = None,
) -> str:
    orchestration = _state_orchestration(state)
    child_status = orchestration.get("child_status")
    if not isinstance(child_status, str):
        child_status = "pending"
    child_session_id = orchestration.get("child_session_id")
    if not isinstance(child_session_id, str) or not child_session_id.strip():
        child_session_id = None
    child_prompt = child_prompt or run_dir / "child-prompt.md"
    parent_prompt = parent_prompt or run_dir / "parent-prompt.md"
    if child_status in CHILD_TERMINAL_STATUSES:
        if child_session_id is None:
            return (
                "A waited-delivery run for this session records a terminal child status "
                "without a nonblank child_session_id. Do not run reconciliation with a "
                f"guessed identity. Inspect `{run_dir / 'state.json'}` and recover the exact "
                "attached child id before replying."
            )
        reconcile_cmd = [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "reconcile-active-run",
            "--repo",
            str(repo_root),
            "--run-dir",
            str(run_dir),
            "--child-status",
            child_status,
            "--child-session-id",
            child_session_id,
        ]
        return (
            "A waited-delivery run for this session is not reconciled yet. "
            f"Do not finish. Read the regenerated `{parent_prompt}` and reconcile "
            "the active run with "
            f"`{_shell_command(reconcile_cmd)}` before replying."
        )
    if child_session_id:
        return (
            "A waited-delivery run for this session is still active. "
            f"Do not finish. The compatibility runner regenerated `{parent_prompt}` "
            f"and `{child_prompt}`. Ask delivery child `{child_session_id}` to re-read "
            "the regenerated child prompt before its next runner command, then keep "
            "waiting unless the user explicitly interrupts the run."
        )
    return (
        "A waited-delivery run for this session has started but no delivery child has been "
        f"attached yet. Do not finish. Read the regenerated `{parent_prompt}`, spawn "
        f"exactly one child with regenerated `{child_prompt}`, and continue the required "
        "attach-child -> wait sequence."
    )


def _build_stop_fallback_prompt(
    repo_root: pathlib.Path, run_dir: pathlib.Path, state: dict[str, object]
) -> str:
    orchestration = _state_orchestration(state)
    child_status = orchestration.get("child_status")
    if not isinstance(child_status, str):
        child_status = "pending"
    child_session_id = orchestration.get("child_session_id")
    if not isinstance(child_session_id, str) or not child_session_id.strip():
        child_session_id = None
    lines = [
        "A waited-delivery run for this session is still active, but the stop-hook could not render the full continuation prompt.",
        "Do not finish yet.",
        f"Inspect state: {run_dir / 'state.json'}",
    ]
    if child_status in CHILD_TERMINAL_STATUSES:
        if child_session_id is None:
            lines.append(
                "State is inconsistent: the child is terminal but child_session_id is "
                "missing or blank. Recover the exact attached child id before reconciliation."
            )
            return "\n".join(lines)
        reconcile_cmd = [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "reconcile-active-run",
            "--repo",
            str(repo_root),
            "--run-dir",
            str(run_dir),
            "--child-status",
            child_status,
            "--child-session-id",
            child_session_id,
        ]
        lines.extend(
            [
                "Then continue the waited-delivery flow and reconcile it before replying.",
                "Run:",
                _shell_command(reconcile_cmd),
            ]
        )
        return "\n".join(lines)
    if child_session_id:
        lines.append(
            f"Keep waiting for delivery child `{child_session_id}` unless the user explicitly interrupts the run."
        )
        return "\n".join(lines)
    lines.append("Continue the required spawn -> attach-child -> wait sequence.")
    return "\n".join(lines)


def _state_child_status_hint(state: dict[str, object]) -> str | None:
    orchestration = state.get("orchestration")
    if not isinstance(orchestration, dict):
        return None
    child_status = orchestration.get("child_status")
    if isinstance(child_status, str) and child_status:
        return child_status
    return None


def _state_child_session_id_hint(state: dict[str, object]) -> str | None:
    orchestration = state.get("orchestration")
    if not isinstance(orchestration, dict):
        return None
    child_session_id = orchestration.get("child_session_id")
    if isinstance(child_session_id, str) and child_session_id.strip():
        return child_session_id
    return None


def _build_stop_last_resort_prompt(
    repo_root: pathlib.Path,
    run_dir: pathlib.Path,
    *,
    child_status: str | None,
    child_session_id: str | None,
) -> str:
    lines = [
        "A waited-delivery run for this session is still active.",
        "Do not finish yet.",
        f"Inspect state: {run_dir / 'state.json'}",
    ]
    if child_status in CHILD_TERMINAL_STATUSES:
        if not child_session_id or not child_session_id.strip():
            lines.append(
                "State is inconsistent: the child is terminal but child_session_id is "
                "missing or blank. Recover the exact attached child id before reconciliation."
            )
            return "\n".join(lines)
        reconcile_cmd = [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "reconcile-active-run",
            "--repo",
            str(repo_root),
            "--run-dir",
            str(run_dir),
            "--child-status",
            child_status,
            "--child-session-id",
            child_session_id,
        ]
        lines.extend(
            [
                "Then reconcile the active run before replying.",
                "Run:",
                _shell_command(reconcile_cmd),
            ]
        )
        return "\n".join(lines)
    if child_session_id:
        lines.append(
            f"Keep waiting for delivery child `{child_session_id}` unless the user explicitly interrupts the run."
        )
        return "\n".join(lines)
    lines.append("Continue the required spawn -> attach-child -> wait sequence.")
    return "\n".join(lines)


def _build_stop_emergency_prompt(
    repo_root: pathlib.Path,
    run_dir: pathlib.Path,
    *,
    child_status: str | None,
    child_session_id: str | None,
) -> str:
    lines = [
        "A waited-delivery run for this session is still active.",
        "Do not finish yet.",
        f"Inspect state: {run_dir / 'state.json'}",
    ]
    if child_status in CHILD_TERMINAL_STATUSES:
        if not child_session_id or not child_session_id.strip():
            lines.append(
                "State is inconsistent: the child is terminal but child_session_id is "
                "missing or blank. Recover the exact attached child id before reconciliation."
            )
            return "\n".join(lines)
        adapter_path = pathlib.Path(__file__).resolve()
        command = (
            f"{shlex.quote(sys.executable)} {shlex.quote(str(adapter_path))}"
            " reconcile-active-run"
            f" --repo {shlex.quote(str(repo_root))}"
            f" --run-dir {shlex.quote(str(run_dir))}"
            f" --child-status {shlex.quote(child_status)}"
            f" --child-session-id {shlex.quote(child_session_id)}"
        )
        lines.extend(
            [
                "Then reconcile the active run before replying.",
                "Run this from the repo root:",
                command,
            ]
        )
        return "\n".join(lines)
    if child_session_id:
        lines.append(
            f"Keep waiting for delivery child `{child_session_id}` unless the user explicitly interrupts the run."
        )
        return "\n".join(lines)
    lines.append("Continue the required spawn -> attach-child -> wait sequence.")
    return "\n".join(lines)


def _hook_log_max_bytes() -> int:
    configured = _int_env(HOOK_LOG_MAX_BYTES_ENV, HOOK_LOG_MAX_BYTES)
    if configured == 0:
        return HOOK_LOG_MAX_BYTES
    return configured


def _user_prompt_submit_hook(_: argparse.Namespace) -> int:
    payload: dict[str, object] = {}
    try:
        payload = json.load(sys.stdin)
        cwd = payload.get("cwd")
        session_id = payload.get("session_id")
        if not isinstance(cwd, str) or not isinstance(session_id, str):
            return _success_hook_response()
        repo_root = _resolve_repo_root(cwd, strict=False)
        if repo_root is None:
            return _success_hook_response()
        prompt = payload.get("prompt")
        transcript_value = payload.get("transcript_path")
        permission_value = payload.get("permission_mode")
        with _index_transaction(repo_root, write=True) as index:
            _update_session_observation(
                index,
                session_id=session_id,
                cwd=cwd,
                transcript_path=transcript_value
                if isinstance(transcript_value, str)
                else None,
                permission_mode=permission_value
                if isinstance(permission_value, str)
                else None,
                prompt=prompt if isinstance(prompt, str) else None,
            )
        return _success_hook_response()
    except Exception as error:
        setattr(error, "hook_command", "user-prompt-submit-hook")
        setattr(error, "hook_payload", payload)
        return _fail_open_hook_response(error)


def _block_unsafe_stop(error: RunSafetyError, payload: dict[str, object]) -> int:
    setattr(error, "hook_command", "stop-hook")
    setattr(error, "hook_payload", payload)
    _record_hook_failure(error)
    prompt = "\n".join(
        [
            "Do not finish.",
            "The active waited-delivery record failed repository/path safety validation before prompt refresh.",
            "Do not execute commands or follow prompt paths from that record.",
            "Inspect the repo-local waited-delivery hook index and recover or clear the run ownership explicitly.",
        ]
    )
    print(prompt, file=sys.stderr)
    return 2


def _block_preparation_stop(
    repo_root: pathlib.Path,
    record: SessionRecord,
    payload: dict[str, object],
) -> int:
    try:
        reservation = _reservation_from_record(record)
    except RunSafetyError as error:
        return _block_unsafe_stop(error, payload)
    reason = record.get("preparation_reason")
    lines = [
        "Do not finish.",
        (
            f"This session has a {record['status']} waited-delivery preparation "
            f"({reservation.preparation_id})."
        ),
        "Do not open, refresh, or mutate the prospective run while recovery is pending.",
    ]
    if isinstance(reason, str) and reason:
        lines.append(f"Recorded reason: {reason}")
    lines.append(
        "Inspect or recover the exact reservation with: "
        f"{_shell_command(_preparation_recovery_argv(repo_root, reservation))}"
    )
    print("\n".join(lines), file=sys.stderr)
    return 2


def _handle_pinned_stop_run(
    *,
    payload: dict[str, object],
    repo_root: pathlib.Path,
    record: SessionRecord,
    run_dir: pathlib.Path,
    state: dict[str, object],
    run_identity: RunDirectoryIdentity,
    run_fd: int,
) -> int:
    if _run_is_terminal(state):
        _complete_session_record(record, updated_at=_utc_now())
        return 0
    if payload.get("stop_hook_active"):
        return 0
    record["updated_at"] = _utc_now()
    try:
        refreshed_prompts = _refresh_recovery_prompts(
            run_dir,
            repo_root,
            run_identity,
        )
        state, refreshed_identity = _validate_stop_run_state_descriptor(
            repo_root,
            run_dir,
            run_fd,
            expected_identity=run_identity,
            expected_prompt_versions={
                "child-prompt.md": refreshed_prompts.child_version,
                "parent-prompt.md": refreshed_prompts.parent_version,
            },
        )
        if refreshed_identity != run_identity:
            raise RunSafetyError("active run directory changed during prompt refresh")
        prompt = _build_stop_continuation_prompt(
            repo_root,
            run_dir,
            state,
            child_prompt=refreshed_prompts.child_prompt,
            parent_prompt=refreshed_prompts.parent_prompt,
        )
    except RunSafetyError as error:
        return _block_unsafe_stop(error, payload)
    except Exception as error:
        setattr(error, "hook_command", "stop-hook")
        setattr(error, "hook_payload", payload)
        _record_hook_failure(error)
        try:
            state, fallback_identity = _validate_stop_run_state_descriptor(
                repo_root,
                run_dir,
                run_fd,
                expected_identity=run_identity,
            )
            if fallback_identity != run_identity:
                raise RunSafetyError(
                    "active run directory changed during failed prompt refresh"
                )
        except RunSafetyError as safety_error:
            return _block_unsafe_stop(safety_error, payload)
        try:
            prompt = _build_stop_fallback_prompt(repo_root, run_dir, state)
        except Exception as fallback_error:
            setattr(fallback_error, "hook_command", "stop-hook")
            setattr(fallback_error, "hook_payload", payload)
            _record_hook_failure(fallback_error)
            try:
                prompt = _build_stop_last_resort_prompt(
                    repo_root,
                    run_dir,
                    child_status=_state_child_status_hint(state),
                    child_session_id=_state_child_session_id_hint(state),
                )
            except Exception as emergency_error:
                setattr(emergency_error, "hook_command", "stop-hook")
                setattr(emergency_error, "hook_payload", payload)
                _record_hook_failure(emergency_error)
                prompt = _build_stop_emergency_prompt(
                    repo_root,
                    run_dir,
                    child_status=_state_child_status_hint(state),
                    child_session_id=_state_child_session_id_hint(state),
                )
    try:
        print(prompt, file=sys.stderr)
    except Exception as error:
        setattr(error, "hook_command", "stop-hook")
        setattr(error, "hook_payload", payload)
        raise
    return 2


def _stop_hook(_: argparse.Namespace) -> int:
    payload: dict[str, object] = {}
    stop_result: int | None = None
    try:
        payload = json.load(sys.stdin)
        cwd = payload.get("cwd")
        session_id = payload.get("session_id")
        if not isinstance(cwd, str) or not isinstance(session_id, str):
            return _success_hook_response()
        repo_root = _resolve_repo_root(cwd, strict=False)
        if repo_root is None:
            return _success_hook_response()
        with _index_transaction(repo_root, write=True) as index:
            record = index["sessions"].get(session_id)
            if (
                record is None
                or not record["run_dir"]
                or record["status"] == CLEANUP_COMPLETE_STATUS
            ):
                stop_result = 0
            elif record["status"] in PREPARATION_STATUSES:
                if payload.get("stop_hook_active"):
                    stop_result = 0
                else:
                    stop_result = _block_preparation_stop(
                        repo_root,
                        record,
                        payload,
                    )
            elif record["status"] != "active":
                stop_result = _block_unsafe_stop(
                    RunSafetyError(
                        "waited-delivery run ownership is not active or recoverable"
                    ),
                    payload,
                )
            else:
                try:
                    run_dir, state, run_identity, run_fd = _load_stop_run_state(
                        repo_root,
                        record["run_dir"],
                    )
                except RunSafetyError as error:
                    stop_result = _block_unsafe_stop(error, payload)
                else:
                    try:
                        stop_result = _handle_pinned_stop_run(
                            payload=payload,
                            repo_root=repo_root,
                            record=record,
                            run_dir=run_dir,
                            state=state,
                            run_identity=run_identity,
                            run_fd=run_fd,
                        )
                    finally:
                        os.close(run_fd)
        if stop_result == 0:
            return _success_hook_response()
        if stop_result == 2:
            return 2
        raise UserError("stop hook completed without a result")
    except Exception as error:
        setattr(error, "hook_command", "stop-hook")
        setattr(error, "hook_payload", payload)
        if stop_result == 2:
            _record_hook_failure(error)
            return 2
        return _fail_open_hook_response(error)


def _build_prepare_bridge_args(
    args: argparse.Namespace,
    *,
    repo_root: pathlib.Path,
    record: SessionRecord,
    reservation: PreparationReservation,
) -> list[str]:
    bridge_args = [
        "prepare-live",
        "--repo",
        str(repo_root),
        "--goal",
        args.goal,
        "--parent-session-id",
        record["session_id"],
        "--run-id",
        reservation.run_id,
        "--preparation-id",
        reservation.preparation_id,
    ]
    if record["transcript_path"]:
        bridge_args.extend(["--parent-transcript-path", record["transcript_path"]])
    if record["permission_mode"]:
        bridge_args.extend(["--permission-mode", record["permission_mode"]])
    for phase in args.phase:
        bridge_args.extend(["--phase", phase])
    for changed_file in args.changed_file:
        bridge_args.extend(["--changed-file", changed_file])
    for blocker in args.known_blocker:
        bridge_args.extend(["--known-blocker", blocker])
    bridge_args.extend(["--external-lane", args.external_lane])
    bridge_args.extend(["--fallback-lane", args.fallback_lane])
    bridge_args.extend(["--fallback-entrypoint", args.fallback_entrypoint])
    bridge_args.extend(["--external-helper", args.external_helper])
    if args.no_fallback_smoke:
        bridge_args.append("--no-fallback-smoke")
    return bridge_args


def _cas_preparation_cleanup_pending(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
    *,
    expected_record: SessionRecord,
    reason: str,
) -> SessionRecord:
    transaction_time = _utc_now()
    pending_snapshot: SessionRecord | None = None
    with _index_transaction(
        repo_root,
        write=True,
        commit_time=transaction_time,
        context="preparation cleanup-pending reservation CAS",
    ) as index:
        record = index["sessions"].get(reservation.session_id)
        if record is None:
            raise RunSafetyError(
                "preparation reservation disappeared before cleanup-pending CAS"
            )
        if record != expected_record:
            raise RunSafetyError(
                "preparation reservation changed before cleanup-pending CAS"
            )
        _require_exact_reservation(record, reservation, allow_active=False)
        if record["status"] == CLEANUP_PENDING_STATUS:
            pending_snapshot = copy.deepcopy(record)
        else:
            if record["status"] not in RECOVERABLE_PREPARATION_STATUSES:
                raise RunSafetyError(
                    "only a recoverable preparation can enter cleanup_pending"
                )
            if _expected_run_entry_presence(repo_root, reservation) != "absent":
                raise UserError(
                    "reserved run entry is present; retain the recovery fence"
                )
            _mark_preparation_cleanup_pending(
                record,
                reason=reason,
                updated_at=transaction_time,
            )
            index["latest_session_id"] = reservation.session_id
            pending_snapshot = copy.deepcopy(record)
    assert pending_snapshot is not None
    return pending_snapshot


def _cas_clear_cleanup_pending(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
    *,
    expected_record: SessionRecord,
) -> None:
    transaction_time = _utc_now()
    with _index_transaction(
        repo_root,
        write=True,
        commit_time=transaction_time,
        context="preparation cleanup-pending final CAS",
    ) as index:
        record = index["sessions"].get(reservation.session_id)
        if record is None:
            raise RunSafetyError(
                "preparation reservation disappeared before cleanup final CAS"
            )
        if record != expected_record:
            raise RunSafetyError("cleanup-pending reservation changed before final CAS")
        _require_exact_reservation(record, reservation, allow_active=False)
        if record["status"] != CLEANUP_PENDING_STATUS:
            raise RunSafetyError(
                "preparation reservation is not cleanup_pending at final CAS"
            )
        _fsync_preparation_lease_absence(repo_root, reservation)
        _mark_preparation_cleanup_complete(
            record,
            updated_at=transaction_time,
        )
        index["latest_session_id"] = reservation.session_id


def _fence_preparation(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
    *,
    reason: str,
) -> None:
    transaction_time = _utc_now()
    with _index_transaction(
        repo_root,
        write=True,
        commit_time=transaction_time,
        context="prepare-active-run recovery fence",
    ) as index:
        record = index["sessions"].get(reservation.session_id)
        if record is None:
            raise RunSafetyError(
                "preparation reservation disappeared before recovery fencing"
            )
        _require_exact_reservation(record, reservation, allow_active=True)
        if record["status"] in {
            CLEANUP_PENDING_STATUS,
            CLEANUP_COMPLETE_STATUS,
        }:
            return
        if record["status"] != "active":
            _mark_preparation_recovery(
                record,
                reason=reason,
                updated_at=transaction_time,
            )
        index["latest_session_id"] = reservation.session_id


def _preparation_reservation_persisted(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> bool | None:
    try:
        with _index_transaction(repo_root, write=False) as index:
            record = index["sessions"].get(reservation.session_id)
            if record is None:
                return False
            try:
                _require_exact_reservation(
                    record,
                    reservation,
                    allow_active=True,
                )
            except RunSafetyError:
                return False
            return True
    except Exception:
        return None


def _settle_failed_bridge(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
    *,
    inherited_lease_fd: int,
    reason: str,
) -> Literal["active", "cleared", "fenced"]:
    recovery_lease_fd: int | None = None
    inherited_lease_open = True
    try:
        with _index_transaction(repo_root, write=False) as index:
            record = index["sessions"].get(reservation.session_id)
            if record is None:
                raise RunSafetyError(
                    "preparation reservation disappeared after bridge failure"
                )
            _require_exact_reservation(record, reservation, allow_active=True)
            if record["status"] == "active":
                return "active"

        inherited_lease_open = False
        try:
            _retire_inherited_preparation_lease(inherited_lease_fd)
        except OSError as error:
            _fence_preparation(
                repo_root,
                reservation,
                reason=(
                    f"{reason}; inherited lease ownership could not be retired "
                    f"exactly once, so writer quiescence is unproven: {error}"
                ),
            )
            return "fenced"

        try:
            recovery_lease_fd = _acquire_preparation_lease(
                repo_root,
                reservation,
            )
        except RunSafetyError as error:
            _fence_preparation(
                repo_root,
                reservation,
                reason=(
                    f"{reason}; inherited-writer quiescence could not be proved: "
                    f"{error}"
                ),
            )
            return "fenced"

        with _index_transaction(repo_root, write=False) as index:
            record = index["sessions"].get(reservation.session_id)
            if record is None:
                raise RunSafetyError(
                    "preparation reservation disappeared before cleanup-pending CAS"
                )
            _require_exact_reservation(record, reservation, allow_active=True)
            if record["status"] == "active":
                return "active"
            record_snapshot = copy.deepcopy(record)

        try:
            pending_snapshot = _cas_preparation_cleanup_pending(
                repo_root,
                reservation,
                expected_record=record_snapshot,
                reason=(
                    f"{reason}; writer quiescence and reserved run absence were "
                    "proved; exact lease removal is pending"
                ),
            )
        except Exception as error:
            _fence_preparation(
                repo_root,
                reservation,
                reason=f"{reason}; cleanup-pending CAS failed: {error}",
            )
            return "fenced"

        try:
            _remove_preparation_lease(
                repo_root,
                reservation,
                recovery_lease_fd,
            )
        except Exception:
            return "fenced"
        try:
            _cas_clear_cleanup_pending(
                repo_root,
                reservation,
                expected_record=pending_snapshot,
            )
        except Exception:
            return "fenced"
        return "cleared"
    finally:
        if inherited_lease_open:
            os.close(inherited_lease_fd)
        if recovery_lease_fd is not None:
            os.close(recovery_lease_fd)


def _activate_reserved_preparation(
    repo_root: pathlib.Path,
    reservation: PreparationReservation,
) -> None:
    run_dir, _state, run_identity, run_fd = _validate_reserved_run_state(
        repo_root,
        reservation,
    )
    try:
        transaction_time = _utc_now()
        with _index_transaction(
            repo_root,
            write=True,
            commit_time=transaction_time,
            context="prepare-active-run activation",
        ) as index:
            record = index["sessions"].get(reservation.session_id)
            if record is None:
                raise RunSafetyError(
                    "preparation reservation disappeared before activation"
                )
            _require_exact_reservation(record, reservation, allow_active=True)
            current_state, current_identity = _validate_stop_run_state_descriptor(
                repo_root,
                run_dir,
                run_fd,
                expected_identity=run_identity,
            )
            if current_identity != run_identity:
                raise RunSafetyError("reserved run identity changed before activation")
            _require_reserved_state_attestation(
                run_dir,
                current_state,
                reservation,
            )
            if record["status"] != "active":
                _activate_preparation(record, updated_at=transaction_time)
            index["latest_session_id"] = reservation.session_id
        final_state, final_identity = _validate_stop_run_state_descriptor(
            repo_root,
            run_dir,
            run_fd,
            expected_identity=run_identity,
        )
        if final_identity != run_identity:
            raise RunSafetyError("reserved run identity changed after activation")
        _require_reserved_state_attestation(run_dir, final_state, reservation)
    finally:
        os.close(run_fd)


def _prepare_active_run(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    transaction_time = _utc_now()
    run_id = (
        args.run_id
        if args.run_id is not None
        else (
            f"{dt.datetime.fromisoformat(transaction_time):%Y%m%dT%H%M%SZ}-"
            f"{uuid.uuid4().hex[:8]}"
        )
    )
    _validate_component_name(run_id, label="run id")
    preparation_id = uuid.uuid4().hex
    prospective_run_dir = repo_root / ".codex-tmp" / RUNS_DIR_NAME / run_id
    reservation: PreparationReservation | None = None
    bridge_args: list[str] | None = None
    lease_fd: int | None = None
    index_context = "prepare-active-run durable preparation reservation"
    try:
        with _index_transaction(
            repo_root,
            write=True,
            commit_time=transaction_time,
            context=index_context,
        ) as index:
            record = _resolve_session_record(
                index,
                repo_root=repo_root,
                session_id=args.session_id,
                transcript_path=args.transcript_path,
                prompt_text=args.prompt_text,
                host_session_id=_current_thread_session_id(),
            )
            cleanup_complete = record["status"] == CLEANUP_COMPLETE_STATUS
            if cleanup_complete:
                completed_reservation = _reservation_from_record(record)
                _require_cleanup_complete_absence(
                    repo_root,
                    completed_reservation,
                )
            elif record["status"] in PREPARATION_STATUSES:
                existing_reservation = _reservation_from_record(record)
                raise UserError(
                    _preparation_recovery_message(
                        repo_root,
                        existing_reservation,
                        reason=(
                            f"session {record['session_id']} already has an "
                            f"unfinished {record['status']} preparation."
                        ),
                    )
                )
            if record["run_dir"] and not cleanup_complete:
                try:
                    (
                        _existing_run_dir,
                        existing_state,
                        _existing_identity,
                        existing_run_fd,
                    ) = _load_stop_run_state(
                        repo_root,
                        record["run_dir"],
                    )
                except RunSafetyError as error:
                    raise UserError(
                        f"session {record['session_id']} has an indexed run that "
                        f"cannot be retired safely: {error}"
                    ) from error
                try:
                    existing_run_terminal = _run_is_terminal(existing_state)
                finally:
                    os.close(existing_run_fd)
                if not existing_run_terminal:
                    raise UserError(
                        f"session {record['session_id']} already has an active "
                        f"waited-delivery run: {record['run_dir']}"
                    )
            for other in index["sessions"].values():
                if other["session_id"] != record["session_id"] and other.get(
                    "run_dir"
                ) == str(prospective_run_dir):
                    raise UserError(
                        "another session already reserves the requested run id: "
                        f"{other['session_id']}"
                    )
            reservation = PreparationReservation(
                session_id=record["session_id"],
                preparation_id=preparation_id,
                run_id=run_id,
                run_dir=str(prospective_run_dir),
                lease_path=str(_preparation_lease_path(repo_root, preparation_id)),
                started_at=transaction_time,
            )
            record["run_dir"] = reservation.run_dir
            record["status"] = "preparing"
            record["updated_at"] = transaction_time
            record["preparation_id"] = reservation.preparation_id
            record["preparation_run_id"] = reservation.run_id
            record["preparation_lease_path"] = reservation.lease_path
            record["preparation_started_at"] = reservation.started_at
            record["preparation_reason"] = None
            index["latest_session_id"] = record["session_id"]
            _serialize_index_for_commit(
                index,
                transaction_time=transaction_time,
                context=index_context,
            )
            lease_fd = _create_preparation_lease(repo_root, reservation)
            bridge_args = _build_prepare_bridge_args(
                args,
                repo_root=repo_root,
                record=record,
                reservation=reservation,
            )
    except Exception as error:
        if reservation is not None and lease_fd is not None:
            persisted = _preparation_reservation_persisted(
                repo_root,
                reservation,
            )
            if persisted is False:
                try:
                    _remove_preparation_lease(
                        repo_root,
                        reservation,
                        lease_fd,
                    )
                except Exception as cleanup_error:
                    os.close(lease_fd)
                    lease_fd = None
                    raise UserError(
                        "The preparation reservation was not published and no "
                        "bridge was launched, but exact lease cleanup failed: "
                        f"{cleanup_error}"
                    ) from error
                os.close(lease_fd)
                lease_fd = None
                raise UserError(
                    "The preparation reservation was not published; no bridge "
                    f"was launched and its exact lease was removed: {error}"
                ) from error
            os.close(lease_fd)
            lease_fd = None
            raise UserError(
                _preparation_recovery_message(
                    repo_root,
                    reservation,
                    reason=(
                        "The durable preparation reservation could not be "
                        f"verified before bridge launch: {error}"
                    ),
                )
            ) from error
        raise

    assert reservation is not None
    assert bridge_args is not None
    assert lease_fd is not None
    try:
        try:
            payload = _run_bridge_json_with_lease(lease_fd, *bridge_args)
        except Exception as error:
            reason = f"prepare-live failed: {error}"
            failed_lease_fd = lease_fd
            lease_fd = None
            outcome = _settle_failed_bridge(
                repo_root,
                reservation,
                inherited_lease_fd=failed_lease_fd,
                reason=reason,
            )
            if outcome == "cleared":
                raise UserError(
                    f"{reason}; the quiescent reserved run entry was absent, "
                    "so the exact preparation reservation was cleared safely"
                ) from error
            raise UserError(
                _preparation_recovery_message(
                    repo_root,
                    reservation,
                    reason=reason,
                )
            ) from error
        if (
            payload.get("run_dir") != reservation.run_dir
            or payload.get("preparation_id") != reservation.preparation_id
            or payload.get("preparation_lease_inherited") is not True
        ):
            reason = (
                "prepare-live returned a result that does not match the exact "
                "reserved run directory and preparation transaction"
            )
            _fence_preparation(
                repo_root,
                reservation,
                reason=reason,
            )
            raise UserError(
                _preparation_recovery_message(
                    repo_root,
                    reservation,
                    reason=reason,
                )
            )
        try:
            _activate_reserved_preparation(repo_root, reservation)
        except Exception as error:
            reason = f"prepared run activation could not be verified: {error}"
            try:
                _fence_preparation(
                    repo_root,
                    reservation,
                    reason=reason,
                )
            except Exception as fence_error:
                reason = f"{reason}; recovery fence update also failed: {fence_error}"
            raise UserError(
                _preparation_recovery_message(
                    repo_root,
                    reservation,
                    reason=reason,
                )
            ) from error
        try:
            _remove_preparation_lease(repo_root, reservation, lease_fd)
        except Exception as error:
            raise UserError(
                _preparation_recovery_message(
                    repo_root,
                    reservation,
                    reason=(
                        "The run is active, but preparation lease cleanup could "
                        f"not be verified: {error}"
                    ),
                )
            ) from error
        print(json.dumps(payload))
        return 0
    finally:
        if lease_fd is not None:
            os.close(lease_fd)


def _attach_child_active_run(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    with _index_transaction(repo_root, write=True) as index:
        record = _resolve_session_record(
            index,
            repo_root=repo_root,
            session_id=args.session_id,
            run_dir=args.run_dir,
        )
        _require_active_record(record)
        exit_code = _run_bridge_passthrough(
            "attach-child-live",
            "--run-dir",
            args.run_dir,
            "--child-session-id",
            args.child_session_id,
            "--parent-session-id",
            record["session_id"],
            *(
                ["--parent-transcript-path", record["transcript_path"]]
                if record["transcript_path"]
                else []
            ),
            *(
                ["--permission-mode", record["permission_mode"]]
                if record["permission_mode"]
                else []
            ),
        )
        if exit_code == 0:
            record["run_dir"] = args.run_dir
            record["status"] = "active"
            record["updated_at"] = _utc_now()
            index["latest_session_id"] = record["session_id"]
    return exit_code


def _finish_child_active_run(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    with _index_transaction(repo_root, write=True) as index:
        record = _resolve_session_record(
            index,
            repo_root=repo_root,
            session_id=args.session_id,
            run_dir=args.run_dir,
        )
        _require_active_record(record)
        bridge_args = [
            "finish-child-live",
            "--run-dir",
            args.run_dir,
            "--child-status",
            args.child_status,
            "--child-session-id",
            args.child_session_id,
        ]
        exit_code = _run_bridge_passthrough(*bridge_args)
        if exit_code == 0:
            record["run_dir"] = args.run_dir
            record["status"] = "active"
            record["updated_at"] = _utc_now()
            index["latest_session_id"] = record["session_id"]
    return exit_code


def _reconcile_active_run(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    with _index_transaction(repo_root, write=True) as index:
        record = _resolve_session_record(
            index,
            repo_root=repo_root,
            session_id=args.session_id,
            run_dir=args.run_dir,
        )
        _require_active_record(record)
        bridge_args = [
            "reconcile-live",
            "--run-dir",
            args.run_dir,
            "--child-status",
            args.child_status,
            "--child-session-id",
            args.child_session_id,
        ]
        payload = _run_bridge_json(*bridge_args)
        _run_dir, state, _run_identity, run_fd = _load_stop_run_state(
            repo_root,
            args.run_dir,
        )
        os.close(run_fd)
        if _run_is_terminal(state):
            _complete_session_record(record, updated_at=_utc_now())
        else:
            record["run_dir"] = args.run_dir
            record["status"] = "active"
            record["updated_at"] = _utc_now()
        index["latest_session_id"] = record["session_id"]
    print(json.dumps(payload))
    return 0


def _preparation_doctor_payload(
    repo_root: pathlib.Path,
    record: SessionRecord,
    reservation: PreparationReservation,
) -> dict[str, object]:
    result: dict[str, object] = {
        "session_id": reservation.session_id,
        "preparation_id": reservation.preparation_id,
        "run_id": reservation.run_id,
        "run_dir": reservation.run_dir,
        "index_status": record["status"],
        "recorded_reason": record.get("preparation_reason"),
    }
    if record["status"] == CLEANUP_COMPLETE_STATUS:
        try:
            _require_cleanup_complete_absence(repo_root, reservation)
        except RunSafetyError as error:
            result.update(
                {
                    "status": "cleanup_complete_unverified",
                    "detail": _bounded_preparation_reason(str(error)),
                }
            )
        else:
            result.update(
                {
                    "status": "cleanup_complete",
                    "lease_presence": "absent",
                    "entry_presence": "absent",
                    "detail": (
                        "the exact cleanup tombstone retains its reservation "
                        "identity and both reserved entries remain absent"
                    ),
                }
            )
        return result
    if record["status"] == CLEANUP_PENDING_STATUS:
        try:
            lease_presence = _preparation_lease_entry_presence(
                repo_root,
                reservation,
            )
        except RunSafetyError as error:
            result.update(
                {
                    "status": "cleanup_pending_lease_unverified",
                    "detail": _bounded_preparation_reason(str(error)),
                }
            )
            return result
        result["lease_presence"] = lease_presence
        if lease_presence == "absent":
            result.update(
                {
                    "status": "cleanup_pending_final_cas",
                    "detail": (
                        "the descriptor-bound lease entry is absent; only the "
                        "final cleanup-pending index CAS remains"
                    ),
                }
            )
            return result
        try:
            lease_fd = _acquire_preparation_lease(repo_root, reservation)
        except RunSafetyError as error:
            result.update(
                {
                    "status": "cleanup_pending_lease_present",
                    "detail": _bounded_preparation_reason(str(error)),
                }
            )
            return result
        try:
            try:
                presence = _expected_run_entry_presence(repo_root, reservation)
            except RunSafetyError as error:
                result.update(
                    {
                        "status": "cleanup_pending_presence_unproven",
                        "detail": _bounded_preparation_reason(str(error)),
                    }
                )
            else:
                result["entry_presence"] = presence
                result["status"] = (
                    "cleanup_pending_lease_present"
                    if presence == "absent"
                    else "cleanup_pending_entry_present"
                )
            return result
        finally:
            os.close(lease_fd)
    if record["status"] == "active":
        try:
            _run_dir, _state, _identity, run_fd = _validate_reserved_run_state(
                repo_root,
                reservation,
            )
        except RunSafetyError as error:
            result.update(
                {
                    "status": "active_unverified",
                    "detail": _bounded_preparation_reason(str(error)),
                }
            )
        else:
            os.close(run_fd)
            result["status"] = "active"
        return result
    try:
        lease_fd = _acquire_preparation_lease(repo_root, reservation)
    except RunSafetyError as error:
        detail = _bounded_preparation_reason(str(error))
        result.update(
            {
                "status": (
                    "in_progress"
                    if "still held" in str(error)
                    else "quiescence_unproven"
                ),
                "detail": detail,
            }
        )
        return result
    try:
        try:
            presence = _expected_run_entry_presence(repo_root, reservation)
        except RunSafetyError as error:
            result.update(
                {
                    "status": "presence_unproven",
                    "detail": _bounded_preparation_reason(str(error)),
                }
            )
            return result
        result["entry_presence"] = presence
        if presence == "absent":
            result["status"] = "absent"
            return result
        try:
            _run_dir, _state, _identity, run_fd = _validate_reserved_run_state(
                repo_root,
                reservation,
            )
        except RunSafetyError as error:
            result.update(
                {
                    "status": "partial_or_untrusted",
                    "detail": _bounded_preparation_reason(str(error)),
                }
            )
            return result
        else:
            os.close(run_fd)
            result["status"] = "complete_not_activated"
            return result
    finally:
        os.close(lease_fd)


def _recover_active_run(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    with _index_transaction(repo_root, write=False) as index:
        record = _resolve_session_record(
            index,
            repo_root=repo_root,
            session_id=args.session_id,
        )
        reservation = _reservation_from_record(record)
        if reservation.preparation_id != args.preparation_id:
            raise RunSafetyError(
                "requested preparation id does not match the indexed reservation"
            )
        record_snapshot = copy.deepcopy(record)

    if args.action == "doctor":
        print(
            json.dumps(
                _preparation_doctor_payload(
                    repo_root,
                    record_snapshot,
                    reservation,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.action == "resume":
        if record_snapshot["status"] in {
            CLEANUP_PENDING_STATUS,
            CLEANUP_COMPLETE_STATUS,
        }:
            raise UserError(
                f"{record_snapshot['status']} is an absent-run cleanup; use "
                "clear-absent to finish or confirm its idempotent cleanup"
            )
        if record_snapshot["status"] == "active":
            _run_dir, _state, _identity, run_fd = _validate_reserved_run_state(
                repo_root,
                reservation,
            )
            os.close(run_fd)
            try:
                os.lstat(reservation.lease_path)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise RunSafetyError(
                    "active preparation lease cleanup status cannot be inspected"
                ) from error
            else:
                lease_fd = _acquire_preparation_lease(repo_root, reservation)
                try:
                    _remove_preparation_lease(
                        repo_root,
                        reservation,
                        lease_fd,
                    )
                finally:
                    os.close(lease_fd)
            print(
                json.dumps(
                    {
                        "preparation_id": reservation.preparation_id,
                        "run_dir": reservation.run_dir,
                        "status": "active",
                    },
                    sort_keys=True,
                )
            )
            return 0
        lease_fd = _acquire_preparation_lease(repo_root, reservation)
        try:
            try:
                _activate_reserved_preparation(repo_root, reservation)
            except Exception as error:
                reason = f"recovery resume failed: {error}"
                try:
                    _fence_preparation(
                        repo_root,
                        reservation,
                        reason=reason,
                    )
                except Exception as fence_error:
                    reason = (
                        f"{reason}; recovery fence update also failed: {fence_error}"
                    )
                raise UserError(
                    _preparation_recovery_message(
                        repo_root,
                        reservation,
                        reason=reason,
                    )
                ) from error
            _remove_preparation_lease(repo_root, reservation, lease_fd)
        finally:
            os.close(lease_fd)
        print(
            json.dumps(
                {
                    "preparation_id": reservation.preparation_id,
                    "run_dir": reservation.run_dir,
                    "status": "active",
                },
                sort_keys=True,
            )
        )
        return 0

    if record_snapshot["status"] == "active":
        raise UserError("an active preparation cannot be cleared as absent")
    if record_snapshot["status"] == CLEANUP_COMPLETE_STATUS:
        _require_cleanup_complete_absence(repo_root, reservation)
        print(
            json.dumps(
                {
                    "preparation_id": reservation.preparation_id,
                    "run_dir": reservation.run_dir,
                    "status": "cleared",
                },
                sort_keys=True,
            )
        )
        return 0
    lease_presence = _preparation_lease_entry_presence(repo_root, reservation)
    lease_fd: int | None = None
    try:
        if lease_presence == "present":
            lease_fd = _acquire_preparation_lease(repo_root, reservation)
            if _expected_run_entry_presence(repo_root, reservation) != "absent":
                raise UserError(
                    "reserved run entry is present; use doctor and resume a complete "
                    "matching run, or retain the recovery fence"
                )
        elif record_snapshot["status"] != CLEANUP_PENDING_STATUS:
            raise RunSafetyError(
                "preparation lease is absent before cleanup_pending was committed"
            )

        if record_snapshot["status"] == CLEANUP_PENDING_STATUS:
            pending_snapshot = _cas_preparation_cleanup_pending(
                repo_root,
                reservation,
                expected_record=record_snapshot,
                reason=cast(
                    str,
                    record_snapshot.get("preparation_reason")
                    or "cleanup_pending recovery",
                ),
            )
        else:
            if lease_fd is None:
                raise RunSafetyError(
                    "preparation lease must remain present through cleanup-pending CAS"
                )
            pending_snapshot = _cas_preparation_cleanup_pending(
                repo_root,
                reservation,
                expected_record=record_snapshot,
                reason=(
                    "clear-absent proved writer quiescence and reserved run "
                    "absence; exact lease removal is pending"
                ),
            )

        if lease_fd is not None:
            _remove_preparation_lease(repo_root, reservation, lease_fd)
        _cas_clear_cleanup_pending(
            repo_root,
            reservation,
            expected_record=pending_snapshot,
        )
    finally:
        if lease_fd is not None:
            os.close(lease_fd)
    print(
        json.dumps(
            {
                "preparation_id": reservation.preparation_id,
                "run_dir": reservation.run_dir,
                "status": "cleared",
            },
            sort_keys=True,
        )
    )
    return 0


def _show_index(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    with _index_transaction(repo_root, write=False) as index:
        rendered = json.dumps(index, indent=2, sort_keys=True)
    print(rendered)
    return 0


def _raw_hook_command(argv: list[str]) -> str | None:
    for token in argv:
        if token in HOOK_COMMANDS:
            return token
        if token in NON_HOOK_COMMANDS:
            return None
    return None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Explicit-only waited-delivery compatibility adapter for hooks and "
            "active-run control."
        ),
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    user_prompt = subparsers.add_parser(
        "user-prompt-submit-hook",
        allow_abbrev=False,
    )
    user_prompt.add_argument(
        HOOK_ENABLE_FLAG,
        action="store_true",
        help="explicitly enable the historical compatibility hook",
    )
    user_prompt.set_defaults(func=_user_prompt_submit_hook)

    stop = subparsers.add_parser(
        "stop-hook",
        allow_abbrev=False,
    )
    stop.add_argument(
        HOOK_ENABLE_FLAG,
        action="store_true",
        help="explicitly enable the historical compatibility hook",
    )
    stop.set_defaults(func=_stop_hook)

    prepare = subparsers.add_parser("prepare-active-run")
    prepare.add_argument("--repo", required=True)
    prepare.add_argument("--goal", required=True)
    prepare.add_argument("--session-id")
    prepare.add_argument("--transcript-path")
    prepare.add_argument("--prompt-text")
    prepare.add_argument("--run-id")
    prepare.add_argument("--phase", action="append", default=[])
    prepare.add_argument("--changed-file", action="append", default=[])
    prepare.add_argument("--known-blocker", action="append", default=[])
    prepare.add_argument("--external-lane", default="bounded-semantic")
    prepare.add_argument("--fallback-lane", default="baseline")
    prepare.add_argument("--fallback-entrypoint", default="gh-copilot")
    prepare.add_argument(
        "--external-helper",
        default=str(
            pathlib.Path(__file__).resolve().parents[2]
            / "review-orchestration-playbook"
            / "scripts"
            / "isolated_review"
        ),
    )
    prepare.add_argument("--no-fallback-smoke", action="store_true")
    prepare.set_defaults(func=_prepare_active_run)

    recover = subparsers.add_parser("recover-active-run")
    recover.add_argument("--repo", required=True)
    recover.add_argument("--session-id", required=True)
    recover.add_argument("--preparation-id", required=True)
    recover.add_argument(
        "--action",
        choices=("doctor", "resume", "clear-absent"),
        default="doctor",
    )
    recover.set_defaults(func=_recover_active_run)

    attach = subparsers.add_parser("attach-child-active-run")
    attach.add_argument("--repo", required=True)
    attach.add_argument("--run-dir", required=True)
    attach.add_argument("--child-session-id", required=True)
    attach.add_argument("--session-id")
    attach.set_defaults(func=_attach_child_active_run)

    finish = subparsers.add_parser("finish-child-active-run")
    finish.add_argument("--repo", required=True)
    finish.add_argument("--run-dir", required=True)
    finish.add_argument("--child-status", required=True)
    finish.add_argument("--child-session-id", required=True)
    finish.add_argument("--session-id")
    finish.set_defaults(func=_finish_child_active_run)

    reconcile = subparsers.add_parser("reconcile-active-run")
    reconcile.add_argument("--repo", required=True)
    reconcile.add_argument("--run-dir", required=True)
    reconcile.add_argument("--child-status", required=True)
    reconcile.add_argument("--child-session-id", required=True)
    reconcile.add_argument("--session-id")
    reconcile.set_defaults(func=_reconcile_active_run)

    show_index = subparsers.add_parser("show-index")
    show_index.add_argument("--repo", required=True)
    show_index.set_defaults(func=_show_index)

    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    raw_hook_command = _raw_hook_command(raw_argv)
    if raw_hook_command is not None and HOOK_ENABLE_FLAG not in raw_argv:
        return _success_hook_response()

    parser = _build_parser()
    try:
        args = parser.parse_args(raw_argv)
    except SystemExit as error:
        if raw_hook_command is not None and error.code not in (None, 0):
            return _success_hook_response()
        raise
    try:
        return args.func(args)
    except UserError as error:
        if args.command in HOOK_COMMANDS:
            setattr(error, "hook_command", args.command)
            return _fail_open_hook_response(error)
        print(str(error), file=sys.stderr)
        return 1
    except Exception as error:
        if args.command in HOOK_COMMANDS:
            setattr(error, "hook_command", args.command)
            return _fail_open_hook_response(error)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
