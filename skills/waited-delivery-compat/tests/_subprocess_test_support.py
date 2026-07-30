"""Bounded subprocess helpers for proving a command does not read stdin."""

from __future__ import annotations

import ctypes
import os
import pathlib
import select
import selectors
import signal
import subprocess
import sys
import time
from typing import Literal


_DRAIN_CHUNK_BYTES = 64 * 1024
_MAX_CAPTURE_BYTES = 256 * 1024
_POLL_INTERVAL_SECONDS = 0.02
_PROC_GROUP_SCAN_MAX_ENTRIES = 131_072
_PROC_GROUP_SCAN_TIMEOUT_SECONDS = 0.25
_LinuxProcessGroupState = Literal[
    "live",
    "zombie-only",
    "no-members",
    "unknown",
]


class _CaptureLimitExceeded(Exception):
    pass


class _UnreapedLeaderObserver:
    """Observe one session leader without releasing its PID/PGID identity."""

    def __init__(self, pid: int, *, platform: str | None = None) -> None:
        if pid <= 0:
            raise AssertionError("process leader pid must be positive")
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise AssertionError(
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
                raise AssertionError(
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
                        kqueue.close()
                    except OSError:
                        pass
                raise AssertionError(
                    "cannot bind Darwin process-exit observation"
                ) from error
            self._kqueue = kqueue
            self._accept_kqueue_events(observed)
        elif self.platform.startswith("linux"):
            if not callable(getattr(os, "waitid", None)):
                raise AssertionError("Linux process supervision requires waitid")
        else:
            raise AssertionError(
                f"process supervision is unsupported on platform {self.platform}"
            )

    def _accept_kqueue_events(self, events: list[object]) -> None:
        for event in events:
            if (
                getattr(event, "ident", None) != self.pid
                or not (getattr(event, "fflags", 0) & select.KQ_NOTE_EXIT)
            ):
                raise AssertionError(
                    "Darwin process-exit observation returned an unrelated event"
                )
            self._exited = True

    def exited(self) -> bool:
        if self._reaped:
            raise AssertionError("process leader was already reaped")
        if self._exited:
            return True
        if self.platform == "darwin":
            assert self._kqueue is not None
            try:
                events = self._kqueue.control(None, 1, 0)  # type: ignore[attr-defined]
            except OSError as error:
                raise AssertionError(
                    "cannot inspect Darwin process-exit observation"
                ) from error
            self._accept_kqueue_events(events)
            return self._exited
        try:
            result = os.waitid(
                os.P_PID,
                self.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError as error:
            raise AssertionError(
                "process leader was reaped outside its supervisor"
            ) from error
        except OSError as error:
            raise AssertionError(
                "cannot observe process leader without reaping"
            ) from error
        if result is None:
            return False
        if result.si_pid != self.pid:
            raise AssertionError("waitid returned an unrelated process leader")
        self._exited = True
        return True

    def signal_group(self, signum: int) -> None:
        if self._reaped:
            raise AssertionError(
                "refusing to signal a process group after leader reap"
            )
        try:
            os.killpg(self.pid, signum)
        except ProcessLookupError:
            pass

    def reap(self, process: subprocess.Popen[bytes]) -> int:
        if process.pid != self.pid:
            raise AssertionError("process leader identity changed before reap")
        if not self.exited():
            raise AssertionError(
                "cannot reap a process leader before observed exit"
            )
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


def _darwin_process_group_state(
    pgid: int,
    *,
    max_entries: int = _PROC_GROUP_SCAN_MAX_ENTRIES,
) -> _LinuxProcessGroupState:
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
        count = list_group(pgid, pid_array, ctypes.sizeof(pid_array))
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


def _linux_process_group_state(
    pgid: int,
    *,
    proc_root: pathlib.Path = pathlib.Path("/proc"),
    deadline: float | None = None,
    max_entries: int = _PROC_GROUP_SCAN_MAX_ENTRIES,
) -> _LinuxProcessGroupState:
    if deadline is None:
        deadline = time.monotonic() + _PROC_GROUP_SCAN_TIMEOUT_SECONDS
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
                    # Process churn between scandir and read is not ambiguous.
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


def _process_group_exists(
    pgid: int,
    *,
    proc_root: pathlib.Path = pathlib.Path("/proc"),
    platform: str = sys.platform,
) -> bool:
    if platform == "darwin":
        return _darwin_process_group_state(pgid) not in {
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
    state = _linux_process_group_state(pgid, proc_root=proc_root)
    if state == "zombie-only":
        return False
    if state != "no-members":
        return True
    # The group may have disappeared during the scan. Only a second ESRCH proves
    # absence; every other ambiguous result remains live and fails closed.
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_process_group(observer: _UnreapedLeaderObserver) -> None:
    observer.signal_group(signal.SIGKILL)


def _drain_once(
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    timeout: float,
    capture: bool,
) -> None:
    for key, _mask in selector.select(timeout):
        try:
            chunk = os.read(key.fd, _DRAIN_CHUNK_BYTES)
        except BlockingIOError:
            continue
        if not chunk:
            selector.unregister(key.fd)
            continue
        if not capture:
            continue
        captured = sum(len(value) for value in captures.values())
        if captured + len(chunk) > _MAX_CAPTURE_BYTES:
            raise _CaptureLimitExceeded
        captures[key.data].extend(chunk)


def _bounded_cleanup(
    process: subprocess.Popen[bytes],
    observer: _UnreapedLeaderObserver,
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    deadline: float,
    terminate_group: bool,
) -> None:
    if terminate_group:
        _kill_process_group(observer)
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        _drain_once(
            selector,
            captures,
            timeout=min(_POLL_INTERVAL_SECONDS, max(0.0, remaining)),
            capture=False,
        )
        leader_exited = observer.exited()
        group_exists = _process_group_exists(process.pid)
        if leader_exited and not group_exists and not selector.get_map():
            observer.reap(process)
            return
    leader_exited = observer.exited()
    if not leader_exited:
        raise AssertionError("failed to reap subprocess before cleanup deadline")
    if _process_group_exists(process.pid):
        raise AssertionError("failed to prove subprocess process-group disappearance")
    if selector.get_map():
        raise AssertionError("failed to drain subprocess pipes before cleanup deadline")
    observer.reap(process)


def run_before_stdin_eof(
    cmd: list[str],
    *,
    cwd: pathlib.Path,
    env: dict[str, str],
    input_text: str,
    timeout: float = 3,
) -> subprocess.CompletedProcess[str]:
    """Run a command while keeping its stdin writer open until it exits.

    A command that tries any blocking stdin read will block when ``input_text``
    is empty, and a command that reads stdin to EOF will block for any payload.
    The payload is written non-blockingly after the child starts so even an
    oversized sentinel remains subject to the monitor deadline. A fresh process
    group makes timeout and descendant cleanup explicit.
    """

    if timeout <= 0:
        raise ValueError("timeout must be positive")
    started_at = time.monotonic()
    deadline = started_at + timeout
    cleanup_reserve = min(1.0, timeout / 2)
    monitor_deadline = deadline - cleanup_reserve
    selector = selectors.DefaultSelector()
    try:
        read_fd, write_fd = os.pipe()
    except BaseException:
        selector.close()
        raise
    process: subprocess.Popen[bytes] | None = None
    observer: _UnreapedLeaderObserver | None = None
    write_fd_open = True
    try:
        encoded = input_text.encode("utf-8")
        process = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=env,
            stdin=read_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
        try:
            observer = _UnreapedLeaderObserver(process.pid)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    finally:
        os.close(read_fd)
        if process is None:
            os.close(write_fd)
            write_fd_open = False
            selector.close()

    assert process is not None
    assert observer is not None
    assert process.stdout is not None
    assert process.stderr is not None
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        os.set_blocking(write_fd, False)
        for name, stream in (
            ("stdout", process.stdout),
            ("stderr", process.stderr),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ, name)

        failure: str | None = None
        returncode: int | None = None
        input_offset = 0
        stdin_accepting_writes = True
        while time.monotonic() < monitor_deadline:
            if stdin_accepting_writes and input_offset < len(encoded):
                try:
                    input_offset += os.write(
                        write_fd,
                        memoryview(encoded)[input_offset:],
                    )
                except BlockingIOError:
                    pass
                except BrokenPipeError:
                    stdin_accepting_writes = False
            remaining = monitor_deadline - time.monotonic()
            try:
                _drain_once(
                    selector,
                    captures,
                    timeout=min(_POLL_INTERVAL_SECONDS, max(0.0, remaining)),
                    capture=True,
                )
            except _CaptureLimitExceeded:
                failure = (
                    f"subprocess output exceeded {_MAX_CAPTURE_BYTES} captured bytes"
                )
                break
            if not observer.exited():
                continue
            if _process_group_exists(process.pid):
                failure = "subprocess left a child in its process group"
                break
            if not selector.get_map():
                returncode = observer.reap(process)
                break
        else:
            failure = "process did not exit while the stdin writer remained open"

        if failure is not None:
            raise AssertionError(failure)

        if returncode is None:
            raise AssertionError("subprocess reached an impossible terminal state")
        return subprocess.CompletedProcess(
            cmd,
            returncode,
            stdout=captures["stdout"].decode("utf-8", errors="replace"),
            stderr=captures["stderr"].decode("utf-8", errors="replace"),
        )
    except BaseException as error:
        termination_error: BaseException | None = None
        try:
            _kill_process_group(observer)
        except BaseException as exc:
            termination_error = exc
        if write_fd_open:
            os.close(write_fd)
            write_fd_open = False
        try:
            _bounded_cleanup(
                process,
                observer,
                selector,
                captures,
                deadline=deadline,
                terminate_group=termination_error is not None,
            )
        except BaseException as cleanup_error:
            raise cleanup_error from error
        raise
    finally:
        if observer is not None:
            observer.close()
        if write_fd_open:
            os.close(write_fd)
        selector.close()
        process.stdout.close()
        process.stderr.close()
