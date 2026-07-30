"""Bounded subprocess helpers for proving a command does not read stdin."""

from __future__ import annotations

import contextlib
import ctypes
import errno
import json
import os
import pathlib
import select
import selectors
import signal
import subprocess
import sys
import textwrap
import time
import unittest
from typing import Callable, Literal


_DRAIN_CHUNK_BYTES = 64 * 1024
_MAX_CAPTURE_BYTES = 256 * 1024
_POLL_INTERVAL_SECONDS = 0.02
_PROC_GROUP_SCAN_MAX_ENTRIES = 131_072
_PROC_GROUP_SCAN_TIMEOUT_SECONDS = 0.25
_DARWIN_SA_NOCLDWAIT = 0x0020
_LINUX_SA_NOCLDWAIT = 0x00000002
_LINUX_SIGSET_BYTES = 128
_LINUX_SIGACTION_REVIEWED_MULTIARCH = {
    "aarch64": frozenset({"aarch64-linux-gnu"}),
    "x86_64": frozenset({"x86_64-linux-gnu"}),
}
_IDENTITY_LOST_RETURN_CODE = sys.maxsize
_UNREAPED_RECOVERY_PROCESSES: list[subprocess.Popen[bytes]] = []
_LinuxProcessGroupState = Literal[
    "live",
    "zombie-only",
    "no-members",
    "unknown",
]


class _CaptureLimitExceeded(Exception):
    pass


class _ProcessIdentityLost(AssertionError):
    """The direct-child PID/PGID fence can no longer be trusted."""


class _WaitableSigchldUnavailable(AssertionError):
    """The process cannot preserve an unreaped direct-child identity fence."""


class _DarwinSigaction(ctypes.Structure):
    """Darwin's public struct sigaction layout."""

    _fields_ = (
        ("handler", ctypes.c_void_p),
        ("mask", ctypes.c_uint32),
        ("flags", ctypes.c_int),
    )


class _LinuxSigset(ctypes.Structure):
    """The 1024-bit libc sigset_t used by supported Linux ABIs."""

    _fields_ = (
        (
            "bits",
            ctypes.c_ulong * (_LINUX_SIGSET_BYTES // ctypes.sizeof(ctypes.c_ulong)),
        ),
    )


class _LinuxSigaction(ctypes.Structure):
    """The glibc struct sigaction layout for supported 64-bit Linux ABIs."""

    _fields_ = (
        ("handler", ctypes.c_void_p),
        ("mask", _LinuxSigset),
        ("flags", ctypes.c_int),
        ("restorer", ctypes.c_void_p),
    )


def run_native_no_cldwait_preflight_probe(
    script_path: pathlib.Path,
    *,
    entrypoint: Literal["adapter", "runner", "support"],
) -> dict[str, object]:
    """Prove a real native SA_NOCLDWAIT state is rejected before resources."""

    driver = textwrap.dedent(
        """
        import ctypes
        import importlib.util
        import json
        import os
        import pathlib
        import signal
        import subprocess
        import sys

        script_path = pathlib.Path(sys.argv[1])
        entrypoint = sys.argv[2]
        spec = importlib.util.spec_from_file_location(
            f"native_no_cldwait_{entrypoint}",
            script_path,
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        if sys.platform == "darwin":
            action_type = module._DarwinSigaction
            no_cldwait = (
                module.DARWIN_SA_NOCLDWAIT
                if hasattr(module, "DARWIN_SA_NOCLDWAIT")
                else module._DARWIN_SA_NOCLDWAIT
            )
        elif sys.platform.startswith("linux"):
            machine = os.uname().machine.lower()
            multiarch = getattr(sys.implementation, "_multiarch", None)
            reviewed_multiarch = (
                module.LINUX_SIGACTION_REVIEWED_MULTIARCH
                if hasattr(module, "LINUX_SIGACTION_REVIEWED_MULTIARCH")
                else module._LINUX_SIGACTION_REVIEWED_MULTIARCH
            )
            reviewed = reviewed_multiarch.get(machine)
            if (
                ctypes.sizeof(ctypes.c_void_p) != 8
                or ctypes.sizeof(ctypes.c_ulong) != 8
                or reviewed is None
                or multiarch not in reviewed
            ):
                print(
                    f"unreviewed Linux sigaction ABI: "
                    f"{machine!r}, {multiarch!r}",
                    file=sys.stderr,
                )
                raise SystemExit(77)
            action_type = module._LinuxSigaction
            no_cldwait = (
                module.LINUX_SA_NOCLDWAIT
                if hasattr(module, "LINUX_SA_NOCLDWAIT")
                else module._LINUX_SA_NOCLDWAIT
            )
        else:
            print(f"unsupported platform: {sys.platform}", file=sys.stderr)
            raise SystemExit(77)

        library = ctypes.CDLL(None, use_errno=True)
        sigaction = library.sigaction
        sigaction.argtypes = (
            ctypes.c_int,
            ctypes.POINTER(action_type),
            ctypes.POINTER(action_type),
        )
        sigaction.restype = ctypes.c_int
        original = action_type()
        if sigaction(int(signal.SIGCHLD), None, ctypes.byref(original)) != 0:
            raise OSError(ctypes.get_errno(), "failed to read SIGCHLD action")
        modified = action_type.from_buffer_copy(original)
        modified.handler = None
        modified.flags |= no_cldwait
        if sigaction(int(signal.SIGCHLD), ctypes.byref(modified), None) != 0:
            raise OSError(
                ctypes.get_errno(),
                "failed to install native SA_NOCLDWAIT",
            )

        calls = {
            "killpg": 0,
            "kqueue": 0,
            "pipe": 0,
            "popen": 0,
            "selector": 0,
        }
        rejection = None
        auto_reaped = False
        restored_waitable = False
        originals = {
            "killpg": module.os.killpg,
            "pipe": module.os.pipe,
            "popen": module.subprocess.Popen,
            "selector": module.selectors.DefaultSelector,
        }
        if hasattr(module.select, "kqueue"):
            originals["kqueue"] = module.select.kqueue

        def forbidden(name):
            def fail(*args, **kwargs):
                calls[name] += 1
                raise AssertionError(f"{name} ran under native SA_NOCLDWAIT")
            return fail

        try:
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                auto_reaped = True

            module.os.killpg = forbidden("killpg")
            module.os.pipe = forbidden("pipe")
            module.subprocess.Popen = forbidden("popen")
            module.selectors.DefaultSelector = forbidden("selector")
            if "kqueue" in originals:
                module.select.kqueue = forbidden("kqueue")

            try:
                if entrypoint == "adapter":
                    class SignalTransaction:
                        def raise_if_pending(self):
                            return None
                    module._run_bounded_refresh_process_supervised(
                        [sys.executable, "-c", "raise SystemExit(0)"],
                        pass_fds=(),
                        env=os.environ.copy(),
                        input_bytes=None,
                        timeout=1,
                        cleanup_timeout=1,
                        max_capture_bytes=1024,
                        signal_transaction=SignalTransaction(),
                    )
                elif entrypoint == "runner":
                    class SignalTransaction:
                        def raise_if_pending(self):
                            return None
                    module._run_bounded_smoke_process_supervised(
                        [sys.executable, "-c", "raise SystemExit(0)"],
                        cwd=script_path.parent,
                        pass_fds=(),
                        child_read_streams=(),
                        input_stream=None,
                        input_bytes=None,
                        timeout=1,
                        cleanup_timeout=1,
                        max_capture_bytes=1024,
                        signal_transaction=SignalTransaction(),
                        pre_spawn_check=None,
                    )
                elif entrypoint == "support":
                    module.run_before_stdin_eof(
                        [sys.executable, "-c", "raise SystemExit(0)"],
                        cwd=script_path.parent,
                        env=os.environ.copy(),
                        input_text="",
                        timeout=1,
                    )
                else:
                    raise AssertionError(f"unknown entrypoint {entrypoint!r}")
            except module._WaitableSigchldUnavailable as error:
                rejection = str(error)
        finally:
            module.os.killpg = originals["killpg"]
            module.os.pipe = originals["pipe"]
            module.subprocess.Popen = originals["popen"]
            module.selectors.DefaultSelector = originals["selector"]
            if "kqueue" in originals:
                module.select.kqueue = originals["kqueue"]
            if sigaction(
                int(signal.SIGCHLD),
                ctypes.byref(original),
                None,
            ) != 0:
                raise OSError(
                    ctypes.get_errno(),
                    "failed to restore SIGCHLD action",
                )
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            try:
                _, wait_status = os.waitpid(pid, 0)
            except ChildProcessError:
                restored_waitable = False
            else:
                restored_waitable = wait_status == 0

        print(
            json.dumps(
                {
                    "auto_reaped": auto_reaped,
                    "calls": calls,
                    "rejection": rejection,
                    "restored_waitable": restored_waitable,
                },
                sort_keys=True,
            )
        )
        """
    ).lstrip()
    completed = subprocess.run(
        [sys.executable, "-c", driver, str(script_path), entrypoint],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )
    if completed.returncode == 77:
        raise unittest.SkipTest(completed.stderr.strip())
    if completed.returncode != 0:
        raise AssertionError(
            "native SA_NOCLDWAIT probe failed: "
            f"stdout={completed.stdout!r}; stderr={completed.stderr!r}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"native SA_NOCLDWAIT probe returned invalid JSON: {completed.stdout!r}"
        ) from error
    if not isinstance(payload, dict):
        raise AssertionError("native SA_NOCLDWAIT probe returned a non-object")
    return payload


def _darwin_sigchld_action() -> tuple[int, int]:
    previous_errno = ctypes.get_errno()
    try:
        try:
            library = ctypes.CDLL(None, use_errno=True)
            sigaction = library.sigaction
        except (AttributeError, OSError) as error:
            raise _WaitableSigchldUnavailable(
                "Darwin SIGCHLD disposition inspection is unavailable"
            ) from error
        sigaction.argtypes = (
            ctypes.c_int,
            ctypes.POINTER(_DarwinSigaction),
            ctypes.POINTER(_DarwinSigaction),
        )
        sigaction.restype = ctypes.c_int
        action = _DarwinSigaction()
        ctypes.set_errno(0)
        if sigaction(int(signal.SIGCHLD), None, ctypes.byref(action)) != 0:
            error_number = ctypes.get_errno() or errno.EINVAL
            raise _WaitableSigchldUnavailable(
                "failed to inspect Darwin SIGCHLD disposition: "
                f"{os.strerror(error_number)}"
            )
        return int(action.handler or 0), int(action.flags)
    finally:
        ctypes.set_errno(previous_errno)


def _linux_sigchld_action() -> tuple[int, int]:
    try:
        machine = os.uname().machine.lower()
    except (AttributeError, OSError) as error:
        raise _WaitableSigchldUnavailable(
            "Linux SIGCHLD disposition inspection cannot identify the libc ABI"
        ) from error
    multiarch = getattr(sys.implementation, "_multiarch", None)
    reviewed_multiarch = _LINUX_SIGACTION_REVIEWED_MULTIARCH.get(machine)
    if (
        ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(ctypes.c_ulong) != 8
        or reviewed_multiarch is None
        or multiarch not in reviewed_multiarch
    ):
        raise _WaitableSigchldUnavailable(
            "Linux SIGCHLD disposition inspection has no reviewed sigaction "
            f"layout for machine {machine!r} and multiarch {multiarch!r}"
        )
    previous_errno = ctypes.get_errno()
    try:
        try:
            library = ctypes.CDLL(None, use_errno=True)
            sigaction = library.sigaction
        except (AttributeError, OSError) as error:
            raise _WaitableSigchldUnavailable(
                "Linux SIGCHLD disposition inspection is unavailable"
            ) from error
        sigaction.argtypes = (
            ctypes.c_int,
            ctypes.POINTER(_LinuxSigaction),
            ctypes.POINTER(_LinuxSigaction),
        )
        sigaction.restype = ctypes.c_int
        action = _LinuxSigaction()
        ctypes.set_errno(0)
        if sigaction(int(signal.SIGCHLD), None, ctypes.byref(action)) != 0:
            error_number = ctypes.get_errno() or errno.EINVAL
            raise _WaitableSigchldUnavailable(
                "failed to inspect Linux SIGCHLD disposition: "
                f"{os.strerror(error_number)}"
            )
        return int(action.handler or 0), int(action.flags)
    finally:
        ctypes.set_errno(previous_errno)


def _waitable_sigchld_failure(*, platform: str | None = None) -> str | None:
    """Attest the process-global SIGCHLD contract used as the PID/PGID fence.

    The disposition is process-global, so cooperating code must not mutate it
    during a supervised transaction. Callers re-attest immediately before
    spawn and before every operation that consumes the numeric child identity;
    a failed re-attestation permanently abandons PID/PGID operations.
    """

    selected_platform = sys.platform if platform is None else platform
    signum = getattr(signal, "SIGCHLD", None)
    if not isinstance(signum, int):
        return "SIGCHLD is unavailable"
    try:
        handler = signal.getsignal(signum)
    except (OSError, ValueError) as error:
        return f"SIGCHLD disposition inspection failed: {error}"
    if handler == signal.SIG_IGN:
        return (
            "process supervision requires the default SIGCHLD disposition; "
            "SIGCHLD is ignored and direct children may be auto-reaped"
        )
    if handler != signal.SIG_DFL:
        return (
            "process supervision requires the default SIGCHLD disposition; "
            "SIGCHLD has a custom handler that may reap direct children"
        )
    if selected_platform == "darwin":
        try:
            raw_handler, flags = _darwin_sigchld_action()
        except _WaitableSigchldUnavailable as error:
            return str(error)
        platform_name = "Darwin"
        no_cldwait_flag = _DARWIN_SA_NOCLDWAIT
    elif selected_platform.startswith("linux"):
        try:
            raw_handler, flags = _linux_sigchld_action()
        except _WaitableSigchldUnavailable as error:
            return str(error)
        platform_name = "Linux"
        no_cldwait_flag = _LINUX_SA_NOCLDWAIT
    else:
        return (
            "native SIGCHLD disposition inspection is unavailable on "
            f"{selected_platform}"
        )
    if raw_handler != 0:
        return (
            f"{platform_name} SIGCHLD has a non-default native handler that may "
            "reap direct children"
        )
    if flags & no_cldwait_flag:
        return (
            f"{platform_name} SIGCHLD has SA_NOCLDWAIT and direct children may "
            "be auto-reaped"
        )
    return None


def _require_waitable_sigchld_semantics(
    *,
    after_spawn: bool = False,
    platform: str | None = None,
) -> None:
    try:
        failure = _waitable_sigchld_failure(platform=platform)
    except BaseException as query_error:
        if after_spawn:
            raise _ProcessIdentityLost(
                "waitable SIGCHLD re-attestation failed after process launch: "
                f"{type(query_error).__name__}"
            ) from query_error
        raise _WaitableSigchldUnavailable(
            "waitable SIGCHLD attestation failed before process launch: "
            f"{type(query_error).__name__}"
        ) from query_error
    if failure is None:
        return
    if after_spawn:
        raise _ProcessIdentityLost(
            "waitable SIGCHLD semantics changed after process launch: " + failure
        )
    raise _WaitableSigchldUnavailable(
        "waitable SIGCHLD semantics are required before process launch: " + failure
    )


def _preflight_unreaped_leader_observer(
    *,
    platform: str | None = None,
    after_spawn: bool = False,
) -> str:
    if sys.implementation.name != "cpython":
        raise AssertionError(
            "process supervision requires reviewed CPython Popen finalizer semantics"
        )
    selected_platform = sys.platform if platform is None else platform
    if selected_platform == "darwin":
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
            raise AssertionError("Darwin process supervision requires kqueue NOTE_EXIT")
    elif selected_platform.startswith("linux"):
        required = ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
        if not callable(getattr(os, "waitid", None)) or any(
            not hasattr(os, name) for name in required
        ):
            raise AssertionError(
                "Linux process supervision requires waitid with "
                "P_PID/WEXITED/WNOHANG/WNOWAIT"
            )
    else:
        raise AssertionError(
            f"process supervision is unsupported on platform {selected_platform}"
        )
    _require_waitable_sigchld_semantics(
        after_spawn=after_spawn,
        platform=selected_platform,
    )
    return selected_platform


class _UnreapedLeaderObserver:
    """Observe one session leader without releasing its PID/PGID identity."""

    def __init__(self, pid: int, *, platform: str | None = None) -> None:
        if pid <= 0:
            raise AssertionError("process leader pid must be positive")
        self.pid = pid
        self.platform = _preflight_unreaped_leader_observer(
            platform=platform,
            after_spawn=True,
        )
        self._exited = False
        self._reaped = False
        self._kqueue: object | None = None
        if self.platform == "darwin":
            kqueue: object | None = None
            try:
                kqueue = select.kqueue()
                event = select.kevent(
                    pid,
                    filter=select.KQ_FILTER_PROC,
                    flags=(
                        select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT
                    ),
                    fflags=select.KQ_NOTE_EXIT,
                )
                _require_waitable_sigchld_semantics(
                    after_spawn=True,
                )
                observed = kqueue.control([event], 1, 0)
            except BaseException as error:
                if kqueue is not None:
                    try:
                        kqueue.close()
                    except BaseException:
                        pass
                if isinstance(error, OSError):
                    raise AssertionError(
                        "cannot bind Darwin process-exit observation"
                    ) from error
                raise
            self._kqueue = kqueue
            try:
                self._accept_kqueue_events(observed)
                _require_waitable_sigchld_semantics(
                    after_spawn=True,
                )
            except BaseException:
                try:
                    self.close()
                except BaseException:
                    pass
                raise

    def _accept_kqueue_events(self, events: list[object]) -> None:
        for event in events:
            if getattr(event, "ident", None) != self.pid or not (
                getattr(event, "fflags", 0) & select.KQ_NOTE_EXIT
            ):
                raise AssertionError(
                    "Darwin process-exit observation returned an unrelated event"
                )
            _require_waitable_sigchld_semantics(
                after_spawn=True,
            )
            self._exited = True

    def exited(self) -> bool:
        if self._reaped:
            raise AssertionError("process leader was already reaped")
        _require_waitable_sigchld_semantics(
            after_spawn=True,
        )
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
            raise _ProcessIdentityLost(
                "process leader identity was lost before supervisor reap"
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
            raise AssertionError("refusing to signal a process group after leader reap")
        _require_waitable_sigchld_semantics(
            after_spawn=True,
        )
        try:
            os.killpg(self.pid, signum)
        except ProcessLookupError:
            pass

    def reap(
        self,
        process: subprocess.Popen[bytes],
        *,
        timeout: float,
    ) -> int:
        if process.pid != self.pid:
            raise AssertionError("process leader identity changed before reap")
        if not self._exited:
            raise AssertionError("cannot reap a process leader before observed exit")
        if timeout <= 0:
            raise AssertionError("bounded reap timeout must be positive")
        _require_waitable_sigchld_semantics(
            after_spawn=True,
        )
        returncode = process.wait(timeout=timeout)
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


def _darwin_process_group_state_impl(
    pgid: int,
    *,
    known_exited_leader_pid: int | None = None,
    deadline: float | None = None,
    max_entries: int = _PROC_GROUP_SCAN_MAX_ENTRIES,
) -> _LinuxProcessGroupState:
    if deadline is None:
        deadline = time.monotonic() + _PROC_GROUP_SCAN_TIMEOUT_SECONDS
    if time.monotonic() >= deadline:
        return "unknown"
    if max_entries <= 0:
        return "unknown"
    if known_exited_leader_pid is not None and known_exited_leader_pid != pgid:
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
        if time.monotonic() >= deadline:
            return "unknown"
        ctypes.set_errno(0)
        count = list_group(pgid, pid_array, ctypes.sizeof(pid_array))
        if time.monotonic() >= deadline:
            return "unknown"
    except (AttributeError, OSError, ValueError):
        return "unknown"
    if count < 0 or count >= max_entries:
        return "unknown"
    if count == 0 and ctypes.get_errno() != 0:
        return "unknown"
    saw_zombie = False
    for pid in pid_array[:count]:
        if time.monotonic() >= deadline:
            return "unknown"
        if pid <= 0:
            return "unknown"
        info = _DarwinProcBSDInfo()
        try:
            ctypes.set_errno(0)
            size = pid_info(
                pid,
                3,
                1,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if time.monotonic() >= deadline:
                return "unknown"
        except (OSError, ValueError):
            return "unknown"
        if size == 0:
            process_error = ctypes.get_errno()
            if (
                process_error == errno.ESRCH
                and known_exited_leader_pid is not None
                and pid == known_exited_leader_pid
                and pid == pgid
            ):
                saw_zombie = True
                continue
            return "unknown"
        if size != ctypes.sizeof(info) or info.pbi_pid != pid or info.pbi_pgid != pgid:
            return "unknown"
        if (
            known_exited_leader_pid is not None
            and pid == known_exited_leader_pid
            and pid == pgid
        ):
            # NOTE_EXIT already bound this still-unreaped leader as exited.
            # libproc may briefly retain its pre-zombie status after that event.
            saw_zombie = True
            continue
        if info.pbi_status != 5:
            return "live"
        saw_zombie = True
    if saw_zombie:
        return "zombie-only"
    return "no-members"


def _darwin_process_group_state(
    pgid: int,
    *,
    known_exited_leader_pid: int | None = None,
    deadline: float | None = None,
    max_entries: int = _PROC_GROUP_SCAN_MAX_ENTRIES,
) -> _LinuxProcessGroupState:
    saved_errno = ctypes.get_errno()
    try:
        return _darwin_process_group_state_impl(
            pgid,
            known_exited_leader_pid=known_exited_leader_pid,
            deadline=deadline,
            max_entries=max_entries,
        )
    finally:
        ctypes.set_errno(saved_errno)


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


def _process_group_state(
    pgid: int,
    *,
    proc_root: pathlib.Path = pathlib.Path("/proc"),
    platform: str = sys.platform,
    deadline: float | None = None,
    known_exited_leader_pid: int | None = None,
) -> _LinuxProcessGroupState:
    if deadline is not None and time.monotonic() >= deadline:
        return "unknown"
    _require_waitable_sigchld_semantics(after_spawn=True)
    if platform == "darwin":
        return _darwin_process_group_state(
            pgid,
            known_exited_leader_pid=known_exited_leader_pid,
            deadline=deadline,
        )
    _require_waitable_sigchld_semantics(after_spawn=True)
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return "no-members"
    except PermissionError:
        return "unknown"
    if not platform.startswith("linux"):
        return "unknown"
    _require_waitable_sigchld_semantics(after_spawn=True)
    state = _linux_process_group_state(
        pgid,
        proc_root=proc_root,
        deadline=deadline,
    )
    if state == "zombie-only":
        return state
    if state != "no-members":
        return state
    if deadline is not None and time.monotonic() >= deadline:
        return "unknown"
    # The group may have disappeared during the scan. Only a second ESRCH proves
    # absence; every other ambiguous result remains live and fails closed.
    _require_waitable_sigchld_semantics(after_spawn=True)
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return "no-members"
    except PermissionError:
        return "unknown"
    return "unknown"


def _process_group_exists(
    pgid: int,
    *,
    proc_root: pathlib.Path = pathlib.Path("/proc"),
    platform: str = sys.platform,
    deadline: float | None = None,
    known_exited_leader_pid: int | None = None,
) -> bool:
    return _process_group_state(
        pgid,
        proc_root=proc_root,
        platform=platform,
        deadline=deadline,
        known_exited_leader_pid=known_exited_leader_pid,
    ) not in {"zombie-only", "no-members"}


def _kill_process_group(observer: _UnreapedLeaderObserver) -> None:
    observer.signal_group(signal.SIGKILL)


def _best_effort_close_resource(resource: object | None) -> None:
    if resource is None:
        return
    close = getattr(resource, "close", None)
    if not callable(close):
        return
    try:
        close()
    except BaseException:
        pass


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


def _retain_unreaped_process(process: subprocess.Popen[bytes]) -> None:
    if not any(candidate is process for candidate in _UNREAPED_RECOVERY_PROCESSES):
        _UNREAPED_RECOVERY_PROCESSES.append(process)


def _disarm_process_after_identity_loss(process: subprocess.Popen[bytes]) -> None:
    """Prevent every future Popen poll, wait, and finalizer waitpid."""

    object.__setattr__(process, "returncode", _IDENTITY_LOST_RETURN_CODE)
    object.__setattr__(process, "_child_created", False)
    if (
        object.__getattribute__(process, "returncode") != _IDENTITY_LOST_RETURN_CODE
        or object.__getattribute__(process, "_child_created") is not False
    ):
        raise AssertionError("could not disarm identity-lost Popen finalization")


def _permanently_pin_process_after_identity_loss(
    process: subprocess.Popen[bytes],
) -> None:
    """Leak one CPython reference so interpreter teardown cannot run __del__."""

    py_incref = ctypes.pythonapi.Py_IncRef
    py_incref.argtypes = (ctypes.py_object,)
    py_incref.restype = None
    py_incref(process)


def _settle_direct_child_after_identity_loss(
    process: subprocess.Popen[bytes],
) -> str:
    """Close owned pipes without consuming any reused numeric child identity."""

    close_issues: list[str] = []
    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(process, stream_name, None)
        close = getattr(stream, "close", None)
        if not callable(close):
            continue
        try:
            close()
        except BaseException as error:
            close_issues.append(f"{stream_name}:{type(error).__name__}")
    settlement = (
        "direct-child wait, poll, and reap were skipped after identity loss; "
        "the numeric PID may have been reused and status is unavailable"
    )
    if close_issues:
        settlement += "; pipe-close issues=" + ",".join(close_issues)
    return settlement


def _identity_loss_cleanup_error(
    process: subprocess.Popen[bytes],
    error: _ProcessIdentityLost,
    *,
    context: str,
) -> AssertionError:
    safety_issues: list[str] = []
    try:
        object.__setattr__(process, "returncode", _IDENTITY_LOST_RETURN_CODE)
    except BaseException as sentinel_error:
        safety_issues.append(f"sentinel:{type(sentinel_error).__name__}")
    try:
        _retain_unreaped_process(process)
    except BaseException as retain_error:
        safety_issues.append(f"retain:{type(retain_error).__name__}")
    for _attempt in range(2):
        try:
            _disarm_process_after_identity_loss(process)
            break
        except BaseException as disarm_error:
            safety_issues.append(f"disarm:{type(disarm_error).__name__}")
    try:
        core_disarmed = (
            object.__getattribute__(process, "returncode") == _IDENTITY_LOST_RETURN_CODE
        )
    except BaseException as verify_error:
        safety_issues.append(f"verify-sentinel:{type(verify_error).__name__}")
        core_disarmed = False
    permanently_pinned = False
    if not core_disarmed:
        for _attempt in range(2):
            try:
                _permanently_pin_process_after_identity_loss(process)
                permanently_pinned = True
                break
            except BaseException as pin_error:
                safety_issues.append(f"pin:{type(pin_error).__name__}")
        if not permanently_pinned:
            os._exit(70)
    try:
        _retain_unreaped_process(process)
    except BaseException as retain_error:
        safety_issues.append(f"retain-retry:{type(retain_error).__name__}")
    try:
        retained = any(
            candidate is process for candidate in _UNREAPED_RECOVERY_PROCESSES
        )
    except BaseException as verify_error:
        safety_issues.append(f"verify-retain:{type(verify_error).__name__}")
        retained = False
    settlement = _settle_direct_child_after_identity_loss(process)
    if core_disarmed:
        finalizer_state = "Popen numeric-child polling disarmed"
    else:
        finalizer_state = "Popen permanently pinned after sentinel failure"
    if safety_issues:
        finalizer_state += " after safety retries=" + ",".join(safety_issues)
    evidence_state = (
        "strong process identity is retained as recovery evidence"
        if retained
        else "recovery-list retention failed after numeric-identity safety was secured"
    )
    cleanup_error = AssertionError(
        f"{error}; {context} cleanup-incomplete: numeric PID/PGID signalling "
        f"and probing were skipped after leader identity loss; {settlement}; "
        f"leader_pid={process.pid}; {finalizer_state}; {evidence_state}"
    )
    if error.__cause__ is not None:
        cleanup_error.__cause__ = error.__cause__
    return cleanup_error


def _register_cleanup_output(
    selector: selectors.BaseSelector,
    process: subprocess.Popen[bytes],
) -> None:
    if process.stdout is None or process.stderr is None:
        raise AssertionError("subprocess pipes were not created")
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        os.set_blocking(stream.fileno(), False)
        try:
            selector.get_key(stream.fileno())
        except KeyError:
            selector.register(stream.fileno(), selectors.EVENT_READ, name)


def _emergency_cleanup_after_observer_failure_impl(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    deadline: float,
    platform: str,
    close_input_writer: Callable[[], None],
) -> None:
    signal_error: str | None = None
    _require_waitable_sigchld_semantics(
        after_spawn=True,
    )
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        signal_error = f"{type(error).__name__}: {error}"
    close_input_writer()
    try:
        _register_cleanup_output(selector, process)
    except (OSError, AssertionError) as error:
        _retain_unreaped_process(process)
        raise AssertionError(
            "subprocess observer binding failed and emergency cleanup could not "
            f"initialize nonblocking pipe drain; leader_pid={process.pid}; "
            f"signal_error={signal_error or 'none'}; leader remains unreaped and "
            "retained for recovery"
        ) from error

    last_group_state: _LinuxProcessGroupState = "unknown"
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        _drain_once(
            selector,
            captures,
            timeout=min(_POLL_INTERVAL_SECONDS, max(0.0, remaining)),
            capture=False,
        )
        if time.monotonic() >= deadline:
            break
        _require_waitable_sigchld_semantics(
            after_spawn=True,
        )
        last_group_state = _process_group_state(
            process.pid,
            platform=platform,
            deadline=deadline,
        )
        if last_group_state in {"zombie-only", "no-members"} and not selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            _require_waitable_sigchld_semantics(
                after_spawn=True,
            )
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                break
            except BaseException as error:
                _retain_unreaped_process(process)
                raise AssertionError(
                    "subprocess observer binding failed and bounded emergency "
                    f"reap failed; leader_pid={process.pid} is retained for recovery"
                ) from error
            # The successful wait releases the PID/PGID fence. Do not signal or
            # probe that numeric process-group identity again.
            return

    _retain_unreaped_process(process)
    open_pipes = sorted(
        str(key.data)
        for key in selector.get_map().values()
        if key.data in {"stdout", "stderr"}
    )
    raise AssertionError(
        "subprocess observer binding failed and emergency cleanup did not complete "
        f"before its hard deadline; leader_pid={process.pid}; pgid={process.pid}; "
        f"group_state={last_group_state}; open_pipes={open_pipes}; "
        f"signal_error={signal_error or 'none'}; leader remains unreaped and "
        "retained for recovery"
    )


def _emergency_cleanup_after_observer_failure(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    deadline: float,
    platform: str,
    close_input_writer: Callable[[], None],
) -> None:
    try:
        _emergency_cleanup_after_observer_failure_impl(
            process,
            selector,
            captures,
            deadline=deadline,
            platform=platform,
            close_input_writer=close_input_writer,
        )
    except _ProcessIdentityLost as error:
        raise _identity_loss_cleanup_error(
            process,
            error,
            context="subprocess observer-binding emergency",
        ) from error
    except BaseException:
        _retain_unreaped_process(process)
        raise


def _bounded_cleanup_impl(
    process: subprocess.Popen[bytes],
    observer: _UnreapedLeaderObserver,
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    deadline: float,
    platform: str,
) -> None:
    signal_error: str | None = None
    try:
        _kill_process_group(observer)
    except OSError as error:
        signal_error = f"{type(error).__name__}: {error}"
    last_leader_exited = False
    last_group_state: _LinuxProcessGroupState = "unknown"
    last_open_pipes = sorted(str(key.data) for key in selector.get_map().values())
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        _drain_once(
            selector,
            captures,
            timeout=min(_POLL_INTERVAL_SECONDS, max(0.0, remaining)),
            capture=False,
        )
        last_open_pipes = sorted(str(key.data) for key in selector.get_map().values())
        if time.monotonic() >= deadline:
            break
        last_leader_exited = observer.exited()
        if last_leader_exited:
            if time.monotonic() >= deadline:
                break
            _require_waitable_sigchld_semantics(
                after_spawn=True,
            )
            last_group_state = _process_group_state(
                process.pid,
                platform=platform,
                deadline=deadline,
                known_exited_leader_pid=process.pid,
            )
            if time.monotonic() >= deadline:
                break
            if (
                last_group_state in {"zombie-only", "no-members"}
                and not last_open_pipes
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    observer.reap(process, timeout=remaining)
                except subprocess.TimeoutExpired as error:
                    _retain_unreaped_process(process)
                    raise AssertionError(
                        "subprocess leader did not complete bounded reap after "
                        "live-group absence and pipe drain; "
                        f"leader_pid={process.pid} remains unreaped and retained "
                        "for recovery"
                    ) from error
                # The successful reap releases the PID/PGID fence. Do not signal
                # or probe that numeric process-group identity again.
                return
    _retain_unreaped_process(process)
    reasons: list[str] = []
    if not last_leader_exited:
        reasons.append("subprocess leader exit was not observed")
    if last_group_state not in {"zombie-only", "no-members"}:
        reasons.append(f"subprocess process-group state remained {last_group_state}")
    if last_open_pipes:
        reasons.append("failed to drain subprocess pipes")
    if signal_error is not None:
        reasons.append(f"process-group SIGKILL failed: {signal_error}")
    reasons.append(
        f"leader_pid={process.pid} remains unreaped and retained for recovery"
    )
    raise AssertionError("; ".join(reasons))


def _bounded_cleanup(
    process: subprocess.Popen[bytes],
    observer: _UnreapedLeaderObserver,
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    deadline: float,
    platform: str,
) -> None:
    try:
        _bounded_cleanup_impl(
            process,
            observer,
            selector,
            captures,
            deadline=deadline,
            platform=platform,
        )
    except _ProcessIdentityLost as error:
        raise _identity_loss_cleanup_error(
            process,
            error,
            context="subprocess",
        ) from error
    except BaseException:
        if not getattr(observer, "_reaped", False):
            _retain_unreaped_process(process)
        raise


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
    observer_platform = _preflight_unreaped_leader_observer()
    started_at = time.monotonic()
    deadline = started_at + timeout
    cleanup_reserve = min(1.0, timeout / 2)
    monitor_deadline = deadline - cleanup_reserve
    selector = selectors.DefaultSelector()
    try:
        read_fd, write_fd = os.pipe()
    except BaseException:
        _best_effort_close_resource(selector)
        raise
    process: subprocess.Popen[bytes] | None = None
    observer: _UnreapedLeaderObserver | None = None
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    write_fd_open = True

    def close_input_writer() -> None:
        nonlocal write_fd_open
        if write_fd_open:
            write_fd_open = False
            with contextlib.suppress(BaseException):
                os.close(write_fd)

    try:
        encoded = input_text.encode("utf-8")
        _require_waitable_sigchld_semantics()
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
            observer = _UnreapedLeaderObserver(
                process.pid,
                platform=observer_platform,
            )
        except BaseException as observer_error:
            cleanup_error: BaseException | None = None
            try:
                if isinstance(observer_error, _ProcessIdentityLost):
                    cleanup_error = _identity_loss_cleanup_error(
                        process,
                        observer_error,
                        context="subprocess observer binding",
                    )
                else:
                    _emergency_cleanup_after_observer_failure(
                        process,
                        selector,
                        captures,
                        deadline=deadline,
                        platform=observer_platform,
                        close_input_writer=close_input_writer,
                    )
            except BaseException as error:
                cleanup_error = error
            if cleanup_error is not None:
                raise observer_error from cleanup_error
            raise
    finally:
        with contextlib.suppress(BaseException):
            os.close(read_fd)
        if observer is None:
            close_input_writer()
            _best_effort_close_resource(selector)
            if process is not None:
                _best_effort_close_resource(process.stdout)
                _best_effort_close_resource(process.stderr)

    assert process is not None
    assert observer is not None
    assert process.stdout is not None
    assert process.stderr is not None
    leader_reaped = False
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
            if time.monotonic() >= monitor_deadline:
                failure = "process did not exit while the stdin writer remained open"
                break
            if not observer.exited():
                continue
            if time.monotonic() >= monitor_deadline:
                failure = "process did not exit while the stdin writer remained open"
                break
            _require_waitable_sigchld_semantics(
                after_spawn=True,
            )
            if _process_group_exists(
                process.pid,
                deadline=monitor_deadline,
                known_exited_leader_pid=process.pid,
            ):
                failure = "subprocess left a child in its process group"
                break
            if not selector.get_map():
                remaining = monitor_deadline - time.monotonic()
                if remaining <= 0:
                    failure = (
                        "subprocess completed at the monitor deadline before "
                        "bounded reap"
                    )
                    break
                try:
                    returncode = observer.reap(process, timeout=remaining)
                    leader_reaped = True
                except subprocess.TimeoutExpired:
                    failure = "subprocess did not complete bounded reap"
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
        if leader_reaped:
            raise
        if isinstance(error, _ProcessIdentityLost):
            cleanup_evidence = _identity_loss_cleanup_error(
                process,
                error,
                context="subprocess",
            )
            with contextlib.suppress(BaseException):
                close_input_writer()
            raise error from cleanup_evidence
        try:
            close_input_writer()
            _bounded_cleanup(
                process,
                observer,
                selector,
                captures,
                deadline=deadline,
                platform=observer_platform,
            )
        except BaseException as cleanup_error:
            raise error from cleanup_error
        raise
    finally:
        if observer is not None:
            _best_effort_close_resource(observer)
        with contextlib.suppress(BaseException):
            close_input_writer()
        _best_effort_close_resource(selector)
        _best_effort_close_resource(process.stdout)
        _best_effort_close_resource(process.stderr)
