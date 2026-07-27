"""Bounded subprocess helpers for proving a command does not read stdin."""

from __future__ import annotations

import os
import pathlib
import selectors
import signal
import subprocess
import time


_DRAIN_CHUNK_BYTES = 64 * 1024
_MAX_CAPTURE_BYTES = 256 * 1024
_POLL_INTERVAL_SECONDS = 0.02


class _CaptureLimitExceeded(Exception):
    pass


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_process_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
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


def _bounded_cleanup(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    deadline: float,
    terminate_group: bool,
) -> None:
    if terminate_group:
        _kill_process_group(process.pid)
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        _drain_once(
            selector,
            captures,
            timeout=min(_POLL_INTERVAL_SECONDS, max(0.0, remaining)),
            capture=False,
        )
        returncode = process.poll()
        group_exists = _process_group_exists(process.pid)
        if returncode is not None and not group_exists and not selector.get_map():
            return
    if process.poll() is None:
        raise AssertionError("failed to reap subprocess before cleanup deadline")
    if _process_group_exists(process.pid):
        raise AssertionError("failed to prove subprocess process-group disappearance")
    if selector.get_map():
        raise AssertionError("failed to drain subprocess pipes before cleanup deadline")


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
    read_fd, write_fd = os.pipe()
    process: subprocess.Popen[bytes] | None = None
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
    finally:
        os.close(read_fd)
        if process is None:
            os.close(write_fd)
            write_fd_open = False

    assert process is not None
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
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
            returncode = process.poll()
            if returncode is None:
                continue
            if _process_group_exists(process.pid):
                failure = "subprocess left a child in its process group"
                break
            if not selector.get_map():
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
            _kill_process_group(process.pid)
        except BaseException as exc:
            termination_error = exc
        if write_fd_open:
            os.close(write_fd)
            write_fd_open = False
        try:
            _bounded_cleanup(
                process,
                selector,
                captures,
                deadline=deadline,
                terminate_group=termination_error is not None,
            )
        except BaseException as cleanup_error:
            raise cleanup_error from error
        raise
    finally:
        if write_fd_open:
            os.close(write_fd)
        selector.close()
        process.stdout.close()
        process.stderr.close()
