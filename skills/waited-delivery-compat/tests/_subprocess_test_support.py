"""Bounded subprocess helpers for proving a command does not read stdin."""

from __future__ import annotations

import os
import pathlib
import signal
import subprocess


def run_before_stdin_eof(
    cmd: list[str],
    *,
    cwd: pathlib.Path,
    env: dict[str, str],
    input_text: str,
    timeout: float = 3,
) -> subprocess.CompletedProcess[str]:
    """Run a command while keeping its stdin writer open until it exits.

    A command that tries to read stdin to EOF will block and fail the bounded
    wait. A fresh process group makes timeout and descendant cleanup explicit.
    """

    read_fd, write_fd = os.pipe()
    process: subprocess.Popen[str] | None = None
    try:
        encoded = input_text.encode("utf-8")
        written = os.write(write_fd, encoded)
        if written != len(encoded):
            raise RuntimeError("failed to seed the stdin sentinel pipe")
        process = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=env,
            stdin=read_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
            start_new_session=True,
        )
    finally:
        os.close(read_fd)

    assert process is not None
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=timeout)
            raise AssertionError(
                "process did not exit while the stdin writer remained open"
            ) from error

        stdout = process.stdout.read()
        stderr = process.stderr.read()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            os.killpg(process.pid, signal.SIGKILL)
            raise AssertionError("subprocess left a child in its process group")
        return subprocess.CompletedProcess(
            cmd,
            returncode,
            stdout=stdout,
            stderr=stderr,
        )
    finally:
        os.close(write_fd)
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=timeout)
        process.stdout.close()
        process.stderr.close()
