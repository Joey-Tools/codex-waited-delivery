#!/usr/bin/env python3
"""Redirect active pre-rename runs to the packaged compatibility runner."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys


RUNNER_SOURCE_MAX_BYTES = 4 * 1024 * 1024
RUNNER_READ_CHUNK_BYTES = 64 * 1024
PIPE_BOOTSTRAP = """\
import hashlib
import os
import sys

canonical_path = sys.argv[1]
runner_fd = int(sys.argv[2])
writer_pid = int(sys.argv[3])
expected_size = int(sys.argv[4])
expected_sha256 = sys.argv[5]
runner_args = sys.argv[6:]
frame_error = None
runner_source = b""
try:
    if expected_size <= 0 or expected_size > 4 * 1024 * 1024:
        raise SystemExit("invalid compatibility runner pipe size")
    with os.fdopen(runner_fd, "rb", closefd=True) as runner:
        runner_fd = -1
        chunks = []
        remaining = expected_size
        while remaining:
            chunk = runner.read(min(64 * 1024, remaining))
            if not chunk:
                raise SystemExit("truncated compatibility runner pipe")
            chunks.append(chunk)
            remaining -= len(chunk)
        if runner.read(1):
            raise SystemExit("oversized compatibility runner pipe")
    runner_source = b"".join(chunks)
    if hashlib.sha256(runner_source).hexdigest() != expected_sha256:
        raise SystemExit("compatibility runner pipe digest mismatch")
except BaseException as error:
    frame_error = error
    if runner_fd >= 0:
        try:
            os.close(runner_fd)
        except OSError:
            pass
try:
    waited_pid, writer_status = os.waitpid(writer_pid, 0)
except ChildProcessError:
    pass
else:
    if (
        waited_pid != writer_pid
        or not os.WIFEXITED(writer_status)
        or os.WEXITSTATUS(writer_status) != 0
    ):
        raise SystemExit("compatibility runner pipe writer failed")
if frame_error is not None:
    raise frame_error
sys.argv[:] = [canonical_path, *runner_args]
runner_globals = {
    "__name__": "__main__",
    "__file__": canonical_path,
    "__package__": None,
    "__cached__": None,
}
exec(compile(runner_source, canonical_path, "exec"), runner_globals)
"""


def _compat_runner_path() -> Path:
    loaded_path = Path(__file__).resolve(strict=True)
    container = loaded_path.parents[2]
    if container.name == "skills":
        skills_root = container
    elif container.name == "legacy-hook-shims":
        skills_root = container.parent / "skills"
    else:
        raise RuntimeError("legacy runner is outside a supported release layout")
    return (
        skills_root / "waited-delivery-compat" / "scripts" / "waited_delivery_runner.py"
    )


def _validate_compat_runner_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("compatibility runner is not a regular file")
    if metadata.st_uid != os.geteuid():
        raise RuntimeError("compatibility runner is not owned by the current user")
    if metadata.st_mode & 0o022:
        raise RuntimeError("compatibility runner is group- or other-writable")
    if metadata.st_size <= 0 or metadata.st_size > RUNNER_SOURCE_MAX_BYTES:
        raise RuntimeError("compatibility runner size is outside the accepted bound")


def _object_access_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _runner_version(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        *_object_access_identity(metadata),
        metadata.st_size,
    )


def _read_runner_fd(runner_fd: int) -> bytes:
    os.lseek(runner_fd, 0, os.SEEK_SET)
    content = bytearray()
    while len(content) <= RUNNER_SOURCE_MAX_BYTES:
        chunk = os.read(
            runner_fd,
            min(
                RUNNER_READ_CHUNK_BYTES,
                RUNNER_SOURCE_MAX_BYTES + 1 - len(content),
            ),
        )
        if not chunk:
            return bytes(content)
        content.extend(chunk)
    raise RuntimeError("compatibility runner exceeds the accepted byte bound")


def _stable_runner_source(path: Path) -> bytes:
    runner_fd = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(runner_fd)
        _validate_compat_runner_metadata(before)
        first = _read_runner_fd(runner_fd)
        second = _read_runner_fd(runner_fd)
        after = os.fstat(runner_fd)
        _validate_compat_runner_metadata(after)
        if _runner_version(after) != _runner_version(before) or first != second:
            raise RuntimeError(
                "compatibility runner changed while its bytes were being bound"
            )
        if len(second) != after.st_size:
            raise RuntimeError("compatibility runner size changed during stable read")
        return second
    finally:
        os.close(runner_fd)


def _runner_source_pipe(content: bytes) -> tuple[int, int]:
    if not hasattr(os, "fork"):
        raise RuntimeError("compatibility runner pipe requires POSIX fork support")
    read_fd, write_fd = os.pipe()
    try:
        writer_pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if writer_pid == 0:
        try:
            os.close(read_fd)
            offset = 0
            while offset < len(content):
                written = os.write(write_fd, content[offset:])
                if written <= 0:
                    os._exit(126)
                offset += written
            os.close(write_fd)
        except BaseException:
            os._exit(126)
        os._exit(0)
    os.close(write_fd)
    try:
        os.set_inheritable(read_fd, True)
    except BaseException:
        os.close(read_fd)
        try:
            os.waitpid(writer_pid, 0)
        except ChildProcessError:
            pass
        raise
    return read_fd, writer_pid


def _exec_runner_pipe(
    canonical_path: Path,
    source_fd: int,
    writer_pid: int,
    source: bytes,
) -> None:
    os.execv(
        sys.executable,
        [
            sys.executable,
            "-I",
            "-B",
            "-S",
            "-c",
            PIPE_BOOTSTRAP,
            str(canonical_path),
            str(source_fd),
            str(writer_pid),
            str(len(source)),
            hashlib.sha256(source).hexdigest(),
            *sys.argv[1:],
        ],
    )
    raise AssertionError("os.execv returned unexpectedly")


def main() -> int:
    source_fd: int | None = None
    writer_pid: int | None = None
    try:
        runner_path = _compat_runner_path()
        source = _stable_runner_source(runner_path)
        source_fd, writer_pid = _runner_source_pipe(source)
        _exec_runner_pipe(runner_path, source_fd, writer_pid, source)
    except (IndexError, OSError, RuntimeError) as error:
        print(
            f"ERROR: waited-delivery compatibility runner is unavailable: {error}",
            file=sys.stderr,
        )
        return 126
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if writer_pid is not None:
            try:
                os.waitpid(writer_pid, 0)
            except ChildProcessError:
                pass
    raise AssertionError("runner pipe execution returned unexpectedly")


if __name__ == "__main__":
    raise SystemExit(main())
