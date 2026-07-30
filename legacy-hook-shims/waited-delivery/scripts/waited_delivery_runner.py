#!/usr/bin/env python3
"""Redirect active pre-rename runs to the packaged compatibility runner."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile


RUNNER_SOURCE_MAX_BYTES = 4 * 1024 * 1024
RUNNER_READ_CHUNK_BYTES = 64 * 1024
SNAPSHOT_FILE_MODE = 0o600
SNAPSHOT_DIRECTORY_MODE = 0o700
DESCRIPTOR_BOOTSTRAP = """\
import os
import sys

canonical_path = sys.argv[1]
runner_fd = int(sys.argv[2])
runner_args = sys.argv[3:]
with os.fdopen(runner_fd, "rb", closefd=True) as runner:
    runner_source = runner.read()
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


def _private_runner_snapshot(content: bytes) -> int:
    snapshot_dir = Path(tempfile.mkdtemp(prefix="waited-delivery-runner-redirect-"))
    snapshot_name = "waited_delivery_runner.snapshot"
    directory_fd: int | None = None
    write_fd: int | None = None
    snapshot_fd: int | None = None
    name_exists = False
    try:
        named_directory = os.lstat(snapshot_dir)
        directory_fd = os.open(
            snapshot_dir,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_directory = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(named_directory.st_mode)
            or not stat.S_ISDIR(opened_directory.st_mode)
            or _object_access_identity(opened_directory)
            != _object_access_identity(named_directory)
            or opened_directory.st_uid != os.geteuid()
            or stat.S_IMODE(opened_directory.st_mode) != SNAPSHOT_DIRECTORY_MODE
        ):
            raise RuntimeError("runner snapshot directory is not owner-private")
        write_fd = os.open(
            snapshot_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            SNAPSHOT_FILE_MODE,
            dir_fd=directory_fd,
        )
        name_exists = True
        os.fchmod(write_fd, SNAPSHOT_FILE_MODE)
        offset = 0
        while offset < len(content):
            written = os.write(write_fd, content[offset:])
            if written <= 0:
                raise RuntimeError("cannot write compatibility runner snapshot")
            offset += written
        os.fsync(write_fd)
        os.close(write_fd)
        write_fd = None

        snapshot_fd = os.open(
            snapshot_name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        named_snapshot = os.stat(
            snapshot_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        opened_snapshot = os.fstat(snapshot_fd)
        if (
            not stat.S_ISREG(named_snapshot.st_mode)
            or not stat.S_ISREG(opened_snapshot.st_mode)
            or _runner_version(opened_snapshot) != _runner_version(named_snapshot)
            or opened_snapshot.st_uid != os.geteuid()
            or stat.S_IMODE(opened_snapshot.st_mode) != SNAPSHOT_FILE_MODE
            or opened_snapshot.st_size != len(content)
            or _read_runner_fd(snapshot_fd) != content
        ):
            raise RuntimeError("compatibility runner snapshot verification failed")
        os.lseek(snapshot_fd, 0, os.SEEK_SET)
        os.unlink(snapshot_name, dir_fd=directory_fd)
        name_exists = False
        os.fsync(directory_fd)
        os.close(directory_fd)
        directory_fd = None
        os.rmdir(snapshot_dir)
        result_fd = snapshot_fd
        snapshot_fd = None
        return result_fd
    finally:
        if write_fd is not None:
            os.close(write_fd)
        if snapshot_fd is not None:
            os.close(snapshot_fd)
        if directory_fd is not None:
            if name_exists:
                try:
                    os.unlink(snapshot_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            os.close(directory_fd)
        try:
            os.rmdir(snapshot_dir)
        except FileNotFoundError:
            pass


def _exec_runner_snapshot(
    canonical_path: Path,
    snapshot_fd: int,
) -> None:
    os.set_inheritable(snapshot_fd, True)
    os.execv(
        sys.executable,
        [
            sys.executable,
            "-c",
            DESCRIPTOR_BOOTSTRAP,
            str(canonical_path),
            str(snapshot_fd),
            *sys.argv[1:],
        ],
    )
    raise AssertionError("os.execv returned unexpectedly")


def main() -> int:
    snapshot_fd: int | None = None
    try:
        runner_path = _compat_runner_path()
        source = _stable_runner_source(runner_path)
        snapshot_fd = _private_runner_snapshot(source)
        _exec_runner_snapshot(runner_path, snapshot_fd)
    except (IndexError, OSError, RuntimeError) as error:
        print(
            f"ERROR: waited-delivery compatibility runner is unavailable: {error}",
            file=sys.stderr,
        )
        return 126
    finally:
        if snapshot_fd is not None:
            os.close(snapshot_fd)
    raise AssertionError("runner snapshot execution returned unexpectedly")


if __name__ == "__main__":
    raise SystemExit(main())
