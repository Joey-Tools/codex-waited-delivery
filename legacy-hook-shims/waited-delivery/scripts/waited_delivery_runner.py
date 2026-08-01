#!/usr/bin/env python3
"""Redirect active pre-rename runs to the packaged compatibility runner."""

from __future__ import annotations

import ctypes
import errno
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


def _validate_compat_directory_metadata(
    metadata: os.stat_result,
    *,
    label: str,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"{label} is not a directory")
    if metadata.st_uid != os.geteuid():
        raise RuntimeError(f"{label} is not owned by the current user")
    if metadata.st_mode & 0o022:
        raise RuntimeError(f"{label} is group- or other-writable")


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
            raise RuntimeError(f"{label} extended ACL cannot be inspected safely")
        if acl_free(acl) != 0:
            raise RuntimeError(f"{label} extended ACL inspection cleanup failed")
        return True
    if sys.platform.startswith("linux"):
        getxattr = getattr(os, "getxattr", None)
        if getxattr is None:
            raise RuntimeError(
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
                raise RuntimeError(
                    f"{label} POSIX ACL cannot be inspected safely"
                ) from error
            except (TypeError, ValueError) as error:
                raise RuntimeError(
                    f"{label} POSIX ACL cannot be inspected descriptor-relatively"
                ) from error
            return True
        return False
    raise RuntimeError(f"{label} ACL inspection is unsupported on {sys.platform}")


def _require_no_extended_acl(file_fd: int, *, label: str) -> None:
    if _descriptor_has_extended_acl(file_fd, label=label):
        raise RuntimeError(f"{label} must not carry a named or extended ACL")


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


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _validate_directory_binding(
    parent_fd: int | None,
    name: str | None,
    directory_fd: int,
    *,
    label: str,
) -> None:
    descriptor = os.fstat(directory_fd)
    _validate_compat_directory_metadata(descriptor, label=label)
    _require_no_extended_acl(directory_fd, label=label)
    if parent_fd is None or name is None:
        return
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _validate_compat_directory_metadata(named, label=f"named {label}")
    if not _same_object(descriptor, named):
        raise RuntimeError(f"{label} identity changed while binding runner source")


def _validate_runner_binding(
    parent_fd: int,
    name: str,
    runner_fd: int,
) -> os.stat_result:
    descriptor = os.fstat(runner_fd)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _validate_compat_runner_metadata(descriptor)
    _validate_compat_runner_metadata(named)
    _require_no_extended_acl(runner_fd, label="compatibility runner")
    if not _same_object(descriptor, named):
        raise RuntimeError("compatibility runner identity changed while binding")
    return descriptor


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
    nonblock = getattr(os, "O_NONBLOCK", None)
    if nonblock is None:
        raise RuntimeError(
            "compatibility runner binding requires nonblocking source open"
        )
    path = Path(os.path.abspath(path))
    expected_relative = Path(
        "skills/waited-delivery-compat/scripts/waited_delivery_runner.py"
    )
    try:
        bundle_root = path.parents[3]
        relative = path.relative_to(bundle_root)
    except (IndexError, ValueError) as error:
        raise RuntimeError("compatibility runner path layout is invalid") from error
    if relative != expected_relative:
        raise RuntimeError("compatibility runner path layout is invalid")

    directory_fds: list[tuple[int | None, str | None, int, str]] = []
    runner_fd: int | None = None
    try:
        bundle_fd = os.open(bundle_root, _directory_open_flags())
        directory_fds.append((None, None, bundle_fd, "release bundle root"))
        _validate_directory_binding(
            None,
            None,
            bundle_fd,
            label="release bundle root",
        )
        parent_fd = bundle_fd
        for component, label in (
            ("skills", "release skills directory"),
            ("waited-delivery-compat", "compatibility skill directory"),
            ("scripts", "compatibility scripts directory"),
        ):
            directory_fd = os.open(
                component,
                _directory_open_flags(),
                dir_fd=parent_fd,
            )
            directory_fds.append((parent_fd, component, directory_fd, label))
            _validate_directory_binding(
                parent_fd,
                component,
                directory_fd,
                label=label,
            )
            parent_fd = directory_fd
        runner_name = expected_relative.name
        runner_fd = os.open(
            runner_name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | nonblock,
            dir_fd=parent_fd,
        )
        before = _validate_runner_binding(parent_fd, runner_name, runner_fd)
        first = _read_runner_fd(runner_fd)
        second = _read_runner_fd(runner_fd)
        for binding in directory_fds:
            _validate_directory_binding(
                binding[0],
                binding[1],
                binding[2],
                label=binding[3],
            )
        after = _validate_runner_binding(parent_fd, runner_name, runner_fd)
        if _runner_version(after) != _runner_version(before) or first != second:
            raise RuntimeError(
                "compatibility runner changed while its bytes were being bound"
            )
        if len(second) != after.st_size:
            raise RuntimeError("compatibility runner size changed during stable read")
        return second
    finally:
        if runner_fd is not None:
            os.close(runner_fd)
        for _parent_fd, _name, directory_fd, _label in reversed(directory_fds):
            os.close(directory_fd)


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
