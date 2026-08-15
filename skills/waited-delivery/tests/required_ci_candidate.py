from __future__ import annotations

import atexit
import base64
import binascii
import ctypes
import errno
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import resource
import select
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import unicodedata
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack, contextmanager, nullcontext
from typing import IO, Iterator


CANDIDATE_ROOT_ENV = "REQUIRED_CI_CANDIDATE_ROOT"
CANDIDATE_SHA_ENV = "REQUIRED_CI_CANDIDATE_SHA"
ISOLATION_MODE_ENV = "REQUIRED_CI_ISOLATION_MODE"
STRICT_ISOLATION_MODE = "sudo-setpriv-v1"
_ISOLATION_UID_ENV = "REQUIRED_CI_INTERNAL_ISOLATION_UID"
_ISOLATION_GID_ENV = "REQUIRED_CI_INTERNAL_ISOLATION_GID"
_ISOLATION_LOCK_FD_ENV = "REQUIRED_CI_INTERNAL_ISOLATION_LOCK_FD"
_ISOLATION_REGISTRY_ENV = "REQUIRED_CI_INTERNAL_ISOLATION_REGISTRY"
_ISOLATION_REGISTRY_TOKEN_ENV = "REQUIRED_CI_INTERNAL_ISOLATION_REGISTRY_TOKEN"
_ISOLATION_WATCHDOG_TOKEN_ENV = "REQUIRED_CI_INTERNAL_ISOLATION_WATCHDOG_TOKEN"
CANDIDATE_PROCESS_TIMEOUT_SECONDS = 30
CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES = 1024 * 1024
CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS = 5
CANDIDATE_GIT_TIMEOUT_SECONDS = 15
CANDIDATE_GIT_OUTPUT_LIMIT_BYTES = 1024 * 1024
CANDIDATE_GIT_REAP_TIMEOUT_SECONDS = 5
_CANDIDATE_GIT_PIPE_READ_BYTES = 64 * 1024
CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES = 4 * 1024 * 1024
CANDIDATE_WORKSPACE_FILE_LIMIT = 256
CANDIDATE_WORKSPACE_DIRECTORY_LIMIT = 256
CANDIDATE_WORKSPACE_TOTAL_SIZE_LIMIT_BYTES = 3 * 1024 * 1024
CANDIDATE_WORKSPACE_ARCHIVE_LIMIT_BYTES = 4 * 1024 * 1024
_CANDIDATE_WORKSPACE_TAR_RECORD_BYTES = 20 * 512
_STRICT_WRITABLE_ROOT_LIMIT = 64
_STRICT_HOST_READ_ROOT_LIMIT = 32
_STRICT_BOOTSTRAP_NOFILE_MINIMUM = 64
_STRICT_BOOTSTRAP_NOFILE_LIMIT = 256
_STRICT_MOUNTINFO_LIMIT_BYTES = 1024 * 1024
_STRICT_NETWORK_INTERFACE_FD = 63
_STRICT_PRIVATE_SURFACE_PATHS = (
    Path("/tmp"),
    Path("/var/tmp"),
    Path("/run"),
    Path("/dev/shm"),
)
_STRICT_HOST_READ_ROOT_PURPOSES = {
    "configured-destshared": "directory",
    "configured-executable": "file",
    "configured-libdir": "directory",
    "configured-platstdlib": "directory",
    "configured-pyvenv": "file",
    "configured-stdlib": "directory",
    "continuation-env": "file",
    "continuation-python": "file",
    "continuation-setpriv": "file",
    "ld-cache": "file",
    "localtime": "file",
    "system-arch-library": "directory",
    "system-loader": "file",
    "system-python-dynload": "directory",
    "system-python-stdlib": "directory",
    "trusted-git": "file",
    "trusted-test-file": "file",
}


def _strict_bootstrap_nofile_requirement(
    writable_bindings: Sequence[Mapping[str, object]],
    read_bindings: Sequence[Mapping[str, object]],
) -> int:
    if (
        type(writable_bindings) not in (list, tuple)
        or not 1 <= len(writable_bindings) <= _STRICT_WRITABLE_ROOT_LIMIT
        or type(read_bindings) not in (list, tuple)
        or not 1 <= len(read_bindings) <= _STRICT_HOST_READ_ROOT_LIMIT
    ):
        raise AssertionError(
            "strict bootstrap descriptor capacity binding is malformed"
        )
    component_depths: list[int] = []
    for binding in read_bindings:
        if type(binding) is not dict:
            raise AssertionError(
                "strict bootstrap descriptor capacity binding is malformed"
            )
        components = binding.get("components")
        if type(components) is not list or not components:
            raise AssertionError(
                "strict bootstrap descriptor capacity binding is malformed"
            )
        component_depths.append(len(components))
    # The bootstrap simultaneously holds 2W writable source/bind FDs and R
    # read-root FDs.  Landlock adds 31 fixed FDs, while component revalidation
    # adds D+7 instead.  The fixed ceiling admits the public W=64/R=32 maxima
    # through D=89 and turns deeper control-plane input into a prelaunch error.
    required = max(
        _STRICT_BOOTSTRAP_NOFILE_MINIMUM,
        (2 * len(writable_bindings))
        + len(read_bindings)
        + max(31, max(component_depths) + 7),
    )
    if required > _STRICT_BOOTSTRAP_NOFILE_LIMIT:
        raise AssertionError(
            "strict bootstrap descriptor capacity exceeds its fixed limit"
        )
    return required


def _assert_strict_bootstrap_nofile_capacity(required: int) -> None:
    if (
        type(required) is not int
        or not _STRICT_BOOTSTRAP_NOFILE_MINIMUM
        <= required
        <= _STRICT_BOOTSTRAP_NOFILE_LIMIT
    ):
        raise AssertionError("strict bootstrap descriptor capacity is malformed")
    _soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if (
        type(hard_limit) is not int
        or (
            hard_limit != resource.RLIM_INFINITY
            and hard_limit < required
        )
    ):
        raise AssertionError(
            "strict bootstrap inherited hard limit is insufficient"
        )
_STRICT_ZERO_SCAN_COUNT = 3
_STRICT_ZERO_SCAN_INTERVAL_SECONDS = 0.05
_STRICT_REGISTRY_ENTRY_LIMIT = 256
_STRICT_WATCHDOG_HEARTBEAT_SECONDS = 1.0
_STRICT_WATCHDOG_TIMEOUT_SECONDS = 5.0
_STRICT_WATCHDOG_REPLAY_BACKOFF_INITIAL_SECONDS = 0.05
_STRICT_WATCHDOG_REPLAY_BACKOFF_MAX_SECONDS = 1.0
_WATCHDOG_READY_PREFIX = "REQUIRED_CI_WATCHDOG_READY:"
_WATCHDOG_RESULT_PREFIX = "REQUIRED_CI_WATCHDOG_RESULT:"
_OUTER_OWNER_FAULT_BOUNDARIES = (
    "after-outer-popen",
    "after-outer-bound",
    "after-root-authorized",
    "after-root-authorized-barrier",
    "after-target-active",
)
_STRICT_PRIMITIVES = {
    "sudo": Path("/usr/bin/sudo"),
    "python": Path("/usr/bin/python3"),
    "unshare": Path("/usr/bin/unshare"),
    "setpriv": Path("/usr/bin/setpriv"),
    "env": Path("/usr/bin/env"),
    "true": Path("/usr/bin/true"),
}
_ROOT_PYTHON_ARGUMENTS = ("-I", "-B", "-S")
_CANDIDATE_ENV_KEYS = frozenset(
    {
        "CODEX_THREAD_ID",
        "WAITED_DELIVERY_PARENT_SESSION_ID",
        "WAITED_DELIVERY_PARENT_TURN_ID",
        "WAITED_DELIVERY_PARENT_TRANSCRIPT_PATH",
        "WAITED_DELIVERY_PERMISSION_MODE",
        "WAITED_DELIVERY_HOOK_DEBUG",
        "WAITED_DELIVERY_HOOK_LOG_MAX_BYTES",
        "WAITED_DELIVERY_HOOK_LOG_UNCOMPRESSED_SLOTS",
        "WAITED_DELIVERY_HOOK_LOG_RETENTION_DAYS",
    }
)
_HOOK_FAULT_PROFILES = frozenset(
    {
        ("continuation",),
        ("continuation", "fallback"),
        ("continuation", "fallback", "last-resort"),
        ("continuation", "diagnostic-log", "diagnostic-stderr"),
        ("prompt-stderr",),
    }
)
_SKILL_RELATIVE_TO_CONTENT_ROOT = Path("skills/waited-delivery")
CANDIDATE_SCRIPT_RELATIVE_PATHS = (
    _SKILL_RELATIVE_TO_CONTENT_ROOT / "scripts/waited_delivery_bridge.py",
    _SKILL_RELATIVE_TO_CONTENT_ROOT / "scripts/waited_delivery_hook_adapter.py",
    _SKILL_RELATIVE_TO_CONTENT_ROOT / "scripts/waited_delivery_runner.py",
)
_CANDIDATE_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
_DISTRIBUTION_LAYOUTS = (
    (
        Path("personal_codex/skills/waited-delivery"),
        Path("personal_codex"),
        "private",
    ),
    (Path("skills/waited-delivery"), Path(), "canonical"),
)


def _neutralize_failure_workflow_commands(value: str) -> str:
    lines: list[str] = []
    for line in value.split("\n"):
        prefix_length = 0
        while prefix_length < len(line) and line[prefix_length].isspace():
            prefix_length += 1
        if line[prefix_length:].startswith("::"):
            line = line[:prefix_length] + "\\" + line[prefix_length:]
        lines.append(line)
    return "\n".join(lines)


def _canonical_failure_text(value: str) -> str:
    escaped: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == "\n":
            escaped.append(character)
        elif unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            if codepoint <= 0xFF:
                escaped.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                escaped.append(f"\\u{codepoint:04x}")
            else:
                escaped.append(f"\\U{codepoint:08x}")
        else:
            escaped.append(character)
    return _neutralize_failure_workflow_commands("".join(escaped))


def _bounded_failure_text(value: str, limit: int = 2000) -> str:
    normalized = _canonical_failure_text(value)
    if len(normalized) <= limit:
        return normalized
    marker = "...[middle truncated]..."
    if limit <= 0:
        return ""
    if limit <= len(marker) + 1:
        return marker[:limit]
    # Existing logical-line prefixes are already neutralized.  Reserve one
    # byte so the post-join pass can also neutralize any prefix exposed at a
    # truncation boundary without exceeding the caller's total limit.
    retained = limit - len(marker) - 1
    head_length = retained // 2
    tail_length = retained - head_length
    bounded = normalized[:head_length] + marker + normalized[-tail_length:]
    return _neutralize_failure_workflow_commands(bounded)


def _trusted_distribution_context() -> tuple[Path, Path, Path, str]:
    skill_root = Path(__file__).resolve(strict=True).parents[1]
    for skill_relative, content_relative, profile in _DISTRIBUTION_LAYOUTS:
        layout_depth = len(skill_relative.parts)
        if skill_root.parts[-layout_depth:] != skill_relative.parts:
            continue
        checkout_root = skill_root.parents[layout_depth - 1]
        content_root = checkout_root / content_relative
        if (
            checkout_root / skill_relative != skill_root
            or content_root / _SKILL_RELATIVE_TO_CONTENT_ROOT != skill_root
        ):
            continue
        return checkout_root, content_root, content_relative, profile
    raise AssertionError(
        f"unsupported waited-delivery distribution layout: {skill_root}"
    )


(
    _TRUSTED_CHECKOUT_ROOT,
    _TRUSTED_CONTENT_ROOT,
    _TRUSTED_CONTENT_RELATIVE_ROOT,
    _TRUSTED_DISTRIBUTION_PROFILE,
) = _trusted_distribution_context()
# Retain the private name for compatibility with trusted test fixtures while
# making its value unambiguously identify the Git checkout root.
_TRUSTED_REPO_ROOT = _TRUSTED_CHECKOUT_ROOT
_TRUSTED_SUPPORT_PATH = Path(__file__).resolve(strict=True)
try:
    _TRUSTED_SUPPORT_SOURCE = _TRUSTED_SUPPORT_PATH.read_bytes()
except OSError as error:
    raise AssertionError("trusted candidate support source cannot be read") from error
_TRUSTED_SUPPORT_SHA256 = hashlib.sha256(_TRUSTED_SUPPORT_SOURCE).hexdigest()
_STRICT_REALM: dict[str, object] | None = None
_STRICT_SESSION: dict[str, object] | None = None
_ABANDONED_REGISTRY_ACQUISITIONS: list[dict[str, object]] = []
_REGISTERED_FIXTURE_ROOTS: dict[Path, tuple[int, int]] = {}
_STRICT_BACKEND_VALIDATED = False
_STRICT_PLATFORM_VALIDATED = False
_REGISTRY_GATE_STATE = threading.local()
_CHAIN_LOCK_STATE = threading.local()


def _resolve_trusted_git() -> str:
    selected = shutil.which("git")
    if selected is None:
        raise AssertionError("trusted runner PATH does not provide Git")
    path = Path(selected).resolve(strict=True)
    _capture_trusted_git_binding(path)
    return str(path)


def _capture_trusted_git_binding(path: Path) -> dict[str, object]:
    if not path.is_absolute():
        raise AssertionError("trusted Git executable path is not absolute")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise AssertionError("trusted Git executable path is missing") from error
    except PermissionError as error:
        raise AssertionError("trusted Git executable path is unreadable") from error
    except OSError as error:
        raise AssertionError("trusted Git executable path cannot be inspected") from error
    if resolved != path:
        raise AssertionError("trusted Git executable path is not canonical")
    objects: list[tuple[str, int, int, int]] = []
    policies: list[tuple[str, int, int, int]] = []
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:]):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError as error:
            raise AssertionError("trusted Git executable path is missing") from error
        except PermissionError as error:
            raise AssertionError("trusted Git executable path is unreadable") from error
        except OSError as error:
            raise AssertionError(
                "trusted Git executable path cannot be inspected"
            ) from error
        is_leaf = index == len(path.parts[1:]) - 1
        if not (
            stat.S_ISREG(metadata.st_mode)
            if is_leaf
            else stat.S_ISDIR(metadata.st_mode)
        ):
            raise AssertionError("trusted Git executable path has an unsafe object type")
        objects.append(
            (
                str(current),
                metadata.st_dev,
                metadata.st_ino,
                stat.S_IFMT(metadata.st_mode),
            )
        )
        policies.append(
            (
                str(current),
                metadata.st_uid,
                metadata.st_gid,
                stat.S_IMODE(metadata.st_mode),
            )
        )
    if not policies or not policies[-1][3] & 0o111:
        raise AssertionError("trusted Git executable is not executable")
    return {
        "path": str(path),
        # dev/inode/type protect the selected object chain; uid/gid/mode
        # separately protect the access policy.  Size, times, and link count
        # do not serve either property and are intentionally excluded.
        "objects": tuple(objects),
        "policies": tuple(policies),
    }


def _revalidate_trusted_git_binding(binding: Mapping[str, object]) -> Path:
    path_value = binding.get("path")
    if type(path_value) is not str:
        raise AssertionError("trusted Git executable binding is malformed")
    current = _capture_trusted_git_binding(Path(path_value))
    if current["objects"] != binding.get("objects"):
        raise AssertionError("trusted Git executable object identity changed")
    if current["policies"] != binding.get("policies"):
        raise AssertionError("trusted Git executable access policy changed")
    return Path(path_value)


TRUSTED_GIT_EXECUTABLE = _resolve_trusted_git()
_TRUSTED_GIT_BINDING = _capture_trusted_git_binding(
    Path(TRUSTED_GIT_EXECUTABLE)
)
_STRICT_PRIMITIVES["git"] = Path(TRUSTED_GIT_EXECUTABLE)
_GIT_SAFE_ARGUMENTS = (
    "--no-pager",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "advice.graftFileDeprecated=false",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.commitGraph=false",
    "-c",
    "core.multiPackIndex=false",
    "-c",
    "diff.external=",
)


def candidate_repository_root() -> Path:
    value = os.environ.get(CANDIDATE_ROOT_ENV)
    if value is None:
        if _TRUSTED_CHECKOUT_ROOT.name == ".required-ci":
            raise AssertionError(
                f"{CANDIDATE_ROOT_ENV} is required in the trusted checkout"
            )
        return _TRUSTED_CHECKOUT_ROOT

    root = Path(value)
    if not root.is_absolute() or root.name != ".candidate":
        raise AssertionError(
            f"{CANDIDATE_ROOT_ENV} must be an absolute .candidate path"
        )
    if root.is_symlink():
        raise AssertionError(f"{CANDIDATE_ROOT_ENV} must not select a symlink")
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            f"{CANDIDATE_ROOT_ENV} must select an existing directory"
        ) from error
    if resolved != root or not resolved.is_dir():
        raise AssertionError(
            f"{CANDIDATE_ROOT_ENV} must select a canonical directory"
        )
    return resolved


def _candidate_content_root_for_checkout(checkout_root: Path) -> Path:
    content_root = checkout_root / _TRUSTED_CONTENT_RELATIVE_ROOT
    if content_root == checkout_root:
        return checkout_root
    try:
        metadata = content_root.lstat()
        resolved = content_root.resolve(strict=True)
    except OSError as error:
        raise AssertionError("candidate distribution content root is missing") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or resolved != content_root
        or checkout_root not in resolved.parents
    ):
        raise AssertionError(
            "candidate distribution content root must be a canonical directory"
        )
    return content_root


def candidate_content_root() -> Path:
    return _candidate_content_root_for_checkout(candidate_repository_root())


def _candidate_checkout_relative_path(content_relative_path: Path) -> Path:
    if content_relative_path.is_absolute() or ".." in content_relative_path.parts:
        raise AssertionError("candidate content path must be distribution-relative")
    return _TRUSTED_CONTENT_RELATIVE_ROOT / content_relative_path


def _candidate_git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_GRAFT_FILE": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
    )
    return environment


def candidate_git_argv(root: Path, *arguments: str) -> list[str]:
    return [
        TRUSTED_GIT_EXECUTABLE,
        *_GIT_SAFE_ARGUMENTS,
        "-C",
        str(root),
        *arguments,
    ]


class _CandidateGitOutputLimit(Exception):
    def __init__(self, description: str) -> None:
        super().__init__(description)
        self.description = description


def _candidate_git_process_group_has_live_members(process_group: int) -> bool:
    if sys.platform.startswith("linux") and Path("/proc").is_dir():
        try:
            process_entries = os.scandir("/proc")
        except OSError as error:
            raise AssertionError(
                "candidate Git process inventory is unreadable"
            ) from error
        with process_entries:
            for entry in process_entries:
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                try:
                    descriptor = os.open(
                        f"/proc/{entry.name}/stat",
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    )
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
                try:
                    status = os.read(descriptor, 4097)
                finally:
                    os.close(descriptor)
                if len(status) > 4096:
                    raise AssertionError(
                        "candidate Git process inventory entry is oversized"
                    )
                fields = status[status.rfind(b") ") + 2 :].split()
                if len(fields) < 3:
                    raise AssertionError(
                        "candidate Git process inventory entry is malformed"
                    )
                try:
                    member_group = int(fields[2])
                except ValueError as error:
                    raise AssertionError(
                        "candidate Git process inventory entry is malformed"
                    ) from error
                if member_group == process_group and fields[0] != b"Z":
                    return True
        return False
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError as error:
        if sys.platform == "darwin":
            # The fixed trusted-Git argv/environment cannot transition a
            # descendant into a different signal-permission domain. With the
            # unreaped leader pinning this process-group generation, Darwin's
            # EPERM (no signal-authorized non-zombie member) therefore proves
            # that this trusted process group has no live member.
            return False
        raise AssertionError(
            "candidate Git process inventory is unreadable"
        ) from error
    return True


def _terminate_candidate_git_process_tree(
    process: subprocess.Popen[bytes], process_group: int
) -> None:
    cleanup_failures: list[str] = []
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError as error:
        if sys.platform != "darwin":
            cleanup_failures.append(f"signal: {error}")
        # Darwin EPERM is not itself terminal. The still-unreaped leader below
        # pins the PGID generation, and the fresh inventory applies the fixed
        # trusted-Git all-live-descendants-signalable invariant before success.
    except OSError as error:
        cleanup_failures.append(f"signal: {error}")
    deadline = time.monotonic() + CANDIDATE_GIT_REAP_TIMEOUT_SECONDS
    try:
        _wait_candidate_git_exit_without_reaping(process, deadline)
    except BaseException as error:
        cleanup_failures.append(f"leader exit: {error}")
    while not cleanup_failures and time.monotonic() < deadline:
        try:
            if not _candidate_git_process_group_has_live_members(process_group):
                break
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            break
        except PermissionError as error:
            if sys.platform != "darwin":
                cleanup_failures.append(f"live-member cleanup: {error}")
                break
            # A Darwin group can transition from a live child to only the
            # unreaped leader between inventory and signal. Accept EPERM only
            # after a fresh signal-authority inventory under the fixed trusted-
            # Git invariant; the leader still pins this exact PGID generation.
            try:
                live_members_remain = (
                    _candidate_git_process_group_has_live_members(process_group)
                )
            except BaseException as verification_error:
                cleanup_failures.append(
                    "live-member revalidation: " f"{verification_error}"
                )
                break
            if not live_members_remain:
                break
            cleanup_failures.append(f"live-member cleanup: {error}")
            break
        except OSError as error:
            cleanup_failures.append(f"live-member cleanup: {error}")
            break
        time.sleep(0.01)
    else:
        if not cleanup_failures:
            cleanup_failures.append("live process-group members remained active")
    try:
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        cleanup_failures.append(f"reap: {error}")
    if cleanup_failures:
        raise AssertionError(
            "candidate Git process tree cleanup is incomplete: "
            + "; ".join(cleanup_failures)
        )


def _wait_candidate_git_exit_without_reaping(
    process: subprocess.Popen[bytes], deadline: float
) -> None:
    while True:
        try:
            status = os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError as error:
            raise AssertionError(
                "candidate Git exit identity became unavailable"
            ) from error
        if status is not None:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("candidate Git process deadline expired")
        time.sleep(min(0.01, remaining))


def _drain_candidate_git_pipes(
    process: subprocess.Popen[bytes],
    *,
    output_limit: int,
    deadline: float,
) -> tuple[bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        raise AssertionError("candidate Git output pipes are unavailable")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    selector = selectors.DefaultSelector()
    try:
        for description, stream in streams.items():
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ, description)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("candidate Git output deadline expired")
            ready = selector.select(remaining)
            if not ready:
                raise TimeoutError("candidate Git output deadline expired")
            for key, _ in ready:
                description = str(key.data)
                buffer = buffers[description]
                total_size = sum(len(value) for value in buffers.values())
                stream_remaining = output_limit - len(buffer)
                aggregate_remaining = output_limit - total_size
                read_size = min(
                    _CANDIDATE_GIT_PIPE_READ_BYTES,
                    stream_remaining + 1,
                    aggregate_remaining + 1,
                )
                try:
                    chunk = os.read(key.fd, max(1, read_size))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    streams[description].close()
                    continue
                if len(buffer) + len(chunk) > output_limit:
                    raise _CandidateGitOutputLimit(description)
                if total_size + len(chunk) > output_limit:
                    raise _CandidateGitOutputLimit("combined output")
                buffer.extend(chunk)
        _wait_candidate_git_exit_without_reaping(process, deadline)
    finally:
        for key in tuple(selector.get_map().values()):
            try:
                selector.unregister(key.fd)
            except BaseException:
                pass
        selector.close()
        for stream in streams.values():
            if not stream.closed:
                stream.close()
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def _run_candidate_git(
    root: Path,
    *arguments: str,
    output_limit: int = CANDIDATE_GIT_OUTPUT_LIMIT_BYTES,
) -> bytes:
    strict_isolation_platform_preflight()
    if (
        type(output_limit) is not int
        or output_limit < 0
        or output_limit > CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES
    ):
        raise AssertionError("candidate Git output limit is invalid")
    command = candidate_git_argv(root, *arguments)
    deadline = time.monotonic() + CANDIDATE_GIT_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            command,
            env=_candidate_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise AssertionError("candidate Git validation could not start") from error
    process_group = process.pid
    try:
        stdout, stderr_bytes = _drain_candidate_git_pipes(
            process,
            output_limit=output_limit,
            deadline=deadline,
        )
    except BaseException as error:
        try:
            _terminate_candidate_git_process_tree(process, process_group)
        except BaseException as cleanup_error:
            raise AssertionError(
                "candidate Git process tree cleanup is incomplete: "
                f"{cleanup_error}"
            ) from error
        if isinstance(error, _CandidateGitOutputLimit):
            raise AssertionError(
                "candidate Git validation exceeded its "
                f"{error.description} limit"
            ) from error
        if isinstance(error, TimeoutError):
            raise AssertionError(
                "candidate Git validation exceeded its fixed timeout"
            ) from error
        raise
    try:
        _terminate_candidate_git_process_tree(process, process_group)
    except BaseException as cleanup_error:
        raise AssertionError(
            "candidate Git process tree cleanup is incomplete: "
            f"{cleanup_error}"
        ) from cleanup_error
    if process.returncode != 0:
        stderr = stderr_bytes[:2000].decode("utf-8", errors="replace")
        raise AssertionError(
            f"candidate Git validation failed with exit {process.returncode}: {stderr}"
        )
    if stderr_bytes:
        stderr = stderr_bytes[:2000].decode("utf-8", errors="replace")
        raise AssertionError(f"candidate Git validation wrote stderr: {stderr}")
    return stdout


def _parse_candidate_sha(value: str, description: str) -> str:
    if _CANDIDATE_SHA_PATTERN.fullmatch(value) is None:
        raise AssertionError(f"{description} must be a lowercase 40-hex commit SHA")
    return value


def _without_single_trailing_newline(value: str) -> str:
    return value[:-1] if value.endswith("\n") else value


def expected_candidate_sha(root: Path) -> tuple[str, bool]:
    value = os.environ.get(CANDIDATE_SHA_ENV)
    if value is not None:
        return _parse_candidate_sha(value, CANDIDATE_SHA_ENV), True
    if _TRUSTED_CHECKOUT_ROOT.name == ".required-ci":
        raise AssertionError(
            f"{CANDIDATE_SHA_ENV} is required in the trusted checkout"
        )
    head = _run_candidate_git(root, "rev-parse", "--verify", "HEAD^{commit}")
    try:
        decoded = head.decode("ascii")
    except UnicodeDecodeError as error:
        raise AssertionError("candidate HEAD is not ASCII") from error
    return _parse_candidate_sha(
        _without_single_trailing_newline(decoded), "candidate HEAD"
    ), False


def _ordinary_candidate_file(root: Path, relative_path: Path) -> Path:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise AssertionError("candidate file path must be repository-relative")
    path = root / relative_path
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise AssertionError(f"candidate file is missing: {relative_path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or resolved != path
        or root not in resolved.parents
    ):
        raise AssertionError(
            f"candidate file must be an ordinary single-link file: {relative_path}"
        )
    if metadata.st_size > CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES:
        raise AssertionError(f"candidate file exceeds its size limit: {relative_path}")
    return path


def _candidate_script_sources(root: Path) -> dict[Path, bytes]:
    if not root.is_absolute() or root.anchor != os.path.sep:
        raise AssertionError("candidate checkout root must be an absolute POSIX path")
    try:
        initial_root_metadata = root.lstat()
        canonical_root = root.resolve(strict=True)
    except OSError as error:
        raise AssertionError("candidate checkout root cannot be bound") from error
    if (
        not stat.S_ISDIR(initial_root_metadata.st_mode)
        or canonical_root != root
    ):
        raise AssertionError("candidate checkout root path binding changed")
    initial_root_identity = (
        initial_root_metadata.st_dev,
        initial_root_metadata.st_ino,
    )
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    file_flags = (
        os.O_RDONLY
        | os.O_NONBLOCK
        | os.O_NOCTTY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    scripts_relative = (
        _TRUSTED_CONTENT_RELATIVE_ROOT
        / "skills/waited-delivery/scripts"
    )
    expected_names = sorted(path.name for path in CANDIDATE_SCRIPT_RELATIVE_PATHS)
    with ExitStack() as descriptor_stack:
        anchor_descriptor = os.open(root.anchor, directory_flags)
        descriptor_stack.callback(os.close, anchor_descriptor)
        anchor_metadata = os.fstat(anchor_descriptor)
        if not stat.S_ISDIR(anchor_metadata.st_mode):
            raise AssertionError("candidate content path binding changed")

        directory_bindings: list[
            tuple[int, str, int, tuple[int, int]]
        ] = []
        parent_descriptor = anchor_descriptor
        directory_components = (*root.parts[1:], *scripts_relative.parts)
        root_component_index = len(root.parts) - 2
        for component_index, component in enumerate(directory_components):
            try:
                component_metadata = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                component_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=parent_descriptor,
                )
            except OSError as error:
                raise AssertionError(
                    "candidate script directory cannot be bound safely"
                ) from error
            descriptor_stack.callback(os.close, component_descriptor)
            opened_component = os.fstat(component_descriptor)
            component_identity = (
                component_metadata.st_dev,
                component_metadata.st_ino,
            )
            if component_index == root_component_index and (
                not stat.S_ISDIR(component_metadata.st_mode)
                or not stat.S_ISDIR(opened_component.st_mode)
                or component_identity != initial_root_identity
                or (opened_component.st_dev, opened_component.st_ino)
                != initial_root_identity
            ):
                raise AssertionError("candidate checkout root path binding changed")
            if (
                not stat.S_ISDIR(component_metadata.st_mode)
                or not stat.S_ISDIR(opened_component.st_mode)
                or (opened_component.st_dev, opened_component.st_ino)
                != component_identity
            ):
                raise AssertionError(
                    "candidate script directory path binding changed"
                )
            directory_bindings.append(
                (
                    parent_descriptor,
                    component,
                    component_descriptor,
                    component_identity,
                )
            )
            parent_descriptor = component_descriptor

        scripts_descriptor = parent_descriptor
        try:
            initial_names = sorted(os.listdir(scripts_descriptor))
        except OSError as error:
            raise AssertionError(
                "candidate scripts directory cannot be enumerated"
            ) from error
        if initial_names != expected_names:
            raise AssertionError("candidate scripts directory inventory is not exact")

        sources: dict[Path, bytes] = {}
        file_bindings: list[
            tuple[str, int, tuple[int, int], int, bytes]
        ] = []
        for relative_path in CANDIDATE_SCRIPT_RELATIVE_PATHS:
            name = relative_path.name
            try:
                path_metadata = os.stat(
                    name,
                    dir_fd=scripts_descriptor,
                    follow_symlinks=False,
                )
                descriptor = os.open(
                    name,
                    file_flags,
                    dir_fd=scripts_descriptor,
                )
            except OSError as error:
                raise AssertionError(
                    f"candidate file cannot be opened safely: {relative_path}"
                ) from error
            descriptor_stack.callback(os.close, descriptor)
            opened_metadata = os.fstat(descriptor)
            expected_identity = (
                path_metadata.st_dev,
                path_metadata.st_ino,
            )
            if (
                not stat.S_ISREG(path_metadata.st_mode)
                or not stat.S_ISREG(opened_metadata.st_mode)
                or path_metadata.st_nlink != 1
                or opened_metadata.st_nlink != 1
                or path_metadata.st_size < 0
                or opened_metadata.st_size != path_metadata.st_size
                or opened_metadata.st_size > CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES
                or (opened_metadata.st_dev, opened_metadata.st_ino)
                != expected_identity
            ):
                raise AssertionError(
                    f"candidate file identity is unsafe: {relative_path}"
                )

            def read_once() -> bytes:
                os.lseek(descriptor, 0, os.SEEK_SET)
                remaining = opened_metadata.st_size + 1
                chunks: list[bytes] = []
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 65536))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                return b"".join(chunks)

            first = read_once()
            second = read_once()
            if len(first) != opened_metadata.st_size or first != second:
                raise AssertionError(
                    f"candidate file content changed during capture: {relative_path}"
                )
            sources[relative_path] = first
            file_bindings.append(
                (
                    name,
                    descriptor,
                    expected_identity,
                    opened_metadata.st_size,
                    first,
                )
            )

        try:
            final_names = sorted(os.listdir(scripts_descriptor))
            final_anchor = os.fstat(anchor_descriptor)
            if (
                not stat.S_ISDIR(final_anchor.st_mode)
                or (final_anchor.st_dev, final_anchor.st_ino)
                != (anchor_metadata.st_dev, anchor_metadata.st_ino)
            ):
                raise AssertionError(
                    "candidate script directory path binding changed"
                )
            for (
                bound_parent_descriptor,
                component,
                component_descriptor,
                component_identity,
            ) in directory_bindings:
                final_component = os.fstat(component_descriptor)
                linked_component = os.stat(
                    component,
                    dir_fd=bound_parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(final_component.st_mode)
                    or not stat.S_ISDIR(linked_component.st_mode)
                    or (final_component.st_dev, final_component.st_ino)
                    != component_identity
                    or (linked_component.st_dev, linked_component.st_ino)
                    != component_identity
                ):
                    raise AssertionError(
                        "candidate script directory path binding changed"
                    )
            for name, descriptor, identity, expected_size, source in file_bindings:
                final_opened = os.fstat(descriptor)
                final_path = os.stat(
                    name,
                    dir_fd=scripts_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(final_opened.st_mode)
                    or not stat.S_ISREG(final_path.st_mode)
                    or (final_opened.st_dev, final_opened.st_ino) != identity
                    or (final_path.st_dev, final_path.st_ino) != identity
                    or final_opened.st_nlink != 1
                    or final_path.st_nlink != 1
                    or final_opened.st_size != expected_size
                    or final_path.st_size != expected_size
                    or len(source) != expected_size
                ):
                    raise AssertionError(
                        f"candidate file changed during stable capture: {name}"
                    )
        except OSError as error:
            raise AssertionError(
                "candidate script path could not be revalidated"
            ) from error
        if final_names != expected_names:
            raise AssertionError("candidate scripts directory inventory changed")
        return sources


def candidate_path(relative_path: str | Path) -> Path:
    root = candidate_content_root()
    relative = Path(relative_path)
    path = root / relative
    if relative.is_absolute() or ".." in relative.parts:
        raise AssertionError("candidate path must be repository-relative")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise AssertionError(f"candidate path is missing: {relative}") from error
    if resolved != path or (resolved != root and root not in resolved.parents):
        raise AssertionError(f"candidate path escapes the candidate root: {relative}")
    return resolved


def candidate_script(name: str) -> Path:
    if Path(name).name != name:
        raise AssertionError("candidate script name must be a basename")
    relative = Path("skills/waited-delivery/scripts") / name
    if relative not in CANDIDATE_SCRIPT_RELATIVE_PATHS:
        raise AssertionError(f"unexpected candidate script: {name}")
    return _ordinary_candidate_file(candidate_content_root(), relative)


def _candidate_script_manifest(
    checkout_root: Path,
    candidate_sha: str,
    *,
    require_clean: bool,
) -> tuple[dict[str, str], dict[Path, bytes]]:
    _candidate_content_root_for_checkout(checkout_root)
    captured_sources = _candidate_script_sources(checkout_root)
    execution_sources = dict(captured_sources)

    manifest: dict[str, str] = {}
    for content_relative_path in CANDIDATE_SCRIPT_RELATIVE_PATHS:
        checkout_relative_path = _candidate_checkout_relative_path(
            content_relative_path
        )
        working_bytes = captured_sources[content_relative_path]
        if require_clean:
            size_output = _run_candidate_git(
                checkout_root,
                "cat-file",
                "-s",
                f"{candidate_sha}:{checkout_relative_path.as_posix()}",
                output_limit=128,
            )
            try:
                tracked_size = int(
                    _without_single_trailing_newline(
                        size_output.decode("ascii")
                    )
                )
            except (UnicodeDecodeError, ValueError) as error:
                raise AssertionError(
                    f"candidate tracked size is malformed: {checkout_relative_path}"
                ) from error
            if (
                tracked_size < 0
                or tracked_size > CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES
            ):
                raise AssertionError(
                    "candidate tracked file exceeds its size limit: "
                    f"{checkout_relative_path}"
                )
            tracked_bytes = _run_candidate_git(
                checkout_root,
                "cat-file",
                "blob",
                f"{candidate_sha}:{checkout_relative_path.as_posix()}",
                output_limit=CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES,
            )
            if (
                len(tracked_bytes) != tracked_size
                or working_bytes != tracked_bytes
            ):
                raise AssertionError(
                    "candidate implementation bytes do not match the frozen commit: "
                    f"{checkout_relative_path}"
                )
            execution_sources[content_relative_path] = tracked_bytes
        manifest[checkout_relative_path.as_posix()] = hashlib.sha256(
            working_bytes
        ).hexdigest()
    return manifest, execution_sources


def _candidate_workspace_blob_oid(data: bytes, object_format: str) -> str:
    if object_format != "sha1":
        raise AssertionError(
            "candidate Git object format is outside the SHA-1 authority contract"
        )
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.new(object_format, header + data).hexdigest()


def _candidate_workspace_path(raw_path: bytes) -> Path:
    try:
        text = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AssertionError("candidate workspace path is not UTF-8") from error
    pure_path = PurePosixPath(text)
    folded_parts = tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in pure_path.parts
    )
    if (
        not text
        or not pure_path.parts
        or pure_path.is_absolute()
        or pure_path.as_posix() != text
        or any(part in ("", ".", "..") for part in pure_path.parts)
        # The candidate workspace reproduces tracked content only. It never
        # exposes Git administrative metadata, including filesystem aliases.
        or ".git" in folded_parts
    ):
        raise AssertionError("candidate workspace path is unsafe")
    return Path(*pure_path.parts)


def _admit_candidate_workspace_directories(
    trie: dict[str, object],
    relative_path: Path,
    directory_count: int,
) -> int:
    node = trie
    for component in relative_path.parts[:-1]:
        child = node.get(component)
        if child is None:
            if directory_count >= CANDIDATE_WORKSPACE_DIRECTORY_LIMIT:
                raise AssertionError(
                    "candidate workspace directory inventory exceeds its limit"
                )
            child = {}
            node[component] = child
            directory_count += 1
        if not isinstance(child, dict):
            raise AssertionError(
                "candidate workspace directory inventory is malformed"
            )
        node = child
    return directory_count


def _candidate_workspace_directory_trie(
    paths: Mapping[Path, object],
) -> tuple[dict[str, object], int]:
    trie: dict[str, object] = {}
    directory_count = 0
    for relative_path in paths:
        if not isinstance(relative_path, Path):
            raise AssertionError(
                "candidate workspace directory inventory is malformed"
            )
        directory_count = _admit_candidate_workspace_directories(
            trie, relative_path, directory_count
        )
    return trie, directory_count


def _candidate_workspace_directory_is_expected(
    trie: Mapping[str, object], relative_path: Path
) -> bool:
    if not relative_path.parts:
        return False
    node = trie
    for component in relative_path.parts:
        child = node.get(component)
        if not isinstance(child, dict):
            return False
        node = child
    return True


def _candidate_workspace_tree_inventory(
    tree_output: bytes, object_format: str
) -> dict[Path, tuple[str, int, bool]]:
    oid_size = {"sha1": 40}.get(object_format)
    if oid_size is None:
        raise AssertionError("candidate Git object format is unsupported")
    if tree_output and not tree_output.endswith(b"\0"):
        raise AssertionError("candidate workspace tree inventory is truncated")
    records = tree_output.split(b"\0")[:-1] if tree_output else []
    if not records or len(records) > CANDIDATE_WORKSPACE_FILE_LIMIT:
        raise AssertionError("candidate workspace file inventory exceeds its limit")
    inventory: dict[Path, tuple[str, int, bool]] = {}
    directory_trie: dict[str, object] = {}
    directory_count = 0
    total_size = 0
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, raw_oid, raw_size = header.split()
            oid = raw_oid.decode("ascii")
            size_text = raw_size.decode("ascii")
        except (UnicodeDecodeError, ValueError) as error:
            raise AssertionError(
                "candidate workspace tree inventory is malformed"
            ) from error
        if (
            mode not in (b"100644", b"100755")
            or object_type != b"blob"
            or re.fullmatch(rf"[0-9a-f]{{{oid_size}}}", oid) is None
            or not size_text.isascii()
            or not size_text.isdecimal()
        ):
            raise AssertionError("candidate workspace tree entry is unsupported")
        size = int(size_text)
        if str(size) != size_text or size > CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES:
            raise AssertionError("candidate workspace file exceeds its size limit")
        relative_path = _candidate_workspace_path(raw_path)
        if relative_path in inventory:
            raise AssertionError("candidate workspace tree path is duplicated")
        directory_count = _admit_candidate_workspace_directories(
            directory_trie, relative_path, directory_count
        )
        total_size += size
        if total_size > CANDIDATE_WORKSPACE_TOTAL_SIZE_LIMIT_BYTES:
            raise AssertionError("candidate workspace content exceeds its total limit")
        inventory[relative_path] = (oid, size, mode == b"100755")
    return inventory


def _candidate_workspace_archive_sources(
    archive_output: bytes,
    *,
    candidate_sha: str,
    object_format: str,
    tree_inventory: Mapping[Path, tuple[str, int, bool]],
) -> dict[Path, tuple[bytes, bool]]:
    directory_trie, expected_directory_count = (
        _candidate_workspace_directory_trie(tree_inventory)
    )
    sources: dict[Path, tuple[bytes, bool]] = {}
    observed_directories: set[Path] = set()
    observed_names: set[Path] = set()
    def field_bytes(field: bytes) -> bytes:
        if b"\0" not in field:
            return field
        value, padding = field.split(b"\0", 1)
        if any(padding):
            raise AssertionError("candidate workspace archive header is malformed")
        return value

    def octal_field(field: bytes) -> int:
        value = field.rstrip(b"\0 ")
        if not value or re.fullmatch(rb"[0-7]+", value) is None:
            raise AssertionError("candidate workspace archive header is malformed")
        return int(value, 8)

    def pax_comment() -> bytes:
        body = f" comment={candidate_sha}\n".encode("ascii")
        size = len(body) + 1
        while True:
            record = str(size).encode("ascii") + body
            if len(record) == size:
                return record
            size = len(record)

    if not archive_output or len(archive_output) % 512 != 0:
        raise AssertionError("candidate workspace archive framing is malformed")
    offset = 0
    saw_global_header = False
    saw_end = False
    while offset < len(archive_output):
        header = archive_output[offset : offset + 512]
        if len(header) != 512:
            raise AssertionError("candidate workspace archive is truncated")
        if not any(header):
            expected_archive_size = (
                (
                    offset
                    + 1024
                    + _CANDIDATE_WORKSPACE_TAR_RECORD_BYTES
                    - 1
                )
                // _CANDIDATE_WORKSPACE_TAR_RECORD_BYTES
                * _CANDIDATE_WORKSPACE_TAR_RECORD_BYTES
            )
            if (
                len(archive_output) != expected_archive_size
                or any(archive_output[offset:])
            ):
                raise AssertionError(
                    "candidate workspace archive framing is malformed"
                )
            saw_end = True
            break
        if (
            header[257:263] != b"ustar\0"
            or header[263:265] != b"00"
            or field_bytes(header[157:257])
            or field_bytes(header[265:297]) != b"root"
            or field_bytes(header[297:329]) != b"root"
            or octal_field(header[108:116]) != 0
            or octal_field(header[116:124]) != 0
            or octal_field(header[329:337]) != 0
            or octal_field(header[337:345]) != 0
            or any(header[500:512])
        ):
            raise AssertionError("candidate workspace archive header is unsupported")
        expected_checksum = octal_field(header[148:156])
        actual_checksum = sum(header[:148]) + 8 * 0x20 + sum(header[156:])
        if actual_checksum != expected_checksum:
            raise AssertionError("candidate workspace archive checksum changed")
        mode = octal_field(header[100:108])
        size = octal_field(header[124:136])
        octal_field(header[136:148])
        type_flag = header[156:157]
        name = field_bytes(header[:100])
        prefix = field_bytes(header[345:500])
        raw_name = (prefix + b"/" if prefix else b"") + name
        data_offset = offset + 512
        data_end = data_offset + size
        padded_end = data_offset + ((size + 511) // 512) * 512
        if data_end > len(archive_output) or padded_end > len(archive_output):
            raise AssertionError("candidate workspace archive is truncated")
        if any(archive_output[data_end:padded_end]):
            raise AssertionError("candidate workspace archive padding is malformed")
        data = archive_output[data_offset:data_end]
        if type_flag == b"g":
            if (
                saw_global_header
                or offset != 0
                or raw_name != b"pax_global_header"
                or mode != 0o666
                or data != pax_comment()
            ):
                raise AssertionError(
                    "candidate workspace archive provenance is malformed"
                )
            saw_global_header = True
            offset = padded_end
            continue
        if not saw_global_header or type_flag not in (b"0", b"5"):
            raise AssertionError(
                "candidate workspace archive member type is unsupported"
            )
        if type_flag == b"5":
            if not raw_name.endswith(b"/"):
                raise AssertionError(
                    "candidate workspace archive directory is malformed"
                )
            raw_name = raw_name[:-1]
        elif raw_name.endswith(b"/"):
            raise AssertionError("candidate workspace archive file is malformed")
        relative_path = _candidate_workspace_path(raw_name)
        if relative_path in observed_names:
            raise AssertionError(
                "candidate workspace archive member is duplicated or extended"
            )
        observed_names.add(relative_path)
        if type_flag == b"5":
            if (
                size != 0
                or mode != 0o755
                or not _candidate_workspace_directory_is_expected(
                    directory_trie, relative_path
                )
            ):
                raise AssertionError(
                    "candidate workspace archive directory is unexpected"
                )
            observed_directories.add(relative_path)
        else:
            expected = tree_inventory.get(relative_path)
            if expected is None:
                raise AssertionError(
                    "candidate workspace archive file is not in the Git tree"
                )
            oid, expected_size, executable = expected
            if size != expected_size or mode != (0o755 if executable else 0o644):
                raise AssertionError(
                    "candidate workspace archive file policy changed"
                )
            if _candidate_workspace_blob_oid(data, object_format) != oid:
                raise AssertionError(
                    "candidate workspace archive blob identity changed"
                )
            sources[relative_path] = (data, executable)
        offset = padded_end
    if not saw_global_header or not saw_end:
        raise AssertionError("candidate workspace archive framing is malformed")
    if set(sources) != set(tree_inventory):
        raise AssertionError("candidate workspace archive file inventory is incomplete")
    if len(observed_directories) != expected_directory_count:
        raise AssertionError(
            "candidate workspace archive directory inventory is incomplete"
        )
    return sources


def _candidate_workspace_sources(
    checkout_root: Path,
    candidate_sha: str,
    candidate_sources: Mapping[Path, bytes],
) -> dict[Path, tuple[bytes, bool]]:
    if set(candidate_sources) != set(CANDIDATE_SCRIPT_RELATIVE_PATHS) or not all(
        isinstance(source, bytes) for source in candidate_sources.values()
    ):
        raise AssertionError(
            "candidate workspace helper override inventory is not exact"
        )
    object_format_output = _run_candidate_git(
        checkout_root,
        "rev-parse",
        "--show-object-format",
        output_limit=32,
    )
    try:
        object_format = _without_single_trailing_newline(
            object_format_output.decode("ascii")
        )
    except UnicodeDecodeError as error:
        raise AssertionError("candidate Git object format is malformed") from error
    if object_format != "sha1" or len(candidate_sha) != 40:
        raise AssertionError(
            "candidate Git object format is outside the SHA-1 authority contract"
        )
    tree_output = _run_candidate_git(
        checkout_root,
        "ls-tree",
        "-r",
        "-z",
        "-l",
        "--full-tree",
        candidate_sha,
        output_limit=CANDIDATE_GIT_OUTPUT_LIMIT_BYTES,
    )
    tree_inventory = _candidate_workspace_tree_inventory(tree_output, object_format)
    archive_output = _run_candidate_git(
        checkout_root,
        "-c",
        "tar.umask=0022",
        "archive",
        "--format=tar",
        candidate_sha,
        output_limit=CANDIDATE_WORKSPACE_ARCHIVE_LIMIT_BYTES,
    )
    workspace_sources = _candidate_workspace_archive_sources(
        archive_output,
        candidate_sha=candidate_sha,
        object_format=object_format,
        tree_inventory=tree_inventory,
    )
    for content_relative_path, source in candidate_sources.items():
        checkout_relative_path = _candidate_checkout_relative_path(
            content_relative_path
        )
        existing = workspace_sources.get(checkout_relative_path)
        if existing is None or not isinstance(source, bytes):
            raise AssertionError(
                "candidate workspace helper override is not in the Git tree"
            )
        workspace_sources[checkout_relative_path] = (source, existing[1])
    if (
        sum(len(source) for source, _ in workspace_sources.values())
        > CANDIDATE_WORKSPACE_TOTAL_SIZE_LIMIT_BYTES
    ):
        raise AssertionError("candidate workspace content exceeds its total limit")
    return _validated_candidate_workspace_sources(workspace_sources)


def _candidate_checkout_binding_with_sources(
    root: Path,
    candidate_sha: str,
    *,
    require_clean: bool,
    capture_workspace: bool = False,
) -> tuple[
    dict[str, object],
    dict[Path, bytes],
    dict[Path, tuple[bytes, bool]] | None,
]:
    canonical_root = candidate_repository_root()
    if root.resolve(strict=True) != canonical_root:
        raise AssertionError("candidate checkout binding root is not canonical")
    candidate_sha = _parse_candidate_sha(candidate_sha, "candidate SHA")

    expected_toplevel = f"{canonical_root}\n".encode()
    expected_head = f"{candidate_sha}\n".encode()
    toplevel = _run_candidate_git(canonical_root, "rev-parse", "--show-toplevel")
    head_before = _run_candidate_git(
        canonical_root, "rev-parse", "--verify", "HEAD^{commit}"
    )
    if toplevel != expected_toplevel or head_before != expected_head:
        raise AssertionError("candidate checkout root or HEAD does not match the workflow")
    if require_clean:
        status_before = _run_candidate_git(
            canonical_root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
            "--ignore-submodules=none",
        )
        if status_before:
            raise AssertionError("candidate checkout is not exactly clean before execution")

    script_manifest, captured_sources = _candidate_script_manifest(
        canonical_root, candidate_sha, require_clean=require_clean
    )
    workspace_sources = (
        _candidate_workspace_sources(
            canonical_root,
            candidate_sha,
            captured_sources,
        )
        if capture_workspace
        else None
    )
    head_after = _run_candidate_git(
        canonical_root, "rev-parse", "--verify", "HEAD^{commit}"
    )
    if head_after != expected_head:
        raise AssertionError("candidate checkout HEAD changed during validation")
    if require_clean:
        status_after = _run_candidate_git(
            canonical_root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
            "--ignore-submodules=none",
        )
        if status_after:
            raise AssertionError("candidate checkout changed during validation")
    return (
        {
            "candidate_root": str(canonical_root),
            "candidate_distribution_profile": _TRUSTED_DISTRIBUTION_PROFILE,
            "candidate_sha": candidate_sha,
            "candidate_script_sha256": script_manifest,
        },
        captured_sources,
        workspace_sources,
    )


def candidate_checkout_binding(
    root: Path,
    candidate_sha: str,
    *,
    require_clean: bool,
) -> dict[str, object]:
    binding, _, _ = _candidate_checkout_binding_with_sources(
        root,
        candidate_sha,
        require_clean=require_clean,
    )
    return binding


def _strict_isolation_requested() -> bool:
    mode = os.environ.get(ISOLATION_MODE_ENV)
    if mode is None:
        return False
    if mode != STRICT_ISOLATION_MODE:
        raise AssertionError(
            f"{ISOLATION_MODE_ENV} must be exactly {STRICT_ISOLATION_MODE!r}"
        )
    return True


def strict_isolation_platform_preflight() -> None:
    global _STRICT_PLATFORM_VALIDATED
    if not _strict_isolation_requested():
        return
    if sys.platform != "linux" or not Path("/proc/self/status").is_file():
        raise AssertionError(
            "strict candidate isolation requires Linux procfs before any subprocess"
        )
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise AssertionError(
            "strict candidate isolation requires pidfd signal support before any subprocess"
        )
    if not hasattr(signal, "pthread_sigmask"):
        raise AssertionError(
            "strict candidate isolation requires a pthread signal mask before any subprocess"
        )
    if _STRICT_PLATFORM_VALIDATED:
        return
    _probe_pidfd_capability()
    for description, path in _STRICT_PRIMITIVES.items():
        _validate_strict_primitive(path, description)
    _STRICT_PLATFORM_VALIDATED = True


def _probe_pidfd_capability() -> None:
    descriptor: int | None = None
    try:
        descriptor = os.pidfd_open(os.getpid(), 0)
        signal.pidfd_send_signal(descriptor, 0, None, 0)
    except (AttributeError, OSError) as error:
        raise AssertionError(
            "strict candidate isolation cannot use pidfd signaling"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_strict_primitive(path: Path, description: str) -> None:
    if not path.is_absolute():
        raise AssertionError(
            f"strict candidate isolation has a relative {description}"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            f"strict candidate isolation is missing {description}"
        ) from error
    for selected in (path, resolved):
        current = Path(selected.anchor)
        for part in selected.parts[1:]:
            current /= part
            try:
                metadata = current.lstat()
            except OSError as error:
                raise AssertionError(
                    f"strict candidate isolation cannot inspect {description}"
                ) from error
            is_leaf = current == selected
            allowed_type = (
                stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                if is_leaf
                else stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            )
            if (
                not allowed_type
                or metadata.st_uid != 0
                or (
                    not stat.S_ISLNK(metadata.st_mode)
                    and metadata.st_mode & 0o022
                )
            ):
                raise AssertionError(
                    f"strict candidate isolation has an unsafe {description} path"
                )
    target_metadata = resolved.stat()
    if (
        not stat.S_ISREG(target_metadata.st_mode)
        or target_metadata.st_uid != 0
        or target_metadata.st_mode & 0o022
        or not target_metadata.st_mode & 0o111
    ):
        raise AssertionError(
            f"strict candidate isolation has an unsafe {description}"
        )


def _strict_target_mode_allows(
    metadata: os.stat_result, target_uid: int, target_gid: int, mask: int
) -> bool:
    shift = (
        6
        if metadata.st_uid == target_uid
        else 3
        if metadata.st_gid == target_gid
        else 0
    )
    return ((metadata.st_mode >> shift) & mask) == mask


def _strict_runtime_acl_is_absent(path: Path, description: str) -> None:
    if not hasattr(os, "listxattr"):
        if sys.platform == "linux":
            raise AssertionError(f"{description} ACL state cannot be read")
        return
    _acl_is_absent(path, description)


def _strict_runtime_identity_document(
    path: Path, metadata: os.stat_result, kind: str, link_target: str | None = None
) -> dict[str, object]:
    # Bind path/object identity and target access policy only. Content bytes,
    # timestamps, and link count are outside this target-UID threat boundary.
    document: dict[str, object] = {
        "path": str(path),
        "kind": kind,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "link_target": link_target,
    }
    if kind != "symlink":
        document.update(
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            permissions=stat.S_IMODE(metadata.st_mode),
        )
    return document


def _strict_runtime_kind(metadata: os.stat_result) -> str | None:
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    if stat.S_ISREG(metadata.st_mode):
        return "file"
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    return None


def _assert_strict_target_runtime_policy(
    metadata: os.stat_result,
    *,
    target_uid: int,
    target_gid: int,
    description: str,
    directory: bool,
    executable: bool,
) -> None:
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_kind(metadata.st_mode):
        raise AssertionError(f"{description} object identity is unsafe")
    required = os.X_OK if directory or executable else os.R_OK
    if (
        metadata.st_uid == target_uid
        or not _strict_target_mode_allows(
            metadata, target_uid, target_gid, required
        )
        or _strict_target_mode_allows(
            metadata, target_uid, target_gid, os.W_OK
        )
        or (not directory and metadata.st_mode & (stat.S_ISUID | stat.S_ISGID))
    ):
        raise AssertionError(f"{description} access policy is unsafe")


def _capture_strict_runtime_lexical_path(
    path: Path,
    *,
    target_uid: int,
    target_gid: int,
    description: str,
    executable: bool,
) -> list[dict[str, object]]:
    current = Path(path.anchor)
    documents: list[dict[str, object]] = []
    for index, component in enumerate(path.parts[1:]):
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError as error:
            raise AssertionError(f"{description} is missing") from error
        except OSError as error:
            raise AssertionError(f"{description} is unreadable") from error
        kind = _strict_runtime_kind(metadata)
        is_leaf = index == len(path.parts[1:]) - 1
        if kind not in (("file", "symlink") if is_leaf else ("directory", "symlink")):
            raise AssertionError(f"{description} path binding changed")
        link_target = None
        if kind == "symlink":
            try:
                link_target = os.readlink(current)
            except OSError as error:
                raise AssertionError(f"{description} is unreadable") from error
        else:
            _assert_strict_target_runtime_policy(
                metadata,
                target_uid=target_uid,
                target_gid=target_gid,
                description=description,
                directory=kind == "directory",
                executable=executable if is_leaf else False,
            )
            _strict_runtime_acl_is_absent(current, description)
        documents.append(
            _strict_runtime_identity_document(
                current, metadata, kind, link_target
            )
        )
    return documents


def _capture_strict_runtime_canonical_path(
    path: Path,
    *,
    target_uid: int,
    target_gid: int,
    description: str,
    executable: bool,
) -> list[dict[str, object]]:
    if not path.is_absolute() or path.anchor != os.path.sep:
        raise AssertionError(f"{description} must be an absolute POSIX path")
    try:
        if path.resolve(strict=True) != path:
            raise AssertionError(f"{description} path binding changed")
    except FileNotFoundError as error:
        raise AssertionError(f"{description} is missing") from error
    except OSError as error:
        raise AssertionError(f"{description} is unreadable") from error
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    readable_file_flags = (
        os.O_RDONLY
        | os.O_NONBLOCK
        | os.O_NOCTTY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    executable_file_flags = (
        getattr(
            os,
            "O_PATH",
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY,
        )
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    documents: list[dict[str, object]] = []
    with ExitStack() as descriptors:
        anchor_descriptor = os.open(path.anchor, directory_flags)
        descriptors.callback(os.close, anchor_descriptor)
        parent_descriptor = anchor_descriptor
        anchor_metadata = os.fstat(anchor_descriptor)
        _assert_strict_target_runtime_policy(
            anchor_metadata,
            target_uid=target_uid,
            target_gid=target_gid,
            description=description,
            directory=True,
            executable=False,
        )
        _strict_runtime_acl_is_absent(Path(path.anchor), description)
        anchor_document = _strict_runtime_identity_document(
            Path(path.anchor), anchor_metadata, "directory"
        )
        documents.append(anchor_document)
        bindings: list[tuple[int, str, int, dict[str, object]]] = []
        current = Path(path.anchor)
        for index, component in enumerate(path.parts[1:]):
            current /= component
            is_leaf = index == len(path.parts[1:]) - 1
            flags = (
                executable_file_flags if executable else readable_file_flags
            ) if is_leaf else directory_flags
            try:
                selected = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                descriptor = os.open(
                    component, flags, dir_fd=parent_descriptor
                )
            except FileNotFoundError as error:
                raise AssertionError(
                    f"{description} disappeared during binding"
                ) from error
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise AssertionError(
                        f"{description} path binding changed"
                    ) from error
                raise AssertionError(f"{description} is unreadable") from error
            descriptors.callback(os.close, descriptor)
            opened = os.fstat(descriptor)
            expected_kind = "file" if is_leaf else "directory"
            if (
                _strict_runtime_kind(selected) != expected_kind
                or _strict_runtime_kind(opened) != expected_kind
                or (selected.st_dev, selected.st_ino)
                != (opened.st_dev, opened.st_ino)
            ):
                raise AssertionError(f"{description} object identity changed")
            _assert_strict_target_runtime_policy(
                opened,
                target_uid=target_uid,
                target_gid=target_gid,
                description=description,
                directory=not is_leaf,
                executable=executable if is_leaf else False,
            )
            _strict_runtime_acl_is_absent(current, description)
            document = _strict_runtime_identity_document(
                current, opened, expected_kind
            )
            documents.append(document)
            bindings.append(
                (parent_descriptor, component, descriptor, document)
            )
            parent_descriptor = descriptor
        for parent_fd, component, descriptor, expected in bindings:
            try:
                opened = os.fstat(descriptor)
                selected = os.stat(
                    component, dir_fd=parent_fd, follow_symlinks=False
                )
            except FileNotFoundError as error:
                raise AssertionError(
                    f"{description} disappeared during revalidation"
                ) from error
            except OSError as error:
                raise AssertionError(
                    f"{description} is unreadable during revalidation"
                ) from error
            kind = str(expected["kind"])
            selected_document = _strict_runtime_identity_document(
                Path(str(expected["path"])), selected, kind
            )
            opened_document = _strict_runtime_identity_document(
                Path(str(expected["path"])), opened, kind
            )
            if (
                _strict_runtime_kind(selected) != kind
                or _strict_runtime_kind(opened) != kind
                or selected_document != expected
                or opened_document != expected
            ):
                raise AssertionError(
                    f"{description} object identity or access policy changed"
                )
        if _strict_runtime_identity_document(
            Path(path.anchor), os.fstat(anchor_descriptor), "directory"
        ) != documents[0]:
            raise AssertionError(
                f"{description} object identity or access policy changed"
            )
    return documents


def _capture_strict_candidate_interpreter_binding(
    selector_value: str,
    stdlib_value: str,
    *,
    target_uid: int,
    target_gid: int,
    version: Sequence[int],
    implementation: str,
) -> dict[str, object]:
    if (
        type(target_uid) is not int
        or type(target_gid) is not int
        or not 50000 <= target_uid <= 64999
        or target_uid != target_gid
    ):
        raise AssertionError(
            "configured candidate interpreter target identity is malformed"
        )
    if (
        type(selector_value) is not str
        or type(stdlib_value) is not str
        or not selector_value
        or not stdlib_value
    ):
        raise AssertionError("configured candidate interpreter selector is malformed")
    selector = Path(selector_value)
    stdlib_selector = Path(stdlib_value)
    if (
        not selector.is_absolute()
        or selector.anchor != os.path.sep
        or not stdlib_selector.is_absolute()
        or stdlib_selector.anchor != os.path.sep
    ):
        raise AssertionError(
            "configured candidate interpreter selectors must be absolute POSIX paths"
        )
    exact_version = list(version)
    if (
        len(exact_version) != 3
        or any(type(item) is not int or item < 0 for item in exact_version)
        or type(implementation) is not str
        or not implementation
    ):
        raise AssertionError("configured candidate interpreter version is malformed")
    lexical_before = _capture_strict_runtime_lexical_path(
        selector,
        target_uid=target_uid,
        target_gid=target_gid,
        description="configured candidate interpreter",
        executable=True,
    )
    stdlib_lexical_before = _capture_strict_runtime_lexical_path(
        stdlib_selector,
        target_uid=target_uid,
        target_gid=target_gid,
        description="configured candidate startup-library sentinel",
        executable=False,
    )
    try:
        resolved = selector.resolve(strict=True)
        stdlib_resolved = stdlib_selector.resolve(strict=True)
    except FileNotFoundError as error:
        raise AssertionError("configured candidate runtime is missing") from error
    except OSError as error:
        raise AssertionError("configured candidate runtime is unreadable") from error
    interpreter_chain = _capture_strict_runtime_canonical_path(
        resolved,
        target_uid=target_uid,
        target_gid=target_gid,
        description="configured candidate interpreter",
        executable=True,
    )
    stdlib_chain = _capture_strict_runtime_canonical_path(
        stdlib_resolved,
        target_uid=target_uid,
        target_gid=target_gid,
        description="configured candidate startup-library sentinel",
        executable=False,
    )
    lexical_after = _capture_strict_runtime_lexical_path(
        selector,
        target_uid=target_uid,
        target_gid=target_gid,
        description="configured candidate interpreter",
        executable=True,
    )
    stdlib_lexical_after = _capture_strict_runtime_lexical_path(
        stdlib_selector,
        target_uid=target_uid,
        target_gid=target_gid,
        description="configured candidate startup-library sentinel",
        executable=False,
    )
    if lexical_after != lexical_before or stdlib_lexical_after != stdlib_lexical_before:
        raise AssertionError("configured candidate runtime path binding changed")
    return {
        "schema_version": 1,
        "target_uid": target_uid,
        "target_gid": target_gid,
        "selector": str(selector),
        "resolved": str(resolved),
        "stdlib_selector": str(stdlib_selector),
        "stdlib_resolved": str(stdlib_resolved),
        "version": exact_version,
        "implementation": implementation,
        "selector_components": lexical_before,
        "stdlib_selector_components": stdlib_lexical_before,
        "interpreter_components": interpreter_chain,
        "stdlib_components": stdlib_chain,
    }


def _bind_configured_candidate_interpreter(
    target_uid: int, target_gid: int
) -> dict[str, object]:
    # Bind one startup-library sentinel and its canonical ancestors. The
    # target-credential bootstrap below proves the configured runtime's other
    # required imports are readable without an unbounded standard-library scan.
    stdlib_value = getattr(os, "__file__", None)
    if type(stdlib_value) is not str:
        raise AssertionError(
            "configured candidate startup-library sentinel is unavailable"
        )
    return _capture_strict_candidate_interpreter_binding(
        sys.executable,
        stdlib_value,
        target_uid=target_uid,
        target_gid=target_gid,
        version=sys.version_info[:3],
        implementation=sys.implementation.name,
    )


def _revalidate_configured_candidate_interpreter(
    binding: object,
) -> dict[str, object]:
    required = {
        "schema_version",
        "target_uid",
        "target_gid",
        "selector",
        "resolved",
        "stdlib_selector",
        "stdlib_resolved",
        "version",
        "implementation",
        "selector_components",
        "stdlib_selector_components",
        "interpreter_components",
        "stdlib_components",
    }
    if type(binding) is not dict or set(binding) != required:
        raise AssertionError("configured candidate interpreter binding is malformed")
    if binding.get("schema_version") != 1:
        raise AssertionError("configured candidate interpreter binding schema is invalid")
    version = binding.get("version")
    recaptured = _capture_strict_candidate_interpreter_binding(
        binding.get("selector"),
        binding.get("stdlib_selector"),
        target_uid=binding.get("target_uid"),
        target_gid=binding.get("target_gid"),
        version=version if isinstance(version, list) else (),
        implementation=binding.get("implementation"),
    )
    if recaptured != binding:
        raise AssertionError("configured candidate interpreter binding changed")
    return recaptured


def _strict_host_read_component_document(
    path: Path, metadata: os.stat_result, kind: str
) -> dict[str, object]:
    # dev/inode/kind protect object identity; uid/gid/mode independently
    # protect the target credential's access policy.  Metadata transitions
    # outside those selected properties are not treated as mutation.
    return {
        "path": str(path),
        "kind": kind,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "permissions": stat.S_IMODE(metadata.st_mode),
    }


def _capture_strict_host_read_root_binding(
    path: Path,
    *,
    purpose: str,
    kind: str,
    target_uid: int,
    target_gid: int,
) -> dict[str, object]:
    if _STRICT_HOST_READ_ROOT_PURPOSES.get(purpose) != kind:
        raise AssertionError("strict host read root purpose or kind is malformed")
    if (
        type(target_uid) is not int
        or type(target_gid) is not int
        or not 50000 <= target_uid <= 64999
        or target_uid != target_gid
    ):
        raise AssertionError("strict host read root target identity is malformed")
    if not path.is_absolute() or path.anchor != os.path.sep or path == Path(path.anchor):
        raise AssertionError("strict host read root path is malformed")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise AssertionError("strict host read root is missing") from error
    except OSError as error:
        raise AssertionError("strict host read root is unreadable") from error
    if resolved != path:
        raise AssertionError("strict host read root path binding changed")
    o_path = getattr(os, "O_PATH", None)
    if type(o_path) is not int:
        raise AssertionError("strict host read root binding is unavailable")
    documents: list[dict[str, object]] = []
    with ExitStack() as descriptors:
        anchor_descriptor = os.open(
            path.anchor,
            o_path | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        descriptors.callback(os.close, anchor_descriptor)
        parent_descriptor = anchor_descriptor
        anchor_metadata = os.fstat(anchor_descriptor)
        _assert_strict_target_runtime_policy(
            anchor_metadata,
            target_uid=target_uid,
            target_gid=target_gid,
            description="strict host read root",
            directory=True,
            executable=False,
        )
        _strict_runtime_acl_is_absent(Path(path.anchor), "strict host read root")
        documents.append(
            _strict_host_read_component_document(
                Path(path.anchor), anchor_metadata, "directory"
            )
        )
        opened_components: list[
            tuple[int, str, int, dict[str, object]]
        ] = []
        current = Path(path.anchor)
        for index, component in enumerate(path.parts[1:]):
            current /= component
            is_leaf = index == len(path.parts[1:]) - 1
            expected_kind = kind if is_leaf else "directory"
            flags = o_path | os.O_NOFOLLOW | os.O_CLOEXEC
            if expected_kind == "directory":
                flags |= os.O_DIRECTORY
            try:
                selected = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                descriptor = os.open(component, flags, dir_fd=parent_descriptor)
            except FileNotFoundError as error:
                raise AssertionError(
                    "strict host read root disappeared during binding"
                ) from error
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise AssertionError(
                        "strict host read root path binding changed"
                    ) from error
                raise AssertionError("strict host read root is unreadable") from error
            descriptors.callback(os.close, descriptor)
            opened = os.fstat(descriptor)
            if (
                _strict_runtime_kind(selected) != expected_kind
                or _strict_runtime_kind(opened) != expected_kind
                or (selected.st_dev, selected.st_ino)
                != (opened.st_dev, opened.st_ino)
            ):
                raise AssertionError("strict host read root object identity changed")
            _assert_strict_target_runtime_policy(
                opened,
                target_uid=target_uid,
                target_gid=target_gid,
                description="strict host read root",
                directory=expected_kind == "directory",
                executable=False,
            )
            _strict_runtime_acl_is_absent(current, "strict host read root")
            document = _strict_host_read_component_document(
                current, opened, expected_kind
            )
            documents.append(document)
            opened_components.append(
                (parent_descriptor, component, descriptor, document)
            )
            parent_descriptor = descriptor
        for parent_fd, component, descriptor, expected in opened_components:
            try:
                selected = os.stat(
                    component, dir_fd=parent_fd, follow_symlinks=False
                )
                opened = os.fstat(descriptor)
            except FileNotFoundError as error:
                raise AssertionError(
                    "strict host read root disappeared during revalidation"
                ) from error
            except OSError as error:
                raise AssertionError(
                    "strict host read root is unreadable during revalidation"
                ) from error
            expected_kind = str(expected["kind"])
            if (
                _strict_runtime_kind(selected) != expected_kind
                or _strict_runtime_kind(opened) != expected_kind
                or _strict_host_read_component_document(
                    Path(str(expected["path"])), selected, expected_kind
                )
                != expected
                or _strict_host_read_component_document(
                    Path(str(expected["path"])), opened, expected_kind
                )
                != expected
            ):
                raise AssertionError(
                    "strict host read root object identity or access policy changed"
                )
        if (
            _strict_host_read_component_document(
                Path(path.anchor), os.fstat(anchor_descriptor), "directory"
            )
            != documents[0]
        ):
            raise AssertionError(
                "strict host read root object identity or access policy changed"
            )
    binding: dict[str, object] = {
        "schema_version": 1,
        "purpose": purpose,
        "kind": kind,
        "path": str(path),
        "target_uid": target_uid,
        "target_gid": target_gid,
        "components": documents,
        "host_mount_id": None,
    }
    if kind == "directory":
        binding["host_mount_id"] = _strict_host_read_root_mount_binding(path)
    return binding


def _canonical_existing_directory(path: Path, description: str) -> Path:
    if not path.is_absolute() or path.anchor != os.path.sep:
        raise AssertionError(f"{description} must be an absolute POSIX path")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except FileNotFoundError as error:
        raise AssertionError(f"{description} is missing") from error
    except OSError as error:
        raise AssertionError(f"{description} is unreadable") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise AssertionError(f"{description} is not a directory")
    return resolved


def _strict_host_read_root_bindings(
    runtime_binding: Mapping[str, object] | None,
    target_uid: int,
    target_gid: int,
    *,
    readable_roots: Sequence[Path] = (),
) -> list[dict[str, object]]:
    selected: list[tuple[str, str, Path]] = []
    exact_runtime: dict[str, object] | None = None
    if runtime_binding is not None:
        exact_runtime = _revalidate_configured_candidate_interpreter(
            dict(runtime_binding)
        )
        if (
            exact_runtime["target_uid"] != target_uid
            or exact_runtime["target_gid"] != target_gid
        ):
            raise AssertionError(
                "strict configured read root target identity changed"
            )
        early_interpreter = Path(str(exact_runtime["resolved"]))
        early_prefix = early_interpreter.parent.parent
        if (
            early_interpreter.parent.name != "bin"
            or early_interpreter.parent != early_prefix / "bin"
            or early_prefix
            in {Path(os.path.sep), Path("/opt"), Path("/usr"), Path("/usr/local")}
        ):
            raise AssertionError(
                "configured candidate runtime prefix is not narrowly bound"
            )
    machine = os.uname().machine
    architecture = {
        "x86_64": (
            "x86_64-linux-gnu",
            (
                Path("/lib64/ld-linux-x86-64.so.2"),
                Path("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
            ),
        ),
        "aarch64": (
            "aarch64-linux-gnu",
            (
                Path("/lib/ld-linux-aarch64.so.1"),
                Path("/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"),
            ),
        ),
    }.get(machine)
    if architecture is None:
        raise AssertionError("strict host runtime architecture is unsupported")
    multiarch, loader_selectors = architecture
    system_library_roots: list[Path] = []
    for selector in (Path("/lib") / multiarch, Path("/usr/lib") / multiarch):
        try:
            resolved = selector.resolve(strict=True)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise AssertionError(
                "strict system library root is unreadable"
            ) from error
        try:
            metadata = resolved.stat()
        except OSError as error:
            raise AssertionError(
                "strict system library root is unreadable"
            ) from error
        if not stat.S_ISDIR(metadata.st_mode):
            raise AssertionError("strict system library root is not a directory")
        if resolved not in system_library_roots:
            system_library_roots.append(resolved)
            selected.append(("system-arch-library", "directory", resolved))
    if not system_library_roots:
        raise AssertionError("strict system library root inventory is empty")
    loader_path = None
    for selector in loader_selectors:
        try:
            loader_path = selector.resolve(strict=True)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise AssertionError("strict system loader is unreadable") from error
        break
    if loader_path is None:
        raise AssertionError("strict system loader is missing")
    selected.append(("system-loader", "file", loader_path))
    try:
        Path("/etc/ld.so.preload").lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise AssertionError("strict ld.so.preload state is unreadable") from error
    else:
        raise AssertionError("strict ld.so.preload is unsupported")

    try:
        system_python = _STRICT_PRIMITIVES["python"].resolve(strict=True)
    except FileNotFoundError as error:
        raise AssertionError("strict system Python executable is missing") from error
    except OSError as error:
        raise AssertionError("strict system Python executable is unreadable") from error
    version_match = re.fullmatch(r"python(3\.[0-9]+)", system_python.name)
    if system_python.parent != Path("/usr/bin") or version_match is None:
        raise AssertionError("strict system Python layout is unsupported")
    system_stdlib = _canonical_existing_directory(
        Path("/usr/lib") / f"python{version_match.group(1)}",
        "strict system Python standard library",
    )
    selected.append(("system-python-stdlib", "directory", system_stdlib))
    system_dynload = _canonical_existing_directory(
        system_stdlib / "lib-dynload",
        "strict system Python dynamic library directory",
    )
    selected.append(("system-python-dynload", "directory", system_dynload))

    if exact_runtime is not None:
        resolved_interpreter = Path(str(exact_runtime["resolved"]))
        prefix = resolved_interpreter.parent.parent
        forbidden_prefixes = {
            Path(os.path.sep),
            Path("/opt"),
            Path("/usr"),
            Path("/usr/local"),
            *system_library_roots,
        }
        runtime_version = exact_runtime.get("version")
        version_prefix = (
            f"{runtime_version[0]}.{runtime_version[1]}"
            if isinstance(runtime_version, list)
            and len(runtime_version) == 3
            and all(type(value) is int for value in runtime_version)
            else None
        )
        if (
            resolved_interpreter.parent.name != "bin"
            or resolved_interpreter.parent != prefix / "bin"
            or prefix in forbidden_prefixes
            or prefix.resolve(strict=True) != prefix
            or version_prefix is None
            or not any(
                re.fullmatch(
                    rf"{re.escape(version_prefix)}(?:\.[0-9]+)?", component
                )
                for component in prefix.parts
            )
        ):
            raise AssertionError(
                "configured candidate runtime prefix is not narrowly bound"
            )
        stdlib_sentinel = Path(str(exact_runtime["stdlib_resolved"]))
        if prefix not in stdlib_sentinel.parents:
            raise AssertionError(
                "configured candidate standard library escapes its narrow prefix"
            )
        # The configured candidate argv uses -I but deliberately not -S, so
        # its versioned prefix/lib tree must cover both the standard library
        # and that installation's isolated site initialization.  The prefix
        # shape checks above prevent this rule from degenerating to /opt,
        # /usr, /usr/local, or a system multiarch library root.
        runtime_paths = sysconfig.get_paths()
        if type(runtime_paths) is not dict:
            raise AssertionError("configured candidate sysconfig paths are malformed")
        runtime_directories: list[tuple[str, Path]] = []
        for purpose, key in (
            ("configured-stdlib", "stdlib"),
            ("configured-platstdlib", "platstdlib"),
        ):
            value = runtime_paths.get(key)
            if type(value) is not str or not value:
                raise AssertionError(
                    f"configured candidate sysconfig {key} is malformed"
                )
            runtime_directories.append(
                (
                    purpose,
                    _canonical_existing_directory(
                        Path(value), f"configured candidate sysconfig {key}"
                    ),
                )
            )
        for purpose, key in (
            ("configured-libdir", "LIBDIR"),
            ("configured-destshared", "DESTSHARED"),
        ):
            value = sysconfig.get_config_var(key)
            if type(value) is not str or not value:
                raise AssertionError(
                    f"configured candidate sysconfig {key} is malformed"
                )
            runtime_directories.append(
                (
                    purpose,
                    _canonical_existing_directory(
                        Path(value), f"configured candidate sysconfig {key}"
                    ),
                )
            )
        if not any(
            path == stdlib_sentinel.parent
            or path in stdlib_sentinel.parents
            for _, path in runtime_directories
        ):
            raise AssertionError(
                "configured candidate standard library is not in sysconfig"
            )
        for purpose, path in runtime_directories:
            if prefix not in path.parents:
                raise AssertionError(
                    "configured candidate sysconfig path escapes its narrow prefix"
                )
            selected.append((purpose, "directory", path))
        selected.append(
            ("configured-executable", "file", resolved_interpreter)
        )
        pyvenv_selector = prefix / "pyvenv.cfg"
        try:
            pyvenv_path = pyvenv_selector.resolve(strict=True)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise AssertionError(
                "configured candidate pyvenv file is unreadable"
            ) from error
        else:
            selected.append(("configured-pyvenv", "file", pyvenv_path))

    for purpose, primitive in (
        ("continuation-setpriv", _STRICT_PRIMITIVES["setpriv"]),
        ("continuation-env", _STRICT_PRIMITIVES["env"]),
        ("continuation-python", _STRICT_PRIMITIVES["python"]),
    ):
        try:
            selected.append((purpose, "file", primitive.resolve(strict=True)))
        except FileNotFoundError as error:
            raise AssertionError("strict continuation executable is missing") from error
        except OSError as error:
            raise AssertionError("strict continuation executable is unreadable") from error

    trusted_git = _revalidate_trusted_git_binding(_TRUSTED_GIT_BINDING)
    if sys.platform == "linux":
        try:
            expected_git = Path("/usr/bin/git").resolve(strict=True)
        except OSError as error:
            raise AssertionError("strict trusted Git executable is missing") from error
        if trusted_git != expected_git or trusted_git.parent != Path("/usr/bin"):
            raise AssertionError(
                "strict trusted Git executable is outside /usr/bin"
            )
    selected.append(("trusted-git", "file", trusted_git))

    for purpose, selector, required in (
        ("ld-cache", Path("/etc/ld.so.cache"), True),
        ("localtime", Path("/etc/localtime"), False),
    ):
        try:
            path = selector.resolve(strict=True)
        except FileNotFoundError as error:
            if not required:
                continue
            raise AssertionError(f"strict {purpose} read file is missing") from error
        except OSError as error:
            raise AssertionError(f"strict {purpose} read file is unreadable") from error
        selected.append((purpose, "file", path))

    for value in readable_roots:
        path = Path(value)
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.stat()
        except FileNotFoundError as error:
            raise AssertionError("strict trusted test read file is missing") from error
        except OSError as error:
            raise AssertionError("strict trusted test read file is unreadable") from error
        if resolved != path or not stat.S_ISREG(metadata.st_mode):
            raise AssertionError("strict trusted test read file is unsafe")
        selected.append(("trusted-test-file", "file", resolved))

    bindings: list[dict[str, object]] = []
    observed_paths: set[Path] = set()
    for purpose, kind, path in selected:
        if path in observed_paths:
            continue
        observed_paths.add(path)
        try:
            binding = _capture_strict_host_read_root_binding(
                path,
                purpose=purpose,
                kind=kind,
                target_uid=target_uid,
                target_gid=target_gid,
            )
        except AssertionError as error:
            raise AssertionError(
                f"strict host read root {purpose} {kind} rejected: {error}"
            ) from error
        bindings.append(binding)
    if not 1 <= len(bindings) <= _STRICT_HOST_READ_ROOT_LIMIT:
        raise AssertionError("strict host read root inventory exceeds its fixed limit")
    return bindings


def _revalidate_strict_host_read_root_bindings(
    value: object,
) -> list[dict[str, object]]:
    if (
        type(value) is not list
        or not 1 <= len(value) <= _STRICT_HOST_READ_ROOT_LIMIT
    ):
        raise AssertionError("strict host read root binding is malformed")
    bindings: list[dict[str, object]] = []
    observed_paths: set[str] = set()
    for document in value:
        if (
            type(document) is not dict
            or set(document)
            != {
                "schema_version",
                "purpose",
                "kind",
                "path",
                "target_uid",
                "target_gid",
                "components",
                "host_mount_id",
            }
            or document.get("schema_version") != 1
            or _STRICT_HOST_READ_ROOT_PURPOSES.get(document.get("purpose"))
            != document.get("kind")
            or type(document.get("path")) is not str
            or type(document.get("target_uid")) is not int
            or type(document.get("target_gid")) is not int
            or type(document.get("components")) is not list
            or (
                document.get("kind") == "directory"
                and type(document.get("host_mount_id")) is not int
            )
            or (
                document.get("kind") == "file"
                and document.get("host_mount_id") is not None
            )
        ):
            raise AssertionError("strict host read root binding is malformed")
        path = str(document["path"])
        if path in observed_paths:
            raise AssertionError("strict host read root binding contains a duplicate")
        observed_paths.add(path)
        recaptured = _capture_strict_host_read_root_binding(
            Path(path),
            purpose=str(document["purpose"]),
            kind=str(document["kind"]),
            target_uid=int(document["target_uid"]),
            target_gid=int(document["target_gid"]),
        )
        if recaptured != document:
            raise AssertionError("strict host read root binding changed")
        bindings.append(recaptured)
    return bindings


def _minimal_supervisor_environment() -> dict[str, str]:
    return {
        "HOME": "/root",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _process_identity(
    path: Path,
) -> tuple[int, int, int, int, int, tuple[int, int, int, int]] | None:
    try:
        status_text = (path / "status").read_text(encoding="ascii")
        stat_text = (path / "stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as error:
        raise AssertionError("strict candidate process inventory is unreadable") from error
    uid_lines = [line for line in status_text.splitlines() if line.startswith("Uid:")]
    if len(uid_lines) != 1:
        raise AssertionError("strict candidate process UID inventory is malformed")
    try:
        uid_values = tuple(int(value) for value in uid_lines[0].split()[1:])
    except ValueError as error:
        raise AssertionError("strict candidate process UID inventory is malformed") from error
    if len(uid_values) != 4:
        raise AssertionError("strict candidate process UID inventory is malformed")
    try:
        pid = int(path.name)
        suffix = stat_text.rsplit(")", 1)[1].split()
        parent_pid = int(suffix[1])
        process_group = int(suffix[2])
        session_id = int(suffix[3])
        start_time = int(suffix[19])
    except (IndexError, ValueError) as error:
        raise AssertionError("strict candidate process identity is malformed") from error
    return (
        pid,
        start_time,
        parent_pid,
        process_group,
        session_id,
        uid_values,
    )


def _proc_identity(path: Path, target_uid: int) -> tuple[int, int] | None:
    identity = _process_identity(path)
    if identity is None:
        return None
    uid_values = identity[5]
    if target_uid not in uid_values:
        return None
    if uid_values != (target_uid,) * 4:
        raise AssertionError("strict candidate process has mixed UID identities")
    return identity[0], identity[1]


def _candidate_uid_inventory(target_uid: int) -> set[tuple[int, int]]:
    proc_root = Path("/proc")
    try:
        entries = sorted(
            (entry for entry in proc_root.iterdir() if entry.name.isdecimal()),
            key=lambda entry: int(entry.name),
        )
    except OSError as error:
        raise AssertionError("strict candidate process inventory is unavailable") from error
    identities: set[tuple[int, int]] = set()
    for entry in entries:
        identity = _proc_identity(entry, target_uid)
        if identity is not None:
            identities.add(identity)
    return identities


def _database_ids() -> tuple[set[int], set[int]]:
    try:
        user_ids = {entry.pw_uid for entry in pwd.getpwall()}
        group_ids = {entry.gr_gid for entry in grp.getgrall()}
    except OSError as error:
        raise AssertionError("strict candidate identity database is unreadable") from error
    return user_ids, group_ids


def _parse_internal_identity(name: str, value: str) -> int:
    if not value.isdecimal():
        raise AssertionError(f"{name} must be a decimal identity")
    identity = int(value)
    if identity < 50000 or identity > 64999:
        raise AssertionError(f"{name} is outside the fixed isolated range")
    return identity


def _release_realm_lock(lock_file: IO[bytes], lock_path: Path) -> None:
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    lock_file.close()


def _open_realm_lock(lock_path: Path) -> IO[bytes]:
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(lock_path, flags, 0o600)
        descriptor_metadata = os.fstat(descriptor)
        path_metadata = lock_path.lstat()
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise AssertionError("strict candidate identity lock is unsafe") from error
    if (
        not stat.S_ISREG(descriptor_metadata.st_mode)
        or descriptor_metadata.st_nlink != 1
        or descriptor_metadata.st_uid != os.getuid()
        or stat.S_IMODE(descriptor_metadata.st_mode) != 0o600
        or (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
        or not stat.S_ISREG(path_metadata.st_mode)
        or path_metadata.st_nlink != 1
        or path_metadata.st_uid != os.getuid()
        or stat.S_IMODE(path_metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise AssertionError("strict candidate identity lock is unsafe")
    return os.fdopen(descriptor, "a+b", closefd=True)


def _strict_realm() -> dict[str, object]:
    global _STRICT_REALM
    if _STRICT_REALM is not None:
        return _STRICT_REALM
    if not _strict_isolation_requested():
        raise AssertionError("strict candidate identity requested outside strict mode")
    strict_isolation_platform_preflight()
    user_ids, group_ids = _database_ids()
    configured_uid = os.environ.get(_ISOLATION_UID_ENV)
    configured_gid = os.environ.get(_ISOLATION_GID_ENV)
    configured_lock_fd = os.environ.get(_ISOLATION_LOCK_FD_ENV)
    configured_values = (configured_uid, configured_gid, configured_lock_fd)
    if any(value is None for value in configured_values) and any(
        value is not None for value in configured_values
    ):
        raise AssertionError("strict candidate identity selectors are incomplete")
    if (
        configured_uid is not None
        and configured_gid is not None
        and configured_lock_fd is not None
    ):
        uid = _parse_internal_identity(_ISOLATION_UID_ENV, configured_uid)
        gid = _parse_internal_identity(_ISOLATION_GID_ENV, configured_gid)
        if uid != gid:
            raise AssertionError("strict candidate UID and GID must be identical")
        if not configured_lock_fd.isdecimal():
            raise AssertionError("strict candidate identity lock descriptor is malformed")
        lock_descriptor = int(configured_lock_fd)
        lock_path = Path(
            f"/tmp/codex-required-ci-identities/uid-{uid}.lock"
        )
        try:
            descriptor_metadata = os.fstat(lock_descriptor)
            path_metadata = lock_path.lstat()
            directory_metadata = lock_path.parent.lstat()
            fcntl.flock(
                lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
            )
        except (OSError, ValueError) as error:
            raise AssertionError(
                "strict candidate identity lock is not inherited from the parent"
            ) from error
        if (
            not stat.S_ISREG(descriptor_metadata.st_mode)
            or descriptor_metadata.st_nlink != 1
            or descriptor_metadata.st_uid != os.getuid()
            or stat.S_IMODE(descriptor_metadata.st_mode) != 0o600
            or (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
            or not stat.S_ISREG(path_metadata.st_mode)
            or path_metadata.st_nlink != 1
            or path_metadata.st_uid != os.getuid()
            or stat.S_IMODE(path_metadata.st_mode) != 0o600
            or not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.getuid()
            or directory_metadata.st_mode & 0o077
        ):
            raise AssertionError("strict candidate identity lock is unsafe")
        if uid in user_ids or gid in group_ids or _candidate_uid_inventory(uid):
            raise AssertionError("strict candidate identity is already occupied")
        _STRICT_REALM = {
            "uid": uid,
            "gid": gid,
            "lock": None,
            "lock_path": lock_path,
            "inherited_lock_fd": lock_descriptor,
        }
        return _STRICT_REALM

    lock_directory = Path("/tmp/codex-required-ci-identities")
    lock_directory.mkdir(mode=0o700, exist_ok=True)
    metadata = lock_directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise AssertionError("strict candidate identity lock directory is unsafe")
    for identity in range(60000, 65000):
        if identity in user_ids or identity in group_ids:
            continue
        lock_path = lock_directory / f"uid-{identity}.lock"
        lock_file = _open_realm_lock(lock_path)
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock_file.close()
            continue
        if _candidate_uid_inventory(identity):
            _release_realm_lock(lock_file, lock_path)
            continue
        _STRICT_REALM = {
            "uid": identity,
            "gid": identity,
            "lock": lock_file,
            "lock_path": lock_path,
        }
        atexit.register(_release_realm_lock, lock_file, lock_path)
        return _STRICT_REALM
    raise AssertionError("strict candidate isolation has no unused UID/GID realm")


class _CandidateFixtureDirectory:
    def __init__(self, prefix: str) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix=prefix)
        self.name = self._temporary.name
        self._path = Path(self.name).resolve(strict=True)
        metadata = self._path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink < 1
        ):
            raise AssertionError("candidate fixture root identity is unsafe")
        _REGISTERED_FIXTURE_ROOTS[self._path] = (metadata.st_dev, metadata.st_ino)

    def __enter__(self) -> str:
        return self.name

    def __exit__(self, _exc_type, _exc_value, _traceback) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        identity = _REGISTERED_FIXTURE_ROOTS.pop(self._path, None)
        if identity is None:
            raise AssertionError("candidate fixture root registration is missing")
        metadata = self._path.lstat()
        if (metadata.st_dev, metadata.st_ino) != identity:
            raise AssertionError("candidate fixture root was replaced")
        self._temporary.cleanup()


def candidate_fixture_directory(prefix: str) -> tempfile.TemporaryDirectory[str] | _CandidateFixtureDirectory:
    if not _strict_isolation_requested():
        return tempfile.TemporaryDirectory(prefix=prefix)
    return _CandidateFixtureDirectory(prefix)


_ROOT_CONTROLLER_RECEIPT_PREFIX = "REQUIRED_CI_ROOT_CONTROLLER:"
_ROOT_TARGET_ACTIVE_PREFIX = "REQUIRED_CI_ROOT_TARGET_ACTIVE:"
_TARGET_ACTIVE_MARKER_PREFIX = "REQUIRED_CI_TARGET_ACTIVE:"
_ROOT_CLEANUP_RECEIPT_PREFIX = "REQUIRED_CI_ROOT_CLEANUP:"
_ROOT_TREE_RECEIPT_PREFIX = "REQUIRED_CI_ROOT_TREE:"
_CONFIGURED_RUNTIME_BOOTSTRAP_SOURCE = r'''
import os
import sys

if len(sys.argv) < 9:
    raise SystemExit(118)
resolved = sys.argv[1]
stdlib_resolved = sys.argv[2]
implementation = sys.argv[3]
version_values = sys.argv[4:7]
environment_count_value = sys.argv[7]
try:
    version = tuple(int(value) for value in version_values)
    environment_count = int(environment_count_value)
except ValueError:
    raise SystemExit(118)
if (
    any(str(value) != encoded for value, encoded in zip(version, version_values))
    or str(environment_count) != environment_count_value
    or environment_count < 0
    or len(sys.argv) < 9 + environment_count
):
    raise SystemExit(118)
environment_arguments = sys.argv[8 : 8 + environment_count]
candidate_argv = sys.argv[8 + environment_count :]
closed_environment = {}
for item in environment_arguments:
    key, separator, value = item.partition("=")
    if not separator or not key or "\x00" in key or "\x00" in value:
        raise SystemExit(118)
    if key in closed_environment:
        raise SystemExit(118)
    closed_environment[key] = value
if (
    version != tuple(sys.version_info[:3])
    or implementation != sys.implementation.name
    or os.path.realpath(sys.executable) != resolved
    or type(getattr(os, "__file__", None)) is not str
    or os.path.realpath(os.__file__) != stdlib_resolved
    or (sys.platform == "linux" and os.path.realpath("/proc/self/exe") != resolved)
    or not candidate_argv
    or candidate_argv[0] != resolved
):
    raise SystemExit(118)
os.execve(candidate_argv[0], candidate_argv, closed_environment)
'''.strip()
_MOUNT_NAMESPACE_BOOTSTRAP_SOURCE = r'''
import ctypes
import errno
import fcntl
import json
import os
import re
import resource
import stat
import sys

NETWORK_INTERFACE_FD = 63


def bootstrap_nofile_requirement(writable_roots, read_roots):
    if (
        type(writable_roots) is not list
        or not 1 <= len(writable_roots) <= 64
        or type(read_roots) is not list
        or not 1 <= len(read_roots) <= 32
    ):
        raise SystemExit(150)
    component_depths = []
    for document in read_roots:
        if type(document) is not dict:
            raise SystemExit(150)
        components = document.get("components")
        if type(components) is not list or not components:
            raise SystemExit(150)
        component_depths.append(len(components))
    # Match the parent/root proof: 2W+R held FDs plus the greater of the 31
    # fixed Landlock FDs and D+7 component-revalidation FDs.
    required = max(
        64,
        (2 * len(writable_roots))
        + len(read_roots)
        + max(31, max(component_depths) + 7),
    )
    if required > 256:
        raise SystemExit(150)
    return required


def set_bootstrap_nofile_limit(required_nofile):
    _inherited_soft, inherited_hard = resource.getrlimit(
        resource.RLIMIT_NOFILE
    )
    if (
        type(inherited_hard) is not int
        or (
            inherited_hard != resource.RLIM_INFINITY
            and inherited_hard < required_nofile
        )
    ):
        raise SystemExit(150)
    resource.setrlimit(
        resource.RLIMIT_NOFILE, (required_nofile, required_nofile)
    )
    if resource.getrlimit(resource.RLIMIT_NOFILE) != (
        required_nofile,
        required_nofile,
    ):
        raise SystemExit(150)


def reject_mount_network_probe(stage, error=None):
    error_number = getattr(error, "errno", None)
    suffix = (
        f":errno={error_number}"
        if type(error_number) is int and 0 <= error_number <= 4095
        else ""
    )
    print(
        f"strict mount network descriptor rejected: stage={stage}{suffix}",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(150)


if len(sys.argv) < 9:
    reject_mount_network_probe("arguments")
try:
    readiness_fd = int(sys.argv[1])
    required_nofile = int(sys.argv[2])
except ValueError:
    reject_mount_network_probe("readiness-number")
if (
    readiness_fd <= 2
    or readiness_fd == NETWORK_INTERFACE_FD
    or str(required_nofile) != sys.argv[2]
):
    reject_mount_network_probe("readiness-number")
try:
    os.fstat(NETWORK_INTERFACE_FD)
except OSError as error:
    if error.errno != errno.EBADF:
        reject_mount_network_probe("reserved-fd-check", error)
else:
    reject_mount_network_probe("reserved-fd-occupied")

host_mount_namespace = sys.argv[3]
host_ipc_namespace = sys.argv[4]
host_network_namespace = sys.argv[5]
try:
    writable_roots = json.loads(sys.argv[6])
    read_roots = json.loads(sys.argv[7])
except json.JSONDecodeError:
    raise SystemExit(150)
continuation_argv = sys.argv[8:]
if required_nofile != bootstrap_nofile_requirement(
    writable_roots, read_roots
):
    raise SystemExit(150)

set_bootstrap_nofile_limit(required_nofile)

STRICT_LIMITS = {
    resource.RLIMIT_NPROC: 64,
    resource.RLIMIT_CPU: 20,
    resource.RLIMIT_AS: 1073741824,
    resource.RLIMIT_FSIZE: 1048576,
    resource.RLIMIT_MSGQUEUE: 8388608,
    resource.RLIMIT_CORE: 1,
}
for limit_name, value in STRICT_LIMITS.items():
    resource.setrlimit(limit_name, (value, value))
    if resource.getrlimit(limit_name) != (value, value):
        raise SystemExit(150)

try:
    os.dup2(readiness_fd, NETWORK_INTERFACE_FD, inheritable=False)
except OSError as error:
    reject_mount_network_probe("reserved-fd-claim", error)
try:
    reserved_inheritable = os.get_inheritable(NETWORK_INTERFACE_FD)
except OSError as error:
    reject_mount_network_probe("reserved-fd-flags", error)
if reserved_inheritable:
    reject_mount_network_probe("reserved-fd-flags")

core_pattern_descriptor = None
try:
    core_pattern_descriptor = os.open(
        "/proc/sys/kernel/core_pattern",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    core_pattern_bytes = os.read(core_pattern_descriptor, 4097)
except OSError:
    raise SystemExit(150)
finally:
    if core_pattern_descriptor is not None:
        os.close(core_pattern_descriptor)
if not core_pattern_bytes or len(core_pattern_bytes) > 4096:
    raise SystemExit(150)
try:
    core_pattern = core_pattern_bytes.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(150)
if core_pattern.endswith("\n"):
    core_pattern = core_pattern[:-1]
if (
    not core_pattern
    or "\n" in core_pattern
    or "\r" in core_pattern
    or "\x00" in core_pattern
):
    raise SystemExit(150)
if core_pattern.startswith("|"):
    if not core_pattern[1:].strip():
        raise SystemExit(150)
elif (
    core_pattern in {".", ".."}
    or "/" in core_pattern
    or not all(0x21 <= ord(character) <= 0x7E for character in core_pattern)
):
    raise SystemExit(150)

AT_EMPTY_PATH = 0x1000
AT_RECURSIVE = 0x8000
AT_SYMLINK_NOFOLLOW = 0x100
MS_BIND = 4096
MS_PRIVATE = 1 << 18
MS_REC = 16384
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MOUNT_ATTR_RDONLY = 1
MOUNT_ATTR_NODEV = 4
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_KILL_PROCESS = 0x80000000
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_JMP_JSET_K = 0x45
BPF_RET_K = 0x06
LANDLOCK_CREATE_RULESET = 444
LANDLOCK_ADD_RULE = 445
LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_MINIMUM_ABI = 4
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_WRITE_ACCESS = (
    LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)
LANDLOCK_ROOT_WRITE_ACCESS = (
    LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)
MOUNTINFO_LIMIT = 1048576
WRITABLE_ROOT_LIMIT = 64
READ_ROOT_LIMIT = 32
PRIVATE_SURFACES = (
    ("/tmp", "mode=1777,size=33554432,nr_inodes=4096"),
    ("/var/tmp", "mode=1777,size=33554432,nr_inodes=4096"),
    ("/run", "mode=0755,size=8388608,nr_inodes=2048"),
    ("/dev/shm", "mode=1777,size=33554432,nr_inodes=4096"),
)
PRIVATE_SURFACE_LIMITS = {
    "/tmp": (33554432, 4096),
    "/var/tmp": (33554432, 4096),
    "/run": (8388608, 2048),
    "/dev/shm": (33554432, 4096),
}
IPC_MEMORY_LIMIT = 8388608
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
if (
    type(PAGE_SIZE) is not int
    or PAGE_SIZE <= 0
    or IPC_MEMORY_LIMIT % PAGE_SIZE != 0
):
    raise SystemExit(152)
IPC_SYSCTLS = (
    ("/proc/sys/kernel/shmmax", str(IPC_MEMORY_LIMIT)),
    ("/proc/sys/kernel/shmall", str(IPC_MEMORY_LIMIT // PAGE_SIZE)),
    ("/proc/sys/kernel/shmmni", "64"),
    ("/proc/sys/kernel/msgmax", "8192"),
    ("/proc/sys/kernel/msgmnb", "65536"),
    ("/proc/sys/kernel/msgmni", "64"),
    ("/proc/sys/kernel/sem", "64 256 32 64"),
    ("/proc/sys/fs/mqueue/queues_max", "64"),
    ("/proc/sys/fs/mqueue/msg_max", "64"),
    ("/proc/sys/fs/mqueue/msgsize_max", "8192"),
    ("/proc/sys/fs/mqueue/msg_default", "16"),
    ("/proc/sys/fs/mqueue/msgsize_default", "8192"),
)
READ_ROOT_PURPOSES = {
    "configured-destshared": "directory",
    "configured-executable": "file",
    "configured-libdir": "directory",
    "configured-platstdlib": "directory",
    "configured-pyvenv": "file",
    "configured-stdlib": "directory",
    "continuation-env": "file",
    "continuation-python": "file",
    "continuation-setpriv": "file",
    "ld-cache": "file",
    "localtime": "file",
    "system-arch-library": "directory",
    "system-loader": "file",
    "system-python-dynload": "directory",
    "system-python-stdlib": "directory",
    "trusted-git": "file",
    "trusted-test-file": "file",
}
NAMESPACE_READ_PATHS = (
    ("/proc/self/status", "file"),
    ("/proc/self/limits", "file"),
    ("/proc/self/mountinfo", "file"),
    ("/proc/sys/kernel/core_pattern", "file"),
    ("/proc/sys/kernel/cap_last_cap", "file"),
    *((path, "file") for path, _ in IPC_SYSCTLS),
)

if (
    readiness_fd <= 2
    or not host_mount_namespace.startswith("mnt:[")
    or not host_ipc_namespace.startswith("ipc:[")
    or re.fullmatch(r"net:\[[1-9][0-9]*\]", host_network_namespace) is None
    or type(writable_roots) is not list
    or not 1 <= len(writable_roots) <= WRITABLE_ROOT_LIMIT
    or type(read_roots) is not list
    or not 1 <= len(read_roots) <= READ_ROOT_LIMIT
    or not continuation_argv
):
    raise SystemExit(150)
if (
    os.readlink("/proc/self/ns/mnt") == host_mount_namespace
    or os.readlink("/proc/self/ns/ipc") == host_ipc_namespace
    or os.readlink("/proc/self/ns/net") == host_network_namespace
):
    raise SystemExit(151)


class MountAttr(ctypes.Structure):
    _fields_ = (
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    )


class SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    )


class SockFprog(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_ushort),
        ("filters", ctypes.POINTER(SockFilter)),
    )


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = (
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    )


class LandlockPathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = (
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int),
    )


libc = ctypes.CDLL(None, use_errno=True)
try:
    mount_setattr = libc.mount_setattr
except AttributeError:
    raise SystemExit(152)
libc.mount.argtypes = (
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
)
libc.mount.restype = ctypes.c_int
libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
libc.umount2.restype = ctypes.c_int
mount_setattr.argtypes = (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
    ctypes.POINTER(MountAttr),
    ctypes.c_size_t,
)
mount_setattr.restype = ctypes.c_int
libc.prctl.argtypes = (
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
)
libc.prctl.restype = ctypes.c_int
libc.syscall.restype = ctypes.c_long


def mount_call(source, target, filesystem, flags, data):
    encoded_source = None if source is None else os.fsencode(source)
    encoded_filesystem = None if filesystem is None else os.fsencode(filesystem)
    encoded_data = None if data is None else os.fsencode(data)
    if libc.mount(
        encoded_source,
        os.fsencode(target),
        encoded_filesystem,
        flags,
        encoded_data,
    ) != 0:
        raise SystemExit(153)


def set_mount_attributes(
    path, *, recursive, descriptor=None, readonly=None, nodev=None
):
    if readonly is None and nodev is None:
        raise SystemExit(154)
    attr_set = 0
    attr_clr = 0
    if readonly is True:
        attr_set |= MOUNT_ATTR_RDONLY
    elif readonly is False:
        attr_clr |= MOUNT_ATTR_RDONLY
    if nodev is True:
        attr_set |= MOUNT_ATTR_NODEV
    elif nodev is False:
        attr_clr |= MOUNT_ATTR_NODEV
    attributes = MountAttr(
        attr_set=attr_set,
        attr_clr=attr_clr,
        propagation=0,
        userns_fd=0,
    )
    flags = AT_RECURSIVE | AT_SYMLINK_NOFOLLOW if recursive else 0
    selected_descriptor = -100 if descriptor is None else descriptor
    selected_path = os.fsencode(path) if descriptor is None else b""
    if descriptor is not None:
        flags |= AT_EMPTY_PATH
    if mount_setattr(
        selected_descriptor,
        selected_path,
        flags,
        ctypes.byref(attributes),
        ctypes.sizeof(attributes),
    ) != 0:
        raise SystemExit(154)


def install_candidate_seccomp_filter():
    machine = os.uname().machine
    architecture = {
        "x86_64": (
            0xC000003E,
            56,
            72,
            302,
            (
                16, 41, 42, 43, 44, 45, 46, 47, 48,
                49, 50, 51, 52, 53, 54, 55,
                86, 160, 248, 249, 250, 265, 272, 288,
                299, 307, 308, 321, 425,
            ),
        ),
        "aarch64": (
            0xC00000B7,
            220,
            25,
            261,
            (
                29, 37, 97, 164, 198, 199, 200, 201, 202,
                203, 204, 205, 206, 207, 208, 209,
                210, 211, 212, 217, 218, 219, 242,
                243, 268, 269, 280, 425,
            ),
        ),
    }.get(machine)
    if architecture is None:
        raise SystemExit(152)
    (
        audit_arch,
        clone_syscall,
        fcntl_syscall,
        prlimit_syscall,
        denied_syscalls,
    ) = architecture
    filter_values = [
        SockFilter(BPF_LD_W_ABS, 0, 0, 4),
        SockFilter(BPF_JMP_JEQ_K, 1, 0, audit_arch),
        SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        SockFilter(BPF_LD_W_ABS, 0, 0, 0),
    ]
    if machine == "x86_64":
        filter_values.extend(
            (
                SockFilter(BPF_JMP_JSET_K, 0, 1, 0x40000000),
                SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
            )
        )
    filter_values.extend(
        (
            SockFilter(BPF_JMP_JEQ_K, 0, 3, clone_syscall),
            SockFilter(BPF_LD_W_ABS, 0, 0, 16),
            SockFilter(BPF_JMP_JSET_K, 0, 1, 0x7E020080),
            SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.EACCES),
            SockFilter(BPF_LD_W_ABS, 0, 0, 0),
            SockFilter(BPF_JMP_JEQ_K, 0, 1, 435),
            SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.ENOSYS),
            SockFilter(BPF_JMP_JEQ_K, 0, 3, fcntl_syscall),
            SockFilter(BPF_LD_W_ABS, 0, 0, 24),
            SockFilter(BPF_JMP_JEQ_K, 0, 1, 1036),
            SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.EACCES),
            SockFilter(BPF_LD_W_ABS, 0, 0, 0),
            # prlimit64 queries have a NULL new-limit pointer.  Reject either
            # nonzero half so the candidate cannot lower the exact CORE=1
            # sentinel or relax any other bootstrap limit.
            SockFilter(BPF_JMP_JEQ_K, 0, 5, prlimit_syscall),
            SockFilter(BPF_LD_W_ABS, 0, 0, 32),
            SockFilter(BPF_JMP_JEQ_K, 0, 2, 0),
            SockFilter(BPF_LD_W_ABS, 0, 0, 36),
            SockFilter(BPF_JMP_JEQ_K, 1, 0, 0),
            SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.EACCES),
            SockFilter(BPF_LD_W_ABS, 0, 0, 0),
        )
    )
    for denied_syscall in denied_syscalls:
        filter_values.extend(
            (
                SockFilter(BPF_JMP_JEQ_K, 0, 1, denied_syscall),
                SockFilter(
                    BPF_RET_K,
                    0,
                    0,
                    SECCOMP_RET_ERRNO | errno.EACCES,
                ),
            )
        )
    filter_values.append(SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    instructions = (SockFilter * len(filter_values))(*filter_values)
    program = SockFprog(len(instructions), instructions)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SystemExit(164)
    if (
        libc.prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            ctypes.addressof(program),
            0,
            0,
        )
        != 0
    ):
        raise SystemExit(164)


def prepare_candidate_landlock(descriptors, read_descriptors):
    # READ_FILE blocks direct reads from host-backed objects outside exact
    # parent-selected runtime roots.  Authorized runtime directories are an
    # explicit trust boundary whose target access is read/execute-only; a
    # trusted root/controller concurrently changing their contents is a
    # non-guarantee.  This is not a host-confidentiality boundary because
    # READ_DIR, metadata lookup, and readlink remain unhandled.
    if (
        ctypes.sizeof(LandlockRulesetAttr) != 16
        or ctypes.sizeof(LandlockPathBeneathAttr) != 12
    ):
        raise SystemExit(152)
    abi = libc.syscall(
        LANDLOCK_CREATE_RULESET,
        0,
        0,
        LANDLOCK_CREATE_RULESET_VERSION,
    )
    if abi < LANDLOCK_MINIMUM_ABI:
        raise SystemExit(165)
    ruleset = LandlockRulesetAttr(
        handled_access_fs=LANDLOCK_WRITE_ACCESS | LANDLOCK_ACCESS_FS_READ_FILE,
        handled_access_net=0,
    )
    ruleset_fd = libc.syscall(
        LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(ctypes.addressof(ruleset)),
        ctypes.sizeof(ruleset),
        0,
    )
    if ruleset_fd < 0:
        raise SystemExit(165)
    private_descriptors = []
    safe_device_descriptors = []
    namespace_read_descriptors = []
    try:
        o_path = getattr(os, "O_PATH", None)
        if type(o_path) is not int:
            raise SystemExit(152)
        flags = o_path | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        for path, _ in PRIVATE_SURFACES:
            private_descriptors.append(os.open(path, flags))
        private_descriptors.append(os.open("/dev/mqueue", flags))
        null_descriptor = os.open(
            "/dev/null", o_path | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        null_metadata = os.fstat(null_descriptor)
        if (
            not stat.S_ISCHR(null_metadata.st_mode)
            or os.major(null_metadata.st_rdev) != 1
            or os.minor(null_metadata.st_rdev) != 3
            or null_metadata.st_uid != 0
        ):
            os.close(null_descriptor)
            raise SystemExit(165)
        safe_device_descriptors.append(null_descriptor)
        namespace_read_descriptors.extend(open_namespace_read_descriptors())
        rules = (
            *(
                (
                    descriptor,
                    LANDLOCK_ROOT_WRITE_ACCESS | LANDLOCK_ACCESS_FS_READ_FILE,
                )
                for descriptor in descriptors
            ),
            *(
                (
                    descriptor,
                    LANDLOCK_WRITE_ACCESS | LANDLOCK_ACCESS_FS_READ_FILE,
                )
                for descriptor in private_descriptors
            ),
            *(
                (
                    descriptor,
                    LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE,
                )
                for descriptor in safe_device_descriptors
            ),
            *(
                (descriptor, LANDLOCK_ACCESS_FS_READ_FILE)
                for descriptor in read_descriptors
            ),
            *(
                (descriptor, LANDLOCK_ACCESS_FS_READ_FILE)
                for descriptor in namespace_read_descriptors
            ),
        )
        for descriptor, allowed_access in rules:
            rule = LandlockPathBeneathAttr(
                allowed_access=allowed_access,
                parent_fd=descriptor,
            )
            if (
                libc.syscall(
                    LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.c_void_p(ctypes.addressof(rule)),
                    0,
                )
                != 0
            ):
                raise SystemExit(165)
        return ruleset_fd
    except BaseException:
        os.close(ruleset_fd)
        raise
    finally:
        for descriptor in (
            *private_descriptors,
            *safe_device_descriptors,
            *namespace_read_descriptors,
        ):
            os.close(descriptor)


def activate_candidate_landlock(ruleset_fd):
    try:
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise SystemExit(165)
        if libc.syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
            raise SystemExit(165)
    finally:
        os.close(ruleset_fd)


def decode_mount_field(value):
    if type(value) is not str or not value:
        raise SystemExit(155)
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    decoded = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            decoded.append(value[index])
            index += 1
            continue
        escape = value[index + 1 : index + 4]
        if len(escape) != 3 or escape not in escapes:
            raise SystemExit(155)
        decoded.append(escapes[escape])
        index += 4
    decoded_value = "".join(decoded)
    if "\x00" in decoded_value:
        raise SystemExit(155)
    return decoded_value


def decode_mount_path(value):
    decoded_value = decode_mount_field(value)
    if not decoded_value.startswith("/"):
        raise SystemExit(155)
    components = decoded_value.split("/")
    if (
        (decoded_value != "/" and decoded_value.endswith("/"))
        or (
            decoded_value != "/"
            and any(
                component in ("", ".", "..")
                for component in components[1:]
            )
        )
        or os.path.normpath(decoded_value) != decoded_value
    ):
        raise SystemExit(155)
    return decoded_value


def mount_inventory():
    descriptor = os.open(
        "/proc/self/mountinfo",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, MOUNTINFO_LIMIT + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MOUNTINFO_LIMIT:
                raise SystemExit(155)
    finally:
        os.close(descriptor)
    try:
        text = b"".join(chunks).decode("utf-8", errors="surrogateescape")
    except UnicodeError:
        raise SystemExit(155)
    records = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise SystemExit(155)
        separator = fields.index("-")
        if separator < 6 or len(fields) != separator + 4:
            raise SystemExit(155)
        try:
            mount_id = int(fields[0])
            parent_id = int(fields[1])
            major_value, minor_value = fields[2].split(":", 1)
            major_minor = (int(major_value), int(minor_value))
        except ValueError:
            raise SystemExit(155)
        if (
            mount_id <= 0
            or parent_id <= 0
            or any(value < 0 for value in major_minor)
            or mount_id in records
        ):
            raise SystemExit(155)
        options = frozenset(fields[5].split(","))
        if ("ro" in options) == ("rw" in options):
            raise SystemExit(155)
        records[mount_id] = {
            "parent_id": parent_id,
            "major_minor": major_minor,
            # Filesystems may supply a custom show_path() representation for
            # this field.  It is retained as bounded opaque evidence and is
            # never interpreted as a source coordinate.
            "root": fields[3],
            "mountpoint": decode_mount_path(fields[4]),
            "options": options,
            "optional": tuple(fields[6:separator]),
            "filesystem": fields[separator + 1],
            "source": decode_mount_field(fields[separator + 2]),
            "super_options": frozenset(fields[separator + 3].split(",")),
        }
    if not records:
        raise SystemExit(155)
    visible_roots = {
        mount_id
        for mount_id, record in records.items()
        if record["parent_id"] == mount_id
        or record["parent_id"] not in records
    }
    if len(visible_roots) != 1:
        raise SystemExit(155)
    visible_root_id = next(iter(visible_roots))
    for mount_id in records:
        current_id = mount_id
        observed = set()
        while current_id != visible_root_id:
            if current_id not in records:
                raise SystemExit(155)
            if current_id in observed:
                raise SystemExit(155)
            observed.add(current_id)
            current_id = records[current_id]["parent_id"]
    return records


def path_at_or_below(path, root):
    try:
        return path == root or os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def validate_directory_mount_topology(
    path, mount_id, device, inventory, exit_code
):
    containing_record = inventory.get(mount_id)
    required_keys = {
        "parent_id",
        "major_minor",
        "root",
        "mountpoint",
        "options",
        "optional",
        "filesystem",
        "source",
        "super_options",
    }
    if containing_record is None:
        raise SystemExit(exit_code)
    for record in inventory.values():
        if (
            set(record) != required_keys
            or type(record.get("parent_id")) is not int
            or type(record.get("major_minor")) is not tuple
            or len(record["major_minor"]) != 2
            or any(type(value) is not int for value in record["major_minor"])
            or type(record.get("root")) is not str
            or type(record.get("mountpoint")) is not str
        ):
            raise SystemExit(155)
    containing_mountpoint = containing_record["mountpoint"]
    containing_major_minor = containing_record["major_minor"]
    if (
        type(device) is not int
        or containing_major_minor != (os.major(device), os.minor(device))
        or not path_at_or_below(path, containing_mountpoint)
    ):
        raise SystemExit(exit_code)
    same_filesystem_mount_ids = [
        candidate_id
        for candidate_id, record in inventory.items()
        if record["major_minor"] == containing_major_minor
    ]
    # mountinfo root is filesystem-defined (show_path), not a universal
    # source coordinate.  A unique visible record for this st_dev is the
    # filesystem-independent proof that no bind alias can inherit the rule.
    if same_filesystem_mount_ids != [mount_id]:
        raise SystemExit(exit_code)
    if containing_mountpoint == path:
        raise SystemExit(exit_code)
    for candidate_id, record in inventory.items():
        if (
            candidate_id != mount_id
            and path_at_or_below(record["mountpoint"], path)
        ):
            raise SystemExit(exit_code)


def descriptor_mount_id(descriptor):
    path = f"/proc/self/fdinfo/{descriptor}"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        data = os.read(fd, 4097)
    finally:
        os.close(fd)
    if len(data) > 4096:
        raise SystemExit(155)
    try:
        lines = data.decode("ascii").splitlines()
        values = [
            int(line.split()[1])
            for line in lines
            if line.startswith("mnt_id:")
        ]
    except (UnicodeError, IndexError, ValueError):
        raise SystemExit(155)
    if len(values) != 1:
        raise SystemExit(155)
    return values[0]


def seal_network_interface_descriptor(inventory, host_network_namespace):
    try:
        current_network_namespace = os.readlink("/proc/self/ns/net")
    except OSError as error:
        reject_mount_network_probe("namespace-read", error)
    if (
        re.fullmatch(r"net:\[[1-9][0-9]*\]", current_network_namespace) is None
        or current_network_namespace == host_network_namespace
    ):
        reject_mount_network_probe("namespace-identity")

    source_descriptor = None
    try:
        source_descriptor = os.open(
            "/proc/self/net/dev",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        if source_descriptor == NETWORK_INTERFACE_FD:
            reject_mount_network_probe("reserved-fd-reused")
        metadata = os.fstat(source_descriptor)
        status_flags = fcntl.fcntl(source_descriptor, fcntl.F_GETFL)
        try:
            mount_id = descriptor_mount_id(source_descriptor)
        except SystemExit:
            reject_mount_network_probe("proc-mount-id")
        record = inventory.get(mount_id)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or status_flags & os.O_ACCMODE != os.O_RDONLY
            or record is None
            or record["mountpoint"] != "/proc"
            or record["filesystem"] != "proc"
            or record["source"] != "proc"
            or "ro" not in record["options"]
            or record["major_minor"]
            != (os.major(metadata.st_dev), os.minor(metadata.st_dev))
        ):
            reject_mount_network_probe("proc-object")
        os.dup2(source_descriptor, NETWORK_INTERFACE_FD, inheritable=True)
        os.set_inheritable(NETWORK_INTERFACE_FD, True)
    except OSError as error:
        reject_mount_network_probe("proc-open", error)
    finally:
        if source_descriptor is not None and source_descriptor != NETWORK_INTERFACE_FD:
            try:
                os.close(source_descriptor)
            except OSError as error:
                reject_mount_network_probe("proc-source-close", error)

    try:
        sealed_metadata = os.fstat(NETWORK_INTERFACE_FD)
        sealed_status_flags = fcntl.fcntl(
            NETWORK_INTERFACE_FD, fcntl.F_GETFL
        )
        try:
            sealed_mount_id = descriptor_mount_id(NETWORK_INTERFACE_FD)
        except SystemExit:
            reject_mount_network_probe("sealed-mount-id")
        sealed_inheritable = os.get_inheritable(NETWORK_INTERFACE_FD)
    except OSError as error:
        reject_mount_network_probe("sealed-fd-check", error)
    if (
        sealed_mount_id != mount_id
        or not stat.S_ISREG(sealed_metadata.st_mode)
        or sealed_status_flags & os.O_ACCMODE != os.O_RDONLY
        or not sealed_inheritable
        or (
            sealed_metadata.st_dev,
            sealed_metadata.st_ino,
            sealed_metadata.st_mode,
        )
        != (metadata.st_dev, metadata.st_ino, metadata.st_mode)
    ):
        reject_mount_network_probe("sealed-fd-identity")


def validate_binding(document):
    if (
        type(document) is not dict
        or set(document) != {"path", "device", "inode"}
        or type(document.get("path")) is not str
        or type(document.get("device")) is not int
        or type(document.get("inode")) is not int
        or not os.path.isabs(document["path"])
    ):
        raise SystemExit(156)
    metadata = os.stat(document["path"], follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (document["device"], document["inode"])
    ):
        raise SystemExit(156)
    return document["path"]


def target_mode_allows(metadata, target_uid, target_gid, mask):
    shift = 6 if metadata.st_uid == target_uid else 3 if metadata.st_gid == target_gid else 0
    return ((metadata.st_mode >> shift) & mask) == mask


def read_root_component_document(path, metadata, kind):
    return {
        "path": path,
        "kind": kind,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "permissions": stat.S_IMODE(metadata.st_mode),
    }


def validate_read_root(document, inventory):
    required_keys = {
        "schema_version",
        "purpose",
        "kind",
        "path",
        "target_uid",
        "target_gid",
        "components",
    }
    if (
        type(document) is not dict
        or set(document) != required_keys
        or document.get("schema_version") != 1
        or READ_ROOT_PURPOSES.get(document.get("purpose"))
        != document.get("kind")
        or type(document.get("path")) is not str
        or not os.path.isabs(document["path"])
        or document["path"] == "/"
        or type(document.get("target_uid")) is not int
        or type(document.get("target_gid")) is not int
        or not 50000 <= document["target_uid"] <= 64999
        or document["target_uid"] != document["target_gid"]
        or type(document.get("components")) is not list
        or not document["components"]
    ):
        raise SystemExit(166)
    path = document["path"]
    if os.path.realpath(path) != path:
        raise SystemExit(166)
    expected_paths = ["/"]
    current_path = ""
    for component in path.split(os.sep)[1:]:
        if not component or component in (".", ".."):
            raise SystemExit(166)
        current_path = os.path.join(current_path, component)
        expected_paths.append(os.path.join("/", current_path))
    if len(document["components"]) != len(expected_paths):
        raise SystemExit(166)
    o_path = getattr(os, "O_PATH", None)
    if type(o_path) is not int:
        raise SystemExit(152)
    descriptors = []
    parent_descriptor = None
    try:
        for index, (component_path, expected) in enumerate(
            zip(expected_paths, document["components"])
        ):
            is_leaf = index == len(expected_paths) - 1
            expected_kind = document["kind"] if is_leaf else "directory"
            if (
                type(expected) is not dict
                or set(expected)
                != {
                    "path",
                    "kind",
                    "device",
                    "inode",
                    "uid",
                    "gid",
                    "permissions",
                }
                or expected.get("path") != component_path
                or expected.get("kind") != expected_kind
                or any(
                    type(expected.get(key)) is not int
                    for key in (
                        "device",
                        "inode",
                        "uid",
                        "gid",
                        "permissions",
                    )
                )
            ):
                raise SystemExit(166)
            flags = o_path | os.O_NOFOLLOW | os.O_CLOEXEC
            if expected_kind == "directory":
                flags |= os.O_DIRECTORY
            try:
                if index == 0:
                    descriptor = os.open("/", flags)
                    selected = os.stat("/", follow_symlinks=False)
                else:
                    name = component_path.rsplit(os.sep, 1)[1]
                    selected = os.stat(
                        name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            except FileNotFoundError:
                raise SystemExit(167)
            except OSError:
                raise SystemExit(168)
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            selected_kind = (
                "directory"
                if stat.S_ISDIR(opened.st_mode)
                else "file"
                if stat.S_ISREG(opened.st_mode)
                else None
            )
            if (
                selected_kind != expected_kind
                or (
                    stat.S_ISDIR(selected.st_mode)
                    if expected_kind == "directory"
                    else stat.S_ISREG(selected.st_mode)
                )
                is not True
                or (selected.st_dev, selected.st_ino)
                != (opened.st_dev, opened.st_ino)
                or read_root_component_document(
                    component_path, selected, expected_kind
                )
                != expected
                or read_root_component_document(
                    component_path, opened, expected_kind
                )
                != expected
            ):
                raise SystemExit(169)
            required_access = os.X_OK if expected_kind == "directory" else os.R_OK
            if (
                opened.st_uid == document["target_uid"]
                or not target_mode_allows(
                    opened,
                    document["target_uid"],
                    document["target_gid"],
                    required_access,
                )
                or target_mode_allows(
                    opened,
                    document["target_uid"],
                    document["target_gid"],
                    os.W_OK,
                )
                or (
                    expected_kind == "file"
                    and opened.st_mode & (stat.S_ISUID | stat.S_ISGID)
                )
            ):
                raise SystemExit(170)
            try:
                attributes = os.listxattr(f"/proc/self/fd/{descriptor}")
            except OSError:
                raise SystemExit(171)
            if {"system.posix_acl_access", "system.posix_acl_default"}.intersection(
                attributes
            ):
                raise SystemExit(170)
            parent_descriptor = descriptor
        leaf_descriptor = descriptors[-1]
        if document["kind"] == "directory" and inventory is not None:
            mount_id = descriptor_mount_id(leaf_descriptor)
            leaf_metadata = os.fstat(leaf_descriptor)
            validate_directory_mount_topology(
                path, mount_id, leaf_metadata.st_dev, inventory, 172
            )
        for descriptor in descriptors[:-1]:
            os.close(descriptor)
        return leaf_descriptor
    except BaseException:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def revalidate_held_read_root(document, held_descriptor):
    current_descriptor = validate_read_root(document, None)
    try:
        kind = document["kind"]
        path = document["path"]
        expected = document["components"][-1]
        held_metadata = os.fstat(held_descriptor)
        current_metadata = os.fstat(current_descriptor)
        held_kind = (
            "directory"
            if stat.S_ISDIR(held_metadata.st_mode)
            else "file"
            if stat.S_ISREG(held_metadata.st_mode)
            else None
        )
        current_kind = (
            "directory"
            if stat.S_ISDIR(current_metadata.st_mode)
            else "file"
            if stat.S_ISREG(current_metadata.st_mode)
            else None
        )
        if (
            held_kind != kind
            or current_kind != kind
            or read_root_component_document(path, held_metadata, kind) != expected
            or read_root_component_document(path, current_metadata, kind) != expected
            or (held_metadata.st_dev, held_metadata.st_ino)
            != (current_metadata.st_dev, current_metadata.st_ino)
        ):
            raise SystemExit(169)
    finally:
        os.close(current_descriptor)


def open_namespace_read_descriptors():
    o_path = getattr(os, "O_PATH", None)
    if type(o_path) is not int:
        raise SystemExit(152)
    descriptors = []
    observed = set()
    try:
        for path, kind in NAMESPACE_READ_PATHS:
            if path in observed:
                raise SystemExit(173)
            observed.add(path)
            flags = o_path | os.O_NOFOLLOW | os.O_CLOEXEC
            if kind == "directory":
                flags |= os.O_DIRECTORY
            descriptor = os.open(path, flags)
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            if not (
                stat.S_ISDIR(metadata.st_mode)
                if kind == "directory"
                else stat.S_ISREG(metadata.st_mode)
            ):
                raise SystemExit(173)
        return descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def private_surface_for(path):
    matches = [
        surface
        for surface, _ in PRIVATE_SURFACES
        if path != surface and os.path.commonpath((path, surface)) == surface
    ]
    return max(matches, key=len) if matches else None


def create_private_mountpoint(path, surface):
    relative = os.path.relpath(path, surface)
    if relative == "." or relative.startswith(".."):
        raise SystemExit(157)
    current = surface
    parts = relative.split(os.sep)
    for index, part in enumerate(parts):
        if not part or part in (".", ".."):
            raise SystemExit(157)
        current = os.path.join(current, part)
        try:
            os.mkdir(current, 0o700 if index == len(parts) - 1 else 0o711)
        except FileExistsError:
            pass
        metadata = os.stat(current, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_mode & 0o066
        ):
            raise SystemExit(157)


def write_ipc_sysctl(path, value):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        payload = value.encode("ascii")
        if os.write(descriptor, payload) != len(payload):
            raise SystemExit(158)
    finally:
        os.close(descriptor)
    descriptor = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        observed = os.read(descriptor, 129)
    finally:
        os.close(descriptor)
    try:
        observed_values = observed.decode("ascii").split()
    except UnicodeError:
        raise SystemExit(158)
    if len(observed) > 128 or observed_values != value.split():
        raise SystemExit(158)


def prove_directory_alias_rejection(inventory):
    source = "/tmp/required-ci-alias-probe-source"
    target = "/tmp/required-ci-alias-probe-target"
    if os.path.lexists(source) or os.path.lexists(target):
        raise SystemExit(174)
    os.mkdir(source, 0o700)
    os.mkdir(target, 0o700)
    descriptor = None
    mounted = False
    try:
        descriptor = os.open(source, root_flags)
        metadata = os.fstat(descriptor)
        source_mount_id = descriptor_mount_id(descriptor)
        validate_directory_mount_topology(
            source, source_mount_id, metadata.st_dev, inventory, 174
        )
        before_ids = set(inventory)
        mount_call(source, target, None, MS_BIND, None)
        mounted = True
        aliased_inventory = mount_inventory()
        created = set(aliased_inventory) - before_ids
        if (
            len(created) != 1
            or aliased_inventory[next(iter(created))]["mountpoint"] != target
        ):
            raise SystemExit(174)
        try:
            validate_directory_mount_topology(
                source,
                source_mount_id,
                metadata.st_dev,
                aliased_inventory,
                174,
            )
        except SystemExit as error:
            if error.code != 174:
                raise
        else:
            raise SystemExit(174)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if mounted and libc.umount2(os.fsencode(target), 0) != 0:
            raise SystemExit(174)
        os.rmdir(target)
        os.rmdir(source)
    restored_inventory = mount_inventory()
    if restored_inventory != inventory:
        raise SystemExit(174)
    return restored_inventory


mount_call(None, "/", None, MS_REC | MS_PRIVATE, None)
initial_inventory = mount_inventory()
if any(
    field.startswith(("shared:", "master:", "propagate_from:"))
    for record in initial_inventory.values()
    for field in record["optional"]
):
    raise SystemExit(158)

root_flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
o_path = getattr(os, "O_PATH", None)
if type(o_path) is not int:
    raise SystemExit(152)
root_flags |= o_path
source_descriptors = []
bound_descriptors = []
read_descriptors = []
binding_paths = []
landlock_ruleset_fd = None
safe_device_source_descriptor = None
safe_device_descriptor = None
safe_device_identity = None
safe_device_mount_id = None
original_cwd = os.getcwd()
try:
    for document in writable_roots:
        path = validate_binding(document)
        if path in binding_paths:
            raise SystemExit(156)
        if any(
            path == surface
            or os.path.commonpath((path, surface)) == path
            for surface, _ in PRIVATE_SURFACES
        ) or path in ("/dev", "/dev/mqueue"):
            raise SystemExit(156)
        descriptor = os.open(path, root_flags)
        metadata = os.fstat(descriptor)
        source_mount_id = descriptor_mount_id(descriptor)
        source_mount_record = initial_inventory.get(source_mount_id)
        # dev/ino bind the selected directory object.  The parent mount ID is
        # intentionally not compared after unshare: cloned mount objects
        # receive fresh IDs.  Full local mount roots, filesystem identities,
        # and parent links prove there is no bind alias or mounted subtree
        # through which the directory Landlock rule could expand.
        if (
            (metadata.st_dev, metadata.st_ino)
            != (document["device"], document["inode"])
            or source_mount_record is None
            or not (
                source_mount_record["mountpoint"] == path
                or os.path.commonpath(
                    (path, source_mount_record["mountpoint"])
                )
                == source_mount_record["mountpoint"]
            )
        ):
            raise SystemExit(156)
        validate_directory_mount_topology(
            path, source_mount_id, metadata.st_dev, initial_inventory, 156
        )
        source_descriptors.append(descriptor)
        binding_paths.append(path)
    if not any(
        original_cwd == path
        or os.path.commonpath((original_cwd, path)) == path
        for path in binding_paths
    ):
        raise SystemExit(156)

    # /usr/bin/unshare is an identity-bound trusted supervisor that shares
    # this mount namespace while waiting/signalling.  Concurrent mutation by
    # that trusted control-plane process is a non-guarantee; exact final
    # inventory and path/object revalidation below still close accidental
    # topology or pathname drift before Landlock activation.
    #
    # Validate and hold every host-backed directory read rule against the
    # cloned pre-mutation topology.  Later intentional writable self-binds may
    # share st_dev with system read roots; they are exact controller-created
    # mounts, not pre-existing aliases.  Path overlap checks ensure none can
    # cover or sit beneath a held read hierarchy before Landlock activation.
    read_paths = set()
    protected_surfaces = tuple(path for path, _ in PRIVATE_SURFACES) + (
        "/dev",
        "/dev/mqueue",
        "/dev/null",
    )
    for document in read_roots:
        path = document.get("path") if type(document) is dict else None
        if type(path) is not str or path in read_paths:
            raise SystemExit(166)
        read_paths.add(path)
        if any(
            path == writable_path
            or os.path.commonpath((path, writable_path)) == path
            or os.path.commonpath((path, writable_path)) == writable_path
            for writable_path in binding_paths
        ) or any(
            path == surface
            or os.path.commonpath((path, surface)) == path
            or os.path.commonpath((path, surface)) == surface
            for surface in protected_surfaces
        ):
            raise SystemExit(166)
        read_descriptors.append(validate_read_root(document, initial_inventory))

    safe_device_source_descriptor = os.open(
        "/dev/null", o_path | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    safe_device_metadata = os.fstat(safe_device_source_descriptor)
    if (
        not stat.S_ISCHR(safe_device_metadata.st_mode)
        or os.major(safe_device_metadata.st_rdev) != 1
        or os.minor(safe_device_metadata.st_rdev) != 3
        or safe_device_metadata.st_uid != 0
        or safe_device_metadata.st_gid != 0
        or stat.S_IMODE(safe_device_metadata.st_mode) != 0o666
    ):
        raise SystemExit(156)
    safe_device_identity = (
        safe_device_metadata.st_dev,
        safe_device_metadata.st_ino,
        safe_device_metadata.st_rdev,
        safe_device_metadata.st_uid,
        safe_device_metadata.st_gid,
        safe_device_metadata.st_mode,
    )

    for sysctl_path, value in IPC_SYSCTLS:
        write_ipc_sysctl(sysctl_path, value)

    set_mount_attributes("/", recursive=True, readonly=True, nodev=True)

    current_inventory = mount_inventory()
    private_mount_records = []
    for surface, options in PRIVATE_SURFACES:
        metadata = os.stat(surface, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(159)
        before_ids = set(current_inventory)
        mount_call(
            "required-ci-private",
            surface,
            "tmpfs",
            MS_NOSUID | MS_NODEV | MS_NOEXEC,
            options,
        )
        current_inventory = mount_inventory()
        created = set(current_inventory) - before_ids
        if len(created) != 1:
            raise SystemExit(159)
        mount_id = created.pop()
        record = current_inventory[mount_id]
        filesystem = os.statvfs(surface)
        byte_limit, inode_limit = PRIVATE_SURFACE_LIMITS[surface]
        if (
            record["mountpoint"] != surface
            or record["filesystem"] != "tmpfs"
            or record["source"] != "required-ci-private"
            or "rw" not in record["options"]
            or not {"nosuid", "nodev", "noexec"}.issubset(record["options"])
            or filesystem.f_frsize <= 0
            or filesystem.f_blocks <= 0
            or filesystem.f_blocks * filesystem.f_frsize > byte_limit
            or filesystem.f_files <= 0
            or filesystem.f_files > inode_limit
        ):
            raise SystemExit(159)
        private_mount_records.append((surface, mount_id))
    current_inventory = prove_directory_alias_rejection(current_inventory)
    os.mkdir("/run/lock", 0o1777)
    os.chmod("/run/lock", 0o1777)
    if not stat.S_ISDIR(os.stat("/dev/mqueue", follow_symlinks=False).st_mode):
        raise SystemExit(159)
    before_ids = set(current_inventory)
    mount_call(
        "mqueue",
        "/dev/mqueue",
        "mqueue",
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        None,
    )
    current_inventory = mount_inventory()
    created = set(current_inventory) - before_ids
    if len(created) != 1:
        raise SystemExit(159)
    mqueue_mount_id = created.pop()
    if (
        current_inventory[mqueue_mount_id]["mountpoint"] != "/dev/mqueue"
        or current_inventory[mqueue_mount_id]["filesystem"] != "mqueue"
        or current_inventory[mqueue_mount_id]["source"] != "mqueue"
        or "rw" not in current_inventory[mqueue_mount_id]["options"]
        or not {"nosuid", "nodev", "noexec"}.issubset(
            current_inventory[mqueue_mount_id]["options"]
        )
    ):
        raise SystemExit(159)
    private_mount_records.append(("/dev/mqueue", mqueue_mount_id))

    before_ids = set(current_inventory)
    mount_call(
        f"/proc/self/fd/{safe_device_source_descriptor}",
        "/dev/null",
        None,
        MS_BIND,
        None,
    )
    current_inventory = mount_inventory()
    created = set(current_inventory) - before_ids
    if len(created) != 1:
        raise SystemExit(159)
    safe_device_mount_id = created.pop()
    safe_device_descriptor = os.open(
        "/dev/null", o_path | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    safe_device_metadata = os.fstat(safe_device_descriptor)
    if (
        current_inventory[safe_device_mount_id]["mountpoint"] != "/dev/null"
        or descriptor_mount_id(safe_device_descriptor)
        != safe_device_mount_id
        or (
            safe_device_metadata.st_dev,
            safe_device_metadata.st_ino,
            safe_device_metadata.st_rdev,
            safe_device_metadata.st_uid,
            safe_device_metadata.st_gid,
            safe_device_metadata.st_mode,
        )
        != safe_device_identity
    ):
        raise SystemExit(159)
    set_mount_attributes(
        "",
        recursive=False,
        descriptor=safe_device_descriptor,
        nodev=False,
    )

    writable_mount_records = []
    for path, source_descriptor, document in zip(
        binding_paths, source_descriptors, writable_roots
    ):
        surface = private_surface_for(path)
        if surface is not None:
            create_private_mountpoint(path, surface)
        before_ids = set(current_inventory)
        mount_call(
            f"/proc/self/fd/{source_descriptor}",
            path,
            None,
            MS_BIND,
            None,
        )
        current_inventory = mount_inventory()
        created = set(current_inventory) - before_ids
        if len(created) != 1:
            raise SystemExit(160)
        mount_id = created.pop()
        bound_descriptor = os.open(path, root_flags)
        bound_descriptors.append(bound_descriptor)
        metadata = os.fstat(bound_descriptor)
        if (
            current_inventory[mount_id]["mountpoint"] != path
            or descriptor_mount_id(bound_descriptor) != mount_id
            or (metadata.st_dev, metadata.st_ino)
            != (document["device"], document["inode"])
        ):
            raise SystemExit(160)
        set_mount_attributes(
            "",
            recursive=False,
            descriptor=bound_descriptor,
            readonly=False,
        )
        writable_mount_records.append(
            (mount_id, path, bound_descriptor, document)
        )

    os.chdir(original_cwd)
    final_inventory = mount_inventory()
    exact_writable_ids = {
        mount_id for _, mount_id in private_mount_records
    } | {
        record[0] for record in writable_mount_records
    }
    observed_writable_ids = {
        mount_id
        for mount_id, record in final_inventory.items()
        if "rw" in record["options"]
    }
    expected_mount_ids = (
        set(initial_inventory)
        | exact_writable_ids
        | {safe_device_mount_id}
    )
    if (
        observed_writable_ids != exact_writable_ids
        or set(final_inventory) != expected_mount_ids
    ):
        raise SystemExit(161)
    if any(
        field.startswith(("shared:", "master:", "propagate_from:"))
        for record in final_inventory.values()
        for field in record["optional"]
    ):
        raise SystemExit(161)
    if (
        type(safe_device_mount_id) is not int
        or safe_device_descriptor is None
        or safe_device_identity is None
    ):
        raise SystemExit(161)
    safe_device_record = final_inventory.get(safe_device_mount_id)
    safe_device_metadata = os.fstat(safe_device_descriptor)
    if (
        safe_device_record is None
        or safe_device_record["mountpoint"] != "/dev/null"
        or "ro" not in safe_device_record["options"]
        or "nodev" in safe_device_record["options"]
        or descriptor_mount_id(safe_device_descriptor)
        != safe_device_mount_id
        or (
            safe_device_metadata.st_dev,
            safe_device_metadata.st_ino,
            safe_device_metadata.st_rdev,
            safe_device_metadata.st_uid,
            safe_device_metadata.st_gid,
            safe_device_metadata.st_mode,
        )
        != safe_device_identity
        or any(
            mount_id != safe_device_mount_id
            and "nodev" not in record["options"]
            for mount_id, record in final_inventory.items()
        )
    ):
        raise SystemExit(161)
    for path, mount_id in private_mount_records:
        descriptor = os.open(path, root_flags)
        try:
            record = final_inventory.get(mount_id)
            if (
                record is None
                or record["mountpoint"] != path
                or "rw" not in record["options"]
                or descriptor_mount_id(descriptor) != mount_id
                or (
                    path in PRIVATE_SURFACE_LIMITS
                    and (
                        record["filesystem"] != "tmpfs"
                        or record["source"] != "required-ci-private"
                        or not {"nosuid", "nodev", "noexec"}.issubset(
                            record["options"]
                        )
                    )
                )
                or (
                    path == "/dev/mqueue"
                    and (
                        record["filesystem"] != "mqueue"
                        or record["source"] != "mqueue"
                    )
                )
            ):
                raise SystemExit(161)
        finally:
            os.close(descriptor)
    for mount_id, path, descriptor, document in writable_mount_records:
        metadata = os.fstat(descriptor)
        record = final_inventory.get(mount_id)
        if (
            record is None
            or record["mountpoint"] != path
            or "rw" not in record["options"]
            or descriptor_mount_id(descriptor) != mount_id
            or (metadata.st_dev, metadata.st_ino)
            != (document["device"], document["inode"])
        ):
            raise SystemExit(161)
    for document, descriptor in zip(
        read_roots, read_descriptors, strict=True
    ):
        revalidate_held_read_root(document, descriptor)
    seal_network_interface_descriptor(
        final_inventory, host_network_namespace
    )
    landlock_ruleset_fd = prepare_candidate_landlock(
        tuple(bound_descriptors), tuple(read_descriptors)
    )
finally:
    for descriptor in (*bound_descriptors, *source_descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass
    for descriptor in read_descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass
    for descriptor in (
        safe_device_descriptor,
        safe_device_source_descriptor,
    ):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

if type(landlock_ruleset_fd) is not int or landlock_ruleset_fd < 0:
    raise SystemExit(165)
activate_candidate_landlock(landlock_ruleset_fd)
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
if resource.getrlimit(resource.RLIMIT_NOFILE) != (64, 64):
    raise SystemExit(162)

try:
    open_descriptors = set()
    for name in os.listdir("/proc/self/fd"):
        if not name.isdecimal() or int(name) <= 2:
            continue
        descriptor = int(name)
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        open_descriptors.add(descriptor)
except OSError:
    raise SystemExit(162)
standard_modes = tuple(os.fstat(descriptor).st_mode for descriptor in (0, 1, 2))
if (
    not stat.S_ISFIFO(standard_modes[0])
    or not stat.S_ISREG(standard_modes[1])
    or not stat.S_ISREG(standard_modes[2])
):
    raise SystemExit(162)
if open_descriptors != {readiness_fd, NETWORK_INTERFACE_FD}:
    raise SystemExit(162)
install_candidate_seccomp_filter()
try:
    if os.write(readiness_fd, b"G") != 1:
        raise SystemExit(163)
finally:
    os.close(readiness_fd)
os.execve(continuation_argv[0], continuation_argv, os.environ.copy())
'''.strip()
_CANDIDATE_BOOTSTRAP_SOURCE = r'''
import errno
import fcntl
import json
import os
import re
import stat
import sys

NETWORK_INTERFACE_FD = 63


def reject_network_probe(stage, error=None):
    error_number = getattr(error, "errno", None)
    suffix = (
        f":errno={error_number}"
        if type(error_number) is int and 0 <= error_number <= 4095
        else ""
    )
    print(
        f"strict candidate network probe rejected: stage={stage}{suffix}",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(127)


uid = int(sys.argv[1])
gid = int(sys.argv[2])
trusted_root = sys.argv[3]
trusted_sentinel = sys.argv[4]
host_parent_pid = int(sys.argv[5])
host_network_namespace = sys.argv[6]
try:
    network_interface_fd_value = sys.argv[7]
    network_interface_fd = int(network_interface_fd_value)
except (IndexError, ValueError):
    reject_network_probe("fd-number")
if network_interface_fd_value != str(network_interface_fd):
    reject_network_probe("fd-number")
runtime_binding_json = sys.argv[8]
configured_bootstrap_source = sys.argv[9]
candidate_argv = sys.argv[10:]


def candidate_open_descriptors():
    descriptors = set()
    try:
        names = os.listdir("/proc/self/fd")
    except OSError as error:
        reject_network_probe("fd-inventory", error)
    for name in names:
        if not name.isdecimal() or int(name) <= 2:
            continue
        descriptor = int(name)
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            reject_network_probe("fd-inventory-stat", error)
        descriptors.add(descriptor)
    return descriptors


def read_network_interfaces(descriptor):
    if type(descriptor) is not int or descriptor != NETWORK_INTERFACE_FD:
        reject_network_probe("fd-number")
    try:
        metadata = os.fstat(descriptor)
        status_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        inheritable = os.get_inheritable(descriptor)
    except OSError as error:
        reject_network_probe("fd-stat", error)
    if not stat.S_ISREG(metadata.st_mode):
        reject_network_probe("fd-type")
    if status_flags & os.O_ACCMODE != os.O_RDONLY or not inheritable:
        reject_network_probe("fd-access")
    if candidate_open_descriptors() != {NETWORK_INTERFACE_FD}:
        reject_network_probe("fd-inventory-before")
    data = bytearray()
    try:
        while True:
            chunk = os.read(descriptor, min(4096, 65537 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 65536:
                reject_network_probe("proc-size")
    except OSError as error:
        reject_network_probe("fd-read", error)
    finally:
        try:
            os.close(descriptor)
        except OSError as error:
            reject_network_probe("fd-close", error)
    if candidate_open_descriptors():
        reject_network_probe("fd-inventory-after")
    try:
        lines = bytes(data).decode("ascii").splitlines()
    except UnicodeDecodeError:
        reject_network_probe("proc-decode")
    if (
        len(lines) < 3
        or not lines[0].startswith("Inter-|")
        or not lines[1].lstrip().startswith("face |")
    ):
        reject_network_probe("proc-header")
    interfaces = set()
    for line in lines[2:]:
        name_field, separator, counters = line.partition(":")
        name = name_field.strip()
        values = counters.split()
        if (
            separator != ":"
            or not name
            or len(name) > 15
            or any(character.isspace() or character in "/:" for character in name)
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in name)
            or name in interfaces
            or len(values) != 16
            or any(not value.isdecimal() for value in values)
        ):
            reject_network_probe("proc-row")
        interfaces.add(name)
    return interfaces

status = {}
with open("/proc/self/status", encoding="ascii") as status_file:
    for line in status_file:
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()

if os.getpid() != 1:
    raise SystemExit(120)
try:
    os.setsid()
except OSError:
    raise SystemExit(120)
if tuple(map(int, status["Uid"].split())) != (uid, uid, uid, uid):
    raise SystemExit(121)
if tuple(map(int, status["Gid"].split())) != (gid, gid, gid, gid):
    raise SystemExit(122)
if status.get("Groups", "").split():
    raise SystemExit(123)
if status.get("NoNewPrivs") != "1":
    raise SystemExit(124)
if status.get("Seccomp") != "2":
    raise SystemExit(124)
try:
    seccomp_filters = int(status.get("Seccomp_filters", "0"))
except ValueError:
    raise SystemExit(124)
if seccomp_filters < 1:
    raise SystemExit(124)
for capability in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    if int(status.get(capability, "1"), 16) != 0:
        raise SystemExit(125)
if not os.path.isfile("/proc/1/status"):
    raise SystemExit(126)
try:
    current_network_namespace = os.readlink("/proc/self/ns/net")
except OSError as error:
    reject_network_probe("namespace-read", error)
if re.fullmatch(r"net:\[[1-9][0-9]*\]", host_network_namespace) is None:
    reject_network_probe("host-namespace-format")
if current_network_namespace == host_network_namespace:
    reject_network_probe("namespace-reused")
if re.fullmatch(r"net:\[[1-9][0-9]*\]", current_network_namespace) is None:
    reject_network_probe("current-namespace-format")
# The inherited sysfs mount remains tagged to the host network namespace.
# procfs generates this inventory from the current namespace instead.  A
# kernel that auto-creates fallback tunnel devices is unsupported here and
# fails closed rather than widening the candidate's network surface.
network_interfaces = read_network_interfaces(network_interface_fd)
if network_interfaces != {"lo"}:
    print(
        "strict candidate network interface inventory rejected: "
        + json.dumps(sorted(network_interfaces), separators=(",", ":")),
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(127)
try:
    os.kill(host_parent_pid, 0)
except ProcessLookupError:
    pass
else:
    raise SystemExit(128)
for operation in (
    lambda: open(trusted_sentinel, "rb"),
    lambda: open(trusted_sentinel, "ab"),
):
    try:
        operation()
    except PermissionError:
        pass
    else:
        raise SystemExit(129)
expected_limit_rows = {
    "Max address space": ("1073741824", "1073741824", "bytes"),
    "Max core file size": ("1", "1", "bytes"),
    "Max cpu time": ("20", "20", "seconds"),
    "Max file size": ("1048576", "1048576", "bytes"),
    "Max msgqueue size": ("8388608", "8388608", "bytes"),
    "Max open files": ("64", "64", "files"),
    "Max processes": ("64", "64", "processes"),
}
limits_descriptor = None
try:
    limits_descriptor = os.open(
        "/proc/self/limits",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    limits_bytes = os.read(limits_descriptor, 65537)
except OSError:
    raise SystemExit(130)
finally:
    if limits_descriptor is not None:
        os.close(limits_descriptor)
if not limits_bytes or len(limits_bytes) > 65536:
    raise SystemExit(130)
try:
    limit_lines = limits_bytes.decode("ascii").splitlines()
except UnicodeDecodeError:
    raise SystemExit(130)
observed_limit_rows = {}
for line in limit_lines:
    for label in expected_limit_rows:
        if line.startswith(label + " "):
            if label in observed_limit_rows:
                raise SystemExit(130)
            observed_limit_rows[label] = tuple(line[len(label) :].split())
if observed_limit_rows != expected_limit_rows:
    raise SystemExit(130)
runtime_binding = json.loads(runtime_binding_json)
if runtime_binding is None:
    os.execve(candidate_argv[0], candidate_argv, os.environ.copy())
required_binding_keys = {
    "schema_version",
    "target_uid",
    "target_gid",
    "selector",
    "resolved",
    "stdlib_selector",
    "stdlib_resolved",
    "version",
    "implementation",
    "selector_components",
    "stdlib_selector_components",
    "interpreter_components",
    "stdlib_components",
}
if (
    type(runtime_binding) is not dict
    or set(runtime_binding) != required_binding_keys
    or runtime_binding.get("schema_version") != 1
    or runtime_binding.get("target_uid") != uid
    or runtime_binding.get("target_gid") != gid
    or not candidate_argv
    or candidate_argv[0] != runtime_binding.get("resolved")
    or os.path.realpath(candidate_argv[0]) != runtime_binding.get("resolved")
    or os.path.realpath(runtime_binding.get("stdlib_selector", ""))
    != runtime_binding.get("stdlib_resolved")
):
    raise SystemExit(131)

def observed_document(expected):
    path = expected.get("path")
    if type(path) is not str or not os.path.isabs(path):
        raise SystemExit(132)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        raise SystemExit(133)
    except OSError:
        raise SystemExit(134)
    mode = metadata.st_mode
    if os.path.islink(path):
        selected_kind = "symlink"
        link_target = os.readlink(path)
    elif os.path.isdir(path):
        selected_kind = "directory"
        link_target = None
    elif os.path.isfile(path):
        selected_kind = "file"
        link_target = None
    else:
        raise SystemExit(135)
    document = {
        "path": path,
        "kind": selected_kind,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "link_target": link_target,
    }
    if selected_kind != "symlink":
        document.update(
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            permissions=mode & 0o7777,
        )
    return document

component_groups = (
    runtime_binding["selector_components"],
    runtime_binding["stdlib_selector_components"],
    runtime_binding["interpreter_components"],
    runtime_binding["stdlib_components"],
)
if any(type(group) is not list or not group for group in component_groups):
    raise SystemExit(136)
for group in component_groups:
    for expected in group:
        if type(expected) is not dict or observed_document(expected) != expected:
            raise SystemExit(137)

directory_paths = {
    expected["path"]
    for group in component_groups
    for expected in group
    if expected.get("kind") == "directory"
}
for selected in sorted(directory_paths):
    if not os.access(selected, os.X_OK) or os.access(selected, os.W_OK):
        raise SystemExit(138)
for selected, required_access in (
    (runtime_binding["selector"], os.X_OK),
    (runtime_binding["resolved"], os.X_OK),
    (runtime_binding["stdlib_selector"], os.R_OK),
    (runtime_binding["stdlib_resolved"], os.R_OK),
):
    if not os.access(selected, required_access) or os.access(selected, os.W_OK):
        raise SystemExit(139)
selected = runtime_binding["stdlib_resolved"]
try:
    descriptor = os.open(
        selected,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    os.read(descriptor, 1)
except OSError:
    raise SystemExit(140)
finally:
    try:
        os.close(descriptor)
    except (OSError, UnboundLocalError):
        pass
for selected in (
    runtime_binding["resolved"],
    runtime_binding["stdlib_resolved"],
):
    try:
        writable = os.open(selected, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EROFS):
            raise SystemExit(141)
    else:
        os.close(writable)
        raise SystemExit(142)
configured_argv = [
    runtime_binding["resolved"],
    "-I",
    "-B",
    "-S",
    "-c",
    configured_bootstrap_source,
    runtime_binding["resolved"],
    runtime_binding["stdlib_resolved"],
    runtime_binding["implementation"],
    *[str(value) for value in runtime_binding["version"]],
    str(len(os.environ)),
    *[
        f"{key}={value}"
        for key, value in sorted(os.environ.items())
    ],
    *candidate_argv,
]
os.execve(configured_argv[0], configured_argv, os.environ.copy())
'''.strip()

_ROOT_WRAPPER_SOURCE = r'''
import ctypes
import os
import signal
import sys

PR_SET_PDEATHSIG = 1
controller_pid = int(sys.argv[1])
controller_start_time = int(sys.argv[2])
barrier_fd = int(sys.argv[3])
unshare_argv = sys.argv[4:]
if controller_pid <= 1 or not unshare_argv:
    raise SystemExit(140)

def process_start_time(pid):
    try:
        stat_text = open(f"/proc/{pid}/stat", encoding="ascii").read()
        return int(stat_text.rsplit(")", 1)[1].split()[19])
    except (OSError, IndexError, ValueError):
        return None

if os.getppid() != controller_pid:
    raise SystemExit(141)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0) != 0:
    raise SystemExit(142)
if (
    os.getppid() != controller_pid
    or process_start_time(controller_pid) != controller_start_time
):
    raise SystemExit(144)
try:
    barrier = os.read(barrier_fd, 1)
finally:
    os.close(barrier_fd)
if barrier != b"G":
    raise SystemExit(143)
if (
    os.getppid() != controller_pid
    or process_start_time(controller_pid) != controller_start_time
):
    raise SystemExit(145)
os.execve(unshare_argv[0], unshare_argv, os.environ.copy())
'''.strip()

_REGISTERED_SUDO_WRAPPER_SOURCE = r'''
import ctypes
import errno
import os
import resource
import signal
import sys

PR_SET_PDEATHSIG = 1
PR_SET_CHILD_SUBREAPER = 36
parent_pid = int(sys.argv[1])
parent_start_time = int(sys.argv[2])
barrier_fd = int(sys.argv[3])
continuation_fd = int(sys.argv[4])
ready_fd = int(sys.argv[5])
output_limit = int(sys.argv[6])
outer_marker = sys.argv[7]
sudo_argv = sys.argv[8:]
if (
    parent_pid <= 1
    or output_limit <= 0
    or not outer_marker.startswith("required-ci-outer-")
    or len(outer_marker) != 50
    or not sudo_argv
):
    raise SystemExit(150)

def process_start_time(pid):
    try:
        stat_text = open(f"/proc/{pid}/stat", encoding="ascii").read()
        return int(stat_text.rsplit(")", 1)[1].split()[19])
    except (OSError, IndexError, ValueError):
        return None

def has_terminal():
    try:
        stat_text = open(f"/proc/{os.getpid()}/stat", encoding="ascii").read()
        tty_number = int(stat_text.rsplit(")", 1)[1].split()[4])
    except (OSError, IndexError, ValueError):
        return True
    if tty_number != 0 or any(os.isatty(descriptor) for descriptor in (0, 1, 2)):
        return True
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    try:
        tty_descriptor = os.open("/dev/tty", flags)
    except OSError as error:
        return error.errno not in (errno.ENXIO, errno.ENODEV, errno.ENOTTY)
    else:
        os.close(tty_descriptor)
        return True

if os.getppid() != parent_pid:
    raise SystemExit(151)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0) != 0:
    raise SystemExit(152)
if os.getppid() != parent_pid or process_start_time(parent_pid) != parent_start_time:
    raise SystemExit(153)
if has_terminal():
    raise SystemExit(164)
if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    raise SystemExit(156)
resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))
try:
    barrier = os.read(barrier_fd, 1)
finally:
    os.close(barrier_fd)
if barrier != b"G":
    raise SystemExit(154)
if libc.prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) != 0:
    raise SystemExit(157)
if os.getppid() != parent_pid or process_start_time(parent_pid) != parent_start_time:
    raise SystemExit(155)
try:
    ready_written = os.write(ready_fd, b"R")
finally:
    os.close(ready_fd)
if ready_written != 1:
    raise SystemExit(161)
try:
    continuation = os.read(continuation_fd, 1)
finally:
    os.close(continuation_fd)
if continuation != b"C":
    raise SystemExit(162)
if os.getppid() != parent_pid or process_start_time(parent_pid) != parent_start_time:
    raise SystemExit(163)
if has_terminal():
    raise SystemExit(165)
anchor_pid = os.getpid()
anchor_start_time = process_start_time(anchor_pid)
sudo_pid = os.fork()
if sudo_pid == 0:
    if libc.prctl(PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0) != 0:
        raise SystemExit(158)
    if (
        os.getppid() != anchor_pid
        or process_start_time(anchor_pid) != anchor_start_time
    ):
        raise SystemExit(159)
    os.execve(sudo_argv[0], sudo_argv, os.environ.copy())

sudo_status = None
while True:
    try:
        child_pid, child_status = os.waitpid(-1, 0)
    except InterruptedError:
        continue
    except ChildProcessError:
        break
    if child_pid == sudo_pid:
        sudo_status = child_status
if sudo_status is None:
    raise SystemExit(160)
sudo_returncode = os.waitstatus_to_exitcode(sudo_status)
raise SystemExit(
    sudo_returncode if sudo_returncode >= 0 else 128 - sudo_returncode
)
'''.strip()


def _enable_child_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(36, 1, 0, 0, 0)
    if result != 0:
        error_number = ctypes.get_errno()
        raise AssertionError(
            f"strict root controller cannot enable subreaper: errno {error_number}"
        )


def _bind_root_controller_parent() -> tuple[int, int, int, int]:
    parent_pid = os.getppid()
    if parent_pid <= 1:
        raise AssertionError("strict root controller has no live sudo parent")
    parent_identity = _process_identity(Path("/proc") / str(parent_pid))
    if parent_identity is None or parent_identity[5][1] != 0:
        raise AssertionError("strict root controller sudo parent is not privileged")
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(1, int(signal.SIGKILL), 0, 0, 0)
    if result != 0:
        error_number = ctypes.get_errno()
        raise AssertionError(
            f"strict root controller cannot bind parent death: errno {error_number}"
        )
    if (
        os.getppid() != parent_pid
        or _process_identity(Path("/proc") / str(parent_pid)) != parent_identity
    ):
        raise AssertionError("strict root controller sudo parent changed")
    return (
        parent_identity[0],
        parent_identity[1],
        parent_identity[3],
        parent_identity[4],
    )


def _root_chain_identity(pid: int) -> tuple[int, int, int, int]:
    identity = _process_identity(Path("/proc") / str(pid))
    if identity is None or identity[5] != (0, 0, 0, 0):
        raise AssertionError("strict root process identity is not root-owned")
    return identity[0], identity[1], identity[3], identity[4]


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise AssertionError("strict durable directory sync failed") from error


def _rename_noreplace(
    source: Path,
    destination: Path,
    *,
    published_callback: Callable[[], None] | None = None,
) -> None:
    if sys.platform == "linux":
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise AssertionError("strict atomic no-replace rename is unavailable")
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        if (
            renameat2(
                -100,
                os.fsencode(source),
                -100,
                os.fsencode(destination),
                1,
            )
            != 0
        ):
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise FileExistsError(error_number, os.strerror(error_number))
            raise OSError(error_number, os.strerror(error_number))
        if published_callback is not None:
            published_callback()
        return
    os.link(source, destination, follow_symlinks=False)
    if published_callback is not None:
        published_callback()
    source.unlink()


def _rename_directory_entry_noreplace(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    if (
        not source_name
        or source_name in (".", "..")
        or "/" in source_name
        or not destination_name
        or destination_name in (".", "..")
        or "/" in destination_name
    ):
        raise AssertionError("strict no-replace directory selector is unsafe")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise AssertionError("strict directory no-replace rename is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            source_directory_fd,
            os.fsencode(source_name),
            destination_directory_fd,
            os.fsencode(destination_name),
            1,
        )
        != 0
    ):
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise AssertionError(
                "strict sealed tombstone destination already exists"
            )
        raise AssertionError(
            "strict sealed tombstone no-replace rename failed"
        ) from OSError(error_number, os.strerror(error_number))


def _atomic_json_document(
    path: Path,
    document: Mapping[str, object],
    *,
    expected_owner: int,
    expected_file_owner: int | None = None,
    expected_file_group: int | None = None,
    expected_file_mode: int = 0o600,
    create: bool,
    published_callback: Callable[[], None] | None = None,
) -> None:
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise AssertionError("strict durable document directory is unreadable") from error
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != expected_owner
        or parent_metadata.st_mode & 0o077
    ):
        raise AssertionError("strict durable document directory is unsafe")
    if create and path.exists():
        raise AssertionError("strict durable document already exists")
    if (
        type(expected_file_mode) is not int
        or expected_file_mode & ~0o777
        or expected_file_mode & 0o027
    ):
        raise AssertionError("strict durable document mode is unsafe")
    data = json.dumps(
        dict(document), sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    if len(data) > 4096:
        raise AssertionError("strict durable document is excessive")
    temporary = parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
        )
        if expected_file_owner is not None or expected_file_group is not None:
            os.fchown(
                descriptor,
                -1 if expected_file_owner is None else expected_file_owner,
                -1 if expected_file_group is None else expected_file_group,
            )
        os.fchmod(descriptor, expected_file_mode)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = None
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if create and path.exists():
            raise AssertionError("strict durable document appeared during create")
        if create:
            try:
                _rename_noreplace(
                    temporary,
                    path,
                    published_callback=published_callback,
                )
            except FileExistsError as error:
                raise AssertionError(
                    "strict durable document appeared during create"
                ) from error
        else:
            os.replace(temporary, path)
        _fsync_directory(parent)
        metadata = path.lstat()
        selected_file_owner = (
            expected_owner
            if expected_file_owner is None
            else expected_file_owner
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != selected_file_owner
            or (
                expected_file_group is not None
                and metadata.st_gid != expected_file_group
            )
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != expected_file_mode
        ):
            raise AssertionError("strict durable document identity is unsafe")
    except OSError as error:
        raise AssertionError("strict durable document cannot be written") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _write_root_controller_handshake(
    path: Path,
    *,
    nonce: str,
    session_id: str,
    target_uid: int,
    sudo_parent: tuple[int, int, int, int],
    wrapper: tuple[int, int, int, int] | None,
) -> None:
    metadata = path.lstat()
    parent_metadata = path.parent.lstat()
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != 0
        or parent_metadata.st_mode & 0o077
    ):
        raise AssertionError("strict root controller handshake path is unsafe")
    controller = _root_chain_identity(os.getpid())
    document = {
        "schema_version": 2,
        "phase": "controller-bound" if wrapper is None else "wrapper-bound",
        "nonce": nonce,
        "session_id": session_id,
        "target_uid": target_uid,
        "controller": list(controller),
        "sudo_parent": list(sudo_parent),
        "wrapper": None if wrapper is None else list(wrapper),
    }
    _atomic_json_document(path, document, expected_owner=0, create=False)


def _read_root_controller_handshake(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise AssertionError(
            "strict root controller handshake is unreadable"
        ) from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or len(data) > 4096
    ):
        raise AssertionError("strict root controller handshake identity is unsafe")
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(
            "strict root controller handshake is malformed"
        ) from error
    if type(document) is not dict:
        raise AssertionError("strict root controller handshake is not a document")
    return document


def _assert_root_completion_sentinel(
    path: Path, nonce: str, owner_uid: int
) -> None:
    try:
        parent_metadata = path.parent.lstat()
        metadata = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise AssertionError(
            "strict root active completion sentinel is unreadable"
        ) from error
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != owner_uid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or data != f"armed:{nonce}".encode("ascii")
    ):
        raise AssertionError("strict root active completion sentinel is unsafe")


def _mark_root_active_completed(path: Path, nonce: str, owner_uid: int) -> None:
    _assert_root_completion_sentinel(path, nonce, owner_uid)
    descriptor: int | None = None
    payload = f"completed:{nonce}".encode("ascii")
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise AssertionError(
                "strict root active completion sentinel changed"
            )
        os.ftruncate(descriptor, 0)
        if os.write(descriptor, payload) != len(payload):
            raise AssertionError(
                "strict root active completion sentinel write was incomplete"
            )
        os.fsync(descriptor)
    except OSError as error:
        raise AssertionError(
            "strict root active completion sentinel cannot be written"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _wait_root_target_active(
    stdout_path: Path,
    *,
    nonce: str,
    target_uid: int,
    wrapper: tuple[int, int, int, int, int, tuple[int, int, int, int]],
) -> tuple[dict[str, object], tuple[int, int, int, int, int, tuple[int, int, int, int]]]:
    expected_prefix = _TARGET_ACTIVE_MARKER_PREFIX.encode("ascii")
    deadline = time.monotonic() + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            data = stdout_path.read_bytes()
        except OSError as error:
            raise AssertionError(
                "strict target-active marker is unreadable"
            ) from error
        if len(data) > 4096:
            raise AssertionError("strict target-active marker is excessive")
        if not data or b"\n" not in data:
            time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
            continue
        if not data.startswith(expected_prefix) or data.count(b"\n") != 1:
            raise AssertionError("strict target-active marker framing is malformed")
        try:
            marker = json.loads(data[len(expected_prefix) :])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AssertionError("strict target-active marker is malformed") from error
        expected_marker = {
            "schema_version": 1,
            "nonce": nonce,
            "uid": target_uid,
            "gid": target_uid,
        }
        if marker != expected_marker:
            raise AssertionError("strict target-active marker binding is inexact")
        inventory = _candidate_uid_inventory(target_uid)
        if len(inventory) != 1:
            raise AssertionError(
                "strict target-active UID inventory is not singular"
            )
        target_pid, target_start = next(iter(inventory))
        target = _process_identity(Path("/proc") / str(target_pid))
        if (
            target is None
            or target[1] != target_start
            or target[2] != wrapper[0]
            or target[0] != target[3]
            or target[0] != target[4]
            or target[5] != (target_uid,) * 4
        ):
            raise AssertionError("strict target-active ancestry is invalid")
        return marker, target
    raise AssertionError("strict target-active marker timed out")


def _publish_root_target_active(document: Mapping[str, object]) -> None:
    print(
        _ROOT_TARGET_ACTIVE_PREFIX
        + json.dumps(dict(document), sort_keys=True, separators=(",", ":")),
        flush=True,
    )


def _root_reap_children() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def _same_process_identity(identity: tuple[int, int], target_uid: int) -> bool:
    pid, start_time = identity
    observed = _proc_identity(Path("/proc") / str(pid), target_uid)
    return observed == (pid, start_time)


def _root_signal_identity(
    identity: tuple[int, int], target_uid: int, selected_signal: int
) -> None:
    try:
        descriptor = os.pidfd_open(identity[0], 0)
    except ProcessLookupError:
        return
    try:
        if not _same_process_identity(identity, target_uid):
            return
        signal.pidfd_send_signal(descriptor, selected_signal, None, 0)
    except ProcessLookupError:
        pass
    finally:
        os.close(descriptor)


def _root_close_candidate_realm(target_uid: int) -> set[tuple[int, int]]:
    observed: set[tuple[int, int]] = set()
    deadline = time.monotonic() + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS
    zero_count = 0
    sent_term = False
    sent_kill = False
    while time.monotonic() < deadline:
        _root_reap_children()
        inventory = _candidate_uid_inventory(target_uid)
        if not inventory:
            zero_count += 1
            if zero_count >= _STRICT_ZERO_SCAN_COUNT:
                return observed
            time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
            continue
        zero_count = 0
        observed.update(inventory)
        selected_signal = signal.SIGTERM if not sent_term else signal.SIGKILL
        if sent_term:
            sent_kill = True
        else:
            sent_term = True
        for identity in sorted(inventory):
            _root_signal_identity(identity, target_uid, selected_signal)
        time.sleep(0.1 if not sent_kill else 0.05)
    survivors = _candidate_uid_inventory(target_uid)
    if survivors:
        raise AssertionError(
            "strict root controller could not close the candidate UID realm"
        )
    raise AssertionError(
        "strict root controller could not prove repeated zero process inventory"
    )


def _host_session_inventory(
    session_id: int,
) -> dict[int, tuple[int, int, int, int, int, tuple[int, int, int, int]]]:
    if session_id <= 1:
        raise AssertionError("strict registered host session identity is unsafe")
    try:
        entries = sorted(
            (entry for entry in Path("/proc").iterdir() if entry.name.isdecimal()),
            key=lambda entry: int(entry.name),
        )
    except OSError as error:
        raise AssertionError("strict host session inventory is unavailable") from error
    inventory: dict[
        int, tuple[int, int, int, int, int, tuple[int, int, int, int]]
    ] = {}
    for entry in entries:
        identity = _process_identity(entry)
        if identity is not None and identity[4] == session_id:
            inventory[identity[0]] = identity
    return inventory


def _root_signal_host_identity(
    expected: tuple[int, int, int, int, int, tuple[int, int, int, int]],
    selected_signal: int,
) -> None:
    try:
        descriptor = os.pidfd_open(expected[0], 0)
    except ProcessLookupError:
        return
    try:
        observed = _process_identity(Path("/proc") / str(expected[0]))
        if observed != expected:
            return
        signal.pidfd_send_signal(descriptor, selected_signal, None, 0)
    except ProcessLookupError:
        pass
    finally:
        os.close(descriptor)


def _registered_anchor_is_terminal(
    outer: tuple[int, int, int, int]
) -> bool:
    try:
        descriptor = os.pidfd_open(outer[0], 0)
    except ProcessLookupError:
        return False
    try:
        observed = _process_identity(Path("/proc") / str(outer[0]))
        if (
            observed is None
            or observed[1] != outer[1]
            or observed[3] != outer[2]
            or observed[4] != outer[3]
        ):
            return False
        readable, _, _ = select.select([descriptor], [], [], 0)
        return bool(readable)
    finally:
        os.close(descriptor)


def _root_close_registered_host_session(
    outer: tuple[int, int, int, int]
) -> int:
    session_id = outer[3]
    deadline = time.monotonic() + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS
    observed: set[tuple[int, int]] = set()
    zero_count = 0
    generation_was_anchored = _assert_registered_session_not_reused(outer)
    zero_was_observed = False
    while time.monotonic() < deadline:
        inventory = _host_session_inventory(session_id)
        inventory.pop(os.getpid(), None)
        if not inventory:
            zero_was_observed = True
            zero_count += 1
            if zero_count >= _STRICT_ZERO_SCAN_COUNT:
                return len(observed)
            time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
            continue
        if zero_was_observed:
            raise AssertionError(
                "strict registered host session reappeared after zero inventory"
            )
        if not generation_was_anchored:
            raise AssertionError(
                "strict registered host session lost its generation anchor"
            )
        current_leader = _process_identity(Path("/proc") / str(outer[0]))
        if current_leader is None:
            raise AssertionError(
                "strict registered host session lost its generation anchor"
            )
        if (
            current_leader[1] != outer[1]
            or current_leader[3] != outer[2]
            or current_leader[4] != outer[3]
        ):
            raise AssertionError("strict registered host session identity was reused")
        zero_count = 0
        nonleaders = [
            identity
            for identity in inventory.values()
            if identity[0] != outer[0]
        ]
        for identity in nonleaders:
            observed.add((identity[0], identity[1]))
            _root_signal_host_identity(identity, signal.SIGKILL)
        if not nonleaders:
            _root_signal_host_identity(current_leader, signal.SIGCONT)
            if _registered_anchor_is_terminal(outer):
                return len(observed)
        time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
    raise AssertionError("strict registered host session could not be closed")


def _assert_registered_session_not_reused(
    outer: tuple[int, int, int, int]
) -> bool:
    observed = _process_identity(Path("/proc") / str(outer[0]))
    if observed is None:
        return False
    if (
        observed[1] != outer[1]
        or observed[3] != outer[2]
        or observed[4] != outer[3]
    ):
        raise AssertionError("strict registered host session identity was reused")
    return True


def _read_root_bounded_output(path: Path, description: str) -> bytes:
    try:
        size = path.stat().st_size
        data = path.read_bytes()
    except OSError as error:
        raise AssertionError(
            f"strict root controller cannot read candidate {description}"
        ) from error
    if size != len(data) or size > CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES:
        raise AssertionError(
            f"strict root controller candidate {description} is incomplete or excessive"
        )
    return data


def _root_controller_candidate_command(
    config: dict[str, object], host_parent_pid: int, mount_readiness_fd: int
) -> list[str]:
    uid = config.get("uid")
    gid = config.get("gid")
    environment = config.get("environment")
    candidate_argv = config.get("candidate_argv")
    runtime_binding = config.get("candidate_interpreter")
    if (
        type(uid) is not int
        or type(gid) is not int
        or type(environment) is not dict
        or type(candidate_argv) is not list
        or not candidate_argv
        or any(type(item) is not str for item in candidate_argv)
        or any(type(key) is not str or type(value) is not str for key, value in environment.items())
    ):
        raise AssertionError("strict root controller configuration is malformed")
    trusted_root = config.get("trusted_root")
    trusted_sentinel = config.get("trusted_sentinel")
    host_mount_namespace = config.get("host_mount_namespace")
    host_ipc_namespace = config.get("host_ipc_namespace")
    host_network_namespace = config.get("host_network_namespace")
    if (
        type(trusted_root) is not str
        or type(trusted_sentinel) is not str
        or type(mount_readiness_fd) is not int
        or mount_readiness_fd <= 2
        or type(host_mount_namespace) is not str
        or re.fullmatch(r"mnt:\[[1-9][0-9]*\]", host_mount_namespace) is None
        or type(host_ipc_namespace) is not str
        or re.fullmatch(r"ipc:\[[1-9][0-9]*\]", host_ipc_namespace) is None
        or type(host_network_namespace) is not str
        or re.fullmatch(r"net:\[[1-9][0-9]*\]", host_network_namespace) is None
    ):
        raise AssertionError("strict root controller trusted boundary is malformed")
    writable_root_bindings = _revalidate_strict_writable_root_bindings(
        config.get("writable_roots")
    )
    read_root_bindings = _revalidate_strict_host_read_root_bindings(
        config.get("read_roots")
    )
    bootstrap_nofile = _strict_bootstrap_nofile_requirement(
        writable_root_bindings, read_root_bindings
    )
    _assert_strict_bootstrap_nofile_capacity(bootstrap_nofile)
    if any(
        binding["target_uid"] != uid or binding["target_gid"] != gid
        for binding in read_root_bindings
    ):
        raise AssertionError(
            "strict root controller read root target identity changed"
        )
    writable_paths = [
        Path(str(binding["path"])) for binding in writable_root_bindings
    ]
    for binding in read_root_bindings:
        read_path = Path(str(binding["path"]))
        if any(
            read_path == writable_path
            or read_path in writable_path.parents
            or writable_path in read_path.parents
            for writable_path in writable_paths
        ):
            raise AssertionError(
                "strict root controller read and writable roots overlap"
            )
    if (
        _strict_host_namespace_identity("mnt") != host_mount_namespace
        or _strict_host_namespace_identity("ipc") != host_ipc_namespace
        or _strict_host_namespace_identity("net") != host_network_namespace
    ):
        raise AssertionError(
            "strict root controller host namespace identity changed"
        )
    if runtime_binding is not None:
        runtime_binding = _revalidate_configured_candidate_interpreter(
            runtime_binding
        )
        if (
            runtime_binding["target_uid"] != uid
            or runtime_binding["target_gid"] != gid
        ):
            raise AssertionError(
                "strict root controller configured interpreter target identity changed"
            )
        if candidate_argv[0] != runtime_binding["resolved"]:
            raise AssertionError(
                "strict root controller configured interpreter identity changed"
            )
    elif candidate_argv[0] != str(_STRICT_PRIMITIVES["python"]):
        raise AssertionError(
            "strict root controller system interpreter identity changed"
        )
    runtime_binding_json = json.dumps(
        runtime_binding, sort_keys=True, separators=(",", ":")
    )
    environment_arguments = [
        f"{key}={value}" for key, value in sorted(environment.items())
    ]
    # Host mount IDs fence topology before unshare.  A cloned mount tree gets
    # new IDs, so the namespace bootstrap receives only stable object identity
    # and derives its own local mount IDs from held O_PATH descriptors.
    namespace_writable_roots = [
        {
            "path": binding["path"],
            "device": binding["device"],
            "inode": binding["inode"],
        }
        for binding in writable_root_bindings
    ]
    writable_root_json = json.dumps(
        namespace_writable_roots, sort_keys=True, separators=(",", ":")
    )
    namespace_read_roots = [
        {
            key: value
            for key, value in binding.items()
            if key != "host_mount_id"
        }
        for binding in read_root_bindings
    ]
    read_root_json = json.dumps(
        namespace_read_roots, sort_keys=True, separators=(",", ":")
    )
    bootstrap_arguments = [
        str(uid),
        str(gid),
        trusted_root,
        trusted_sentinel,
        str(host_parent_pid),
        host_network_namespace,
        str(_STRICT_NETWORK_INTERFACE_FD),
        runtime_binding_json,
        _CONFIGURED_RUNTIME_BOOTSTRAP_SOURCE,
        *candidate_argv,
    ]
    return [
        str(_STRICT_PRIMITIVES["unshare"]),
        "--fork",
        "--pid",
        "--mount",
        "--mount-proc",
        "--ipc",
        "--net",
        "--propagation",
        "private",
        "--kill-child=SIGKILL",
        str(_STRICT_PRIMITIVES["python"]),
        *_ROOT_PYTHON_ARGUMENTS,
        "-c",
        _MOUNT_NAMESPACE_BOOTSTRAP_SOURCE,
        str(mount_readiness_fd),
        str(bootstrap_nofile),
        host_mount_namespace,
        host_ipc_namespace,
        host_network_namespace,
        writable_root_json,
        read_root_json,
        str(_STRICT_PRIMITIVES["setpriv"]),
        f"--reuid={uid}",
        f"--regid={gid}",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "--pdeathsig=keep",
        str(_STRICT_PRIMITIVES["env"]),
        "-i",
        *environment_arguments,
        str(_STRICT_PRIMITIVES["python"]),
        *_ROOT_PYTHON_ARGUMENTS,
        "-c",
        _CANDIDATE_BOOTSTRAP_SOURCE,
        *bootstrap_arguments,
    ]


def _root_wrapper_command(
    config: dict[str, object],
    controller_identity: tuple[int, int, int, int],
    barrier_fd: int,
    mount_readiness_fd: int,
) -> list[str]:
    return [
        str(_STRICT_PRIMITIVES["python"]),
        *_ROOT_PYTHON_ARGUMENTS,
        "-c",
        _ROOT_WRAPPER_SOURCE,
        str(controller_identity[0]),
        str(controller_identity[1]),
        str(barrier_fd),
        *_root_controller_candidate_command(
            config, controller_identity[0], mount_readiness_fd
        ),
    ]


def _release_wrapper_barrier(barrier_fd: int) -> None:
    try:
        if os.write(barrier_fd, b"G") != 1:
            raise AssertionError("strict root wrapper barrier write was incomplete")
    except OSError as error:
        raise AssertionError("strict root wrapper barrier cannot be released") from error
    finally:
        os.close(barrier_fd)


def _wait_mount_namespace_ready(
    readiness_fd: int,
    wrapper_pidfd: int,
    *,
    timeout_seconds: float = _STRICT_WATCHDOG_TIMEOUT_SECONDS,
) -> None:
    if (
        type(readiness_fd) is not int
        or readiness_fd <= 2
        or type(wrapper_pidfd) is not int
        or wrapper_pidfd <= 2
        or type(timeout_seconds) not in (int, float)
        or timeout_seconds <= 0
    ):
        raise AssertionError("strict mount namespace readiness gate is malformed")
    readable, _, _ = select.select(
        [readiness_fd, wrapper_pidfd], [], [], float(timeout_seconds)
    )
    if readiness_fd in readable:
        try:
            marker = os.read(readiness_fd, 2)
        except OSError as error:
            raise AssertionError(
                "strict mount namespace readiness marker is unreadable"
            ) from error
        if marker != b"G":
            raise AssertionError(
                "strict mount namespace bootstrap did not become ready"
            )
        return
    if wrapper_pidfd in readable:
        raise AssertionError(
            "strict mount namespace bootstrap exited before readiness"
        )
    raise AssertionError("strict mount namespace bootstrap readiness timed out")


def _signal_process_pidfd(descriptor: int, selected_signal: int) -> None:
    try:
        signal.pidfd_send_signal(descriptor, selected_signal, None, 0)
    except ProcessLookupError:
        pass


def _root_controller_main(config_value: str) -> int:
    nonce = "unknown"
    process: subprocess.Popen[bytes] | None = None
    target_uid: int | None = None
    output_directory: tempfile.TemporaryDirectory[str] | None = None
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    returncode: int | None = None
    timed_out = False
    observed: set[tuple[int, int]] = set()
    failure: BaseException | None = None
    wrapper_pidfd: int | None = None
    barrier_read_fd: int | None = None
    barrier_write_fd: int | None = None
    mount_readiness_read_fd: int | None = None
    mount_readiness_write_fd: int | None = None
    active_probe: tuple[
        Path,
        int,
        tuple[int, int, int, int, int, tuple[int, int, int, int]],
    ] | None = None
    active_owner_pidfd: int | None = None
    active_published = False
    try:
        if os.geteuid() != 0 or os.getuid() != 0:
            raise AssertionError("strict root controller did not start as root")
        _probe_pidfd_capability()
        sudo_parent = _bind_root_controller_parent()
        sudo_parent_identity = _process_identity(
            Path("/proc") / str(sudo_parent[0])
        )
        if (
            sudo_parent_identity is None
            or _registered_process_binding(sudo_parent_identity)
            != list(sudo_parent)
        ):
            raise AssertionError(
                "strict root controller sudo parent identity changed"
            )
        _enable_child_subreaper()
        config_path = Path(config_value)
        config_metadata = config_path.lstat()
        if (
            not config_path.is_absolute()
            or not stat.S_ISREG(config_metadata.st_mode)
            or config_metadata.st_uid != 0
            or config_metadata.st_nlink != 1
            or config_metadata.st_mode & 0o077
        ):
            raise AssertionError("strict root controller config is not root-only")
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if type(config) is not dict or config.get("schema_version") != 2:
            raise AssertionError("strict root controller config schema is invalid")
        nonce_value = config.get("nonce")
        if type(nonce_value) is not str or not nonce_value:
            raise AssertionError("strict root controller nonce is invalid")
        nonce = nonce_value
        session_id = config.get("session_id")
        if type(session_id) is not str or re.fullmatch(r"[0-9a-f]{32}", session_id) is None:
            raise AssertionError("strict root controller session identity is invalid")
        uid = config.get("uid")
        handshake_value = config.get("handshake_path")
        timeout_value = config.get("timeout_seconds")
        fault_point = config.get("trusted_fault_point")
        active_probe_value = config.get("trusted_active_probe")
        cwd_value = config.get("cwd")
        if type(uid) is not int or type(timeout_value) not in (int, float):
            raise AssertionError("strict root controller limits are malformed")
        if fault_point not in (
            None,
            "after-wrapper-popen-before-handshake-sigkill",
            "after-wrapper-popen-before-handshake-sigstop",
            "after-wrapper-bound-before-barrier-sigkill",
            "after-wrapper-bound-before-barrier-sigstop",
        ):
            raise AssertionError("strict root controller fault point is invalid")
        if active_probe_value is not None:
            if (
                type(active_probe_value) is not dict
                or set(active_probe_value)
                != {
                    "schema_version",
                    "nonce",
                    "completion_sentinel",
                    "owner_uid",
                    "owner_identity",
                }
                or active_probe_value.get("schema_version") != 1
                or active_probe_value.get("nonce") != nonce
                or type(active_probe_value.get("completion_sentinel"))
                is not str
                or type(active_probe_value.get("owner_uid")) is not int
                or int(active_probe_value["owner_uid"]) < 0
            ):
                raise AssertionError(
                    "strict root controller active probe is malformed"
                )
            completion_sentinel = Path(
                str(active_probe_value["completion_sentinel"])
            )
            if not completion_sentinel.is_absolute():
                raise AssertionError(
                    "strict root controller active sentinel is relative"
                )
            active_probe = (
                completion_sentinel,
                int(active_probe_value["owner_uid"]),
                _parse_process_identity_document(
                    active_probe_value.get("owner_identity"),
                    "active owner",
                ),
            )
            if (
                active_probe[2][0] != active_probe[2][3]
                or active_probe[2][0] != active_probe[2][4]
                or active_probe[2][5] != (active_probe[1],) * 4
            ):
                raise AssertionError(
                    "strict root controller active owner is invalid"
                )
            active_owner_pidfd = os.pidfd_open(active_probe[2][0], 0)
            if (
                _process_identity(
                    Path("/proc") / str(active_probe[2][0])
                )
                != active_probe[2]
            ):
                raise AssertionError(
                    "strict root controller active owner changed"
                )
            _assert_root_completion_sentinel(
                active_probe[0], nonce, active_probe[1]
            )
        target_uid = uid
        if type(handshake_value) is not str:
            raise AssertionError("strict root controller handshake selector is malformed")
        handshake_path = Path(handshake_value)
        _write_root_controller_handshake(
            handshake_path,
            nonce=nonce,
            session_id=session_id,
            target_uid=uid,
            sudo_parent=sudo_parent,
            wrapper=None,
        )
        if type(cwd_value) is not str or not Path(cwd_value).is_absolute():
            raise AssertionError("strict root controller cwd is malformed")
        if _candidate_uid_inventory(uid):
            raise AssertionError("strict candidate UID realm is occupied before launch")
        input_bytes = sys.stdin.buffer.read(CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES + 1)
        if len(input_bytes) > CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES:
            raise AssertionError("candidate stdin exceeds its fixed limit")
        controller_identity = _root_chain_identity(os.getpid())
        controller_process_identity = _process_identity(
            Path("/proc") / str(os.getpid())
        )
        if (
            controller_process_identity is None
            or _registered_process_binding(controller_process_identity)
            != list(controller_identity)
            or controller_process_identity[2] != sudo_parent_identity[0]
            or controller_process_identity[5] != (0, 0, 0, 0)
        ):
            raise AssertionError(
                "strict root controller identity is invalid"
            )
        barrier_read_fd, barrier_write_fd = os.pipe2(os.O_CLOEXEC)
        mount_readiness_read_fd, mount_readiness_write_fd = os.pipe2(
            os.O_CLOEXEC
        )
        command = _root_wrapper_command(
            config,
            controller_identity,
            barrier_read_fd,
            mount_readiness_write_fd,
        )
        output_directory = tempfile.TemporaryDirectory(
            prefix="required-ci-root-output-"
        )
        stdout_path = Path(output_directory.name) / "stdout"
        stderr_path = Path(output_directory.name) / "stderr"
        with stdout_path.open("w+b") as stdout_file, stderr_path.open("w+b") as stderr_file:
            process = subprocess.Popen(
                command,
                cwd=cwd_value,
                env=_minimal_supervisor_environment(),
                stdin=subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                pass_fds=(barrier_read_fd, mount_readiness_write_fd),
            )
            os.close(barrier_read_fd)
            barrier_read_fd = None
            os.close(mount_readiness_write_fd)
            mount_readiness_write_fd = None
            wrapper_pidfd = os.pidfd_open(process.pid, 0)
            wrapper_identity = _root_chain_identity(process.pid)
            wrapper_process_identity = _process_identity(
                Path("/proc") / str(process.pid)
            )
            if (
                wrapper_process_identity is None
                or _registered_process_binding(wrapper_process_identity)
                != list(wrapper_identity)
                or wrapper_process_identity[2] != controller_process_identity[0]
                or wrapper_process_identity[5] != (0, 0, 0, 0)
            ):
                raise AssertionError(
                    "strict root wrapper identity is invalid"
                )
            if fault_point == "after-wrapper-popen-before-handshake-sigkill":
                signal.raise_signal(signal.SIGKILL)
            if fault_point == "after-wrapper-popen-before-handshake-sigstop":
                signal.raise_signal(signal.SIGSTOP)
            _write_root_controller_handshake(
                handshake_path,
                nonce=nonce,
                session_id=session_id,
                target_uid=uid,
                sudo_parent=sudo_parent,
                wrapper=wrapper_identity,
            )
            if fault_point == "after-wrapper-bound-before-barrier-sigkill":
                signal.raise_signal(signal.SIGKILL)
            if fault_point == "after-wrapper-bound-before-barrier-sigstop":
                signal.raise_signal(signal.SIGSTOP)
            _release_wrapper_barrier(barrier_write_fd)
            barrier_write_fd = None
            if mount_readiness_read_fd is None:
                raise AssertionError(
                    "strict mount namespace readiness descriptor is missing"
                )
            _wait_mount_namespace_ready(
                mount_readiness_read_fd, wrapper_pidfd
            )
            os.close(mount_readiness_read_fd)
            mount_readiness_read_fd = None
            if active_probe is not None:
                if stdout_path is None:
                    raise AssertionError(
                        "strict root active output path is missing"
                    )
                target_marker, target_identity = _wait_root_target_active(
                    stdout_path,
                    nonce=nonce,
                    target_uid=uid,
                    wrapper=wrapper_process_identity,
                )
                root_handshake = _read_root_controller_handshake(
                    handshake_path
                )
                if (
                    root_handshake.get("controller")
                    != _registered_process_binding(
                        controller_process_identity
                    )
                    or root_handshake.get("sudo_parent")
                    != _registered_process_binding(sudo_parent_identity)
                    or root_handshake.get("wrapper")
                    != _registered_process_binding(wrapper_process_identity)
                    or len(
                        {
                            sudo_parent_identity[0],
                            controller_process_identity[0],
                            wrapper_process_identity[0],
                            target_identity[0],
                        }
                    )
                    != 4
                ):
                    raise AssertionError(
                        "strict root-active handshake identity is invalid"
                    )
                _publish_root_target_active(
                    {
                        "schema_version": 1,
                        "nonce": nonce,
                        "root_handshake": root_handshake,
                        "target_marker": target_marker,
                        "sudo_parent": _process_identity_document(
                            sudo_parent_identity
                        ),
                        "controller": _process_identity_document(
                            controller_process_identity
                        ),
                        "wrapper": _process_identity_document(
                            wrapper_process_identity
                        ),
                        "target": _process_identity_document(
                            target_identity
                        ),
                    }
                )
                active_published = True
            try:
                process.communicate(input_bytes, timeout=float(timeout_value))
            except subprocess.TimeoutExpired:
                timed_out = True
                _signal_process_pidfd(wrapper_pidfd, signal.SIGKILL)
                process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
            returncode = process.returncode
    except BaseException as error:
        failure = error
    finally:
        try:
            if process is not None and process.poll() is None:
                if wrapper_pidfd is None:
                    raise AssertionError(
                        "strict root wrapper identity was not captured"
                    )
                _signal_process_pidfd(wrapper_pidfd, signal.SIGKILL)
                process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
            if target_uid is not None:
                observed.update(_root_close_candidate_realm(target_uid))
        except BaseException as cleanup_error:
            if failure is None:
                failure = cleanup_error
            else:
                failure = AssertionError(
                    f"{failure}; cleanup failed: {cleanup_error}"
                )
        finally:
            if active_published and active_probe is not None:
                try:
                    if active_owner_pidfd is None:
                        raise AssertionError(
                            "strict root active owner pidfd is missing"
                        )
                    terminal, _, _ = select.select(
                        [active_owner_pidfd], [], [], 0
                    )
                    if (
                        not terminal
                        and _process_identity(
                            Path("/proc") / str(active_probe[2][0])
                        )
                        == active_probe[2]
                    ):
                        _mark_root_active_completed(
                            active_probe[0], nonce, active_probe[1]
                        )
                except BaseException as completion_error:
                    if failure is None:
                        failure = completion_error
                    else:
                        failure = AssertionError(
                            f"{failure}; active completion marking failed: "
                            f"{completion_error}"
                        )
            for descriptor in (
                barrier_read_fd,
                barrier_write_fd,
                mount_readiness_read_fd,
                mount_readiness_write_fd,
                wrapper_pidfd,
                active_owner_pidfd,
            ):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
    if failure is None:
        if stdout_path is None or stderr_path is None:
            failure = AssertionError("strict root controller output paths are missing")
        else:
            try:
                stdout = _read_root_bounded_output(stdout_path, "stdout")
                stderr = _read_root_bounded_output(stderr_path, "stderr")
            except BaseException as output_error:
                failure = output_error
    if failure is None:
        receipt = {
            "schema_version": 1,
            "status": "completed",
            "nonce": nonce,
            "returncode": returncode,
            "timed_out": timed_out,
            "process_leak_observed": bool(observed),
            "cleanup_status": "complete",
            "stdout_base64": base64.b64encode(stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        }
    else:
        receipt = {
            "schema_version": 1,
            "status": "blocked-safety",
            "nonce": nonce,
            "cleanup_status": "incomplete",
            "error": f"{type(failure).__name__}: {failure}",
        }
    if output_directory is not None:
        output_directory.cleanup()
    print(
        _ROOT_CONTROLLER_RECEIPT_PREFIX
        + json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    )
    return 0


def _parse_root_chain_identity(
    value: object, description: str
) -> tuple[int, int, int, int]:
    if (
        type(value) is not list
        or len(value) != 4
        or any(type(item) is not int or item <= 0 for item in value)
    ):
        raise AssertionError(f"strict root {description} identity is malformed")
    return value[0], value[1], value[2], value[3]


def _root_cleanup_main(
    entry_value: str, uid_value: str, token_value: str
) -> int:
    try:
        if os.getuid() != 0 or os.geteuid() != 0:
            raise AssertionError("strict root cleanup did not start as root")
        _bind_root_controller_parent()
        uid = _parse_internal_identity("cleanup UID", uid_value)
        if re.fullmatch(r"[0-9a-f]{32}", token_value) is None:
            raise AssertionError("strict root cleanup token is malformed")
        _enable_child_subreaper()
        entry = _load_chain_registry_entry(
            Path(entry_value),
            expected_token=token_value,
            expected_target_uid=uid,
            expected_recovery_controller=Path(__file__).resolve(strict=True),
        )
        if entry.get("target_uid") != uid or entry.get("state") != "closing":
            raise AssertionError("strict root cleanup UID binding is invalid")
        outer = _parse_root_chain_identity(
            entry.get("outer"), "registered outer session"
        )
        if outer[0] != outer[2] or outer[0] != outer[3]:
            raise AssertionError("strict registered outer session is not unique")
        observed = _root_close_candidate_realm(uid)
        host_observed_count = _root_close_registered_host_session(outer)
        receipt = {
            "status": "complete",
            "uid": uid,
            "observed_count": len(observed),
            "host_observed_count": host_observed_count,
        }
    except BaseException as error:
        receipt = {
            "status": "incomplete",
            "error": f"{type(error).__name__}: {error}",
        }
    print(
        _ROOT_CLEANUP_RECEIPT_PREFIX
        + json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    )
    return 0


_ROOT_TREE_MODE_PROFILES = {
    "candidate-code": (0o550, 0o440, 0o550, False),
    "candidate-workspace": (0o770, 0o660, 0o770, False),
    "candidate-home": (0o700, 0o600, 0o700, False),
    "fixture-restore": (0o2770, 0o660, 0o770, True),
    "fixture-shared": (0o2770, 0o660, 0o770, False),
    "runtime": (0o700, 0o600, 0o700, False),
    "trusted-control": (0o700, 0o400, 0o500, False),
}


def _root_fd_tree_operation(
    directory_fd: int,
    owner_uid: int,
    owner_gid: int,
    profile: str,
) -> None:
    try:
        directory_mode, file_mode, executable_mode, prune_unsafe = (
            _ROOT_TREE_MODE_PROFILES[profile]
        )
    except KeyError as error:
        raise AssertionError("strict root tree profile is invalid") from error
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as error:
        raise AssertionError("strict root tree cannot be enumerated") from error
    for name in names:
        if not name or name in (".", "..") or "/" in name:
            raise AssertionError("strict root tree entry name is invalid")
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            if prune_unsafe:
                continue
            raise AssertionError("strict root tree entry disappeared")
        if stat.S_ISDIR(metadata.st_mode):
            try:
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
                opened = os.fstat(child_fd)
            except OSError as error:
                raise AssertionError("strict root tree directory changed") from error
            try:
                if (opened.st_dev, opened.st_ino) != (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    raise AssertionError("strict root tree directory was replaced")
                _root_fd_tree_operation(child_fd, owner_uid, owner_gid, profile)
                os.fchown(child_fd, owner_uid, owner_gid)
                os.fchmod(child_fd, directory_mode)
            finally:
                os.close(child_fd)
            continue
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            try:
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
                opened = os.fstat(child_fd)
            except OSError as error:
                raise AssertionError("strict root tree file changed") from error
            try:
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                ):
                    raise AssertionError("strict root tree file was replaced")
                mode = executable_mode if opened.st_mode & 0o111 else file_mode
                os.fchown(child_fd, owner_uid, owner_gid)
                os.fchmod(child_fd, mode)
            finally:
                os.close(child_fd)
            continue
        if not prune_unsafe:
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise AssertionError("strict root tree file has a hardlink alias")
            raise AssertionError("strict root tree contains a non-ordinary entry")
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError as error:
            raise AssertionError("strict root tree unsafe entry cannot be removed") from error
    os.fchown(directory_fd, owner_uid, owner_gid)
    os.fchmod(directory_fd, directory_mode)


def _root_fd_delete_contents(directory_fd: int) -> None:
    os.fchown(directory_fd, 0, 0)
    os.fchmod(directory_fd, 0o500)
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as error:
        raise AssertionError("strict root cleanup tree cannot be enumerated") from error
    for name in names:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    raise AssertionError("strict root cleanup directory was replaced")
                os.fchown(child_fd, 0, 0)
                os.fchmod(child_fd, 0o500)
                _root_fd_delete_contents(child_fd)
                selected = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (selected.st_dev, selected.st_ino) != (
                    opened.st_dev,
                    opened.st_ino,
                ):
                    raise AssertionError(
                        "strict root cleanup directory changed before unlink"
                    )
                os.rmdir(name, dir_fd=directory_fd)
                deleted = os.fstat(child_fd)
                if (
                    (deleted.st_dev, deleted.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or deleted.st_nlink != 0
                ):
                    raise AssertionError(
                        "strict root cleanup directory unlink is unproved"
                    )
            except OSError as error:
                raise AssertionError(
                    "strict root cleanup directory cannot be removed"
                ) from error
            finally:
                os.close(child_fd)
        else:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError as error:
                raise AssertionError(
                    "strict root cleanup entry cannot be removed"
                ) from error


def _open_bound_tree_root(
    root: Path, expected_device: int, expected_inode: int
) -> int:
    if not root.is_absolute() or root == Path(root.anchor):
        raise AssertionError("strict root tree selector is unsafe")
    try:
        descriptor = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        opened = os.fstat(descriptor)
        selected = root.lstat()
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise AssertionError("strict root tree selector cannot be opened") from error
    identity = (expected_device, expected_inode)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != identity
        or (selected.st_dev, selected.st_ino) != identity
    ):
        os.close(descriptor)
        raise AssertionError("strict root tree selector identity changed")
    return descriptor


def _root_tree_main(arguments: Sequence[str]) -> int:
    try:
        if os.getuid() != 0 or os.geteuid() != 0:
            raise AssertionError("strict root tree broker did not start as root")
        _bind_root_controller_parent()
        if len(arguments) != 12:
            raise AssertionError("strict root tree broker arguments are malformed")
        (
            operation,
            root_value,
            device_value,
            inode_value,
            uid_value,
            gid_value,
            profile,
            receipt_value,
            registry_owner_value,
            token_value,
            session_id_value,
            delete_nonce_value,
        ) = arguments
        if not all(
            value.isdecimal()
            for value in (device_value, inode_value, uid_value, gid_value)
        ):
            raise AssertionError("strict root tree identity is malformed")
        root = Path(root_value)
        expected_device = int(device_value)
        expected_inode = int(inode_value)
        owner_uid = int(uid_value)
        owner_gid = int(gid_value)
        descriptor = _open_bound_tree_root(root, expected_device, expected_inode)
        try:
            if operation == "own":
                _root_fd_tree_operation(descriptor, owner_uid, owner_gid, profile)
            elif operation == "own-root":
                if profile not in (
                    "execution-root",
                    "isolation-ancestor",
                    "isolation-vault",
                    "isolation-vault-release",
                ):
                    raise AssertionError(
                        "strict root-only ownership profile is invalid"
                    )
                if profile == "isolation-vault-release" and os.listdir(
                    descriptor
                ):
                    raise AssertionError(
                        "strict isolation tombstone vault is not empty"
                    )
                os.fchown(descriptor, owner_uid, owner_gid)
                if profile == "isolation-vault-release":
                    os.fchmod(descriptor, 0o700)
                else:
                    os.fchmod(descriptor, 0o710)
            else:
                if any(
                    value != "-"
                    for value in (
                        receipt_value,
                        registry_owner_value,
                        token_value,
                        session_id_value,
                        delete_nonce_value,
                    )
                ):
                    raise AssertionError(
                        "strict root tree nondelete receipt binding is invalid"
                    )
                raise AssertionError("strict root tree operation is invalid")
        finally:
            os.close(descriptor)
        receipt = {"status": "complete", "operation": operation}
    except BaseException as error:
        receipt = {
            "status": "incomplete",
            "error": f"{type(error).__name__}: {error}",
        }
    print(
        _ROOT_TREE_RECEIPT_PREFIX
        + json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    )
    return 0


def _sealed_tombstone_name(session_id: str, delete_nonce: str) -> str:
    if (
        re.fullmatch(r"[0-9a-f]{32}", session_id) is None
        or re.fullmatch(r"[0-9a-f]{32}", delete_nonce) is None
    ):
        raise AssertionError("strict sealed tombstone identity is malformed")
    return f"sealed-{session_id}-{delete_nonce}"


def _open_bound_directory_entry(
    directory_fd: int,
    name: str,
    expected_device: int,
    expected_inode: int,
) -> int:
    if not name or name in (".", "..") or "/" in name:
        raise AssertionError("strict sealed tombstone selector is unsafe")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise AssertionError(
            "strict sealed tombstone object cannot be opened"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (expected_device, expected_inode)
    ):
        os.close(descriptor)
        raise AssertionError("strict sealed tombstone object identity changed")
    return descriptor


def _open_optional_bound_directory_entry(
    directory_fd: int,
    name: str,
    expected_device: int,
    expected_inode: int,
) -> int | None:
    try:
        return _open_bound_directory_entry(
            directory_fd, name, expected_device, expected_inode
        )
    except AssertionError as error:
        if isinstance(error.__cause__, FileNotFoundError):
            return None
        raise


def _gc_bound_sealed_tombstone(
    receipt_path: Path,
    vault_fd: int,
    tombstone_name: str,
    tombstone_fd: int,
    *,
    expected_identity: tuple[int, int],
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> None:
    # A visible final receipt may be the result of a root writer that died
    # after rename but before synchronizing the containing directory.  Bind
    # that directory entry durably before the tombstone stops being the
    # independently openable recovery witness.
    _fsync_directory(receipt_path.parent)
    tombstone_metadata = os.fstat(tombstone_fd)
    if (
        (tombstone_metadata.st_dev, tombstone_metadata.st_ino)
        != expected_identity
        or tombstone_metadata.st_uid != expected_uid
        or tombstone_metadata.st_gid != expected_gid
        or stat.S_IMODE(tombstone_metadata.st_mode) != expected_mode
        or os.listdir(tombstone_fd)
    ):
        raise AssertionError("strict sealed tombstone GC binding is unsafe")
    os.rmdir(tombstone_name, dir_fd=vault_fd)
    deleted = os.fstat(tombstone_fd)
    if deleted.st_nlink != 0:
        raise AssertionError("strict sealed tombstone GC unlink is unproved")
    os.fsync(vault_fd)


def _root_seal_execution_root_main(arguments: Sequence[str]) -> int:
    try:
        if os.getuid() != 0 or os.geteuid() != 0:
            raise AssertionError("strict root seal broker did not start as root")
        _bind_root_controller_parent()
        if len(arguments) != 15:
            raise AssertionError("strict root seal broker arguments are malformed")
        (
            origin_value,
            origin_device_value,
            origin_inode_value,
            resources_value,
            resources_device_value,
            resources_inode_value,
            vault_value,
            vault_device_value,
            vault_inode_value,
            receipt_value,
            runner_uid_value,
            runner_gid_value,
            token_value,
            session_id_value,
            delete_nonce_value,
        ) = arguments
        if not all(
            value.isdecimal()
            for value in (
                origin_device_value,
                origin_inode_value,
                resources_device_value,
                resources_inode_value,
                vault_device_value,
                vault_inode_value,
                runner_uid_value,
                runner_gid_value,
            )
        ):
            raise AssertionError("strict root seal broker identity is malformed")
        if (
            re.fullmatch(r"[0-9a-f]{32}", token_value) is None
            or re.fullmatch(r"[0-9a-f]{32}", session_id_value) is None
            or re.fullmatch(r"[0-9a-f]{32}", delete_nonce_value) is None
        ):
            raise AssertionError("strict root seal broker binding is malformed")
        origin = Path(origin_value)
        resources = Path(resources_value)
        vault = Path(vault_value)
        receipt_path = Path(receipt_value)
        if (
            not origin.is_absolute()
            or not resources.is_absolute()
            or not vault.is_absolute()
            or not receipt_path.is_absolute()
            or origin.parent != resources
            or vault.parent != resources.parent
        ):
            raise AssertionError("strict root seal broker paths are malformed")
        origin_identity = (int(origin_device_value), int(origin_inode_value))
        resources_fd = _open_bound_tree_root(
            resources,
            int(resources_device_value),
            int(resources_inode_value),
        )
        vault_fd = _open_bound_tree_root(
            vault,
            int(vault_device_value),
            int(vault_inode_value),
        )
        origin_fd: int | None = None
        tombstone_fd: int | None = None
        try:
            resources_metadata = os.fstat(resources_fd)
            vault_metadata = os.fstat(vault_fd)
            runner_uid = int(runner_uid_value)
            runner_gid = int(runner_gid_value)
            if (
                resources_metadata.st_uid != runner_uid
                or stat.S_IMODE(resources_metadata.st_mode) != 0o710
                or vault_metadata.st_uid != 0
                or vault_metadata.st_gid != runner_gid
                or stat.S_IMODE(vault_metadata.st_mode) != 0o710
            ):
                raise AssertionError(
                    "strict root seal broker container policy is unsafe"
                )
            tombstone_name = _sealed_tombstone_name(
                session_id_value, delete_nonce_value
            )
            expected_receipt = {
                "schema_version": 2,
                "kind": "sealed-empty-tombstone",
                "token": token_value,
                "session_id": session_id_value,
                "delete_nonce": delete_nonce_value,
                "path": str(origin),
                "device": origin_identity[0],
                "inode": origin_identity[1],
                "vault_device": vault_metadata.st_dev,
                "vault_inode": vault_metadata.st_ino,
                "tombstone_name": tombstone_name,
                "origin_absent": True,
                "tombstone_empty": True,
                "tombstone_owner_uid": 0,
                "tombstone_owner_gid": runner_gid,
                "tombstone_mode": 0o710,
            }
            receipt_exists = False
            try:
                receipt_metadata = receipt_path.lstat()
            except FileNotFoundError:
                pass
            else:
                try:
                    receipt_data = receipt_path.read_bytes()
                except OSError as error:
                    raise AssertionError(
                        "strict sealed tombstone receipt is unreadable"
                    ) from error
                if (
                    not stat.S_ISREG(receipt_metadata.st_mode)
                    or receipt_metadata.st_uid != 0
                    or receipt_metadata.st_gid != runner_gid
                    or receipt_metadata.st_nlink != 1
                    or stat.S_IMODE(receipt_metadata.st_mode) != 0o640
                    or len(receipt_data) > 4096
                    or json.loads(receipt_data) != expected_receipt
                ):
                    raise AssertionError(
                        "strict sealed tombstone receipt is not exact"
                    )
                receipt_exists = True
            origin_fd = _open_optional_bound_directory_entry(
                resources_fd,
                origin.name,
                origin_identity[0],
                origin_identity[1],
            )
            tombstone_fd = _open_optional_bound_directory_entry(
                vault_fd,
                tombstone_name,
                origin_identity[0],
                origin_identity[1],
            )
            if receipt_exists:
                if origin_fd is not None:
                    raise AssertionError(
                        "strict sealed execution root reappeared after receipt"
                    )
            else:
                if (origin_fd is None) == (tombstone_fd is None):
                    raise AssertionError(
                        "strict sealed tombstone recovery state is ambiguous"
                    )
                if origin_fd is not None:
                    _root_fd_delete_contents(origin_fd)
                    os.fchown(origin_fd, 0, runner_gid)
                    os.fchmod(origin_fd, 0o710)
                    _rename_directory_entry_noreplace(
                        resources_fd,
                        origin.name,
                        vault_fd,
                        tombstone_name,
                    )
                    published_tombstone = os.stat(
                        tombstone_name,
                        dir_fd=vault_fd,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISDIR(published_tombstone.st_mode)
                        or (
                            published_tombstone.st_dev,
                            published_tombstone.st_ino,
                        )
                        != origin_identity
                    ):
                        raise AssertionError(
                            "strict sealed tombstone publication identity changed"
                        )
                    os.fsync(resources_fd)
                    os.fsync(vault_fd)
                    tombstone_fd = origin_fd
                    origin_fd = None
                if tombstone_fd is None:
                    raise AssertionError(
                        "strict sealed tombstone object is unavailable"
                    )
                tombstone_metadata = os.fstat(tombstone_fd)
                if (
                    (tombstone_metadata.st_dev, tombstone_metadata.st_ino)
                    != origin_identity
                    or tombstone_metadata.st_uid != 0
                    or tombstone_metadata.st_gid != runner_gid
                    or stat.S_IMODE(tombstone_metadata.st_mode) != 0o710
                    or os.listdir(tombstone_fd)
                ):
                    raise AssertionError(
                        "strict sealed tombstone object is not empty and sealed"
                    )
                try:
                    os.stat(origin.name, dir_fd=resources_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise AssertionError(
                        "strict sealed execution root origin still exists"
                    )
                _atomic_json_document(
                    receipt_path,
                    expected_receipt,
                    expected_owner=runner_uid,
                    expected_file_owner=0,
                    expected_file_group=runner_gid,
                    expected_file_mode=0o640,
                    create=True,
                )
            if tombstone_fd is not None:
                _gc_bound_sealed_tombstone(
                    receipt_path,
                    vault_fd,
                    tombstone_name,
                    tombstone_fd,
                    expected_identity=origin_identity,
                    expected_uid=0,
                    expected_gid=runner_gid,
                    expected_mode=0o710,
                )
            receipt = {
                "status": "complete",
                "operation": "seal",
                "device": origin_identity[0],
                "inode": origin_identity[1],
            }
        finally:
            for descriptor in (
                origin_fd,
                tombstone_fd,
                resources_fd,
                vault_fd,
            ):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
    except BaseException as error:
        receipt = {
            "status": "incomplete",
            "error": f"{type(error).__name__}: {error}",
        }
    print(
        _ROOT_TREE_RECEIPT_PREFIX
        + json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    )
    return 0


def _invoke_registered_resource_seal(
    controller_path: Path,
    entry_path: Path,
    document: Mapping[str, object],
) -> None:
    session = _active_strict_session()
    resources = session.get("resources")
    vault = session.get("tombstones")
    if not isinstance(resources, Path) or not isinstance(vault, Path):
        raise AssertionError("strict sealed tombstone session is malformed")
    root, identity = _registered_execution_root(document)
    delete_nonce = document.get("execution_root_delete_nonce")
    if type(delete_nonce) is not str or root.parent != resources:
        raise AssertionError("strict sealed tombstone entry is malformed")
    resources_metadata = resources.lstat()
    vault_metadata = vault.lstat()
    output = _run_registered_sudo(
        [
            str(_STRICT_PRIMITIVES["python"]),
            *_ROOT_PYTHON_ARGUMENTS,
            str(controller_path),
            "--isolation-seal",
            str(root),
            str(identity[0]),
            str(identity[1]),
            str(resources),
            str(resources_metadata.st_dev),
            str(resources_metadata.st_ino),
            str(vault),
            str(vault_metadata.st_dev),
            str(vault_metadata.st_ino),
            str(_durable_deletion_receipt_path(entry_path, delete_nonce)),
            str(document["registry_owner_uid"]),
            str(os.getgid()),
            str(document["token"]),
            str(document["session_id"]),
            delete_nonce,
        ],
        execution_root=resources,
    )
    expected_prefix = _ROOT_TREE_RECEIPT_PREFIX.encode("ascii")
    if not output.startswith(expected_prefix) or output.count(b"\n") != 1:
        raise AssertionError("strict sealed tombstone broker receipt is malformed")
    try:
        receipt = json.loads(output[len(expected_prefix) :])
    except json.JSONDecodeError as error:
        raise AssertionError(
            "strict sealed tombstone broker receipt is malformed"
        ) from error
    if (
        type(receipt) is not dict
        or receipt.get("status") != "complete"
        or receipt.get("operation") != "seal"
        or receipt.get("device") != identity[0]
        or receipt.get("inode") != identity[1]
    ):
        raise AssertionError(
            "strict sealed tombstone broker did not complete: "
            f"{receipt.get('error') if isinstance(receipt, dict) else 'invalid'}"
        )


def _invoke_root_tree_operation(
    controller_path: Path,
    operation: str,
    root: Path,
    owner_uid: int,
    owner_gid: int,
    profile: str,
    *,
    deletion_authority: Mapping[str, object] | None = None,
) -> dict[str, object]:
    metadata = root.lstat()
    if deletion_authority is None:
        receipt_arguments = ["-", "-", "-", "-", "-"]
    else:
        receipt_path = deletion_authority.get("receipt_path")
        registry_owner_uid = deletion_authority.get("registry_owner_uid")
        token = deletion_authority.get("token")
        session_id = deletion_authority.get("session_id")
        delete_nonce = deletion_authority.get("delete_nonce")
        if (
            operation != "delete"
            or not isinstance(receipt_path, Path)
            or type(registry_owner_uid) is not int
            or type(token) is not str
            or type(session_id) is not str
            or type(delete_nonce) is not str
        ):
            raise AssertionError(
                "strict root tree deletion authority is malformed"
            )
        receipt_arguments = [
            str(receipt_path),
            str(registry_owner_uid),
            token,
            session_id,
            delete_nonce,
        ]
    output = _run_registered_sudo(
        [
            str(_STRICT_PRIMITIVES["python"]),
            *_ROOT_PYTHON_ARGUMENTS,
            str(controller_path),
            "--isolation-tree",
            operation,
            str(root),
            str(metadata.st_dev),
            str(metadata.st_ino),
            str(owner_uid),
            str(owner_gid),
            profile,
            *receipt_arguments,
        ],
        execution_root=root,
    )
    expected_prefix = _ROOT_TREE_RECEIPT_PREFIX.encode("ascii")
    if not output.startswith(expected_prefix) or output.count(b"\n") != 1:
        raise AssertionError("strict root tree broker receipt is malformed")
    try:
        receipt = json.loads(output[len(expected_prefix) :])
    except json.JSONDecodeError as error:
        raise AssertionError("strict root tree broker receipt is malformed") from error
    if (
        type(receipt) is not dict
        or receipt.get("status") != "complete"
        or receipt.get("operation") != operation
    ):
        raise AssertionError(
            "strict root tree broker did not complete: "
            f"{receipt.get('error') if isinstance(receipt, dict) else 'invalid'}"
        )
    return receipt


def _root_uid_cleanup_main(uid_value: str) -> int:
    try:
        if os.getuid() != 0 or os.geteuid() != 0:
            raise AssertionError("strict root UID cleanup did not start as root")
        _bind_root_controller_parent()
        uid = _parse_internal_identity("cleanup UID", uid_value)
        _enable_child_subreaper()
        observed = _root_close_candidate_realm(uid)
        receipt = {
            "status": "complete",
            "uid": uid,
            "observed_count": len(observed),
        }
    except BaseException as error:
        receipt = {
            "status": "incomplete",
            "error": f"{type(error).__name__}: {error}",
        }
    print(
        _ROOT_CLEANUP_RECEIPT_PREFIX
        + json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    )
    return 0


def _invoke_root_uid_cleanup(controller_path: Path, target_uid: int) -> None:
    output = _run_registered_sudo(
        [
            str(_STRICT_PRIMITIVES["python"]),
            *_ROOT_PYTHON_ARGUMENTS,
            str(controller_path),
            "--isolation-uid-cleanup",
            str(target_uid),
        ]
    )
    expected_prefix = _ROOT_CLEANUP_RECEIPT_PREFIX.encode("ascii")
    if not output.startswith(expected_prefix) or output.count(b"\n") != 1:
        raise AssertionError("strict root UID cleanup receipt is malformed")
    try:
        receipt = json.loads(output[len(expected_prefix) :])
    except json.JSONDecodeError as error:
        raise AssertionError("strict root UID cleanup receipt is malformed") from error
    if type(receipt) is not dict or receipt.get("status") != "complete":
        raise AssertionError("strict root UID cleanup did not complete")


def _open_private_lock(path: Path, *, create: bool) -> int:
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise AssertionError("strict durable lock cannot be opened") from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise AssertionError("strict durable lock identity is unsafe")
    return descriptor


def _chain_lock_path(entry_path: Path) -> Path:
    return entry_path.with_name(f".{entry_path.name}.lock")


@contextmanager
def _chain_registry_lock(entry_path: Path, *, create: bool = False) -> Iterator[None]:
    locks = getattr(_CHAIN_LOCK_STATE, "locks", None)
    if locks is None:
        locks = {}
        _CHAIN_LOCK_STATE.locks = locks
    key = str(entry_path)
    active = locks.get(key)
    if active is not None:
        if create:
            raise AssertionError("strict chain lock already exists")
        descriptor, depth = active
        locks[key] = (descriptor, depth + 1)
        try:
            yield
        finally:
            locks[key] = (descriptor, depth)
        return
    descriptor = _open_private_lock(_chain_lock_path(entry_path), create=create)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locks[key] = (descriptor, 1)
        yield
    finally:
        locks.pop(key, None)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _registry_session_lock_path(session: Mapping[str, object]) -> Path:
    root = session.get("root")
    if not isinstance(root, Path):
        raise AssertionError("strict isolation session root is malformed")
    return root / ".session.lock"


@contextmanager
def _registry_session_gate(
    *,
    exclusive: bool,
    session: Mapping[str, object] | None = None,
) -> Iterator[None]:
    depth = int(getattr(_REGISTRY_GATE_STATE, "depth", 0))
    held_exclusive = bool(getattr(_REGISTRY_GATE_STATE, "exclusive", False))
    if depth:
        if exclusive and not held_exclusive:
            raise AssertionError("strict isolation session lock cannot be upgraded")
        _REGISTRY_GATE_STATE.depth = depth + 1
        try:
            yield
        finally:
            _REGISTRY_GATE_STATE.depth = depth
        return
    selected_session = _active_strict_session() if session is None else session
    descriptor = _open_private_lock(
        _registry_session_lock_path(selected_session), create=False
    )
    try:
        fcntl.flock(
            descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        )
        _REGISTRY_GATE_STATE.depth = 1
        _REGISTRY_GATE_STATE.exclusive = exclusive
        yield
    finally:
        _REGISTRY_GATE_STATE.depth = 0
        _REGISTRY_GATE_STATE.exclusive = False
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _write_chain_registry_entry(
    path: Path,
    document: Mapping[str, object],
    *,
    create: bool,
    published_callback: Callable[[], None] | None = None,
) -> None:
    _atomic_json_document(
        path,
        document,
        expected_owner=os.getuid(),
        create=create,
        published_callback=published_callback,
    )


_CHAIN_STATES = (
    "prepared",
    "outer-bound",
    "root-authorized",
    "closing",
    "deleting",
    "closed",
)
_CHAIN_TRANSITIONS = {
    "prepared": frozenset(("outer-bound", "closing")),
    "outer-bound": frozenset(("root-authorized", "closing")),
    "root-authorized": frozenset(("closing",)),
    "closing": frozenset(("deleting", "closed")),
    "deleting": frozenset(("closed",)),
    "closed": frozenset(),
}


def _load_chain_registry_entry(
    path: Path,
    *,
    expected_token: str | None = None,
    expected_target_uid: int | None = None,
    expected_recovery_controller: Path | None = None,
) -> dict[str, object]:
    if (
        expected_token is None
        or expected_target_uid is None
        or expected_recovery_controller is None
    ):
        session = _current_strict_session_unchecked()
        token_value = session.get("token")
        target_uid_value = session.get("target_uid")
        controller_value = session.get("controller_path")
        if (
            type(token_value) is not str
            or type(target_uid_value) is not int
            or not isinstance(controller_value, Path)
        ):
            raise AssertionError("strict active session binding is malformed")
        expected_token = token_value
        expected_target_uid = target_uid_value
        expected_recovery_controller = controller_value
    try:
        metadata = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise AssertionError("strict chain registry entry is unreadable") from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or len(data) > 4096
    ):
        raise AssertionError("strict chain registry entry is unsafe")
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError("strict chain registry entry is malformed") from error
    if (
        type(document) is not dict
        or document.get("schema_version") != 2
        or document.get("state") not in _CHAIN_STATES
        or type(document.get("registry_owner_uid")) is not int
        or document.get("registry_owner_uid") != metadata.st_uid
        or type(document.get("token")) is not str
        or re.fullmatch(r"[0-9a-f]{32}", str(document.get("token"))) is None
        or document.get("token") != expected_token
        or type(document.get("session_id")) is not str
        or re.fullmatch(r"[0-9a-f]{32}", str(document.get("session_id"))) is None
        or type(document.get("publication_nonce")) is not str
        or re.fullmatch(
            r"[0-9a-f]{32}", str(document.get("publication_nonce"))
        )
        is None
        or (
            document.get("outer_marker") is not None
            and (
                type(document.get("outer_marker")) is not str
                or re.fullmatch(
                    r"required-ci-outer-[0-9a-f]{32}",
                    str(document.get("outer_marker")),
                )
                is None
            )
        )
        or type(document.get("cleanup_execution_root")) is not bool
        or type(document.get("target_uid")) is not int
        or not 50000 <= int(document.get("target_uid")) <= 64999
        or document.get("target_uid") != expected_target_uid
        or type(document.get("controller_path")) is not str
        or not Path(str(document.get("controller_path"))).is_absolute()
        or type(document.get("recovery_controller_path")) is not str
        or not Path(str(document.get("recovery_controller_path"))).is_absolute()
        or document.get("recovery_controller_path")
        != str(expected_recovery_controller)
        or (
            document.get("handshake_path") is not None
            and (
                type(document.get("handshake_path")) is not str
                or not Path(str(document.get("handshake_path"))).is_absolute()
            )
        )
        or type(document.get("execution_root")) is not dict
        or type(document["execution_root"].get("path")) is not str
        or not Path(str(document["execution_root"].get("path"))).is_absolute()
        or type(document["execution_root"].get("device")) is not int
        or type(document["execution_root"].get("inode")) is not int
    ):
        raise AssertionError(
            "strict chain registry entry active session binding is invalid"
        )
    deletion_receipt = document.get("execution_root_deleted")
    deletion_nonce = document.get("execution_root_delete_nonce")
    if deletion_nonce is not None and (
        type(deletion_nonce) is not str
        or re.fullmatch(r"[0-9a-f]{32}", deletion_nonce) is None
        or document.get("cleanup_execution_root") is not True
        or document.get("state") not in ("deleting", "closed")
    ):
        raise AssertionError("strict chain registry deletion nonce is invalid")
    if deletion_receipt is not None and (
        type(deletion_receipt) is not dict
        or set(deletion_receipt)
        != {
            "kind",
            "device",
            "inode",
            "vault_device",
            "vault_inode",
            "tombstone_name",
        }
        or deletion_receipt.get("kind") != "sealed-empty-tombstone"
        or deletion_receipt.get("device")
        != document["execution_root"].get("device")
        or deletion_receipt.get("inode")
        != document["execution_root"].get("inode")
        or type(deletion_receipt.get("vault_device")) is not int
        or type(deletion_receipt.get("vault_inode")) is not int
        or deletion_receipt.get("tombstone_name")
        != _sealed_tombstone_name(
            str(document.get("session_id")), str(deletion_nonce)
        )
        or document.get("cleanup_execution_root") is not True
        or deletion_nonce is None
        or document.get("state") not in ("deleting", "closed")
    ):
        raise AssertionError("strict chain registry deletion receipt is invalid")
    if (
        document.get("cleanup_execution_root") is True
        and document.get("state") in ("deleting", "closed")
        and deletion_nonce is None
    ) or (
        document.get("cleanup_execution_root") is True
        and document.get("state") == "closed"
        and deletion_receipt is None
    ):
        raise AssertionError("strict chain registry deletion phase is incomplete")
    outer_value = document.get("outer")
    launcher_parent_value = document.get("launcher_parent")
    if launcher_parent_value is not None:
        _parse_root_chain_identity(
            launcher_parent_value, "registered launcher parent"
        )
    if document["state"] in ("outer-bound", "root-authorized") and outer_value is None:
        raise AssertionError("strict chain registry outer binding is missing")
    if outer_value is not None:
        outer = _parse_root_chain_identity(outer_value, "registered outer")
        if outer[0] != outer[2] or outer[0] != outer[3]:
            raise AssertionError("strict registered outer session is not unique")
    return document


def _execution_root_binding(root: Path) -> dict[str, object]:
    try:
        metadata = root.lstat()
    except OSError as error:
        raise AssertionError("strict registered execution root is unreadable") from error
    if (
        not root.is_absolute()
        or root == Path(root.anchor)
        or any(ord(character) < 32 or ord(character) == 127 for character in str(root))
        or not stat.S_ISDIR(metadata.st_mode)
        or root.resolve(strict=True) != root
    ):
        raise AssertionError("strict registered execution root is unsafe")
    return {
        "path": str(root),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def _decode_strict_mountinfo_path(value: str) -> Path:
    if not value or not value.startswith("/"):
        raise AssertionError("strict host mount topology is malformed")
    decoded: list[str] = []
    index = 0
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    while index < len(value):
        if value[index] != "\\":
            decoded.append(value[index])
            index += 1
            continue
        escape = value[index + 1 : index + 4]
        if len(escape) != 3 or escape not in escapes:
            raise AssertionError("strict host mount topology is malformed")
        decoded.append(escapes[escape])
        index += 4
    decoded_value = "".join(decoded)
    components = decoded_value.split("/")
    if (
        "\x00" in decoded_value
        or (decoded_value != "/" and decoded_value.endswith("/"))
        or (
            decoded_value != "/"
            and any(
                component in ("", ".", "..")
                for component in components[1:]
            )
        )
    ):
        raise AssertionError("strict host mount topology is malformed")
    path = Path(decoded_value)
    if not path.is_absolute() or str(path) != decoded_value:
        raise AssertionError("strict host mount topology is malformed")
    return path


def _strict_mount_inventory() -> dict[int, dict[str, object]]:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            "/proc/self/mountinfo",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(
                descriptor,
                min(65536, _STRICT_MOUNTINFO_LIMIT_BYTES + 1 - size),
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _STRICT_MOUNTINFO_LIMIT_BYTES:
                raise AssertionError(
                    "strict host mount topology exceeds its fixed limit"
                )
    except OSError as error:
        raise AssertionError("strict host mount topology is unreadable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        text = b"".join(chunks).decode(
            "utf-8", errors="surrogateescape"
        )
    except UnicodeError as error:
        raise AssertionError("strict host mount topology is malformed") from error
    inventory: dict[int, dict[str, object]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise AssertionError("strict host mount topology is malformed")
        separator = fields.index("-")
        if separator < 6 or len(fields) != separator + 4:
            raise AssertionError("strict host mount topology is malformed")
        try:
            mount_id = int(fields[0])
            parent_id = int(fields[1])
            major_value, minor_value = fields[2].split(":", 1)
            major_minor = (int(major_value), int(minor_value))
        except ValueError as error:
            raise AssertionError("strict host mount topology is malformed") from error
        if (
            mount_id <= 0
            or parent_id <= 0
            or any(value < 0 for value in major_minor)
            or mount_id in inventory
        ):
            raise AssertionError("strict host mount topology is malformed")
        inventory[mount_id] = {
            "parent_id": parent_id,
            "major_minor": major_minor,
            # mountinfo root is filesystem-defined show_path() output.  Keep
            # the bounded raw token for diagnostics, but never use it as a
            # universal source-coordinate system.
            "root": fields[3],
            "mountpoint": _decode_strict_mountinfo_path(fields[4]),
        }
    if not inventory:
        raise AssertionError("strict host mount topology is malformed")
    visible_roots = {
        mount_id
        for mount_id, record in inventory.items()
        if record["parent_id"] == mount_id
        or record["parent_id"] not in inventory
    }
    if len(visible_roots) != 1:
        raise AssertionError("strict host mount topology is malformed")
    visible_root_id = next(iter(visible_roots))
    for mount_id in inventory:
        current_id = mount_id
        observed: set[int] = set()
        while current_id != visible_root_id:
            if current_id not in inventory:
                raise AssertionError("strict host mount topology is malformed")
            if current_id in observed:
                raise AssertionError("strict host mount topology is malformed")
            observed.add(current_id)
            parent_id = inventory[current_id]["parent_id"]
            if type(parent_id) is not int:
                raise AssertionError("strict host mount topology is malformed")
            current_id = parent_id
    return inventory


def _strict_path_at_or_below(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _strict_validate_directory_mount_topology(
    root: Path,
    mount_id: int,
    device: int,
    inventory: Mapping[int, Mapping[str, object]],
    description: str,
) -> None:
    boundary_error = (
        "strict writable root contains a host mount boundary"
        if description == "writable root"
        else f"strict {description} contains a mount boundary"
    )
    containing_record = inventory.get(mount_id)
    if containing_record is None:
        raise AssertionError(f"strict {description} mount identity changed")
    for record in inventory.values():
        if (
            set(record)
            != {"parent_id", "major_minor", "root", "mountpoint"}
            or type(record.get("parent_id")) is not int
            or type(record.get("major_minor")) is not tuple
            or len(record["major_minor"]) != 2
            or any(type(value) is not int for value in record["major_minor"])
            or type(record.get("root")) is not str
            or not isinstance(record.get("mountpoint"), Path)
        ):
            raise AssertionError("strict host mount topology is malformed")
    containing_mountpoint = containing_record["mountpoint"]
    containing_major_minor = containing_record["major_minor"]
    if (
        not isinstance(containing_mountpoint, Path)
        or type(containing_major_minor) is not tuple
        or type(device) is not int
        or containing_major_minor != (os.major(device), os.minor(device))
        or not _strict_path_at_or_below(root, containing_mountpoint)
    ):
        raise AssertionError(f"strict {description} mount identity changed")
    same_filesystem_mount_ids = [
        candidate_id
        for candidate_id, record in inventory.items()
        if record["major_minor"] == containing_major_minor
    ]
    # Filesystems may override mountinfo show_path(), so its root field is not
    # a universal source-coordinate system.  Requiring the held directory's
    # filesystem identity to have exactly one visible mount record is the
    # conservative, filesystem-independent proof that no bind alias exists.
    if same_filesystem_mount_ids != [mount_id]:
        raise AssertionError(f"strict {description} has a mount alias")
    if containing_mountpoint == root:
        raise AssertionError(boundary_error)
    if any(
        candidate_id != mount_id
        and isinstance(record.get("mountpoint"), Path)
        and _strict_path_at_or_below(record["mountpoint"], root)
        for candidate_id, record in inventory.items()
    ):
        raise AssertionError(boundary_error)


def _strict_descriptor_mount_id(descriptor: int) -> int:
    fdinfo_descriptor: int | None = None
    try:
        fdinfo_descriptor = os.open(
            f"/proc/self/fdinfo/{descriptor}",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        data = os.read(fdinfo_descriptor, 4097)
    except OSError as error:
        raise AssertionError("strict writable root mount identity is unreadable") from error
    finally:
        if fdinfo_descriptor is not None:
            os.close(fdinfo_descriptor)
    if len(data) > 4096:
        raise AssertionError("strict writable root mount identity is malformed")
    try:
        mount_ids = [
            int(line.split()[1])
            for line in data.decode("ascii").splitlines()
            if line.startswith("mnt_id:")
        ]
    except (UnicodeError, IndexError, ValueError) as error:
        raise AssertionError("strict writable root mount identity is malformed") from error
    if len(mount_ids) != 1 or mount_ids[0] <= 0:
        raise AssertionError("strict writable root mount identity is malformed")
    return mount_ids[0]


def _strict_writable_root_mount_binding(root: Path) -> int:
    o_path = getattr(os, "O_PATH", None)
    if type(o_path) is not int:
        raise AssertionError("strict writable root mount binding is unavailable")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            root,
            o_path | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        metadata = os.fstat(descriptor)
        mount_id = _strict_descriptor_mount_id(descriptor)
    except OSError as error:
        raise AssertionError("strict writable root mount binding is unreadable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    expected = _execution_root_binding(root)
    # dev/ino protect directory object identity.  The held FD's st_dev must
    # have one visible mount record, excluding bind aliases independently of
    # filesystem-specific show_path output; lexical mountpoint checks exclude
    # mounted subtrees.  Timestamps and child counts are not relevant signals.
    if (metadata.st_dev, metadata.st_ino) != (
        expected["device"],
        expected["inode"],
    ):
        raise AssertionError("strict writable root mount binding changed")
    inventory = _strict_mount_inventory()
    _strict_validate_directory_mount_topology(
        root, mount_id, metadata.st_dev, inventory, "writable root"
    )
    return mount_id


def _strict_host_read_root_mount_binding(root: Path) -> int:
    o_path = getattr(os, "O_PATH", None)
    if type(o_path) is not int:
        raise AssertionError("strict host read root mount binding is unavailable")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            root,
            o_path | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        metadata = os.fstat(descriptor)
        mount_id = _strict_descriptor_mount_id(descriptor)
    except OSError as error:
        raise AssertionError(
            "strict host read root mount binding is unreadable"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    inventory = _strict_mount_inventory()
    # Landlock directory rules follow bind aliases.  A unique visible mount
    # record for the held FD's st_dev excludes those aliases without trusting
    # filesystem-specific show_path output; lexical mountpoint checks exclude
    # mounted subtrees.  Size, timestamps, and link count do not protect this
    # access-policy property.
    _strict_validate_directory_mount_topology(
        root, mount_id, metadata.st_dev, inventory, "host read root"
    )
    return mount_id


def _strict_writable_root_bindings(
    execution_root: Path, writable_roots: Sequence[Path]
) -> list[dict[str, object]]:
    selected_roots = [execution_root, *writable_roots]
    if not 1 <= len(selected_roots) <= _STRICT_WRITABLE_ROOT_LIMIT:
        raise AssertionError("strict writable root inventory exceeds its fixed limit")
    bindings: list[dict[str, object]] = []
    observed_paths: set[str] = set()
    for value in selected_roots:
        binding = _execution_root_binding(Path(value))
        path = str(binding["path"])
        selected_path = Path(path)
        protected_mountpoints = (
            *_STRICT_PRIVATE_SURFACE_PATHS,
            Path("/dev/mqueue"),
        )
        if any(
            selected_path == mountpoint
            or selected_path in mountpoint.parents
            for mountpoint in protected_mountpoints
        ):
            raise AssertionError(
                "strict writable root would expose a private host surface"
            )
        if path in observed_paths:
            raise AssertionError("strict writable root inventory contains a duplicate")
        observed_paths.add(path)
        binding["host_mount_id"] = _strict_writable_root_mount_binding(
            selected_path
        )
        bindings.append(binding)
    for index, left in enumerate(bindings):
        left_path = Path(str(left["path"]))
        for right in bindings[index + 1 :]:
            right_path = Path(str(right["path"]))
            if left_path in right_path.parents or right_path in left_path.parents:
                raise AssertionError("strict writable roots must not overlap")
    return bindings


def _revalidate_strict_writable_root_bindings(
    value: object,
) -> list[dict[str, object]]:
    if (
        type(value) is not list
        or not 1 <= len(value) <= _STRICT_WRITABLE_ROOT_LIMIT
    ):
        raise AssertionError("strict writable root binding is malformed")
    bindings: list[dict[str, object]] = []
    for document in value:
        if (
            type(document) is not dict
            or set(document) != {
                "path",
                "device",
                "inode",
                "host_mount_id",
            }
            or type(document.get("path")) is not str
            or type(document.get("device")) is not int
            or type(document.get("inode")) is not int
            or type(document.get("host_mount_id")) is not int
        ):
            raise AssertionError("strict writable root binding is malformed")
        path = Path(str(document["path"]))
        recaptured = _execution_root_binding(path)
        recaptured["host_mount_id"] = _strict_writable_root_mount_binding(path)
        if recaptured != document:
            raise AssertionError("strict writable root binding changed")
        bindings.append(recaptured)
    if bindings != _strict_writable_root_bindings(
        Path(str(bindings[0]["path"])),
        tuple(Path(str(binding["path"])) for binding in bindings[1:]),
    ):
        raise AssertionError("strict writable root binding changed")
    return bindings


def _strict_host_namespace_identity(namespace: str) -> str:
    if namespace not in ("mnt", "ipc", "net"):
        raise AssertionError("strict host namespace selector is malformed")
    try:
        identity = os.readlink(f"/proc/self/ns/{namespace}")
    except OSError as error:
        raise AssertionError(
            f"strict host {namespace} namespace identity is unreadable"
        ) from error
    if re.fullmatch(rf"{namespace}:\[[1-9][0-9]*\]", identity) is None:
        raise AssertionError(
            f"strict host {namespace} namespace identity is malformed"
        )
    return identity


def _session_from_environment() -> dict[str, object] | None:
    registry_value = os.environ.get(_ISOLATION_REGISTRY_ENV)
    token = os.environ.get(_ISOLATION_REGISTRY_TOKEN_ENV)
    if registry_value is None and token is None:
        return None
    if (
        registry_value is None
        or token is None
        or re.fullmatch(r"[0-9a-f]{32}", token) is None
    ):
        raise AssertionError("strict inherited isolation registry is malformed")
    entries = Path(registry_value)
    root = entries.parent
    control = root / "trusted-control"
    resources = root / "resources"
    tombstones = root / ".tombstones"
    session_lock = root / ".session.lock"
    watchdog_token_path = root / ".watchdog-token"
    controller_path = (
        control
        / _TRUSTED_CONTENT_RELATIVE_ROOT
        / "skills/waited-delivery/tests/required_ci_candidate.py"
    )
    realm_gid = int(_strict_realm()["gid"])
    for path in (root, entries, control, resources, tombstones):
        metadata = path.lstat()
        selected_mode = stat.S_IMODE(metadata.st_mode)
        ancestor_policy = path in (root, resources)
        vault_policy = path == tombstones
        if (
            not path.is_absolute()
            or not stat.S_ISDIR(metadata.st_mode)
            or (not vault_policy and metadata.st_uid != os.getuid())
            or (
                ancestor_policy
                and not (
                    selected_mode == 0o700
                    or (
                        selected_mode == 0o710
                        and metadata.st_gid == realm_gid
                    )
                )
            )
            or (
                vault_policy
                and not (
                    (
                        metadata.st_uid == os.getuid()
                        and selected_mode == 0o700
                    )
                    or (
                        metadata.st_uid == 0
                        and metadata.st_gid == os.getgid()
                        and selected_mode == 0o710
                    )
                )
            )
            or (
                not ancestor_policy
                and not vault_policy
                and selected_mode != 0o700
            )
        ):
            raise AssertionError("strict inherited isolation registry is unsafe")
    controller_metadata = controller_path.lstat()
    session_lock_metadata = session_lock.lstat()
    watchdog_token_metadata = watchdog_token_path.lstat()
    watchdog_token = watchdog_token_path.read_text(encoding="ascii")
    supplied_watchdog_token = os.environ.get(_ISOLATION_WATCHDOG_TOKEN_ENV)
    if (
        not stat.S_ISREG(controller_metadata.st_mode)
        or controller_metadata.st_uid != os.getuid()
        or controller_metadata.st_nlink != 1
        or stat.S_IMODE(controller_metadata.st_mode) != 0o400
        or hashlib.sha256(controller_path.read_bytes()).hexdigest()
        != _TRUSTED_SUPPORT_SHA256
        or not stat.S_ISREG(session_lock_metadata.st_mode)
        or session_lock_metadata.st_uid != os.getuid()
        or session_lock_metadata.st_nlink != 1
        or stat.S_IMODE(session_lock_metadata.st_mode) != 0o600
        or not stat.S_ISREG(watchdog_token_metadata.st_mode)
        or watchdog_token_metadata.st_uid != os.getuid()
        or watchdog_token_metadata.st_nlink != 1
        or stat.S_IMODE(watchdog_token_metadata.st_mode) != 0o400
        or re.fullmatch(r"[0-9a-f]{32}", watchdog_token) is None
        or (
            supplied_watchdog_token is not None
            and supplied_watchdog_token != watchdog_token
        )
    ):
        raise AssertionError("strict inherited recovery controller is unsafe")
    return {
        "environment": {
            _ISOLATION_REGISTRY_ENV: str(entries),
            _ISOLATION_REGISTRY_TOKEN_ENV: token,
        },
        "root": root,
        "entries": entries,
        "resources": resources,
        "tombstones": tombstones,
        "controller_path": controller_path,
        "token": token,
        "target_uid": int(_strict_realm()["uid"]),
        "closed": False,
        "inherited": True,
        "watchdog_authorized": supplied_watchdog_token == watchdog_token,
    }


def _current_strict_session_unchecked() -> dict[str, object]:
    global _STRICT_SESSION
    if _STRICT_SESSION is None:
        _STRICT_SESSION = _session_from_environment()
    if _STRICT_SESSION is None or _STRICT_SESSION.get("closed") is True:
        raise AssertionError(
            "strict isolation session must be active before any privileged probe"
        )
    return _STRICT_SESSION


def _active_strict_session() -> dict[str, object]:
    session = _current_strict_session_unchecked()
    _assert_registry_watchdog_alive(session)
    return session


def _register_trusted_root_chain(
    controller_path: Path,
    handshake_path: Path | None,
    target_uid: int,
    *,
    execution_root: Path,
    cleanup_execution_root: bool = False,
    session_id: str | None = None,
    publication_nonce: str | None = None,
    published_callback: Callable[[], None] | None = None,
) -> Path:
    session = _active_strict_session()
    entries = session.get("entries")
    token = session.get("token")
    recovery_controller = session.get("controller_path")
    if (
        not isinstance(entries, Path)
        or type(token) is not str
        or not isinstance(recovery_controller, Path)
        or target_uid != session.get("target_uid")
        or type(cleanup_execution_root) is not bool
        or not controller_path.is_absolute()
        or (handshake_path is not None and not handshake_path.is_absolute())
    ):
        raise AssertionError("strict active isolation registry is malformed")
    selected_session_id = uuid.uuid4().hex if session_id is None else session_id
    selected_publication_nonce = (
        uuid.uuid4().hex if publication_nonce is None else publication_nonce
    )
    if re.fullmatch(r"[0-9a-f]{32}", selected_session_id) is None:
        raise AssertionError("strict registered session identity is malformed")
    if re.fullmatch(r"[0-9a-f]{32}", selected_publication_nonce) is None:
        raise AssertionError("strict registered publication identity is malformed")
    entry_path = entries / f"chain-{selected_session_id}.json"
    document = {
        "schema_version": 2,
        "token": token,
        "registry_owner_uid": os.getuid(),
        "state": "prepared",
        "session_id": selected_session_id,
        "publication_nonce": selected_publication_nonce,
        "target_uid": target_uid,
        "controller_path": str(controller_path),
        "recovery_controller_path": str(recovery_controller),
        "handshake_path": None if handshake_path is None else str(handshake_path),
        "execution_root": _execution_root_binding(execution_root),
        "cleanup_execution_root": cleanup_execution_root,
        "execution_root_deleted": None,
        "execution_root_delete_nonce": None,
        "launcher_parent": None,
        "outer_marker": None,
        "outer": None,
    }
    with _chain_registry_lock(entry_path, create=True):
        _write_chain_registry_entry(
            entry_path,
            document,
            create=True,
            published_callback=published_callback,
        )
    return entry_path


def _registered_entry_matches_publication_attempt(
    entry_path: Path,
    *,
    session: Mapping[str, object],
    publication_nonce: str,
    execution_root_binding: Mapping[str, object],
    cleanup_execution_root: bool,
) -> bool:
    token = session.get("token")
    target_uid = session.get("target_uid")
    controller_path = session.get("controller_path")
    if (
        type(publication_nonce) is not str
        or re.fullmatch(r"[0-9a-f]{32}", publication_nonce) is None
        or type(token) is not str
        or type(target_uid) is not int
        or not isinstance(controller_path, Path)
        or type(cleanup_execution_root) is not bool
        or set(execution_root_binding) != {"path", "device", "inode"}
        or type(execution_root_binding.get("path")) is not str
        or type(execution_root_binding.get("device")) is not int
        or type(execution_root_binding.get("inode")) is not int
    ):
        raise AssertionError("strict registered publication attempt is malformed")
    entry_match = _CHAIN_ENTRY_NAME_PATTERN.fullmatch(entry_path.name)
    if entry_match is None:
        raise AssertionError("strict registered publication path is malformed")

    def matches(document: Mapping[str, object]) -> bool:
        return bool(
            document.get("session_id") == entry_match.group(1)
            and document.get("publication_nonce") == publication_nonce
            and document.get("state") == "prepared"
            and document.get("controller_path") == str(controller_path)
            and document.get("execution_root") == dict(execution_root_binding)
            and document.get("cleanup_execution_root")
            is cleanup_execution_root
            and document.get("launcher_parent") is None
            and document.get("outer_marker") is None
            and document.get("outer") is None
        )

    with _chain_registry_lock(entry_path):
        final_document: dict[str, object] | None = None
        try:
            entry_path.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise AssertionError(
                "strict registered publication entry cannot be inspected"
            ) from error
        else:
            final_document = _load_chain_registry_entry(
                entry_path,
                expected_token=token,
                expected_target_uid=target_uid,
                expected_recovery_controller=controller_path,
            )
            if matches(final_document):
                return True

        try:
            staged_paths = [
                path
                for path in entry_path.parent.iterdir()
                if (
                    (staged_match := _CHAIN_STAGING_NAME_PATTERN.fullmatch(
                        path.name
                    ))
                    is not None
                    and staged_match.group(1) == entry_path.name
                )
            ]
        except OSError as error:
            raise AssertionError(
                "strict registered publication staging cannot be inspected"
            ) from error
        if final_document is not None:
            raise AssertionError(
                "strict registered publication collided with an unowned entry; "
                "recovery state retained"
            )
        if not staged_paths:
            return False
        if len(staged_paths) != 1:
            raise AssertionError(
                "strict registered publication staging is ambiguous; "
                "recovery state retained"
            )
        staged_path = staged_paths[0]
        try:
            staged_document = _load_chain_registry_entry(
                staged_path,
                expected_token=token,
                expected_target_uid=target_uid,
                expected_recovery_controller=controller_path,
            )
        except BaseException as error:
            raise AssertionError(
                "strict registered publication staging ownership is unproved; "
                "recovery state retained"
            ) from error
        if not matches(staged_document):
            raise AssertionError(
                "strict registered publication staging belongs to another attempt; "
                "recovery state retained"
            )
        try:
            _rename_noreplace(staged_path, entry_path)
            _fsync_directory(entry_path.parent)
        except OSError as error:
            raise AssertionError(
                "strict registered publication staging cannot be published; "
                "recovery state retained"
            ) from error
        recovered_document = _load_chain_registry_entry(
            entry_path,
            expected_token=token,
            expected_target_uid=target_uid,
            expected_recovery_controller=controller_path,
        )
        if not matches(recovered_document):
            raise AssertionError(
                "strict registered publication staging changed during recovery"
            )
        return True


def _transition_trusted_root_chain(
    entry_path: Path,
    expected_states: Sequence[str],
    selected_state: str,
    **updates: object,
) -> dict[str, object]:
    if selected_state not in _CHAIN_STATES:
        raise AssertionError("strict chain registry transition is invalid")
    with _chain_registry_lock(entry_path):
        document = _load_chain_registry_entry(entry_path)
        current_state = document.get("state")
        if (
            current_state not in expected_states
            or selected_state not in _CHAIN_TRANSITIONS[str(current_state)]
        ):
            raise AssertionError(
                "strict chain registry transition predecessor is invalid"
            )
        document.update(updates)
        document["state"] = selected_state
        _write_chain_registry_entry(entry_path, document, create=False)
        return document


def _update_trusted_root_chain(
    entry_path: Path, expected_state: str, **updates: object
) -> dict[str, object]:
    with _chain_registry_lock(entry_path):
        document = _load_chain_registry_entry(entry_path)
        if document.get("state") != expected_state:
            raise AssertionError("strict chain registry update state is invalid")
        document.update(updates)
        _write_chain_registry_entry(entry_path, document, create=False)
        return document


def _stable_host_session_zero(outer: tuple[int, int, int, int]) -> None:
    session_id = outer[3]
    zero_count = 0
    zero_was_observed = False
    generation_was_anchored = _assert_registered_session_not_reused(outer)
    deadline = time.monotonic() + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        inventory = _host_session_inventory(session_id)
        if inventory:
            if zero_was_observed or not generation_was_anchored:
                raise AssertionError(
                    "strict registered host session generation is no longer provable"
                )
            current_leader = _process_identity(Path("/proc") / str(outer[0]))
            if current_leader is None:
                raise AssertionError(
                    "strict registered host session lost its generation anchor"
                )
            if (
                current_leader[1] != outer[1]
                or current_leader[3] != outer[2]
                or current_leader[4] != outer[3]
            ):
                raise AssertionError(
                    "strict registered host session identity was reused"
                )
            nonleaders = tuple(
                identity
                for identity in inventory.values()
                if identity[0] != outer[0]
            )
            if nonleaders or not _registered_anchor_is_terminal(outer):
                zero_count = 0
            else:
                zero_count += 1
                if zero_count >= _STRICT_ZERO_SCAN_COUNT:
                    return
        else:
            zero_was_observed = True
            zero_count += 1
            if zero_count >= _STRICT_ZERO_SCAN_COUNT:
                return
        time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
    raise AssertionError("strict registered host session is not quiescent")


def _stable_uid_zero(target_uid: int) -> None:
    for _ in range(_STRICT_ZERO_SCAN_COUNT):
        if _candidate_uid_inventory(target_uid):
            raise AssertionError("strict candidate UID realm is not quiescent")
        time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)


def _registered_execution_root(
    document: Mapping[str, object],
) -> tuple[Path, tuple[int, int]]:
    binding = document.get("execution_root")
    if (
        type(binding) is not dict
        or type(binding.get("path")) is not str
        or type(binding.get("device")) is not int
        or type(binding.get("inode")) is not int
    ):
        raise AssertionError("strict registered execution root binding is malformed")
    return Path(binding["path"]), (binding["device"], binding["inode"])


def _durable_deletion_receipt_path(
    entry_path: Path, delete_nonce: str
) -> Path:
    entry_match = _CHAIN_ENTRY_NAME_PATTERN.fullmatch(entry_path.name)
    if (
        entry_match is None
        or re.fullmatch(r"[0-9a-f]{32}", delete_nonce) is None
    ):
        raise AssertionError("strict deletion receipt selector is malformed")
    return entry_path.parent / (
        f".chain-{entry_match.group(1)}.delete-{delete_nonce}.json"
    )


def _exact_durable_deletion_receipt(
    entry_path: Path, document: Mapping[str, object]
) -> dict[str, object]:
    delete_nonce = document.get("execution_root_delete_nonce")
    token = document.get("token")
    session_id = document.get("session_id")
    root, identity = _registered_execution_root(document)
    vault = _active_strict_session().get("tombstones")
    if (
        type(delete_nonce) is not str
        or type(token) is not str
        or type(session_id) is not str
        or not isinstance(vault, Path)
    ):
        raise AssertionError("strict deletion receipt entry binding is malformed")
    vault_metadata = vault.lstat()
    receipt = _read_durable_deletion_receipt_file(
        _durable_deletion_receipt_path(entry_path, delete_nonce)
    )
    expected = {
        "schema_version": 2,
        "kind": "sealed-empty-tombstone",
        "token": token,
        "session_id": session_id,
        "delete_nonce": delete_nonce,
        "path": str(root),
        "device": identity[0],
        "inode": identity[1],
        "vault_device": vault_metadata.st_dev,
        "vault_inode": vault_metadata.st_ino,
        "tombstone_name": _sealed_tombstone_name(session_id, delete_nonce),
        "origin_absent": True,
        "tombstone_empty": True,
        "tombstone_owner_uid": 0,
        "tombstone_owner_gid": os.getgid(),
        "tombstone_mode": 0o710,
    }
    if receipt != expected:
        raise AssertionError("strict durable deletion receipt is not exact")
    return receipt


def _cleanup_registered_execution_root(
    entry_path: Path, document: Mapping[str, object]
) -> None:
    if document.get("cleanup_execution_root") is not True:
        return
    session = _active_strict_session()
    session_root = session.get("root")
    recovery_controller = document.get("recovery_controller_path")
    if not isinstance(session_root, Path) or type(recovery_controller) is not str:
        raise AssertionError("strict recovery session binding is malformed")
    root, identity = _registered_execution_root(document)
    if root == session_root:
        raise AssertionError("strict registered entry cannot delete its session root")
    if document.get("state") == "closing":
        document = _transition_trusted_root_chain(
            entry_path,
            ("closing",),
            "deleting",
            execution_root_delete_nonce=uuid.uuid4().hex,
        )
    if document.get("state") != "deleting":
        raise AssertionError("strict registered execution root is not deleting")
    _invoke_registered_resource_seal(
        Path(recovery_controller), entry_path, document
    )
    durable_receipt = _exact_durable_deletion_receipt(entry_path, document)
    deletion_receipt = {
        "kind": durable_receipt["kind"],
        "device": durable_receipt["device"],
        "inode": durable_receipt["inode"],
        "vault_device": durable_receipt["vault_device"],
        "vault_inode": durable_receipt["vault_inode"],
        "tombstone_name": durable_receipt["tombstone_name"],
    }
    imported_receipt = document.get("execution_root_deleted")
    if imported_receipt is None:
        _update_trusted_root_chain(
            entry_path,
            "deleting",
            execution_root_deleted=deletion_receipt,
        )
    elif imported_receipt != deletion_receipt:
        raise AssertionError(
            "strict registered deletion proof import is inconsistent"
        )
    try:
        root.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise AssertionError(
            "strict registered execution root deletion cannot be revalidated"
        ) from error
    raise AssertionError("strict sealed execution root origin still exists")


def _mark_trusted_root_chain_closed(entry_path: Path) -> None:
    with _chain_registry_lock(entry_path):
        document = _load_chain_registry_entry(entry_path)
        if document.get("state") == "closed":
            return
        if document.get("state") not in ("closing", "deleting"):
            raise AssertionError("strict chain registry cannot close before recovery")
        outer_value = document.get("outer")
        if outer_value is not None:
            outer = _parse_root_chain_identity(outer_value, "registered outer")
            _stable_host_session_zero(outer)
        _stable_uid_zero(int(document["target_uid"]))
        _cleanup_registered_execution_root(entry_path, document)
        final_document = _load_chain_registry_entry(entry_path)
        expected_state = (
            "deleting"
            if final_document.get("cleanup_execution_root") is True
            else "closing"
        )
        _transition_trusted_root_chain(
            entry_path, (expected_state,), "closed"
        )


def _discover_prepared_outer(
    document: Mapping[str, object],
) -> list[int] | None:
    marker = document.get("outer_marker")
    launcher_parent = document.get("launcher_parent")
    if marker is None and launcher_parent is None:
        return None
    if type(marker) is not str or launcher_parent is None:
        raise AssertionError("strict prepared outer recovery binding is malformed")
    _parse_root_chain_identity(launcher_parent, "registered launcher parent")
    marker_bytes = marker.encode("ascii")
    matches: list[list[int]] = []
    try:
        process_paths = sorted(
            (path for path in Path("/proc").iterdir() if path.name.isdecimal()),
            key=lambda path: int(path.name),
        )
    except OSError as error:
        raise AssertionError("strict prepared outer inventory is unavailable") from error
    for process_path in process_paths:
        identity = _process_identity(process_path)
        if (
            identity is None
            or identity[0] != identity[3]
            or identity[0] != identity[4]
            or identity[5] != (os.getuid(),) * 4
        ):
            continue
        try:
            with (process_path / "cmdline").open("rb") as command_file:
                command_bytes = command_file.read(65537)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise AssertionError(
                "strict prepared outer command line is unreadable"
            ) from error
        if len(command_bytes) > 65536:
            raise AssertionError("strict prepared outer command line is excessive")
        arguments = [value for value in command_bytes.split(b"\0") if value]
        if arguments.count(marker_bytes) == 1:
            matches.append(
                [identity[0], identity[1], identity[3], identity[4]]
            )
    if len(matches) > 1:
        raise AssertionError("strict prepared outer recovery marker is ambiguous")
    return None if not matches else matches[0]


def _recover_registered_entry(
    entry_path: Path, *, allow_recovery_broker: bool
) -> None:
    with _chain_registry_lock(entry_path):
        document = _load_chain_registry_entry(entry_path)
        if document.get("state") == "closed":
            return
        if document.get("state") == "prepared" and document.get("outer") is None:
            discovered_outer = _discover_prepared_outer(document)
            if discovered_outer is not None:
                document = _update_trusted_root_chain(
                    entry_path, "prepared", outer=discovered_outer
                )
        if document.get("state") not in ("closing", "deleting"):
            document = _transition_trusted_root_chain(
                entry_path,
                ("prepared", "outer-bound", "root-authorized"),
                "closing",
            )
        outer_value = document.get("outer")
        if outer_value is not None:
            outer = _parse_root_chain_identity(outer_value, "registered outer")
            if outer[0] != outer[2] or outer[0] != outer[3]:
                raise AssertionError("strict registered outer session is not unique")
            generation_is_anchored = _assert_registered_session_not_reused(outer)
            session_inventory = _host_session_inventory(outer[3])
            if session_inventory and not generation_is_anchored:
                raise AssertionError(
                    "strict registered host session lost its generation anchor"
                )
            if session_inventory:
                if not allow_recovery_broker:
                    raise AssertionError(
                        "strict recovery broker left its own registered session active"
                    )
                recovery_controller = Path(
                    str(document["recovery_controller_path"])
                )
                _invoke_registered_session_cleanup(
                    recovery_controller, entry_path, int(document["target_uid"])
                )
        _mark_trusted_root_chain_closed(entry_path)


def _registered_sudo_command(arguments: Sequence[str]) -> list[str]:
    return [str(_STRICT_PRIMITIVES["sudo"]), "-n", *arguments]


def _read_registered_bounded_file(
    output_file: IO[bytes], description: str, output_limit: int
) -> bytes:
    try:
        output_file.flush()
        metadata = os.fstat(output_file.fileno())
        output_file.seek(0)
        data = output_file.read(output_limit + 1)
    except OSError as error:
        raise AssertionError(
            f"strict registered sudo {description} is unreadable"
        ) from error
    if metadata.st_size != len(data) or len(data) > output_limit:
        raise AssertionError(
            f"strict registered sudo {description} is excessive or incomplete"
        )
    return data


def _registered_process_binding(
    identity: tuple[int, int, int, int, int, tuple[int, int, int, int]],
) -> list[int]:
    return [identity[0], identity[1], identity[3], identity[4]]


def _process_identity_document(
    identity: tuple[int, int, int, int, int, tuple[int, int, int, int]],
) -> dict[str, object]:
    return {
        "pid": identity[0],
        "start_time": identity[1],
        "parent_pid": identity[2],
        "process_group": identity[3],
        "session_id": identity[4],
        "uids": list(identity[5]),
    }


def _parse_process_identity_document(
    value: object, description: str
) -> tuple[int, int, int, int, int, tuple[int, int, int, int]]:
    if type(value) is not dict or set(value) != {
        "pid",
        "start_time",
        "parent_pid",
        "process_group",
        "session_id",
        "uids",
    }:
        raise AssertionError(
            f"strict root-active {description} identity is malformed"
        )
    uids = value.get("uids")
    integer_fields = (
        value.get("pid"),
        value.get("start_time"),
        value.get("parent_pid"),
        value.get("process_group"),
        value.get("session_id"),
    )
    if (
        any(type(item) is not int or item <= 0 for item in integer_fields)
        or type(uids) is not list
        or len(uids) != 4
        or any(type(item) is not int or item < 0 for item in uids)
    ):
        raise AssertionError(
            f"strict root-active {description} identity is malformed"
        )
    return (
        int(integer_fields[0]),
        int(integer_fields[1]),
        int(integer_fields[2]),
        int(integer_fields[3]),
        int(integer_fields[4]),
        (int(uids[0]), int(uids[1]), int(uids[2]), int(uids[3])),
    )


def _validate_registered_root_active(
    document: Mapping[str, object],
    *,
    nonce: str,
    outer: tuple[int, int, int, int],
    target_uid: int,
    expected_session_id: str | None = None,
) -> tuple[
    tuple[int, int, int, int, int, tuple[int, int, int, int]],
    tuple[int, int, int, int, int, tuple[int, int, int, int]],
    tuple[int, int, int, int, int, tuple[int, int, int, int]],
    tuple[int, int, int, int, int, tuple[int, int, int, int]],
]:
    if type(document) is not dict or set(document) != {
        "schema_version",
        "nonce",
        "root_handshake",
        "target_marker",
        "sudo_parent",
        "controller",
        "wrapper",
        "target",
    }:
        raise AssertionError("strict root-active document fields are inexact")
    sudo_parent = _parse_process_identity_document(
        document.get("sudo_parent"), "sudo parent"
    )
    controller = _parse_process_identity_document(
        document.get("controller"), "controller"
    )
    wrapper = _parse_process_identity_document(
        document.get("wrapper"), "wrapper"
    )
    target = _parse_process_identity_document(document.get("target"), "target")
    handshake = document.get("root_handshake")
    marker = document.get("target_marker")
    if (
        document.get("schema_version") != 1
        or document.get("nonce") != nonce
        or type(handshake) is not dict
        or set(handshake)
        != {
            "schema_version",
            "phase",
            "nonce",
            "session_id",
            "target_uid",
            "controller",
            "sudo_parent",
            "wrapper",
        }
        or handshake.get("schema_version") != 2
        or handshake.get("phase") != "wrapper-bound"
        or handshake.get("nonce") != nonce
        or re.fullmatch(r"[0-9a-f]{32}", str(handshake.get("session_id")))
        is None
        or (
            expected_session_id is not None
            and handshake.get("session_id") != expected_session_id
        )
        or handshake.get("target_uid") != target_uid
        or handshake.get("controller") != _registered_process_binding(controller)
        or handshake.get("sudo_parent") != _registered_process_binding(sudo_parent)
        or handshake.get("wrapper") != _registered_process_binding(wrapper)
        or type(marker) is not dict
        or marker
        != {
            "schema_version": 1,
            "nonce": nonce,
            "uid": target_uid,
            "gid": target_uid,
        }
    ):
        raise AssertionError("strict root-active handshake or marker is inexact")
    identities = (sudo_parent, controller, wrapper, target)
    if (
        sudo_parent[2] != outer[0]
        or controller[2] != sudo_parent[0]
        or wrapper[2] != controller[0]
        or target[2] != wrapper[0]
        or any(identity[4] != outer[3] for identity in identities[:3])
        or target[0] != target[3]
        or target[0] != target[4]
    ):
        raise AssertionError("strict root-active ancestry is invalid")
    if (
        sudo_parent[5][1] != 0
        or any(identity[5] != (0, 0, 0, 0) for identity in identities[1:3])
        or target[5] != (target_uid,) * 4
        or len({identity[0] for identity in identities}) != len(identities)
    ):
        raise AssertionError("strict root-active access identity is invalid")
    for identity, description in zip(
        identities,
        ("sudo parent", "controller", "wrapper", "target"),
        strict=True,
    ):
        observed = _process_identity(Path("/proc") / str(identity[0]))
        if observed != identity:
            raise AssertionError(
                f"strict root-active {description} identity changed"
            )
    return identities


def _wait_registered_root_active(
    output_file: IO[bytes],
    process: subprocess.Popen[bytes],
    *,
    nonce: str,
    session_id: str,
    outer: tuple[int, int, int, int],
    target_uid: int,
) -> tuple[
    dict[str, object],
    tuple[
        tuple[int, int, int, int, int, tuple[int, int, int, int]],
        tuple[int, int, int, int, int, tuple[int, int, int, int]],
        tuple[int, int, int, int, int, tuple[int, int, int, int]],
        tuple[int, int, int, int, int, tuple[int, int, int, int]],
    ],
]:
    expected_prefix = _ROOT_TARGET_ACTIVE_PREFIX.encode("ascii")
    deadline = time.monotonic() + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            metadata = os.fstat(output_file.fileno())
            data = os.pread(output_file.fileno(), 4097, 0)
        except OSError as error:
            raise AssertionError(
                "strict registered root-active ACK is unreadable"
            ) from error
        if metadata.st_size > 4096 or len(data) > 4096:
            raise AssertionError(
                "strict registered root-active ACK is excessive"
            )
        if not data or b"\n" not in data:
            if process.poll() is not None:
                raise AssertionError(
                    "strict registered outer exited before root-active ACK"
                )
            time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
            continue
        if (
            metadata.st_size != len(data)
            or not data.startswith(expected_prefix)
            or data.count(b"\n") != 1
            or not data.endswith(b"\n")
        ):
            raise AssertionError(
                "strict registered root-active ACK framing is malformed"
            )
        try:
            document = json.loads(data[len(expected_prefix) : -1])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AssertionError(
                "strict registered root-active ACK is malformed"
            ) from error
        identities = _validate_registered_root_active(
            document,
            nonce=nonce,
            outer=outer,
            target_uid=target_uid,
            expected_session_id=session_id,
        )
        return document, identities
    raise AssertionError("strict registered root-active ACK timed out")


def _read_registered_wrapper_ready(
    descriptor: int, process: subprocess.Popen[bytes]
) -> None:
    deadline = time.monotonic() + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    "strict registered wrapper post-gate readiness timed out"
                )
            readable, _, _ = select.select([descriptor], [], [], remaining)
            if readable:
                ready = os.read(descriptor, 2)
                break
            if process.poll() is not None:
                raise AssertionError(
                    "strict registered wrapper exited before post-gate readiness"
                )
    except OSError as error:
        raise AssertionError(
            "strict registered wrapper post-gate readiness is unreadable"
        ) from error
    if ready != b"R":
        raise AssertionError(
            "strict registered wrapper post-gate readiness is inexact"
        )


def _release_registered_wrapper_continuation(descriptor: int) -> None:
    try:
        if os.write(descriptor, b"C") != 1:
            raise AssertionError(
                "strict registered wrapper continuation write was incomplete"
            )
    except OSError as error:
        raise AssertionError(
            "strict registered wrapper continuation cannot be released"
        ) from error
    finally:
        os.close(descriptor)


def _publish_outer_owner_fault_ack(
    ack_path: Path,
    nonce: str,
    boundary: str,
    entry_path: Path,
    outer: tuple[int, int, int, int],
    *,
    wrapper_post_gate_ready: bool,
    root_active: Mapping[str, object] | None = None,
) -> None:
    if (
        boundary not in _OUTER_OWNER_FAULT_BOUNDARIES
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        or not ack_path.is_absolute()
    ):
        raise AssertionError("strict outer owner fault ACK selector is malformed")
    session = _active_strict_session()
    root = session.get("root")
    watchdog_identity = session.get("watchdog_identity")
    target_uid = session.get("target_uid")
    if (
        session.get("inherited") is not False
        or not isinstance(root, Path)
        or type(watchdog_identity) is not tuple
        or len(watchdog_identity) != 6
        or type(target_uid) is not int
    ):
        raise AssertionError("strict outer owner fault session is not independent")
    root_metadata = root.lstat()
    owner_identity = _process_identity(Path("/proc") / str(os.getpid()))
    if (
        owner_identity is None
        or owner_identity[0] != owner_identity[3]
        or owner_identity[0] != owner_identity[4]
        or owner_identity[5] != (os.getuid(),) * 4
    ):
        raise AssertionError("strict outer owner fault owner identity is invalid")
    outer_identity = _process_identity(Path("/proc") / str(outer[0]))
    if (
        outer_identity is None
        or _registered_process_binding(outer_identity) != list(outer)
        or outer_identity[2] != owner_identity[0]
        or outer_identity[0] != outer_identity[3]
        or outer_identity[0] != outer_identity[4]
        or outer_identity[5] != (os.getuid(),) * 4
        or watchdog_identity[2] != owner_identity[0]
        or watchdog_identity[0] != watchdog_identity[3]
        or watchdog_identity[0] != watchdog_identity[4]
        or watchdog_identity[5] != (os.getuid(),) * 4
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or entry_path.parent != root / "entries"
    ):
        raise AssertionError("strict outer owner fault process binding is invalid")
    with _chain_registry_lock(entry_path):
        document = _load_chain_registry_entry(entry_path)
    expected_state = {
        "after-outer-popen": "prepared",
        "after-outer-bound": "outer-bound",
        "after-root-authorized": "root-authorized",
        "after-root-authorized-barrier": "root-authorized",
        "after-target-active": "root-authorized",
    }[boundary]
    if document.get("state") != expected_state:
        raise AssertionError("strict outer owner fault entry state is inexact")
    document_outer = document.get("outer")
    if (
        (boundary == "after-outer-popen" and document_outer is not None)
        or (
            boundary != "after-outer-popen"
            and document_outer != list(outer)
        )
    ):
        raise AssertionError("strict outer owner fault entry binding is inexact")
    if wrapper_post_gate_ready is not (
        boundary
        in ("after-root-authorized-barrier", "after-target-active")
    ):
        raise AssertionError(
            "strict outer owner fault wrapper readiness is inexact"
        )
    if boundary == "after-target-active":
        if root_active is None:
            raise AssertionError(
                "strict outer owner root-active binding is missing"
            )
        _validate_registered_root_active(
            root_active,
            nonce=nonce,
            outer=outer,
            target_uid=target_uid,
            expected_session_id=str(document["session_id"]),
        )
    elif root_active is not None:
        raise AssertionError(
            "strict outer owner root-active binding is unexpected"
        )
    ack_document = {
        "schema_version": 1,
        "nonce": nonce,
        "boundary": boundary,
        "owner": _registered_process_binding(owner_identity),
        "registry_root": {
            "path": str(root),
            "device": root_metadata.st_dev,
            "inode": root_metadata.st_ino,
        },
        "entry": {
            "path": str(entry_path),
            "session_id": document["session_id"],
            "state": document["state"],
        },
        "outer": list(outer),
        "watchdog": _registered_process_binding(watchdog_identity),
        "target_uid": target_uid,
        "wrapper_post_gate_ready": wrapper_post_gate_ready,
        "root_active": (
            None if root_active is None else dict(root_active)
        ),
    }
    _atomic_json_document(
        ack_path,
        ack_document,
        expected_owner=os.getuid(),
        create=True,
    )


def _pause_at_outer_owner_fault_boundary(
    fault_probe: tuple[Path, str, str, int] | None,
    boundary: str,
    entry_path: Path,
    outer: tuple[int, int, int, int],
    *,
    wrapper_post_gate_ready: bool = False,
    root_active: Mapping[str, object] | None = None,
) -> None:
    if fault_probe is None or fault_probe[2] != boundary:
        return
    ack_path, nonce, selected_boundary, pause_descriptor = fault_probe
    _publish_outer_owner_fault_ack(
        ack_path,
        nonce,
        selected_boundary,
        entry_path,
        outer,
        wrapper_post_gate_ready=wrapper_post_gate_ready,
        root_active=root_active,
    )
    try:
        continuation = os.read(pause_descriptor, 1)
    except OSError as error:
        raise AssertionError(
            "strict outer owner fault pause channel is unreadable"
        ) from error
    raise AssertionError(
        "strict outer owner fault pause channel ended unexpectedly"
        + (" with data" if continuation else "")
    )


def _run_registered_sudo_under_gate(
    arguments: Sequence[str],
    *,
    timeout: float = 15,
    input_bytes: bytes = b"",
    cwd: Path | None = None,
    execution_root: Path | None = None,
    cleanup_execution_root: bool = False,
    handshake_path: Path | None = None,
    session_id: str | None = None,
    output_limit: int = 4096,
    recovery_broker: bool = False,
    trusted_fault_probe: tuple[Path, str, str, int] | None = None,
) -> bytes:
    if type(output_limit) is not int or output_limit <= 0:
        raise AssertionError("strict registered sudo output limit is invalid")
    if trusted_fault_probe is not None and (
        type(trusted_fault_probe) is not tuple
        or len(trusted_fault_probe) != 4
        or not isinstance(trusted_fault_probe[0], Path)
        or not trusted_fault_probe[0].is_absolute()
        or re.fullmatch(r"[0-9a-f]{32}", trusted_fault_probe[1]) is None
        or trusted_fault_probe[2] not in _OUTER_OWNER_FAULT_BOUNDARIES
        or type(trusted_fault_probe[3]) is not int
        or trusted_fault_probe[3] < 0
    ):
        raise AssertionError("strict registered outer fault probe is malformed")
    session = _active_strict_session()
    if trusted_fault_probe is not None and session.get("inherited") is not False:
        raise AssertionError(
            "strict registered outer fault probe requires an independent owner"
        )
    target_uid = int(session["target_uid"])
    selected_root = (
        Path(session["root"]) if execution_root is None else execution_root
    )
    selected_session_id = uuid.uuid4().hex if session_id is None else session_id
    if re.fullmatch(r"[0-9a-f]{32}", selected_session_id) is None:
        raise AssertionError("strict registered session identity is malformed")
    entries = session.get("entries")
    if not isinstance(entries, Path):
        raise AssertionError("strict registered entry directory is malformed")
    entry_path = entries / f"chain-{selected_session_id}.json"
    publication_nonce = uuid.uuid4().hex
    selected_root_binding = _execution_root_binding(selected_root)
    parent_identity = _process_identity(Path("/proc") / str(os.getpid()))
    if parent_identity is None:
        raise AssertionError("strict registered sudo parent identity is unavailable")
    outer_marker = f"required-ci-outer-{selected_session_id}"
    entry_owned = False
    barrier_read_fd = -1
    barrier_write_fd = -1
    continuation_read_fd = -1
    continuation_write_fd = -1
    ready_read_fd = -1
    ready_write_fd = -1
    process: subprocess.Popen[bytes] | None = None
    outer_pidfd: int | None = None
    stdout_file: IO[bytes] | None = None
    stderr_file: IO[bytes] | None = None
    stdout = b""
    stderr = b""
    timeout_error: subprocess.TimeoutExpired | None = None
    launch_error: BaseException | None = None
    recovery_error: BaseException | None = None
    outer_unreaped = False

    def mark_entry_owned() -> None:
        nonlocal entry_owned
        entry_owned = True

    try:
        registered_path = _register_trusted_root_chain(
            Path(session["controller_path"]),
            handshake_path,
            target_uid,
            execution_root=selected_root,
            cleanup_execution_root=cleanup_execution_root,
            session_id=selected_session_id,
            publication_nonce=publication_nonce,
            published_callback=mark_entry_owned,
        )
        if registered_path != entry_path:
            raise AssertionError(
                "strict registered publication path is inconsistent"
            )
        entry_owned = True
        _update_trusted_root_chain(
            entry_path,
            "prepared",
            launcher_parent=[
                parent_identity[0],
                parent_identity[1],
                parent_identity[3],
                parent_identity[4],
            ],
            outer_marker=outer_marker,
        )
        barrier_read_fd, barrier_write_fd = os.pipe2(os.O_CLOEXEC)
        continuation_read_fd, continuation_write_fd = os.pipe2(os.O_CLOEXEC)
        ready_read_fd, ready_write_fd = os.pipe2(os.O_CLOEXEC)
        command = [
            str(_STRICT_PRIMITIVES["python"]),
            *_ROOT_PYTHON_ARGUMENTS,
            "-c",
            _REGISTERED_SUDO_WRAPPER_SOURCE,
            str(parent_identity[0]),
            str(parent_identity[1]),
            str(barrier_read_fd),
            str(continuation_read_fd),
            str(ready_write_fd),
            str(output_limit),
            outer_marker,
            *_registered_sudo_command(arguments),
        ]
        stdout_file = tempfile.TemporaryFile()
        stderr_file = tempfile.TemporaryFile()
        process = subprocess.Popen(
            command,
            cwd=str(_TRUSTED_CHECKOUT_ROOT if cwd is None else cwd),
            env=_minimal_supervisor_environment(),
            stdin=subprocess.PIPE,
            stdout=stdout_file,
            stderr=stderr_file,
            pass_fds=(barrier_read_fd, continuation_read_fd, ready_write_fd),
            start_new_session=True,
        )
        os.close(barrier_read_fd)
        barrier_read_fd = -1
        os.close(continuation_read_fd)
        continuation_read_fd = -1
        os.close(ready_write_fd)
        ready_write_fd = -1
        outer_pidfd = os.pidfd_open(process.pid, 0)
        outer_identity = _process_identity(Path("/proc") / str(process.pid))
        if (
            outer_identity is None
            or outer_identity[0] != outer_identity[3]
            or outer_identity[0] != outer_identity[4]
            or outer_identity[5] != (os.getuid(),) * 4
        ):
            raise AssertionError("strict registered outer session binding is invalid")
        outer = [
            outer_identity[0],
            outer_identity[1],
            outer_identity[3],
            outer_identity[4],
        ]
        outer_binding = tuple(outer)
        _pause_at_outer_owner_fault_boundary(
            trusted_fault_probe,
            "after-outer-popen",
            entry_path,
            outer_binding,
        )
        _transition_trusted_root_chain(
            entry_path, ("prepared",), "outer-bound", outer=outer
        )
        _pause_at_outer_owner_fault_boundary(
            trusted_fault_probe,
            "after-outer-bound",
            entry_path,
            outer_binding,
        )
        _transition_trusted_root_chain(
            entry_path, ("outer-bound",), "root-authorized"
        )
        _pause_at_outer_owner_fault_boundary(
            trusted_fault_probe,
            "after-root-authorized",
            entry_path,
            outer_binding,
        )
        _release_wrapper_barrier(barrier_write_fd)
        barrier_write_fd = -1
        _read_registered_wrapper_ready(ready_read_fd, process)
        os.close(ready_read_fd)
        ready_read_fd = -1
        _pause_at_outer_owner_fault_boundary(
            trusted_fault_probe,
            "after-root-authorized-barrier",
            entry_path,
            outer_binding,
            wrapper_post_gate_ready=True,
        )
        _release_registered_wrapper_continuation(continuation_write_fd)
        continuation_write_fd = -1
        if trusted_fault_probe is not None and (
            trusted_fault_probe[2] == "after-target-active"
        ):
            if stdout_file is None:
                raise AssertionError(
                    "strict registered root-active output was not acquired"
                )
            root_active, _ = _wait_registered_root_active(
                stdout_file,
                process,
                nonce=trusted_fault_probe[1],
                session_id=selected_session_id,
                outer=outer_binding,
                target_uid=target_uid,
            )
            _pause_at_outer_owner_fault_boundary(
                trusted_fault_probe,
                "after-target-active",
                entry_path,
                outer_binding,
                wrapper_post_gate_ready=True,
                root_active=root_active,
            )
        try:
            process.communicate(input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            timeout_error = error
    except BaseException as error:
        launch_error = error
    finally:
        for descriptor in (
            barrier_read_fd,
            barrier_write_fd,
            continuation_read_fd,
            continuation_write_fd,
            ready_read_fd,
            ready_write_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if process is not None and process.stdin is not None:
            try:
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        if not entry_owned:
            try:
                entry_owned = _registered_entry_matches_publication_attempt(
                    entry_path,
                    session=session,
                    publication_nonce=publication_nonce,
                    execution_root_binding=selected_root_binding,
                    cleanup_execution_root=cleanup_execution_root,
                )
            except BaseException as error:
                recovery_error = error
        if entry_owned and recovery_error is None:
            try:
                _recover_registered_entry(
                    entry_path, allow_recovery_broker=not recovery_broker
                )
            except BaseException as error:
                recovery_error = error
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
            except BaseException as error:
                outer_unreaped = True
                if recovery_error is None:
                    recovery_error = AssertionError(
                        "strict registered outer anchor could not be reaped; "
                        "state retained"
                    )
                    recovery_error.__cause__ = error
        if outer_unreaped and recovery_error is None:
            recovery_error = AssertionError(
                "strict registered outer anchor could not be reaped; state retained"
            )
        if outer_pidfd is not None:
            os.close(outer_pidfd)
    output_error: BaseException | None = None
    try:
        if stdout_file is None or stderr_file is None:
            if launch_error is None:
                raise AssertionError(
                    "strict registered sudo output files were not acquired"
                )
        else:
            stdout = _read_registered_bounded_file(
                stdout_file, "stdout", output_limit
            )
            stderr = _read_registered_bounded_file(
                stderr_file, "stderr", output_limit
            )
    except BaseException as error:
        output_error = error
    finally:
        if stdout_file is not None:
            stdout_file.close()
        if stderr_file is not None:
            stderr_file.close()
    if recovery_error is not None:
        raise AssertionError(
            f"strict registered sudo recovery failed: {recovery_error}"
        ) from recovery_error
    if output_error is not None:
        raise AssertionError(
            f"strict registered sudo output validation failed: {output_error}"
        ) from output_error
    if timeout_error is not None:
        raise AssertionError("strict registered sudo command timed out") from timeout_error
    if launch_error is not None:
        raise AssertionError("strict registered sudo launch failed") from launch_error
    if process is None or process.returncode != 0 or stderr:
        decoded_stderr = stderr[:2000].decode("utf-8", errors="replace")
        raise AssertionError(
            "strict registered sudo command failed "
            f"with exit {None if process is None else process.returncode}: {decoded_stderr}"
        )
    return stdout


def _run_registered_sudo(
    arguments: Sequence[str],
    *,
    timeout: float = 15,
    input_bytes: bytes = b"",
    cwd: Path | None = None,
    execution_root: Path | None = None,
    cleanup_execution_root: bool = False,
    handshake_path: Path | None = None,
    session_id: str | None = None,
    output_limit: int = 4096,
    recovery_broker: bool = False,
    trusted_fault_probe: tuple[Path, str, str, int] | None = None,
) -> bytes:
    strict_isolation_platform_preflight()
    with _registry_session_gate(exclusive=False):
        return _run_registered_sudo_under_gate(
            arguments,
            timeout=timeout,
            input_bytes=input_bytes,
            cwd=cwd,
            execution_root=execution_root,
            cleanup_execution_root=cleanup_execution_root,
            handshake_path=handshake_path,
            session_id=session_id,
            output_limit=output_limit,
            recovery_broker=recovery_broker,
            trusted_fault_probe=trusted_fault_probe,
        )


_CHAIN_ENTRY_NAME_PATTERN = re.compile(r"chain-([0-9a-f]{32})\.json")
_CHAIN_STAGING_NAME_PATTERN = re.compile(
    r"\.(chain-([0-9a-f]{32})\.json)\.tmp-[0-9a-f]{32}"
)
_DELETE_RECEIPT_NAME_PATTERN = re.compile(
    r"\.chain-([0-9a-f]{32})\.delete-([0-9a-f]{32})\.json"
)
_DELETE_RECEIPT_STAGING_NAME_PATTERN = re.compile(
    r"\.(\.chain-([0-9a-f]{32})\.delete-([0-9a-f]{32})\.json)"
    r"\.tmp-[0-9a-f]{32}"
)


def _read_durable_deletion_receipt_file(
    path: Path, *, allowed_links: frozenset[int] = frozenset((1,))
) -> dict[str, object]:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        metadata = os.fstat(descriptor)
        if (
            not path.is_absolute()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != os.getgid()
            or metadata.st_nlink not in allowed_links
            or stat.S_IMODE(metadata.st_mode) != 0o640
            or metadata.st_size > 4096
        ):
            raise AssertionError("strict durable deletion receipt is unsafe")
        chunks: list[bytes] = []
        remaining = 4097
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        revalidated = os.fstat(descriptor)
    except OSError as error:
        raise AssertionError(
            "strict durable deletion receipt is unreadable"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if any(
        getattr(metadata, field) != getattr(revalidated, field)
        for field in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
        )
    ) or len(data) != metadata.st_size:
        raise AssertionError(
            "strict durable deletion receipt could not be revalidated"
        )
    try:
        receipt = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(
            "strict durable deletion receipt is malformed"
        ) from error
    session = _active_strict_session()
    name_match = _DELETE_RECEIPT_NAME_PATTERN.fullmatch(path.name)
    staged_name_match = _DELETE_RECEIPT_STAGING_NAME_PATTERN.fullmatch(path.name)
    name_session_id = (
        name_match.group(1)
        if name_match is not None
        else (
            staged_name_match.group(2)
            if staged_name_match is not None
            else None
        )
    )
    name_delete_nonce = (
        name_match.group(2)
        if name_match is not None
        else (
            staged_name_match.group(3)
            if staged_name_match is not None
            else None
        )
    )
    if (
        type(receipt) is not dict
        or receipt.get("schema_version") != 2
        or receipt.get("kind") != "sealed-empty-tombstone"
        or receipt.get("token") != session.get("token")
        or type(receipt.get("session_id")) is not str
        or type(receipt.get("delete_nonce")) is not str
        or type(receipt.get("path")) is not str
        or not Path(str(receipt.get("path"))).is_absolute()
        or type(receipt.get("device")) is not int
        or type(receipt.get("inode")) is not int
        or type(receipt.get("vault_device")) is not int
        or type(receipt.get("vault_inode")) is not int
        or type(receipt.get("tombstone_name")) is not str
        or receipt.get("tombstone_name")
        != _sealed_tombstone_name(
            str(receipt.get("session_id")),
            str(receipt.get("delete_nonce")),
        )
        or receipt.get("origin_absent") is not True
        or receipt.get("tombstone_empty") is not True
        or receipt.get("tombstone_owner_uid") != 0
        or receipt.get("tombstone_owner_gid") != os.getgid()
        or receipt.get("tombstone_mode") != 0o710
        or name_session_id is None
        or receipt.get("session_id") != name_session_id
        or receipt.get("delete_nonce") != name_delete_nonce
    ):
        raise AssertionError("strict durable deletion receipt binding is invalid")
    return receipt


def _recover_deletion_receipt_staging(entries: Path) -> None:
    def retire_incomplete(staged_path: Path) -> None:
        try:
            metadata = staged_path.lstat()
        except OSError as error:
            raise AssertionError(
                "strict durable deletion receipt staging is unreadable"
            ) from error
        selected_mode = stat.S_IMODE(metadata.st_mode)
        if (
            not staged_path.is_absolute()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or metadata.st_size > 4096
            or (
                (metadata.st_gid, selected_mode)
                not in (
                    (0, 0o600),
                    (os.getgid(), 0o600),
                    (os.getgid(), 0o640),
                )
            )
        ):
            raise AssertionError(
                "strict incomplete deletion receipt staging is unsafe"
            )
        try:
            staged_path.unlink()
            _fsync_directory(entries)
        except OSError as error:
            raise AssertionError(
                "strict incomplete deletion receipt staging cannot be retired"
            ) from error

    staged_by_final: dict[Path, list[Path]] = {}
    for path in entries.iterdir():
        match = _DELETE_RECEIPT_STAGING_NAME_PATTERN.fullmatch(path.name)
        if match is not None:
            staged_by_final.setdefault(entries / match.group(1), []).append(path)
    for final_path, staged_paths in staged_by_final.items():
        if len(staged_paths) != 1:
            raise AssertionError(
                "strict durable deletion receipt staging is ambiguous"
            )
        staged_path = staged_paths[0]
        try:
            final_metadata = final_path.lstat()
        except FileNotFoundError:
            final_metadata = None
        if final_metadata is None:
            retire_incomplete(staged_path)
            continue
        final_identity = (final_metadata.st_dev, final_metadata.st_ino)
        staged_metadata = staged_path.lstat()
        staged_identity = (staged_metadata.st_dev, staged_metadata.st_ino)
        if final_identity == staged_identity:
            _read_durable_deletion_receipt_file(
                final_path, allowed_links=frozenset((2,))
            )
            try:
                staged_path.unlink()
                _fsync_directory(entries)
            except OSError as error:
                raise AssertionError(
                    "strict linked deletion receipt staging cannot be retired"
                ) from error
            _read_durable_deletion_receipt_file(final_path)
            continue
        else:
            _read_durable_deletion_receipt_file(final_path)
        retire_incomplete(staged_path)


def _recover_chain_registry_staging(entries: Path) -> None:
    _recover_deletion_receipt_staging(entries)
    staged_by_final: dict[Path, list[Path]] = {}
    for path in entries.iterdir():
        match = _CHAIN_STAGING_NAME_PATTERN.fullmatch(path.name)
        if match is not None:
            staged_by_final.setdefault(entries / match.group(1), []).append(path)
    for final_path, staged_paths in staged_by_final.items():
        if len(staged_paths) != 1:
            raise AssertionError(
                "strict chain registry has ambiguous staged documents"
            )
        staged_path = staged_paths[0]
        try:
            staged_metadata = staged_path.lstat()
        except OSError as error:
            raise AssertionError(
                "strict chain registry staged document is unreadable"
            ) from error
        if (
            not stat.S_ISREG(staged_metadata.st_mode)
            or staged_metadata.st_uid != os.getuid()
            or stat.S_IMODE(staged_metadata.st_mode) != 0o600
        ):
            raise AssertionError("strict chain registry staged document is unsafe")
        try:
            final_metadata = final_path.lstat()
        except FileNotFoundError:
            final_metadata = None
        except OSError as error:
            raise AssertionError(
                "strict chain registry final document is unreadable"
            ) from error
        if final_metadata is None:
            if staged_metadata.st_nlink != 1:
                raise AssertionError(
                    "strict chain registry unpublished document has aliases"
                )
            try:
                document = _load_chain_registry_entry(staged_path)
            except AssertionError:
                try:
                    staged_path.unlink()
                    _fsync_directory(entries)
                except OSError as error:
                    raise AssertionError(
                        "strict chain registry incomplete staged create cannot be retired"
                    ) from error
                continue
            expected_session_id = _CHAIN_ENTRY_NAME_PATTERN.fullmatch(
                final_path.name
            )
            if (
                expected_session_id is None
                or document.get("session_id") != expected_session_id.group(1)
                or document.get("state") != "prepared"
            ):
                raise AssertionError(
                    "strict chain registry staged create intent is invalid"
                )
            try:
                _rename_noreplace(staged_path, final_path)
                _fsync_directory(entries)
            except OSError as error:
                raise AssertionError(
                    "strict chain registry staged create cannot be published"
                ) from error
            continue
        final_identity = (final_metadata.st_dev, final_metadata.st_ino)
        staged_identity = (staged_metadata.st_dev, staged_metadata.st_ino)
        if final_identity == staged_identity:
            if final_metadata.st_nlink != 2 or staged_metadata.st_nlink != 2:
                raise AssertionError(
                    "strict chain registry linked create intent is unsafe"
                )
        else:
            _load_chain_registry_entry(final_path)
            if staged_metadata.st_nlink != 1:
                raise AssertionError(
                    "strict chain registry abandoned update has aliases"
                )
        try:
            staged_path.unlink()
            _fsync_directory(entries)
        except OSError as error:
            raise AssertionError(
                "strict chain registry staged document cannot be retired"
            ) from error


def _chain_registry_entries(
    entries: Path, *, recover_staging: bool = False
) -> list[Path]:
    try:
        if recover_staging:
            _recover_chain_registry_staging(entries)
        paths = list(entries.iterdir())
    except OSError as error:
        raise AssertionError("strict chain registry cannot be inspected") from error
    selected: list[Path] = []
    for path in paths:
        if _CHAIN_ENTRY_NAME_PATTERN.fullmatch(path.name):
            selected.append(path)
        elif _CHAIN_STAGING_NAME_PATTERN.fullmatch(path.name):
            continue
        elif _DELETE_RECEIPT_NAME_PATTERN.fullmatch(path.name):
            continue
        elif _DELETE_RECEIPT_STAGING_NAME_PATTERN.fullmatch(path.name):
            continue
        elif not re.fullmatch(r"\.chain-[0-9a-f]{32}\.json\.lock", path.name):
            raise AssertionError("strict chain registry contains an unknown entry")
    return sorted(selected, key=lambda path: path.name)


def _trusted_root_chain_is_pending(handshake_path: Path) -> bool:
    registry = _active_strict_session().get("entries")
    if not isinstance(registry, Path):
        raise AssertionError("strict chain registry path is malformed")
    for entry_path in _chain_registry_entries(registry):
        document = _load_chain_registry_entry(entry_path)
        if document.get("handshake_path") == str(handshake_path):
            return document.get("state") != "closed"
    return False


def _read_watchdog_line(
    stream: IO[bytes], timeout_seconds: float, description: str
) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    line = bytearray()
    try:
        while len(line) <= 4096:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"strict registry watchdog {description} timed out"
                )
            readable, _, _ = select.select(
                [stream.fileno()], [], [], remaining
            )
            if not readable:
                raise AssertionError(
                    f"strict registry watchdog {description} timed out"
                )
            chunk = os.read(stream.fileno(), 1)
            if not chunk:
                break
            line.extend(chunk)
            if chunk == b"\n":
                return bytes(line)
    except OSError as error:
        raise AssertionError(
            f"strict registry watchdog {description} is unreadable"
        ) from error
    raise AssertionError(f"strict registry watchdog {description} is malformed")


def _registry_watchdog_heartbeat(
    stream: IO[bytes],
    stop_event: threading.Event,
    write_lock: threading.Lock,
    failures: list[str],
) -> None:
    while not stop_event.wait(_STRICT_WATCHDOG_HEARTBEAT_SECONDS):
        try:
            with write_lock:
                stream.write(b"H\n")
                stream.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            failures.append(f"{type(error).__name__}: {error}")
            return


def _registry_watchdog_lock_descriptor() -> int:
    realm = _strict_realm()
    lock = realm.get("lock")
    descriptor = (
        lock.fileno()
        if lock is not None and hasattr(lock, "fileno")
        else realm.get("inherited_lock_fd")
    )
    if type(descriptor) is not int:
        raise AssertionError("strict registry watchdog realm lock is unavailable")
    return descriptor


def _drain_authorized_watchdog_launch(
    launch: Mapping[str, object], watchdog_token: str
) -> None:
    process = launch.get("process")
    pidfd = launch.get("pidfd")
    identity = launch.get("identity")
    stop_event = launch.get("stop_event")
    write_lock = launch.get("write_lock")
    heartbeat = launch.get("heartbeat")
    if (
        not isinstance(process, subprocess.Popen)
        or type(pidfd) is not int
        or type(identity) is not tuple
        or len(identity) != 6
        or type(watchdog_token) is not str
        or process.stdin is None
        or process.stdout is None
    ):
        raise AssertionError(
            "strict authorized watchdog abort state is malformed"
        )
    if isinstance(stop_event, threading.Event):
        stop_event.set()
    if isinstance(heartbeat, threading.Thread):
        try:
            if heartbeat.is_alive():
                heartbeat.join(
                    timeout=_STRICT_WATCHDOG_HEARTBEAT_SECONDS * 2
                )
            if heartbeat.is_alive():
                raise AssertionError(
                    "strict authorized watchdog heartbeat did not stop"
                )
        except RuntimeError as error:
            raise AssertionError(
                "strict authorized watchdog heartbeat cannot be joined"
            ) from error
    observed = _process_identity(Path("/proc") / str(process.pid))
    if observed != identity:
        raise AssertionError(
            "strict authorized watchdog identity changed before abort"
        )
    try:
        signal.pidfd_send_signal(pidfd, 0, None, 0)
    except (ProcessLookupError, OSError) as error:
        raise AssertionError(
            "strict authorized watchdog pidfd is not alive"
        ) from error
    lock_context = (
        write_lock
        if hasattr(write_lock, "__enter__")
        else nullcontext()
    )
    with lock_context:
        process.stdin.write(b"D\n")
        process.stdin.flush()
    result_line = _read_watchdog_line(
        process.stdout,
        CANDIDATE_PROCESS_TIMEOUT_SECONDS
        + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS,
        "authorized abort result",
    )
    expected_ready = f"{_WATCHDOG_READY_PREFIX}{watchdog_token}\n".encode(
        "ascii"
    )
    if result_line == expected_ready:
        result_line = _read_watchdog_line(
            process.stdout,
            CANDIDATE_PROCESS_TIMEOUT_SECONDS
            + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS,
            "authorized abort result",
        )
    process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
    prefix = _WATCHDOG_RESULT_PREFIX.encode("ascii")
    if not result_line.startswith(prefix):
        raise AssertionError(
            "strict authorized watchdog abort result prefix is invalid"
        )
    try:
        result = json.loads(result_line[len(prefix) :])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(
            "strict authorized watchdog abort result is malformed"
        ) from error
    if (
        type(result) is not dict
        or result.get("status") != "complete"
        or result.get("token") != watchdog_token
        or process.returncode != 0
    ):
        raise AssertionError(
            "strict authorized watchdog abort cleanup was incomplete"
        )


def _start_registry_watchdog(session: dict[str, object]) -> None:
    controller_path = session.get("controller_path")
    environment = session.get("environment")
    watchdog_token = session.get("watchdog_token")
    if (
        not isinstance(controller_path, Path)
        or not isinstance(environment, dict)
        or type(watchdog_token) is not str
    ):
        raise AssertionError("strict registry watchdog session is malformed")
    if any(
        key in session
        for key in (
            "watchdog_process",
            "watchdog_pidfd",
            "watchdog_identity",
            "watchdog_bootstrapping",
            "watchdog_launch",
        )
    ):
        raise AssertionError(
            "strict registry watchdog launch would overwrite recovery state"
        )
    parent_identity = _process_identity(Path("/proc") / str(os.getpid()))
    if parent_identity is None:
        raise AssertionError("strict registry watchdog parent is unavailable")
    lock_descriptor = _registry_watchdog_lock_descriptor()
    realm = _strict_realm()
    child_environment = _minimal_supervisor_environment()
    child_environment.update(
        {
            ISOLATION_MODE_ENV: STRICT_ISOLATION_MODE,
            _ISOLATION_UID_ENV: str(realm["uid"]),
            _ISOLATION_GID_ENV: str(realm["gid"]),
            _ISOLATION_LOCK_FD_ENV: str(lock_descriptor),
            _ISOLATION_WATCHDOG_TOKEN_ENV: watchdog_token,
            **{str(key): str(value) for key, value in environment.items()},
        }
    )
    stderr_file: IO[bytes] | None = None
    process: subprocess.Popen[bytes] | None = None
    pidfd: int | None = None
    identity: tuple[int, int, int, int, int, tuple[int, int, int, int]] | None = None
    stop_event: threading.Event | None = None
    write_lock: threading.Lock | None = None
    failures: list[str] | None = None
    heartbeat: threading.Thread | None = None
    gate_read_fd = -1
    gate_write_fd = -1
    launch: dict[str, object] = {
        "phase": "allocated",
        "process": None,
        "pidfd": None,
        "identity": None,
        "stderr": None,
        "gate_read_fd": -1,
        "gate_write_fd": -1,
        "stop_event": None,
        "write_lock": None,
        "failures": None,
        "heartbeat": None,
        "authorized": False,
    }
    session["watchdog_launch"] = launch
    session["watchdog_bootstrapping"] = True
    session["watchdog_closing"] = True
    try:
        gate_read_fd, gate_write_fd = os.pipe2(os.O_CLOEXEC)
        launch["gate_read_fd"] = gate_read_fd
        launch["gate_write_fd"] = gate_write_fd
        stderr_file = tempfile.TemporaryFile()
        launch["stderr"] = stderr_file
        previous_signal_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            {
                signal.SIGHUP,
                signal.SIGINT,
                signal.SIGQUIT,
                signal.SIGTERM,
            },
        )
        try:
            process = subprocess.Popen(
                [
                    str(_STRICT_PRIMITIVES["python"]),
                    *_ROOT_PYTHON_ARGUMENTS,
                    str(controller_path),
                    "--isolation-registry-watchdog",
                    str(parent_identity[0]),
                    str(parent_identity[1]),
                    str(parent_identity[3]),
                    str(parent_identity[4]),
                    watchdog_token,
                    str(gate_read_fd),
                ],
                cwd=str(_TRUSTED_CHECKOUT_ROOT),
                env=child_environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                pass_fds=(lock_descriptor, gate_read_fd),
                start_new_session=True,
            )
            launch["process"] = process
            launch["phase"] = "spawned-gated"
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
        os.close(gate_read_fd)
        gate_read_fd = -1
        launch["gate_read_fd"] = -1
        if process.stdin is None or process.stdout is None:
            raise AssertionError("strict registry watchdog pipes are unavailable")
        pidfd = os.pidfd_open(process.pid, 0)
        launch["pidfd"] = pidfd
        launch["phase"] = "pidfd-bound"
        identity = _process_identity(Path("/proc") / str(process.pid))
        if (
            identity is None
            or identity[0] != identity[3]
            or identity[0] != identity[4]
            or identity[5] != (os.getuid(),) * 4
        ):
            raise AssertionError("strict registry watchdog identity is invalid")
        launch["identity"] = identity
        launch["authorized"] = True
        launch["phase"] = "authorizing"
        if os.write(gate_write_fd, b"G") != 1:
            raise AssertionError(
                "strict registry watchdog bootstrap gate could not be released"
            )
        os.close(gate_write_fd)
        gate_write_fd = -1
        launch["gate_write_fd"] = -1
        launch["phase"] = "authorized"
        ready = _read_watchdog_line(
            process.stdout,
            _STRICT_WATCHDOG_TIMEOUT_SECONDS,
            "readiness",
        )
        expected_ready = f"{_WATCHDOG_READY_PREFIX}{watchdog_token}\n".encode(
            "ascii"
        )
        if ready != expected_ready:
            raise AssertionError("strict registry watchdog readiness is inexact")
        stop_event = threading.Event()
        write_lock = threading.Lock()
        failures = []
        heartbeat = threading.Thread(
            target=_registry_watchdog_heartbeat,
            args=(process.stdin, stop_event, write_lock, failures),
            name="required-ci-registry-watchdog-heartbeat",
            daemon=True,
        )
        launch.update(
            {
                "stop_event": stop_event,
                "write_lock": write_lock,
                "failures": failures,
                "heartbeat": heartbeat,
                "phase": "ready",
            }
        )
        heartbeat.start()
        session.update(
            {
                "watchdog_process": process,
                "watchdog_pidfd": pidfd,
                "watchdog_identity": identity,
                "watchdog_stderr": stderr_file,
                "watchdog_stop": stop_event,
                "watchdog_write_lock": write_lock,
                "watchdog_failures": failures,
                "watchdog_heartbeat": heartbeat,
                "watchdog_closing": False,
            }
        )
        session.pop("watchdog_bootstrapping", None)
        session.pop("watchdog_launch", None)
    except BaseException as launch_error:
        if process is not None:
            launch["process"] = process
        if pidfd is not None:
            launch["pidfd"] = pidfd
        if identity is not None:
            launch["identity"] = identity
        if stderr_file is not None:
            launch["stderr"] = stderr_file
        if stop_event is not None:
            launch["stop_event"] = stop_event
        if write_lock is not None:
            launch["write_lock"] = write_lock
        if failures is not None:
            launch["failures"] = failures
        if heartbeat is not None:
            launch["heartbeat"] = heartbeat
        if isinstance(stop_event, threading.Event):
            stop_event.set()
        launch["phase"] = "retiring"
        for descriptor in (gate_read_fd, gate_write_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        launch["gate_read_fd"] = -1
        launch["gate_write_fd"] = -1
        authorized_abort_error: BaseException | None = None
        if launch.get("authorized") is True:
            try:
                _drain_authorized_watchdog_launch(
                    launch, watchdog_token
                )
            except BaseException as error:
                authorized_abort_error = error
        cleanup_failures = _retire_registry_watchdog_handles(
            session,
            terminate=pidfd is not None
            and launch.get("authorized") is not True,
        )
        if authorized_abort_error is not None:
            cleanup_failures.append(
                f"watchdog authorized abort: {authorized_abort_error}"
            )
        if process is None and stderr_file is not None and not stderr_file.closed:
            try:
                stderr_file.close()
            except BaseException as error:
                cleanup_failures.append(f"watchdog stderr close: {error}")
        if (
            isinstance(process, subprocess.Popen)
            and process.poll() is None
        ):
            session["watchdog_bootstrapping"] = True
            raise AssertionError(
                "strict registry watchdog launch failed with a live gated child; "
                f"recovery state retained: {launch_error}; "
                + "; ".join(cleanup_failures)
            ) from launch_error
        raise


def _assert_registry_watchdog_alive(session: Mapping[str, object]) -> None:
    inherited = session.get("inherited")
    if inherited is True:
        return
    if inherited is not False:
        raise AssertionError(
            "strict registry watchdog ownership is malformed"
        )
    process = session.get("watchdog_process")
    pidfd = session.get("watchdog_pidfd")
    identity = session.get("watchdog_identity")
    stop_event = session.get("watchdog_stop")
    write_lock = session.get("watchdog_write_lock")
    heartbeat = session.get("watchdog_heartbeat")
    failures = session.get("watchdog_failures")
    if (
        session.get("watchdog_closing") is not False
        or session.get("watchdog_bootstrapping") is not None
        or not isinstance(process, subprocess.Popen)
        or process.poll() is not None
        or type(pidfd) is not int
        or type(identity) is not tuple
        or len(identity) != 6
        or type(process.pid) is not int
        or identity[0] != process.pid
        or not isinstance(stop_event, threading.Event)
        or stop_event.is_set()
        or not hasattr(write_lock, "acquire")
        or not isinstance(heartbeat, threading.Thread)
        or not heartbeat.is_alive()
        or type(failures) is not list
        or process.stdin is None
        or process.stdout is None
    ):
        raise AssertionError("strict registry watchdog active state is malformed")
    observed_identity = _process_identity(Path("/proc") / str(process.pid))
    if observed_identity != identity:
        raise AssertionError("strict registry watchdog identity changed")
    try:
        signal.pidfd_send_signal(pidfd, 0, None, 0)
    except (ProcessLookupError, OSError) as error:
        raise AssertionError("strict registry watchdog pidfd is not alive") from error
    if failures:
        raise AssertionError(
            f"strict registry watchdog heartbeat failed: {failures[-1]}"
        )


def _watchdog_client_inventory(
    registry_path: Path, registry_token: str
) -> dict[int, tuple[int, int, int, int, int, tuple[int, int, int, int]]]:
    expected_registry = (
        f"{_ISOLATION_REGISTRY_ENV}={registry_path}".encode("ascii")
    )
    expected_token = (
        f"{_ISOLATION_REGISTRY_TOKEN_ENV}={registry_token}".encode("ascii")
    )
    inventory: dict[
        int, tuple[int, int, int, int, int, tuple[int, int, int, int]]
    ] = {}
    for process_path in Path("/proc").iterdir():
        if not process_path.name.isdecimal() or int(process_path.name) == os.getpid():
            continue
        identity = _process_identity(process_path)
        if identity is None or identity[5] != (os.getuid(),) * 4:
            continue
        try:
            environment = (process_path / "environ").read_bytes()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        except OSError as error:
            raise AssertionError(
                "strict registry watchdog client environment is unreadable"
            ) from error
        if len(environment) > 65536:
            raise AssertionError(
                "strict registry watchdog client environment is excessive"
            )
        values = set(environment.split(b"\0"))
        if expected_registry in values and expected_token in values:
            inventory[identity[0]] = identity
    return inventory


def _watchdog_close_runner_clients(
    registry_path: Path, registry_token: str
) -> None:
    zero_count = 0
    deadline = time.monotonic() + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        inventory = _watchdog_client_inventory(registry_path, registry_token)
        if not inventory:
            zero_count += 1
            if zero_count >= _STRICT_ZERO_SCAN_COUNT:
                return
        else:
            zero_count = 0
            for identity in inventory.values():
                _root_signal_host_identity(identity, signal.SIGKILL)
        time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
    raise AssertionError("strict registry watchdog clients are not quiescent")


def _registry_watchdog_replay(
    parent_identity: tuple[int, int, int, int],
    session: dict[str, object] | None,
) -> None:
    observed_parent = _process_identity(
        Path("/proc") / str(parent_identity[0])
    )
    if observed_parent is not None:
        parent_identity_changed = (
            observed_parent[1] != parent_identity[1]
            or observed_parent[3] != parent_identity[2]
            or observed_parent[4] != parent_identity[3]
            or observed_parent[5] != (os.getuid(),) * 4
        )
        if not parent_identity_changed:
            _root_signal_host_identity(observed_parent, signal.SIGKILL)
    selected_session = (
        _current_strict_session_unchecked() if session is None else session
    )
    environment = selected_session.get("environment")
    if not isinstance(environment, dict):
        raise AssertionError(
            "strict registry watchdog environment is malformed"
        )
    _watchdog_close_runner_clients(
        Path(str(environment[_ISOLATION_REGISTRY_ENV])),
        str(environment[_ISOLATION_REGISTRY_TOKEN_ENV]),
    )
    close_trusted_isolation_chains(selected_session)


def _registry_watchdog_replay_until_complete(
    parent_identity: tuple[int, int, int, int],
    session: dict[str, object] | None,
) -> None:
    delay = _STRICT_WATCHDOG_REPLAY_BACKOFF_INITIAL_SECONDS
    while True:
        try:
            _registry_watchdog_replay(parent_identity, session)
            return
        except BaseException:
            time.sleep(delay)
            delay = min(
                delay * 2,
                _STRICT_WATCHDOG_REPLAY_BACKOFF_MAX_SECONDS,
            )


def _registry_watchdog_main(arguments: Sequence[str]) -> int:
    token = "unknown"
    result: dict[str, object]
    recovery_responsibility = len(arguments) == 5
    recovery_completed = False
    session: dict[str, object] | None = None
    parent_identity: tuple[int, int, int, int] | None = None
    try:
        if len(arguments) not in (5, 6):
            raise AssertionError("strict registry watchdog arguments are malformed")
        (
            parent_pid_value,
            parent_start_value,
            parent_pgrp_value,
            parent_sid_value,
            token,
        ) = arguments[:5]
        if not all(
            value.isdecimal()
            for value in (
                parent_pid_value,
                parent_start_value,
                parent_pgrp_value,
                parent_sid_value,
            )
        ) or re.fullmatch(r"[0-9a-f]{32}", token) is None:
            raise AssertionError("strict registry watchdog identity is malformed")
        parent_identity = (
            int(parent_pid_value),
            int(parent_start_value),
            int(parent_pgrp_value),
            int(parent_sid_value),
        )
        if len(arguments) == 6:
            gate_value = arguments[5]
            if not gate_value.isdecimal():
                raise AssertionError(
                    "strict registry watchdog bootstrap gate is malformed"
                )
            gate_fd = int(gate_value)
            try:
                readable, _, _ = select.select(
                    [gate_fd], [], [], _STRICT_WATCHDOG_TIMEOUT_SECONDS
                )
                gate = os.read(gate_fd, 1) if readable else b""
            finally:
                os.close(gate_fd)
            if gate != b"G":
                raise AssertionError(
                    "strict registry watchdog bootstrap was not authorized"
                )
            recovery_responsibility = True
        elif __name__ == "__main__":
            raise AssertionError(
                "strict registry watchdog bootstrap gate is required"
            )
        strict_isolation_platform_preflight()
        session = _active_strict_session()
        if session.get("watchdog_authorized") is not True:
            raise AssertionError("strict registry watchdog is unauthorized")
        print(f"{_WATCHDOG_READY_PREFIX}{token}", flush=True)
        deadline = time.monotonic() + _STRICT_WATCHDOG_TIMEOUT_SECONDS
        buffer = b""
        drain_requested = False
        owner_lost = False
        while not drain_requested and not owner_lost:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                owner_lost = True
                break
            readable, _, _ = select.select([sys.stdin.fileno()], [], [], remaining)
            if not readable:
                owner_lost = True
                break
            data = os.read(sys.stdin.fileno(), 64)
            if not data:
                owner_lost = True
                break
            buffer += data
            if len(buffer) > 64:
                raise AssertionError("strict registry watchdog control is excessive")
            while b"\n" in buffer:
                frame, buffer = buffer.split(b"\n", 1)
                if frame == b"H":
                    deadline = time.monotonic() + _STRICT_WATCHDOG_TIMEOUT_SECONDS
                elif frame == b"D":
                    drain_requested = True
                    break
                else:
                    raise AssertionError(
                        "strict registry watchdog control is malformed"
                    )
        if owner_lost:
            if parent_identity is None:
                raise AssertionError(
                    "strict registry watchdog parent binding is unavailable"
                )
            _registry_watchdog_replay_until_complete(
                parent_identity, session
            )
            recovery_completed = True
        else:
            close_trusted_isolation_chains(session)
        result = {"status": "complete", "token": token}
    except BaseException as error:
        recovery_error: BaseException | None = None
        if (
            recovery_responsibility
            and not recovery_completed
            and parent_identity is not None
        ):
            try:
                _registry_watchdog_replay_until_complete(
                    parent_identity, session
                )
                recovery_completed = True
            except BaseException as replay_error:
                recovery_error = replay_error
        result = {
            "status": "incomplete",
            "token": token,
            "error": (
                f"{type(error).__name__}: {error}"
                + (
                    "; recovery: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                    if recovery_error is not None
                    else ""
                )
            ),
        }
    try:
        print(
            _WATCHDOG_RESULT_PREFIX
            + json.dumps(result, sort_keys=True, separators=(",", ":")),
            flush=True,
        )
    except (BrokenPipeError, OSError):
        pass
    return 0 if result.get("status") == "complete" else 1


def _bind_empty_registry_acquisition_root(
    raw_root: Path,
) -> tuple[int, int, tuple[int, int]]:
    if (
        not raw_root.is_absolute()
        or not raw_root.name
        or raw_root.name in (".", "..")
        or "/" in raw_root.name
    ):
        raise AssertionError("strict provisional registry root path is unsafe")
    parent_fd = -1
    root_fd = -1
    try:
        parent_fd = os.open(
            raw_root.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        root_fd = os.open(
            raw_root.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        metadata = os.fstat(root_fd)
    except OSError as error:
        for descriptor in (root_fd, parent_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise AssertionError(
            "strict provisional registry root cannot be bound"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(root_fd)
        os.close(parent_fd)
        raise AssertionError("strict provisional registry root is not a directory")
    return parent_fd, root_fd, (metadata.st_dev, metadata.st_ino)


def _open_or_create_registry_directory_at(
    parent_fd: int, name: str, mode: int
) -> int:
    if not name or name in (".", "..") or "/" in name:
        raise AssertionError("strict registry directory selector is unsafe")
    try:
        os.mkdir(name, mode=mode, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as error:
        raise AssertionError(
            "strict registry directory cannot be created"
        ) from error
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        metadata = os.fstat(descriptor)
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise AssertionError("strict registry directory cannot be opened") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        os.close(descriptor)
        raise AssertionError("strict registry directory policy is unsafe")
    return descriptor


def _write_registry_acquisition_file_at(
    directory_fd: int, name: str, source: bytes, mode: int
) -> None:
    if not name or name in (".", "..") or "/" in name:
        raise AssertionError("strict registry file selector is unsafe")
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            mode,
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise AssertionError("strict registry file cannot be opened") from error
    try:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise AssertionError("strict registry file identity is unsafe")
        os.ftruncate(descriptor, 0)
        offset = 0
        while offset < len(source):
            written = os.write(descriptor, source[offset:])
            if written <= 0:
                raise AssertionError("strict registry file write was incomplete")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_uid != os.getuid()
            or final.st_nlink != 1
            or final.st_size != len(source)
            or stat.S_IMODE(final.st_mode) != mode
        ):
            raise AssertionError("strict registry file policy is unsafe")
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)


def _configure_registry_acquisition_at(
    root_fd: int,
    *,
    watchdog_token: str,
) -> None:
    directory_fds: list[int] = []
    try:
        entries_fd = _open_or_create_registry_directory_at(
            root_fd, "entries", 0o700
        )
        directory_fds.append(entries_fd)
        control_fd = _open_or_create_registry_directory_at(
            root_fd, "trusted-control", 0o700
        )
        directory_fds.append(control_fd)
        resources_fd = _open_or_create_registry_directory_at(
            root_fd, "resources", 0o700
        )
        directory_fds.append(resources_fd)
        tombstones_fd = _open_or_create_registry_directory_at(
            root_fd, ".tombstones", 0o700
        )
        directory_fds.append(tombstones_fd)
        controller_parent_fd = control_fd
        components = [
            *(
                part
                for part in _TRUSTED_CONTENT_RELATIVE_ROOT.parts
                if part not in ("", ".")
            ),
            "skills",
            "waited-delivery",
            "tests",
        ]
        for component in components:
            controller_parent_fd = _open_or_create_registry_directory_at(
                controller_parent_fd, component, 0o700
            )
            directory_fds.append(controller_parent_fd)
        _write_registry_acquisition_file_at(root_fd, ".session.lock", b"", 0o600)
        _write_registry_acquisition_file_at(
            root_fd,
            ".watchdog-token",
            watchdog_token.encode("ascii"),
            0o400,
        )
        _write_registry_acquisition_file_at(
            controller_parent_fd,
            "required_ci_candidate.py",
            _TRUSTED_SUPPORT_SOURCE,
            0o400,
        )
        os.fsync(root_fd)
    finally:
        for descriptor in reversed(directory_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _registry_acquisition_identity(
    session: Mapping[str, object],
) -> tuple[Path, tuple[int, int]]:
    raw_root = session.get("root")
    retained = session.get("acquisition_retained")
    if not isinstance(raw_root, Path) or not isinstance(retained, dict):
        raise AssertionError("strict registry acquisition state is malformed")
    device = retained.get("device")
    inode = retained.get("inode")
    if type(device) is not int or type(inode) is not int:
        raise AssertionError(
            "strict registry acquisition identity is unavailable; root retained"
        )
    return raw_root, (device, inode)


def _close_registry_acquisition_descriptors(
    session: dict[str, object],
) -> list[str]:
    failures: list[str] = []
    for descriptor_name in (
        "acquisition_root_fd",
        "acquisition_parent_fd",
    ):
        descriptor = session.get(descriptor_name)
        if type(descriptor) is not int:
            session.pop(descriptor_name, None)
            continue
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                failures.append(f"{descriptor_name}: {error}")
                continue
        session.pop(descriptor_name, None)
    return failures


def _record_abandoned_registry_acquisition(
    session: Mapping[str, object], cause: BaseException
) -> None:
    root = session.get("root")
    retained = session.get("acquisition_retained")
    record: dict[str, object] = {
        "path": str(root) if isinstance(root, Path) else "unavailable",
        "device": retained.get("device") if isinstance(retained, dict) else None,
        "inode": retained.get("inode") if isinstance(retained, dict) else None,
        "reason": f"{type(cause).__name__}: {cause}"[:512],
    }
    if len(_ABANDONED_REGISTRY_ACQUISITIONS) >= 64:
        del _ABANDONED_REGISTRY_ACQUISITIONS[0]
    _ABANDONED_REGISTRY_ACQUISITIONS.append(record)


def _settle_failed_registry_acquisition(
    session: dict[str, object], cause: BaseException
) -> None:
    global _STRICT_BACKEND_VALIDATED, _STRICT_SESSION
    watchdog_failures = _retire_registry_watchdog_handles(
        session, terminate=True
    )
    retained = session.get("acquisition_retained")
    if watchdog_failures:
        if isinstance(retained, dict):
            retained["phase"] = "watchdog-unresolved"
        _STRICT_SESSION = session
        raise AssertionError(
            "strict registry acquisition failed and watchdog terminal state "
            "is unproved; exact recovery authority retained: "
            + "; ".join(watchdog_failures)
        ) from cause
    descriptor_failures = _close_registry_acquisition_descriptors(session)
    if descriptor_failures:
        if isinstance(retained, dict):
            retained["phase"] = "descriptor-unresolved"
        _STRICT_SESSION = session
        raise AssertionError(
            "strict registry acquisition failed and descriptor retirement "
            "is incomplete; recovery authority retained: "
            + "; ".join(descriptor_failures)
        ) from cause
    _record_abandoned_registry_acquisition(session, cause)
    _STRICT_SESSION = None
    _STRICT_BACKEND_VALIDATED = False
    raise AssertionError(
        "strict registry acquisition failed; terminal attempt was abandoned "
        f"without path mutation: {cause}"
    ) from cause


def _consume_retained_registry_acquisition(
    session: dict[str, object],
) -> None:
    global _STRICT_BACKEND_VALIDATED, _STRICT_SESSION
    watchdog_failures = _retire_registry_watchdog_handles(
        session, terminate=True
    )
    if watchdog_failures:
        raise AssertionError(
            "strict retained registry watchdog is still unresolved: "
            + "; ".join(watchdog_failures)
        )
    descriptor_failures = _close_registry_acquisition_descriptors(session)
    if descriptor_failures:
        raise AssertionError(
            "strict retained registry descriptors are still unresolved: "
            + "; ".join(descriptor_failures)
        )
    _record_abandoned_registry_acquisition(
        session,
        AssertionError("retained acquisition was retired before fresh retry"),
    )
    _STRICT_SESSION = None
    _STRICT_BACKEND_VALIDATED = False


def _initialize_bound_registry_acquisition(
    session: dict[str, object],
) -> dict[str, object]:
    global _STRICT_BACKEND_VALIDATED
    raw_root, expected_identity = _registry_acquisition_identity(session)
    parent_fd = session.get("acquisition_parent_fd")
    root_fd = session.get("acquisition_root_fd")
    try:
        if type(parent_fd) is not int or type(root_fd) is not int:
            raise AssertionError(
                "strict bound registry acquisition descriptors are unavailable"
            )
        opened = os.fstat(root_fd)
        current = os.stat(
            raw_root.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or (opened.st_dev, opened.st_ino) != expected_identity
            or (current.st_dev, current.st_ino) != expected_identity
            or opened.st_uid != os.getuid()
            or current.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or stat.S_IMODE(current.st_mode) != 0o700
        ):
            raise AssertionError(
                "strict registry acquisition root identity or policy changed"
            )
        if not raw_root.is_absolute():
            raise AssertionError("strict registry acquisition root is not absolute")
        root = raw_root
        realm = session.get("acquisition_realm")
        token = session.get("acquisition_token")
        watchdog_token = session.get("acquisition_watchdog_token")
        if (
            not isinstance(realm, dict)
            or type(realm.get("uid")) is not int
            or type(realm.get("gid")) is not int
            or not isinstance(token, str)
            or re.fullmatch(r"[0-9a-f]{32}", token) is None
            or not isinstance(watchdog_token, str)
            or re.fullmatch(r"[0-9a-f]{32}", watchdog_token) is None
        ):
            raise AssertionError("strict registry acquisition binding is malformed")
        entries = root / "entries"
        control = root / "trusted-control"
        resources = root / "resources"
        tombstones = root / ".tombstones"
        controller_path = (
            control
            / _TRUSTED_CONTENT_RELATIVE_ROOT
            / "skills/waited-delivery/tests/required_ci_candidate.py"
        )
        _configure_registry_acquisition_at(
            root_fd,
            watchdog_token=watchdog_token,
        )
        current_after_setup = os.stat(
            raw_root.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISDIR(current_after_setup.st_mode)
            or (current_after_setup.st_dev, current_after_setup.st_ino)
            != expected_identity
        ):
            raise AssertionError(
                "strict registry acquisition root was replaced during setup"
            )
        session.update(
            {
                "environment": {
                    _ISOLATION_REGISTRY_ENV: str(entries),
                    _ISOLATION_REGISTRY_TOKEN_ENV: token,
                },
                "root": root,
                "entries": entries,
                "resources": resources,
                "tombstones": tombstones,
                "controller_path": controller_path,
                "token": token,
                "target_uid": int(realm["uid"]),
                "closed": False,
                "inherited": False,
                "watchdog_authorized": False,
                "watchdog_token": watchdog_token,
            }
        )
        _STRICT_BACKEND_VALIDATED = False
        _start_registry_watchdog(session)
        selected_session = _active_strict_session()
    except BaseException as acquisition_error:
        _settle_failed_registry_acquisition(session, acquisition_error)
        raise AssertionError("unreachable registry acquisition recovery")
    descriptor_failures = _close_registry_acquisition_descriptors(session)
    if descriptor_failures:
        _settle_failed_registry_acquisition(
            session,
            AssertionError(
                "strict registry acquisition descriptor retirement failed: "
                + "; ".join(descriptor_failures)
            ),
        )
        raise AssertionError("unreachable descriptor retirement recovery")
    for field in (
        "acquisition_retained",
        "acquisition_realm",
        "acquisition_token",
        "acquisition_watchdog_token",
    ):
        session.pop(field, None)
    return selected_session


def trusted_isolation_chain_registry() -> dict[str, object]:
    global _STRICT_BACKEND_VALIDATED, _STRICT_SESSION
    if not _strict_isolation_requested():
        return {"environment": {}, "root": None, "closed": False}
    strict_isolation_platform_preflight()
    if (
        isinstance(_STRICT_SESSION, dict)
        and _STRICT_SESSION.get("acquisition_retained") is not None
    ):
        _consume_retained_registry_acquisition(_STRICT_SESSION)
    if _STRICT_SESSION is None:
        inherited = _session_from_environment()
        if inherited is not None:
            _STRICT_SESSION = inherited
            _STRICT_BACKEND_VALIDATED = False
        else:
            realm = _strict_realm()
            provisional_root = Path(
                tempfile.mkdtemp(prefix="required-ci-chain-registry-")
            )
            try:
                observed = provisional_root.lstat()
            except OSError as acquisition_error:
                failed_session: dict[str, object] = {
                    "root": provisional_root,
                    "closed": False,
                    "inherited": False,
                    "watchdog_authorized": False,
                    "acquisition_retained": {"phase": "unbound"},
                }
                _STRICT_SESSION = failed_session
                _settle_failed_registry_acquisition(
                    failed_session, acquisition_error
                )
                raise AssertionError("unreachable unbound acquisition recovery")
            if (
                not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid != os.getuid()
                or stat.S_IMODE(observed.st_mode) != 0o700
            ):
                failed_session = {
                    "root": provisional_root,
                    "closed": False,
                    "inherited": False,
                    "watchdog_authorized": False,
                    "acquisition_retained": {
                        "phase": "observed",
                        "device": observed.st_dev,
                        "inode": observed.st_ino,
                    },
                }
                _STRICT_SESSION = failed_session
                _settle_failed_registry_acquisition(
                    failed_session,
                    AssertionError(
                        "strict registry acquisition root policy is unsafe"
                    ),
                )
                raise AssertionError("unreachable unsafe acquisition recovery")
            new_session: dict[str, object] = {
                "root": provisional_root,
                "closed": False,
                "inherited": False,
                "watchdog_authorized": False,
                "acquisition_retained": {
                    "phase": "observed",
                    "device": observed.st_dev,
                    "inode": observed.st_ino,
                },
                "acquisition_realm": {
                    "uid": int(realm["uid"]),
                    "gid": int(realm["gid"]),
                },
                "acquisition_token": uuid.uuid4().hex,
                "acquisition_watchdog_token": uuid.uuid4().hex,
            }
            _STRICT_SESSION = new_session
            _STRICT_BACKEND_VALIDATED = False
            try:
                (
                    parent_fd,
                    root_fd,
                    opened_identity,
                ) = _bind_empty_registry_acquisition_root(provisional_root)
                if opened_identity != (observed.st_dev, observed.st_ino):
                    os.close(root_fd)
                    os.close(parent_fd)
                    raise AssertionError(
                        "strict registry acquisition root changed while binding"
                    )
                new_session["acquisition_parent_fd"] = parent_fd
                new_session["acquisition_root_fd"] = root_fd
                retained = new_session["acquisition_retained"]
                if isinstance(retained, dict):
                    retained["phase"] = "bound"
            except BaseException as acquisition_error:
                _settle_failed_registry_acquisition(
                    new_session, acquisition_error
                )
                raise AssertionError("unreachable descriptor acquisition recovery")
            return _initialize_bound_registry_acquisition(new_session)
    return _active_strict_session()


def _retire_registry_watchdog_handles(
    session: dict[str, object], *, terminate: bool
) -> list[str]:
    failures: list[str] = []
    launch = session.get("watchdog_launch")
    launch_state = launch if isinstance(launch, dict) else {}
    process = session.get("watchdog_process", launch_state.get("process"))
    pidfd = session.get("watchdog_pidfd", launch_state.get("pidfd"))
    stderr_file = session.get("watchdog_stderr", launch_state.get("stderr"))
    stop_event = session.get("watchdog_stop", launch_state.get("stop_event"))
    heartbeat = session.get(
        "watchdog_heartbeat", launch_state.get("heartbeat")
    )
    heartbeat_unresolved = False
    if isinstance(stop_event, threading.Event):
        stop_event.set()
    if isinstance(heartbeat, threading.Thread):
        try:
            if heartbeat.is_alive():
                heartbeat.join(
                    timeout=_STRICT_WATCHDOG_HEARTBEAT_SECONDS * 2
                )
            if heartbeat.is_alive():
                failures.append("watchdog heartbeat did not stop")
                heartbeat_unresolved = True
        except RuntimeError as error:
            failures.append(f"watchdog heartbeat reap: {error}")
            heartbeat_unresolved = heartbeat.is_alive()
    if isinstance(process, subprocess.Popen):
        if terminate and process.poll() is None:
            if type(pidfd) is int:
                try:
                    _signal_process_pidfd(pidfd, signal.SIGKILL)
                except BaseException as error:
                    failures.append(f"watchdog signal: {error}")
            else:
                failures.append("watchdog signal: exact pidfd is unavailable")
        if process.poll() is None:
            try:
                process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
            except BaseException as error:
                failures.append(f"watchdog reap: {error}")
        if process.poll() is None:
            return failures
        if heartbeat_unresolved:
            return failures
        for description, stream in (
            ("stdin", process.stdin),
            ("stdout", process.stdout),
        ):
            if stream is not None:
                try:
                    stream.close()
                except BaseException as error:
                    failures.append(f"watchdog {description} close: {error}")
    if heartbeat_unresolved:
        return failures
    if type(pidfd) is int:
        session["watchdog_pidfd"] = None
        launch_state["pidfd"] = None
        try:
            os.close(pidfd)
        except OSError as error:
            if error.errno != errno.EBADF:
                failures.append(f"watchdog pidfd close: {error}")
    if hasattr(stderr_file, "close"):
        try:
            stderr_file.close()
        except BaseException as error:
            failures.append(f"watchdog stderr close: {error}")
        else:
            session.pop("watchdog_stderr", None)
            launch_state.pop("stderr", None)
    if failures:
        return failures
    for key in tuple(session):
        if str(key).startswith("watchdog_") and key not in (
            "watchdog_authorized",
            "watchdog_token",
        ):
            session.pop(key, None)
    session["watchdog_closing"] = False
    return failures


def _close_registry_through_watchdog(
    session: dict[str, object], *, retry: bool = True
) -> None:
    global _STRICT_BACKEND_VALIDATED, _STRICT_SESSION
    process = session.get("watchdog_process")
    pidfd = session.get("watchdog_pidfd")
    stderr_file = session.get("watchdog_stderr")
    stop_event = session.get("watchdog_stop")
    write_lock = session.get("watchdog_write_lock")
    heartbeat = session.get("watchdog_heartbeat")
    watchdog_token = session.get("watchdog_token")
    if (
        not isinstance(process, subprocess.Popen)
        or type(pidfd) is not int
        or not hasattr(stderr_file, "read")
        or not isinstance(stop_event, threading.Event)
        or not hasattr(write_lock, "acquire")
        or not isinstance(heartbeat, threading.Thread)
        or type(watchdog_token) is not str
        or process.stdin is None
        or process.stdout is None
    ):
        raise AssertionError("strict registry watchdog close state is malformed")
    session["watchdog_closing"] = True
    stop_event.set()
    heartbeat.join(timeout=_STRICT_WATCHDOG_HEARTBEAT_SECONDS * 2)
    if heartbeat.is_alive():
        session["watchdog_closing"] = False
        raise AssertionError("strict registry watchdog heartbeat did not stop")
    try:
        with write_lock:
            process.stdin.write(b"D\n")
            process.stdin.flush()
        result_line = _read_watchdog_line(
            process.stdout,
            CANDIDATE_PROCESS_TIMEOUT_SECONDS
            + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS,
            "result",
        )
        process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
        expected_prefix = _WATCHDOG_RESULT_PREFIX.encode("ascii")
        if not result_line.startswith(expected_prefix):
            raise AssertionError("strict registry watchdog result prefix is invalid")
        result = json.loads(result_line[len(expected_prefix) :])
        if (
            type(result) is not dict
            or result.get("status") != "complete"
            or result.get("token") != watchdog_token
            or process.returncode != 0
        ):
            raise AssertionError(
                "strict registry watchdog cleanup was incomplete: "
                f"{result.get('error') if isinstance(result, dict) else 'invalid'}"
            )
    except BaseException as error:
        cleanup_failures = _retire_registry_watchdog_handles(
            session, terminate=False
        )
        raise AssertionError(
            f"strict registry watchdog close failed: {error}"
            + (
                "; cleanup: " + "; ".join(cleanup_failures)
                if cleanup_failures
                else ""
            )
        ) from error
    cleanup_failures = _retire_registry_watchdog_handles(
        session, terminate=False
    )
    if cleanup_failures:
        raise AssertionError(
            "strict registry watchdog completed but handle cleanup failed: "
            + "; ".join(cleanup_failures)
        )
    session["closed"] = True
    _STRICT_BACKEND_VALIDATED = False
    _STRICT_SESSION = None


def close_trusted_isolation_chains(registry: Mapping[str, object]) -> None:
    root = registry.get("root")
    if root is None:
        return
    session = _current_strict_session_unchecked()
    inherited = session.get("inherited")
    if inherited not in (True, False):
        raise AssertionError("strict isolation registry ownership is malformed")
    if inherited is False:
        if session.get("watchdog_authorized") is not False:
            raise AssertionError(
                "strict owner registry watchdog authority is malformed"
            )
        if session.get("watchdog_process") is None:
            raise AssertionError(
                "strict owner registry watchdog is unavailable"
            )
        _close_registry_through_watchdog(session)
        return
    if (
        inherited is True and session.get("watchdog_authorized") is not True
    ):
        raise AssertionError("strict inherited child cannot close parent registry")
    with _registry_session_gate(exclusive=True, session=session):
        _close_trusted_isolation_chains_under_gate(registry)


def _cleanup_orphan_resource_roots(
    session: Mapping[str, object], documents: Sequence[Mapping[str, object]]
) -> None:
    resources = session.get("resources")
    if resources is None and not any(
        document.get("cleanup_execution_root") is True
        for document in documents
    ):
        return
    if not isinstance(resources, Path):
        raise AssertionError("strict resource container is malformed")
    registered_identities = {
        (
            int(document["execution_root"]["device"]),
            int(document["execution_root"]["inode"]),
        )
        for document in documents
        if document.get("cleanup_execution_root") is True
        and isinstance(document.get("execution_root"), dict)
    }
    try:
        children = list(resources.iterdir())
    except OSError as error:
        raise AssertionError("strict resource container is unreadable") from error
    for child in children:
        try:
            metadata = child.lstat()
            contents = list(child.iterdir())
        except OSError as error:
            raise AssertionError(
                "strict orphan resource root is unreadable"
            ) from error
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in registered_identities:
            raise AssertionError(
                "strict closed resource root still exists in its container"
            )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or child.resolve(strict=True) != child
            or contents
        ):
            raise AssertionError(
                "strict unregistered resource root is not an empty owner-only directory"
            )
        try:
            child.rmdir()
        except OSError as error:
            raise AssertionError(
                "strict orphan resource root cannot be removed"
            ) from error
    _fsync_directory(resources)


def _close_trusted_isolation_chains_under_gate(
    registry: Mapping[str, object],
) -> None:
    global _STRICT_BACKEND_VALIDATED, _STRICT_SESSION
    root = registry.get("root")
    session = _current_strict_session_unchecked()
    entries = session.get("entries")
    controller_path = session.get("controller_path")
    target_uid = session.get("target_uid")
    if (
        not isinstance(root, Path)
        or not isinstance(entries, Path)
        or not isinstance(controller_path, Path)
        or type(target_uid) is not int
        or root != session.get("root")
    ):
        raise AssertionError("strict parent isolation registry is malformed")
    failures: list[str] = []
    all_closed = False
    previous_signature: tuple[tuple[object, ...], ...] | None = None
    stalled_rounds = 0
    rounds = 0
    while rounds < _STRICT_REGISTRY_ENTRY_LIMIT * 3:
        rounds += 1
        round_failures: list[str] = []
        try:
            entry_paths = _chain_registry_entries(
                entries, recover_staging=True
            )
            if len(entry_paths) > _STRICT_REGISTRY_ENTRY_LIMIT:
                raise AssertionError(
                    "strict chain registry entry limit was exceeded"
                )
        except BaseException as error:
            failures = [f"registry inventory: {error}"]
            break
        process_entries: list[Path] = []
        resource_entries: list[Path] = []
        for entry_path in entry_paths:
            try:
                document = _load_chain_registry_entry(entry_path)
            except BaseException as error:
                round_failures.append(f"{entry_path.name}: {error}")
                continue
            if document.get("cleanup_execution_root") is True:
                resource_entries.append(entry_path)
            else:
                process_entries.append(entry_path)
        for entry_path in process_entries:
            try:
                _recover_registered_entry(
                    entry_path, allow_recovery_broker=True
                )
            except BaseException as error:
                round_failures.append(f"{entry_path.name}: {error}")
        try:
            _invoke_root_uid_cleanup(controller_path, target_uid)
        except BaseException as error:
            round_failures.append(f"uid cleanup: {error}")
        try:
            _stable_uid_zero(target_uid)
        except BaseException as error:
            round_failures.append(f"parent UID proof: {error}")
        if not round_failures:
            for entry_path in resource_entries:
                try:
                    _recover_registered_entry(
                        entry_path, allow_recovery_broker=True
                    )
                except BaseException as error:
                    round_failures.append(f"{entry_path.name}: {error}")
                    break
        try:
            current_entries = _chain_registry_entries(
                entries, recover_staging=True
            )
            current_documents = [
                _load_chain_registry_entry(entry_path)
                for entry_path in current_entries
            ]
            signature = tuple(
                (
                    entry_path.name,
                    document.get("state"),
                    document.get("outer") is not None,
                    document.get("execution_root_delete_nonce"),
                    document.get("execution_root_deleted") is not None,
                )
                for entry_path, document in zip(
                    current_entries, current_documents, strict=True
                )
            )
            all_closed = all(
                document.get("state") == "closed"
                for document in current_documents
            )
        except BaseException as error:
            round_failures.append(f"registry final inventory: {error}")
            all_closed = False
            signature = ()
        if all_closed and not round_failures:
            failures = []
            break
        if signature == previous_signature:
            stalled_rounds += 1
        else:
            stalled_rounds = 0
        previous_signature = signature
        failures = round_failures
        if stalled_rounds >= 2:
            break
    if not all_closed or failures:
        if not failures:
            failures = ["registry did not reach a closed fixpoint"]
        raise AssertionError(
            "strict parent isolation cleanup was incomplete; recovery state retained: "
            + "; ".join(failures)
        )
    final_entries = _chain_registry_entries(entries, recover_staging=True)
    final_documents = [
        _load_chain_registry_entry(entry_path) for entry_path in final_entries
    ]
    _cleanup_orphan_resource_roots(session, final_documents)
    tombstones = session.get("tombstones")
    if not isinstance(tombstones, Path):
        raise AssertionError("strict isolation tombstone vault is malformed")
    _invoke_root_tree_operation(
        controller_path,
        "own-root",
        tombstones,
        os.getuid(),
        os.getgid(),
        "isolation-vault-release",
    )
    try:
        shutil.rmtree(root)
    except OSError as error:
        raise AssertionError(
            "strict parent isolation registry could not be removed after closure"
        ) from error
    session["closed"] = True
    _STRICT_BACKEND_VALIDATED = False
    _STRICT_SESSION = None


def _acl_is_absent(path: Path, description: str) -> None:
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        raise AssertionError(f"{description} ACL state cannot be read") from error
    forbidden = {"system.posix_acl_access", "system.posix_acl_default"}
    if forbidden.intersection(attributes):
        raise AssertionError(f"{description} has an unexpected POSIX ACL")


def _protect_strict_checkout_boundaries() -> None:
    for path, description in (
        (_TRUSTED_CHECKOUT_ROOT, "trusted checkout"),
        (candidate_repository_root(), "candidate checkout"),
    ):
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or path.resolve(strict=True) != path
        ):
            raise AssertionError(f"strict {description} boundary is not runner-owned")
        path.chmod(0o700)
        final_metadata = path.lstat()
        if stat.S_IMODE(final_metadata.st_mode) != 0o700:
            raise AssertionError(f"strict {description} boundary is not owner-only")
        _acl_is_absent(path, f"strict {description} boundary")
    support_metadata = _TRUSTED_SUPPORT_PATH.lstat()
    if (
        not stat.S_ISREG(support_metadata.st_mode)
        or support_metadata.st_nlink != 1
        or _TRUSTED_SUPPORT_PATH.resolve(strict=True) != _TRUSTED_SUPPORT_PATH
        or hashlib.sha256(_TRUSTED_SUPPORT_PATH.read_bytes()).hexdigest()
        != _TRUSTED_SUPPORT_SHA256
    ):
        raise AssertionError("trusted support source identity is not stable")


def _registered_fixture_root(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    matches = [
        root
        for root in _REGISTERED_FIXTURE_ROOTS
        if resolved == root or root in resolved.parents
    ]
    if len(matches) != 1:
        raise AssertionError(
            "strict candidate writable path is outside a registered fixture root"
        )
    root = matches[0]
    metadata = root.lstat()
    if (metadata.st_dev, metadata.st_ino) != _REGISTERED_FIXTURE_ROOTS[root]:
        raise AssertionError("strict candidate fixture root identity changed")
    return root


def _fixture_tree_paths(root: Path) -> list[Path]:
    paths = [root]
    for directory, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        directory_path = Path(directory)
        for name in sorted(directory_names + file_names):
            path = directory_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise AssertionError("strict candidate fixture tree contains a symlink")
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise AssertionError("strict candidate fixture file has a hardlink alias")
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise AssertionError("strict candidate fixture tree has a special file")
            paths.append(path)
    return paths


def _prepare_strict_fixture_roots(
    controller_path: Path,
    writable_roots: Sequence[Path],
    requested_home: Path | None,
) -> tuple[Path, ...]:
    realm = _strict_realm()
    candidate_gid = int(realm["gid"])
    roots: list[Path] = []
    for value in writable_roots:
        root = _registered_fixture_root(Path(value))
        if root not in roots:
            roots.append(root)
    if requested_home is not None:
        home = requested_home.resolve(strict=True)
        registered_root = _registered_fixture_root(home)
        if registered_root not in roots:
            roots.append(registered_root)
    for root in roots:
        _fixture_tree_paths(root)
    started_roots: list[Path] = []
    try:
        for root in roots:
            started_roots.append(root)
            _invoke_root_tree_operation(
                controller_path,
                "own",
                root,
                os.getuid(),
                candidate_gid,
                "fixture-shared",
            )
        if requested_home is not None:
            _invoke_root_tree_operation(
                controller_path,
                "own",
                home,
                int(realm["uid"]),
                candidate_gid,
                "candidate-home",
            )
    except BaseException as prepare_error:
        rollback_failures: list[str] = []
        for root in reversed(started_roots):
            try:
                _invoke_root_tree_operation(
                    controller_path,
                    "own",
                    root,
                    os.getuid(),
                    candidate_gid,
                    "fixture-restore",
                )
            except BaseException as rollback_error:
                rollback_failures.append(f"{root}: {rollback_error}")
        if rollback_failures:
            raise AssertionError(
                "strict fixture preparation and rollback failed: "
                f"{prepare_error}; {'; '.join(rollback_failures)}"
            ) from prepare_error
        raise
    return tuple(roots)


def _restore_strict_fixture_roots(
    controller_path: Path, roots: Sequence[Path]
) -> None:
    realm = _strict_realm()
    if _candidate_uid_inventory(int(realm["uid"])):
        raise AssertionError("candidate fixture restore began with live candidate processes")
    for root in roots:
        _invoke_root_tree_operation(
            controller_path,
            "own",
            root,
            os.getuid(),
            int(realm["gid"]),
            "fixture-restore",
        )


@contextmanager
def _prepared_candidate_fixtures(
    controller_path: Path,
    writable_roots: Sequence[Path],
    requested_home: Path | None,
) -> Iterator[tuple[Path, ...]]:
    if not _strict_isolation_requested():
        yield ()
        return
    roots = _prepare_strict_fixture_roots(
        controller_path, writable_roots, requested_home
    )
    try:
        yield roots
    finally:
        _restore_strict_fixture_roots(controller_path, roots)


def _tracked_candidate_script_bytes(
    checkout_root: Path, candidate_sha: str
) -> dict[Path, bytes]:
    sources: dict[Path, bytes] = {}
    for content_relative_path in CANDIDATE_SCRIPT_RELATIVE_PATHS:
        checkout_relative_path = _candidate_checkout_relative_path(
            content_relative_path
        )
        source = _run_candidate_git(
            checkout_root,
            "cat-file",
            "blob",
            f"{candidate_sha}:{checkout_relative_path.as_posix()}",
            output_limit=CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES,
        )
        sources[content_relative_path] = source
    return sources


def _candidate_snapshot_script_bytes(
    checkout_root: Path,
    candidate_sha: str,
    *,
    require_clean: bool,
) -> dict[Path, bytes]:
    if require_clean:
        return _tracked_candidate_script_bytes(checkout_root, candidate_sha)
    _candidate_content_root_for_checkout(checkout_root)
    return _candidate_script_sources(checkout_root)


def _write_single_link_file(path: Path, source: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(source)
    path.chmod(mode)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise AssertionError("execution snapshot file identity is unsafe")


def _validated_candidate_workspace_sources(
    sources: Mapping[Path, tuple[bytes, bool]],
) -> dict[Path, tuple[bytes, bool]]:
    if not sources or len(sources) > CANDIDATE_WORKSPACE_FILE_LIMIT:
        raise AssertionError("candidate workspace file inventory exceeds its limit")
    validated: dict[Path, tuple[bytes, bool]] = {}
    alias_bindings: dict[tuple[str, ...], tuple[str, Path]] = {}
    total_size = 0
    for relative_path, value in sources.items():
        if (
            not isinstance(relative_path, Path)
            or not isinstance(value, tuple)
            or len(value) != 2
            or not isinstance(value[0], bytes)
            or type(value[1]) is not bool
        ):
            raise AssertionError("candidate workspace source is malformed")
        canonical_path = _candidate_workspace_path(
            relative_path.as_posix().encode("utf-8")
        )
        if canonical_path != relative_path or canonical_path in validated:
            raise AssertionError("candidate workspace source path is duplicated")
        for parent in reversed(canonical_path.parents[:-1]):
            alias = tuple(
                unicodedata.normalize("NFC", part).casefold()
                for part in parent.parts
            )
            existing = alias_bindings.setdefault(alias, ("directory", parent))
            if existing != ("directory", parent):
                raise AssertionError("candidate workspace path has a filesystem alias")
        file_alias = tuple(
            unicodedata.normalize("NFC", part).casefold()
            for part in canonical_path.parts
        )
        existing = alias_bindings.setdefault(file_alias, ("file", canonical_path))
        if existing != ("file", canonical_path):
            raise AssertionError("candidate workspace path has a filesystem alias")
        source, executable = value
        if len(source) > CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES:
            raise AssertionError("candidate workspace file exceeds its size limit")
        total_size += len(source)
        if total_size > CANDIDATE_WORKSPACE_TOTAL_SIZE_LIMIT_BYTES:
            raise AssertionError("candidate workspace content exceeds its total limit")
        validated[canonical_path] = (source, executable)
    return validated


def _materialize_candidate_workspace(
    execution_root: Path,
    sources: Mapping[Path, tuple[bytes, bool]],
) -> Path:
    validated = _validated_candidate_workspace_sources(sources)
    directories = {
        parent
        for relative_path in validated
        for parent in relative_path.parents
        if parent != Path(".")
    }
    if len(directories) > CANDIDATE_WORKSPACE_DIRECTORY_LIMIT:
        raise AssertionError(
            "candidate workspace directory inventory exceeds its limit"
        )
    child_directories: dict[Path, set[str]] = {
        directory: set() for directory in (*directories, Path("."))
    }
    child_files: dict[Path, dict[str, tuple[bytes, bool]]] = {
        directory: {} for directory in (*directories, Path("."))
    }
    for directory in directories:
        child_directories[directory.parent].add(directory.name)
    for relative_path, source in validated.items():
        child_files[relative_path.parent][relative_path.name] = source

    def populate(directory_fd: int, relative_directory: Path) -> None:
        expected_names = child_directories[relative_directory] | set(
            child_files[relative_directory]
        )
        for name in sorted(child_directories[relative_directory]):
            try:
                os.mkdir(name, mode=0o755, dir_fd=directory_fd)
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
            except OSError as error:
                raise AssertionError(
                    "candidate workspace directory cannot be created uniquely"
                ) from error
            try:
                opened = os.fstat(child_fd)
                if not stat.S_ISDIR(opened.st_mode):
                    raise AssertionError(
                        "candidate workspace directory identity is unsafe"
                    )
                os.fchmod(child_fd, 0o755)
                populate(child_fd, relative_directory / name)
                final_opened = os.fstat(child_fd)
                linked = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (
                    not stat.S_ISDIR(final_opened.st_mode)
                    or not stat.S_ISDIR(linked.st_mode)
                    or (final_opened.st_dev, final_opened.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or (linked.st_dev, linked.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or stat.S_IMODE(final_opened.st_mode) != 0o755
                ):
                    raise AssertionError(
                        "candidate workspace directory identity changed"
                    )
            finally:
                os.close(child_fd)
        file_identities: dict[str, tuple[int, int, int, int]] = {}
        for name, (source, executable) in sorted(
            child_files[relative_directory].items()
        ):
            mode = 0o755 if executable else 0o644
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK
                    | os.O_NOCTTY
                    | os.O_CLOEXEC,
                    mode,
                    dir_fd=directory_fd,
                )
            except OSError as error:
                raise AssertionError(
                    "candidate workspace file cannot be created uniquely"
                ) from error
            try:
                offset = 0
                while offset < len(source):
                    written = os.write(descriptor, source[offset:])
                    if written <= 0:
                        raise AssertionError(
                            "candidate workspace file cannot be written completely"
                        )
                    offset += written
                os.fchmod(descriptor, mode)
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or opened.st_size != len(source)
                    or stat.S_IMODE(opened.st_mode) != mode
                ):
                    raise AssertionError(
                        "candidate workspace file identity is unsafe"
                    )
                file_identities[name] = (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    mode,
                )
            finally:
                os.close(descriptor)
        try:
            final_names = set(os.listdir(directory_fd))
        except OSError as error:
            raise AssertionError(
                "candidate workspace directory cannot be enumerated"
            ) from error
        if final_names != expected_names:
            raise AssertionError(
                "candidate workspace filesystem name binding changed"
            )
        for name, identity in file_identities.items():
            try:
                linked = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
            except OSError as error:
                raise AssertionError(
                    "candidate workspace file cannot be revalidated"
                ) from error
            if (
                not stat.S_ISREG(linked.st_mode)
                or linked.st_nlink != 1
                or (linked.st_dev, linked.st_ino, linked.st_size)
                != identity[:3]
                or stat.S_IMODE(linked.st_mode) != identity[3]
            ):
                raise AssertionError(
                    "candidate workspace file identity changed"
                )

    try:
        execution_fd = os.open(
            execution_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise AssertionError("candidate execution root cannot be bound") from error
    workspace_fd: int | None = None
    try:
        try:
            os.mkdir(".candidate", mode=0o700, dir_fd=execution_fd)
            workspace_fd = os.open(
                ".candidate",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=execution_fd,
            )
        except OSError as error:
            raise AssertionError(
                "candidate workspace root cannot be created uniquely"
            ) from error
        opened_root = os.fstat(workspace_fd)
        if not stat.S_ISDIR(opened_root.st_mode):
            raise AssertionError("candidate workspace root identity is unsafe")
        populate(workspace_fd, Path("."))
        os.fchmod(workspace_fd, 0o770)
        try:
            os.stat(".git", dir_fd=workspace_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise AssertionError(
                "candidate workspace Git metadata lookup is unreadable"
            ) from error
        else:
            raise AssertionError("candidate workspace exposes a Git metadata alias")
        final_opened_root = os.fstat(workspace_fd)
        linked_root = os.stat(
            ".candidate", dir_fd=execution_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISDIR(final_opened_root.st_mode)
            or not stat.S_ISDIR(linked_root.st_mode)
            or (final_opened_root.st_dev, final_opened_root.st_ino)
            != (opened_root.st_dev, opened_root.st_ino)
            or (linked_root.st_dev, linked_root.st_ino)
            != (opened_root.st_dev, opened_root.st_ino)
            or stat.S_IMODE(final_opened_root.st_mode) != 0o770
        ):
            raise AssertionError("candidate workspace root identity changed")
    finally:
        if workspace_fd is not None:
            os.close(workspace_fd)
        os.close(execution_fd)
    return execution_root / ".candidate"


def _prepare_isolation_resource_ancestors(
    session: Mapping[str, object],
) -> None:
    root = session.get("root")
    resources = session.get("resources")
    tombstones = session.get("tombstones")
    entries = session.get("entries")
    controller_path = session.get("controller_path")
    realm_gid = int(_strict_realm()["gid"])
    if (
        not isinstance(root, Path)
        or not isinstance(resources, Path)
        or not isinstance(tombstones, Path)
        or not isinstance(entries, Path)
        or not isinstance(controller_path, Path)
        or resources.parent != root
        or tombstones.parent != root
        or entries.parent != root
    ):
        raise AssertionError("strict isolation resource ancestors are malformed")
    for protected in (entries, root / "trusted-control"):
        metadata = protected.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise AssertionError(
                "strict isolation protected directory policy changed"
            )
    for ancestor in (root, resources):
        before = ancestor.lstat()
        if (
            not ancestor.is_absolute()
            or not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) not in (0o700, 0o710)
            or (
                stat.S_IMODE(before.st_mode) == 0o710
                and before.st_gid != realm_gid
            )
        ):
            raise AssertionError(
                "strict isolation resource ancestor policy is unsafe"
            )
        if stat.S_IMODE(before.st_mode) != 0o710:
            _invoke_root_tree_operation(
                controller_path,
                "own-root",
                ancestor,
                os.getuid(),
                realm_gid,
                "isolation-ancestor",
            )
        after = ancestor.lstat()
        if (
            (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISDIR(after.st_mode)
            or after.st_uid != os.getuid()
            or after.st_gid != realm_gid
            or stat.S_IMODE(after.st_mode) != 0o710
        ):
            raise AssertionError(
                "strict isolation resource ancestor could not be bound"
            )
    vault_before = tombstones.lstat()
    if (
        not stat.S_ISDIR(vault_before.st_mode)
        or (
            not (
                vault_before.st_uid == os.getuid()
                and stat.S_IMODE(vault_before.st_mode) == 0o700
            )
            and not (
                vault_before.st_uid == 0
                and vault_before.st_gid == os.getgid()
                and stat.S_IMODE(vault_before.st_mode) == 0o710
            )
        )
    ):
        raise AssertionError("strict isolation tombstone vault is unsafe")
    if vault_before.st_uid != 0:
        _invoke_root_tree_operation(
            controller_path,
            "own-root",
            tombstones,
            0,
            os.getgid(),
            "isolation-vault",
        )
    vault_after = tombstones.lstat()
    if (
        (vault_after.st_dev, vault_after.st_ino)
        != (vault_before.st_dev, vault_before.st_ino)
        or not stat.S_ISDIR(vault_after.st_mode)
        or vault_after.st_uid != 0
        or vault_after.st_gid != os.getgid()
        or stat.S_IMODE(vault_after.st_mode) != 0o710
    ):
        raise AssertionError("strict isolation tombstone vault could not be bound")


@contextmanager
def _execution_snapshot(
    checkout_root: Path,
    candidate_sha: str,
    *,
    require_clean: bool = True,
    expected_script_manifest: Mapping[str, str] | None = None,
    candidate_sources: Mapping[Path, bytes] | None = None,
    candidate_workspace_sources: Mapping[Path, tuple[bytes, bool]] | None = None,
    materialize_workspace: bool = True,
    probe_source: bytes | None = None,
) -> Iterator[dict[str, object]]:
    if (
        probe_source is not None
        and (candidate_sources is not None or candidate_workspace_sources is not None)
    ):
        raise AssertionError(
            "candidate sources and a capability probe are mutually exclusive"
        )
    workspace_required = probe_source is None and materialize_workspace
    if not workspace_required and candidate_workspace_sources is not None:
        raise AssertionError(
            "candidate workspace sources were supplied without a workspace"
        )
    resolved_sources: dict[Path, bytes] | None = None
    resolved_workspace_sources: dict[Path, tuple[bytes, bool]] | None = None
    if probe_source is None:
        if candidate_sources is None:
            resolved_sources = _candidate_snapshot_script_bytes(
                checkout_root,
                candidate_sha,
                require_clean=require_clean,
            )
        else:
            resolved_sources = dict(candidate_sources)
            if set(resolved_sources) != set(CANDIDATE_SCRIPT_RELATIVE_PATHS):
                raise AssertionError("candidate captured source inventory is not exact")
            if not all(
                isinstance(source, bytes) for source in resolved_sources.values()
            ):
                raise AssertionError("candidate captured source bytes are malformed")
        snapshot_manifest = {
            _candidate_checkout_relative_path(relative_path).as_posix(): hashlib.sha256(
                source
            ).hexdigest()
            for relative_path, source in resolved_sources.items()
        }
        if (
            expected_script_manifest is not None
            and snapshot_manifest != dict(expected_script_manifest)
        ):
            raise AssertionError(
                "candidate implementation changed before snapshot capture"
            )
        if workspace_required:
            if candidate_workspace_sources is None:
                resolved_workspace_sources = (
                    _validated_candidate_workspace_sources(
                        _candidate_workspace_sources(
                            checkout_root,
                            candidate_sha,
                            resolved_sources,
                        )
                    )
                )
            else:
                resolved_workspace_sources = (
                    _validated_candidate_workspace_sources(
                        candidate_workspace_sources
                    )
                )
    strict = _strict_isolation_requested()
    temporary: tempfile.TemporaryDirectory[str] | None = None
    resource_entry_path: Path | None = None
    resource_entry_owned = False
    gate = _registry_session_gate(exclusive=False) if strict else nullcontext()
    with gate:
        if strict:
            session = _active_strict_session()
            recovery_controller = session.get("controller_path")
            target_uid = session.get("target_uid")
            resource_container = session.get("resources")
            if (
                not isinstance(recovery_controller, Path)
                or type(target_uid) is not int
                or not isinstance(resource_container, Path)
            ):
                raise AssertionError("strict execution resource session is malformed")
            _prepare_isolation_resource_ancestors(session)
            execution_root = Path(
                tempfile.mkdtemp(
                    prefix="required-ci-execution-", dir=resource_container
                )
            ).resolve(strict=True)
            resource_session_id = uuid.uuid4().hex
            resource_publication_nonce = uuid.uuid4().hex
            resource_root_binding: dict[str, object] | None = None
            entries = session.get("entries")
            if not isinstance(entries, Path):
                raise AssertionError(
                    "strict execution resource registry is malformed"
                )
            expected_resource_entry = (
                entries / f"chain-{resource_session_id}.json"
            )
            resource_entry_path = expected_resource_entry

            def mark_resource_entry_owned() -> None:
                nonlocal resource_entry_owned
                resource_entry_owned = True

            try:
                resource_root_binding = _execution_root_binding(execution_root)
                registered_resource_entry = _register_trusted_root_chain(
                    recovery_controller,
                    None,
                    target_uid,
                    execution_root=execution_root,
                    cleanup_execution_root=True,
                    session_id=resource_session_id,
                    publication_nonce=resource_publication_nonce,
                    published_callback=mark_resource_entry_owned,
                )
                if registered_resource_entry != expected_resource_entry:
                    raise AssertionError(
                        "strict execution resource publication path is inconsistent"
                    )
            except BaseException as registration_error:
                if not resource_entry_owned and resource_root_binding is not None:
                    try:
                        resource_entry_owned = (
                            _registered_entry_matches_publication_attempt(
                                expected_resource_entry,
                                session=session,
                                publication_nonce=resource_publication_nonce,
                                execution_root_binding=resource_root_binding,
                                cleanup_execution_root=True,
                            )
                        )
                    except BaseException as ownership_error:
                        raise AssertionError(
                            "strict execution resource publication failed and "
                            "ownership is unproved; execution root retained: "
                            f"{ownership_error}"
                        ) from registration_error
                if resource_entry_owned:
                    try:
                        _recover_registered_entry(
                            expected_resource_entry,
                            allow_recovery_broker=True,
                        )
                    except BaseException as recovery_error:
                        raise AssertionError(
                            "strict execution resource publication failed and "
                            f"recovery was incomplete: {recovery_error}"
                        ) from registration_error
                else:
                    shutil.rmtree(execution_root)
                raise
        else:
            temporary = tempfile.TemporaryDirectory(
                prefix="required-ci-execution-"
            )
            execution_root = Path(temporary.name).resolve(strict=True)
        try:
            candidate_snapshot_root = execution_root / "candidate-code"
            candidate_workspace_root: Path | None = None
            control_snapshot_root = execution_root / "trusted-control"
            runtime_root = execution_root / "runtime"
            candidate_content_root = (
                candidate_snapshot_root / _TRUSTED_CONTENT_RELATIVE_ROOT
            )
            control_content_root = (
                control_snapshot_root / _TRUSTED_CONTENT_RELATIVE_ROOT
            )
            controller_path = (
                control_content_root
                / "skills/waited-delivery/tests/required_ci_candidate.py"
            )
            config_path = control_snapshot_root / "controller-config.json"
            handshake_path = control_snapshot_root / "controller-handshake.json"
            _write_single_link_file(
                controller_path, _TRUSTED_SUPPORT_SOURCE, 0o400
            )
            _write_single_link_file(handshake_path, b"", 0o600)
            candidate_paths: dict[str, str] = {}
            if probe_source is None:
                if resolved_sources is None or (
                    workspace_required and resolved_workspace_sources is None
                ):
                    raise AssertionError("candidate execution sources are unavailable")
                for relative_path, source in resolved_sources.items():
                    path = candidate_content_root / relative_path
                    _write_single_link_file(path, source, 0o440)
                    candidate_paths[relative_path.name] = str(path)
                functional_probe_path = (
                    candidate_content_root
                    / "skills/waited-delivery/tests/required_ci_candidate.py"
                )
                _write_single_link_file(
                    functional_probe_path, _TRUSTED_SUPPORT_SOURCE, 0o440
                )
                candidate_paths[functional_probe_path.name] = str(
                    functional_probe_path
                )
                if workspace_required:
                    assert resolved_workspace_sources is not None
                    candidate_workspace_root = _materialize_candidate_workspace(
                        execution_root,
                        resolved_workspace_sources,
                    )
            else:
                path = candidate_snapshot_root / "strict-capability-probe.py"
                _write_single_link_file(path, probe_source, 0o440)
                candidate_paths[path.name] = str(path)
            runtime_root.mkdir()
            candidate_snapshot_root.chmod(0o550)
            control_snapshot_root.chmod(0o700)
            runtime_root.chmod(0o700)
            execution_root.chmod(0o710)
            if strict:
                realm = _strict_realm()
                uid = int(realm["uid"])
                gid = int(realm["gid"])
                _invoke_root_tree_operation(
                    controller_path,
                    "own",
                    candidate_snapshot_root,
                    0,
                    gid,
                    "candidate-code",
                )
                if workspace_required:
                    if candidate_workspace_root is None:
                        raise AssertionError(
                            "candidate workspace was not materialized"
                        )
                    _invoke_root_tree_operation(
                        controller_path,
                        "own",
                        candidate_workspace_root,
                        uid,
                        gid,
                        "candidate-workspace",
                    )
                _invoke_root_tree_operation(
                    controller_path,
                    "own",
                    runtime_root,
                    uid,
                    gid,
                    "runtime",
                )
                _invoke_root_tree_operation(
                    controller_path,
                    "own-root",
                    execution_root,
                    os.getuid(),
                    gid,
                    "execution-root",
                )
            yield {
                "execution_root": execution_root,
                "candidate_root": candidate_snapshot_root,
                "workspace_root": candidate_workspace_root,
                "control_root": control_snapshot_root,
                "runtime_root": runtime_root,
                "controller_path": controller_path,
                "config_path": config_path,
                "handshake_path": handshake_path,
                "candidate_paths": candidate_paths,
                "resource_entry_path": resource_entry_path,
            }
        finally:
            if strict:
                if resource_entry_path is None:
                    raise AssertionError(
                        "strict execution resource was not registered"
                    )
                _recover_registered_entry(
                    resource_entry_path, allow_recovery_broker=True
                )
            elif temporary is not None:
                temporary.cleanup()


def _closed_candidate_environment(
    supplied: Mapping[str, str] | None,
    *,
    home: Path,
    temporary_root: Path,
    safe_git_directories: Sequence[Path] = (),
) -> dict[str, str]:
    source = {} if supplied is None else dict(supplied)
    trusted_git = _revalidate_trusted_git_binding(_TRUSTED_GIT_BINDING)
    trusted_git_directory = str(trusted_git.parent)
    if os.pathsep in trusted_git_directory or "\x00" in trusted_git_directory:
        raise AssertionError("trusted Git executable directory is malformed")
    candidate_path = os.pathsep.join(
        dict.fromkeys((trusted_git_directory, "/usr/bin", "/bin"))
    )
    environment = {
        "HOME": str(home),
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": "required-ci-candidate",
        "PATH": candidate_path,
        "SHELL": "/bin/sh",
        "TEMP": str(temporary_root),
        "TMP": str(temporary_root),
        "TMPDIR": str(temporary_root),
        "USER": "required-ci-candidate",
    }
    exact_git_directories = sorted(
        {str(path.resolve(strict=True)) for path in safe_git_directories}
    )
    environment["GIT_CONFIG_COUNT"] = str(len(exact_git_directories) + 2)
    environment["GIT_CONFIG_KEY_0"] = "safe.directory"
    environment["GIT_CONFIG_VALUE_0"] = ""
    environment["GIT_CONFIG_KEY_1"] = "core.attributesFile"
    environment["GIT_CONFIG_VALUE_1"] = "/dev/null"
    for index, directory in enumerate(exact_git_directories, start=2):
        environment[f"GIT_CONFIG_KEY_{index}"] = "safe.directory"
        environment[f"GIT_CONFIG_VALUE_{index}"] = directory
    for key in _CANDIDATE_ENV_KEYS:
        value = source.get(key)
        if value is not None:
            if type(value) is not str or "\x00" in value:
                raise AssertionError("candidate environment value is malformed")
            environment[key] = value
    return environment


def _fixture_git_repositories(roots: Sequence[Path]) -> tuple[Path, ...]:
    repositories: list[Path] = []
    for value in roots:
        root = Path(value).resolve(strict=True)
        for directory, directory_names, _ in os.walk(
            root, topdown=True, followlinks=False
        ):
            directory_path = Path(directory)
            if ".git" in directory_names:
                git_directory = directory_path / ".git"
                metadata = git_directory.lstat()
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or git_directory.resolve(strict=True) != git_directory
                ):
                    raise AssertionError(
                        "candidate fixture Git directory is not canonical"
                    )
                repositories.append(directory_path)
                directory_names.remove(".git")
    return tuple(sorted(set(repositories)))


def _decode_controller_receipt(
    stdout: bytes, stderr: bytes, nonce: str
) -> dict[str, object]:
    if stderr:
        raise AssertionError("strict root controller wrote stderr")
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AssertionError("strict root controller receipt is not UTF-8") from error
    expected_prefix = _ROOT_CONTROLLER_RECEIPT_PREFIX
    if not text.startswith(expected_prefix) or text.count("\n") != 1:
        raise AssertionError("strict root controller receipt framing is malformed")
    try:
        receipt = json.loads(text[len(expected_prefix) :])
    except json.JSONDecodeError as error:
        raise AssertionError("strict root controller receipt is malformed") from error
    if type(receipt) is not dict or receipt.get("nonce") != nonce:
        raise AssertionError("strict root controller receipt nonce is invalid")
    return receipt


def _invoke_strict_controller(
    snapshot: Mapping[str, object],
    candidate_argv: Sequence[str],
    environment: Mapping[str, str],
    cwd: Path,
    input_bytes: bytes,
    *,
    timeout_seconds: float,
    trusted_fault_point: str | None = None,
    outer_timeout_seconds: float | None = None,
    trusted_outer_fault_probe: tuple[Path, str, str, int] | None = None,
    trusted_completion_sentinel: Path | None = None,
    registered_session_id: str | None = None,
    candidate_interpreter_binding: Mapping[str, object] | None = None,
    writable_roots: Sequence[Path] = (),
    readable_roots: Sequence[Path] = (),
) -> dict[str, object]:
    exact_candidate_argv = list(candidate_argv)
    if (
        not exact_candidate_argv
        or type(exact_candidate_argv[0]) is not str
        or not exact_candidate_argv[0]
        or any(
            type(item) is not str or "\x00" in item
            for item in exact_candidate_argv
        )
    ):
        raise AssertionError("strict candidate command is malformed")
    if candidate_interpreter_binding is None:
        expected_interpreter = str(_STRICT_PRIMITIVES["python"])
    else:
        expected_interpreter = candidate_interpreter_binding.get("resolved")
        if type(expected_interpreter) is not str or not expected_interpreter:
            raise AssertionError(
                "strict candidate configured interpreter binding is malformed"
            )
    if exact_candidate_argv[0] != expected_interpreter:
        raise AssertionError(
            "strict candidate interpreter identity changed before privilege"
        )
    exact_interpreter_binding = (
        None
        if candidate_interpreter_binding is None
        else _revalidate_configured_candidate_interpreter(
            dict(candidate_interpreter_binding)
        )
    )
    realm = _strict_realm()
    if exact_interpreter_binding is not None and (
        exact_interpreter_binding["target_uid"] != realm.get("uid")
        or exact_interpreter_binding["target_gid"] != realm.get("gid")
    ):
        raise AssertionError(
            "strict candidate configured interpreter target identity changed"
        )
    if exact_interpreter_binding is not None and (
        exact_candidate_argv[0] != exact_interpreter_binding["resolved"]
    ):
        raise AssertionError(
            "strict candidate interpreter identity changed during revalidation"
        )
    if trusted_outer_fault_probe is not None and (
        type(trusted_outer_fault_probe) is not tuple
        or len(trusted_outer_fault_probe) != 4
        or not isinstance(trusted_outer_fault_probe[0], Path)
        or not trusted_outer_fault_probe[0].is_absolute()
        or re.fullmatch(r"[0-9a-f]{32}", trusted_outer_fault_probe[1])
        is None
        or trusted_outer_fault_probe[2] != "after-target-active"
        or type(trusted_outer_fault_probe[3]) is not int
        or trusted_outer_fault_probe[3] < 0
    ):
        raise AssertionError(
            "strict root-active outer fault probe is malformed"
        )
    if (trusted_outer_fault_probe is None) is not (
        trusted_completion_sentinel is None
    ):
        raise AssertionError(
            "strict root-active completion binding is incomplete"
        )
    if trusted_completion_sentinel is not None and (
        not isinstance(trusted_completion_sentinel, Path)
        or not trusted_completion_sentinel.is_absolute()
    ):
        raise AssertionError(
            "strict root-active completion sentinel is malformed"
        )
    active_owner_identity = (
        None
        if trusted_completion_sentinel is None
        else _process_identity(Path("/proc") / str(os.getpid()))
    )
    if trusted_completion_sentinel is not None and (
        active_owner_identity is None
        or active_owner_identity[0] != active_owner_identity[3]
        or active_owner_identity[0] != active_owner_identity[4]
        or active_owner_identity[5] != (os.getuid(),) * 4
    ):
        raise AssertionError(
            "strict root-active owner identity is invalid"
        )
    nonce = (
        uuid.uuid4().hex
        if trusted_outer_fault_probe is None
        else trusted_outer_fault_probe[1]
    )
    selected_session_id = (
        uuid.uuid4().hex
        if registered_session_id is None
        else registered_session_id
    )
    if re.fullmatch(r"[0-9a-f]{32}", selected_session_id) is None:
        raise AssertionError(
            "strict root controller registered session is malformed"
        )
    config_path = snapshot["config_path"]
    controller_path = snapshot["controller_path"]
    handshake_path = snapshot["handshake_path"]
    execution_root = snapshot.get("execution_root")
    if (
        not isinstance(config_path, Path)
        or not isinstance(controller_path, Path)
        or not isinstance(handshake_path, Path)
        or not isinstance(execution_root, Path)
    ):
        raise AssertionError("strict execution snapshot is malformed")
    writable_root_bindings = _strict_writable_root_bindings(
        execution_root, tuple(Path(path) for path in writable_roots)
    )
    read_root_bindings = _strict_host_read_root_bindings(
        exact_interpreter_binding,
        int(realm["uid"]),
        int(realm["gid"]),
        readable_roots=tuple(Path(path) for path in readable_roots),
    )
    bootstrap_nofile = _strict_bootstrap_nofile_requirement(
        writable_root_bindings, read_root_bindings
    )
    _assert_strict_bootstrap_nofile_capacity(bootstrap_nofile)
    writable_paths = [
        Path(str(binding["path"])) for binding in writable_root_bindings
    ]
    for binding in read_root_bindings:
        read_path = Path(str(binding["path"]))
        if any(
            read_path == writable_path
            or read_path in writable_path.parents
            or writable_path in read_path.parents
            for writable_path in writable_paths
        ):
            raise AssertionError("strict read and writable roots overlap")
    host_mount_namespace = _strict_host_namespace_identity("mnt")
    host_ipc_namespace = _strict_host_namespace_identity("ipc")
    host_network_namespace = _strict_host_namespace_identity("net")
    inner_fault_point = (
        trusted_fault_point
        if trusted_fault_point
        in (
            "after-wrapper-popen-before-handshake-sigkill",
            "after-wrapper-popen-before-handshake-sigstop",
            "after-wrapper-bound-before-barrier-sigkill",
            "after-wrapper-bound-before-barrier-sigstop",
        )
        else None
    )
    config = {
        "schema_version": 2,
        "nonce": nonce,
        "session_id": selected_session_id,
        "uid": int(realm["uid"]),
        "gid": int(realm["gid"]),
        "handshake_path": str(handshake_path),
        "trusted_root": str(_TRUSTED_CHECKOUT_ROOT),
        "trusted_sentinel": str(_TRUSTED_SUPPORT_PATH),
        "candidate_argv": exact_candidate_argv,
        "candidate_interpreter": exact_interpreter_binding,
        "writable_roots": writable_root_bindings,
        "read_roots": read_root_bindings,
        "host_mount_namespace": host_mount_namespace,
        "host_ipc_namespace": host_ipc_namespace,
        "host_network_namespace": host_network_namespace,
        "environment": dict(environment),
        "cwd": str(cwd),
        "timeout_seconds": timeout_seconds,
        "trusted_fault_point": inner_fault_point,
        "trusted_active_probe": (
            None
            if trusted_completion_sentinel is None
            else {
                "schema_version": 1,
                "nonce": nonce,
                "completion_sentinel": str(trusted_completion_sentinel),
                "owner_uid": os.getuid(),
                "owner_identity": _process_identity_document(
                    active_owner_identity
                ),
            }
        ),
    }
    config_path.write_text(
        json.dumps(config, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    config_path.chmod(0o400)
    _invoke_root_tree_operation(
        controller_path,
        "own",
        Path(snapshot["control_root"]),
        0,
        0,
        "trusted-control",
    )
    output = _run_registered_sudo(
        [
            str(_STRICT_PRIMITIVES["python"]),
            *_ROOT_PYTHON_ARGUMENTS,
            str(controller_path),
            "--isolation-root-controller",
            str(config_path),
        ],
        timeout=(
            timeout_seconds + CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS + 5
            if outer_timeout_seconds is None
            else outer_timeout_seconds
        ),
        input_bytes=input_bytes,
        cwd=_TRUSTED_CHECKOUT_ROOT,
        execution_root=execution_root,
        cleanup_execution_root=False,
        handshake_path=handshake_path,
        session_id=selected_session_id,
        output_limit=(CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES * 3),
        trusted_fault_probe=trusted_outer_fault_probe,
    )
    receipt = _decode_controller_receipt(output, b"", nonce)
    return receipt


def _invoke_registered_session_cleanup(
    controller_path: Path, entry_path: Path, target_uid: int
) -> None:
    token = _active_strict_session().get("token")
    if type(token) is not str:
        raise AssertionError("strict registered cleanup token is malformed")
    output = _run_registered_sudo(
        [
            str(_STRICT_PRIMITIVES["python"]),
            *_ROOT_PYTHON_ARGUMENTS,
            str(controller_path),
            "--isolation-cleanup",
            str(entry_path),
            str(target_uid),
            token,
        ],
        recovery_broker=True,
    )
    expected_prefix = _ROOT_CLEANUP_RECEIPT_PREFIX.encode("ascii")
    if not output.startswith(expected_prefix) or output.count(b"\n") != 1:
        raise AssertionError("strict registered cleanup receipt is malformed")
    try:
        receipt = json.loads(output[len(expected_prefix) :])
    except json.JSONDecodeError as error:
        raise AssertionError("strict registered cleanup receipt is malformed") from error
    if type(receipt) is not dict or receipt.get("status") != "complete":
        raise AssertionError(
            "strict registered cleanup did not complete: "
            f"{receipt.get('error') if isinstance(receipt, dict) else 'invalid'}"
        )


_NORMAL_NAMESPACE_PROBE = b"""\
import os
import time

first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second == 0:
        time.sleep(30)
    os._exit(0)
raise SystemExit(0)
"""
_KILL_NAMESPACE_PROBE = b"""\
import os
import time

first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second == 0:
        time.sleep(30)
    os._exit(0)
time.sleep(30)
"""


def _decode_strict_probe_output_text(
    receipt: Mapping[str, object], field: str
) -> str:
    encoded = receipt.get(field)
    encoded_limit = ((CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES + 2) // 3) * 4
    if type(encoded) is not str or len(encoded) > encoded_limit:
        raise AssertionError(f"strict candidate {field} receipt is malformed")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise AssertionError(
            f"strict candidate {field} receipt is malformed"
        ) from error
    if len(decoded) > CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES:
        raise AssertionError(f"strict candidate {field} receipt is malformed")
    return decoded.decode("utf-8", errors="backslashreplace")


def _strict_probe_output_text(
    receipt: Mapping[str, object], field: str
) -> str:
    try:
        return _decode_strict_probe_output_text(receipt, field)
    except AssertionError:
        return f"<malformed {field}>"


def _strict_normal_probe_failure_details(
    receipt: Mapping[str, object],
) -> str:
    string_fields = ("status", "cleanup_status")
    boolean_fields = ("timed_out", "process_leak_observed")
    summary: dict[str, object] = {
        field: (
            receipt.get(field)
            if type(receipt.get(field)) is str
            and len(str(receipt.get(field))) <= 64
            else "<malformed>"
        )
        for field in string_fields
    }
    summary.update(
        {
            field: (
                receipt.get(field)
                if type(receipt.get(field)) is bool
                else "<malformed>"
            )
            for field in boolean_fields
        }
    )
    returncode = receipt.get("returncode")
    summary["returncode"] = (
        returncode
        if type(returncode) is int or returncode is None
        else "<malformed>"
    )
    summary_text = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    details = (
        "receipt="
        + summary_text
        + "\nstdout:\n"
        + _strict_probe_output_text(receipt, "stdout_base64")
        + "\nstderr:\n"
        + _strict_probe_output_text(receipt, "stderr_base64")
        + "\nreceipt-final="
        + summary_text
    )
    return _bounded_failure_text(details)


_TARGET_ACTIVE_PROBE_SOURCE = b"""\
import json
import os
import sys
import time

nonce = sys.argv[1]
marker = {
    "schema_version": 1,
    "nonce": nonce,
    "uid": os.getuid(),
    "gid": os.getgid(),
}
print(
    "REQUIRED_CI_TARGET_ACTIVE:"
    + json.dumps(marker, sort_keys=True, separators=(",", ":")),
    flush=True,
)
time.sleep(120)
"""

_OUTER_OWNER_SENTINEL_SOURCE = r'''
import os
import stat
import sys

path = sys.argv[1]
nonce = sys.argv[2]
owner_uid = int(sys.argv[3])
descriptor = os.open(
    path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
)
try:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise SystemExit(171)
    payload = f"executed:{nonce}".encode("ascii")
    os.ftruncate(descriptor, 0)
    if os.write(descriptor, payload) != len(payload):
        raise SystemExit(172)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
'''.strip()


def _read_outer_owner_json(path: Path, description: str) -> dict[str, object]:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        before = os.fstat(descriptor)
        data = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
    except OSError as error:
        raise AssertionError(
            f"strict outer owner {description} is unreadable"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        any(getattr(before, field) != getattr(after, field) for field in stable_fields)
        or (before.st_dev, before.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size != len(data)
        or len(data) > 4096
    ):
        raise AssertionError(
            f"strict outer owner {description} identity is unstable"
        )
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(
            f"strict outer owner {description} is malformed"
        ) from error
    if type(document) is not dict:
        raise AssertionError(
            f"strict outer owner {description} is not a document"
        )
    return document


def _wait_outer_owner_fault_ack(
    path: Path,
    process: subprocess.Popen[bytes],
    *,
    boundary: str,
    selected_signal: int,
    stdout_file: IO[bytes],
    stderr_file: IO[bytes],
    timeout_seconds: float = _STRICT_WATCHDOG_TIMEOUT_SECONDS,
) -> dict[str, object]:
    if (
        boundary not in _OUTER_OWNER_FAULT_BOUNDARIES
        or selected_signal not in (signal.SIGKILL, signal.SIGSTOP)
    ):
        raise AssertionError(
            "strict outer owner fault diagnostic context is malformed"
        )
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            return _read_outer_owner_json(path, "fault ACK")
        except AssertionError as error:
            if not isinstance(error.__cause__, FileNotFoundError):
                raise
        returncode = process.poll()
        if returncode is not None:
            if type(returncode) is not int:
                raise AssertionError(
                    "strict outer owner terminal return code is malformed"
                )
            signal_name = {
                signal.SIGKILL: "SIGKILL",
                signal.SIGSTOP: "SIGSTOP",
            }[selected_signal]
            context = json.dumps(
                {
                    "boundary": boundary,
                    "returncode": returncode,
                    "selected_signal": signal_name,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            stdout = _read_outer_owner_terminal_diagnostic(stdout_file)
            stderr = _read_outer_owner_terminal_diagnostic(stderr_file)
            detail = _bounded_failure_text(
                context + "\nstdout: " + stdout + "\nstderr: " + stderr,
                2000,
            )
            raise AssertionError(
                "strict outer owner exited before publishing its fault ACK: "
                + detail
            )
        time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
    raise AssertionError("strict outer owner fault ACK timed out")


def _read_outer_owner_terminal_diagnostic(
    stream: IO[bytes],
    *,
    byte_limit: int = 4096,
    text_limit: int = 700,
) -> str:
    if byte_limit != 4096 or text_limit != 700:
        raise AssertionError("strict outer owner diagnostic bounds are malformed")
    try:
        descriptor = stream.fileno()
        if type(descriptor) is not int or descriptor < 0:
            raise OSError(errno.EBADF, "invalid diagnostic descriptor")
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 0:
            raise OSError(errno.EINVAL, "invalid diagnostic object")
        if metadata.st_size <= byte_limit:
            data = os.pread(descriptor, metadata.st_size, 0)
        else:
            head_limit = byte_limit // 2
            tail_limit = byte_limit - head_limit
            head = os.pread(descriptor, head_limit, 0)
            tail = os.pread(
                descriptor,
                tail_limit,
                metadata.st_size - tail_limit,
            )
            data = head + b"...[output middle truncated]..." + tail
    except OSError as error:
        error_number = error.errno if type(error.errno) is int else errno.EIO
        return f"[diagnostic unavailable errno={error_number}]"
    return _bounded_failure_text(
        data.decode("utf-8", errors="backslashreplace"),
        text_limit,
    )


def _validate_outer_owner_fault_ack(
    ack: Mapping[str, object],
    *,
    nonce: str,
    boundary: str,
    expected_session_id: str,
    owner_identity: tuple[int, int, int, int, int, tuple[int, int, int, int]],
    parent_registry_root: Path,
) -> tuple[
    Path,
    tuple[int, int],
    tuple[int, int, int, int],
    tuple[int, int, int, int],
    int,
    tuple[
        tuple[int, int, int, int, int, tuple[int, int, int, int]],
        ...,
    ],
]:
    if set(ack) != {
        "schema_version",
        "nonce",
        "boundary",
        "owner",
        "registry_root",
        "entry",
        "outer",
        "watchdog",
        "target_uid",
        "wrapper_post_gate_ready",
        "root_active",
    }:
        raise AssertionError("strict outer owner fault ACK fields are inexact")
    owner = _parse_root_chain_identity(ack.get("owner"), "fault owner")
    outer = _parse_root_chain_identity(ack.get("outer"), "fault outer")
    watchdog = _parse_root_chain_identity(
        ack.get("watchdog"), "fault watchdog"
    )
    root_binding = ack.get("registry_root")
    entry_binding = ack.get("entry")
    expected_state = {
        "after-outer-popen": "prepared",
        "after-outer-bound": "outer-bound",
        "after-root-authorized": "root-authorized",
        "after-root-authorized-barrier": "root-authorized",
        "after-target-active": "root-authorized",
    }.get(boundary)
    if (
        ack.get("schema_version") != 1
        or ack.get("nonce") != nonce
        or ack.get("boundary") != boundary
        or owner != tuple(_registered_process_binding(owner_identity))
        or type(root_binding) is not dict
        or set(root_binding) != {"path", "device", "inode"}
        or type(root_binding.get("path")) is not str
        or type(root_binding.get("device")) is not int
        or type(root_binding.get("inode")) is not int
        or type(entry_binding) is not dict
        or set(entry_binding) != {"path", "session_id", "state"}
        or type(entry_binding.get("path")) is not str
        or re.fullmatch(
            r"[0-9a-f]{32}", str(entry_binding.get("session_id"))
        )
        is None
        or entry_binding.get("session_id") != expected_session_id
        or entry_binding.get("state") != expected_state
        or type(ack.get("target_uid")) is not int
        or not 50000 <= int(ack["target_uid"]) <= 64999
        or ack.get("wrapper_post_gate_ready")
        is not (
            boundary
            in ("after-root-authorized-barrier", "after-target-active")
        )
    ):
        raise AssertionError("strict outer owner fault ACK binding is malformed")
    root = Path(str(root_binding["path"]))
    root_identity = (int(root_binding["device"]), int(root_binding["inode"]))
    entry_path = Path(str(entry_binding["path"]))
    session_id = str(entry_binding["session_id"])
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise AssertionError(
            "strict outer owner registry root is unreadable"
        ) from error
    if (
        not root.is_absolute()
        or root == parent_registry_root
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or (root_metadata.st_dev, root_metadata.st_ino) != root_identity
        or entry_path
        != root / "entries" / f"chain-{session_id}.json"
    ):
        raise AssertionError("strict outer owner registry root binding changed")
    entry = _read_outer_owner_json(entry_path, "fault entry")
    if (
        entry.get("session_id") != session_id
        or entry.get("state") != expected_state
        or entry.get("target_uid") != ack.get("target_uid")
        or entry.get("launcher_parent") != list(owner)
        or (
            boundary == "after-outer-popen"
            and entry.get("outer") is not None
        )
        or (
            boundary != "after-outer-popen"
            and entry.get("outer") != list(outer)
        )
    ):
        raise AssertionError("strict outer owner fault entry changed after ACK")
    observed_owner = _process_identity(Path("/proc") / str(owner[0]))
    observed_outer = _process_identity(Path("/proc") / str(outer[0]))
    observed_watchdog = _process_identity(Path("/proc") / str(watchdog[0]))
    if (
        observed_owner != owner_identity
        or observed_outer is None
        or _registered_process_binding(observed_outer) != list(outer)
        or observed_outer[2] != owner[0]
        or observed_outer[5] != (os.getuid(),) * 4
        or observed_watchdog is None
        or _registered_process_binding(observed_watchdog) != list(watchdog)
        or observed_watchdog[2] != owner[0]
        or observed_watchdog[5] != (os.getuid(),) * 4
    ):
        raise AssertionError("strict outer owner fault process identity changed")
    root_active_value = ack.get("root_active")
    if boundary == "after-target-active":
        if type(root_active_value) is not dict:
            raise AssertionError(
                "strict outer owner root-active ACK is missing"
            )
        root_active_identities = _validate_registered_root_active(
            root_active_value,
            nonce=nonce,
            outer=outer,
            target_uid=int(ack["target_uid"]),
            expected_session_id=session_id,
        )
    else:
        if root_active_value is not None:
            raise AssertionError(
                "strict outer owner root-active ACK is unexpected"
            )
        root_active_identities = ()
    return (
        root,
        root_identity,
        outer,
        watchdog,
        int(ack["target_uid"]),
        root_active_identities,
    )


def _wait_exact_registry_root_absent(
    root: Path,
    identity: tuple[int, int],
    *,
    timeout_seconds: float,
    bound_descriptor: int | None = None,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    zero_count = 0
    while time.monotonic() < deadline:
        try:
            metadata = root.lstat()
        except FileNotFoundError:
            zero_count += 1
            if zero_count >= _STRICT_ZERO_SCAN_COUNT:
                if bound_descriptor is not None:
                    bound_metadata = os.fstat(bound_descriptor)
                    if (
                        (bound_metadata.st_dev, bound_metadata.st_ino) != identity
                        or bound_metadata.st_nlink != 0
                    ):
                        raise AssertionError(
                            "strict outer owner exact registry unlink is unproved"
                        )
                return
        except OSError as error:
            raise AssertionError(
                "strict outer owner registry root cannot be revalidated"
            ) from error
        else:
            if (metadata.st_dev, metadata.st_ino) != identity:
                raise AssertionError(
                    "strict outer owner registry root identity changed"
                )
            zero_count = 0
        time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
    raise AssertionError("strict outer owner registry root was not removed")


def _wait_outer_owner_session_quiescent(
    outer: tuple[int, int, int, int], *, timeout_seconds: float
) -> None:
    deadline = time.monotonic() + timeout_seconds
    zero_count = 0
    while time.monotonic() < deadline:
        inventory = _host_session_inventory(outer[3])
        if not inventory:
            zero_count += 1
        else:
            leader = inventory.get(outer[0])
            nonleaders = tuple(
                identity
                for identity in inventory.values()
                if identity[0] != outer[0]
            )
            if leader is None or _registered_process_binding(leader) != list(outer):
                raise AssertionError(
                    "strict outer owner session generation changed"
                )
            zero_count = (
                zero_count + 1
                if not nonleaders and _registered_anchor_is_terminal(outer)
                else 0
            )
        if zero_count >= _STRICT_ZERO_SCAN_COUNT:
            return
        time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)
    raise AssertionError("strict outer owner session is not quiescent")


def _wait_process_pidfd_terminal(
    descriptor: int, *, timeout_seconds: float, description: str
) -> None:
    readable, _, _ = select.select([descriptor], [], [], timeout_seconds)
    if not readable:
        raise AssertionError(
            f"strict outer owner {description} did not become terminal"
        )


def _outer_owner_fault_probe_main(arguments: Sequence[str]) -> int:
    registry: dict[str, object] | None = None
    pause_descriptor = -1
    try:
        if len(arguments) != 7:
            raise AssertionError("strict outer owner probe arguments are malformed")
        (
            nonce,
            boundary,
            ack_value,
            session_id,
            bootstrap_value,
            pause_value,
            sentinel_value,
        ) = arguments
        if (
            re.fullmatch(r"[0-9a-f]{32}", nonce) is None
            or boundary not in _OUTER_OWNER_FAULT_BOUNDARIES
            or re.fullmatch(r"[0-9a-f]{32}", session_id) is None
            or not bootstrap_value.isdecimal()
            or not pause_value.isdecimal()
        ):
            raise AssertionError("strict outer owner probe selectors are malformed")
        ack_path = Path(ack_value)
        sentinel_path = Path(sentinel_value)
        pause_descriptor = int(pause_value)
        bootstrap_descriptor = int(bootstrap_value)
        try:
            readable, _, _ = select.select(
                [bootstrap_descriptor], [], [], _STRICT_WATCHDOG_TIMEOUT_SECONDS
            )
            bootstrap = (
                os.read(bootstrap_descriptor, 1) if readable else b""
            )
        finally:
            os.close(bootstrap_descriptor)
        if bootstrap != b"G":
            raise AssertionError("strict outer owner bootstrap was not authorized")
        ack_parent = ack_path.parent.resolve(strict=True)
        parent_metadata = ack_parent.lstat()
        if (
            not ack_path.is_absolute()
            or ack_path.parent != ack_parent
            or sentinel_path.parent != ack_parent
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or sentinel_path.read_bytes()
            != f"armed:{nonce}".encode("ascii")
        ):
            raise AssertionError("strict outer owner control root is unsafe")
        strict_isolation_platform_preflight()
        registry = trusted_isolation_chain_registry()
        if registry.get("inherited") is not False:
            raise AssertionError("strict outer owner inherited a registry")
        fault_probe = (
            ack_path,
            nonce,
            boundary,
            pause_descriptor,
        )
        if boundary == "after-target-active":
            candidate_root = candidate_repository_root()
            candidate_sha, _ = expected_candidate_sha(candidate_root)
            with _execution_snapshot(
                candidate_root,
                candidate_sha,
                probe_source=_TARGET_ACTIVE_PROBE_SOURCE,
            ) as snapshot:
                candidate_paths = snapshot.get("candidate_paths")
                runtime_root = snapshot.get("runtime_root")
                if (
                    not isinstance(candidate_paths, dict)
                    or len(candidate_paths) != 1
                    or not isinstance(runtime_root, Path)
                ):
                    raise AssertionError(
                        "strict outer owner active snapshot is malformed"
                    )
                probe_path = Path(next(iter(candidate_paths.values())))
                environment = _closed_candidate_environment(
                    None,
                    home=runtime_root,
                    temporary_root=runtime_root,
                )
                _invoke_strict_controller(
                    snapshot,
                    [
                        str(_STRICT_PRIMITIVES["python"]),
                        "-I",
                        "-B",
                        "-S",
                        str(probe_path),
                        nonce,
                    ],
                    environment,
                    runtime_root,
                    b"",
                    timeout_seconds=90.0,
                    trusted_outer_fault_probe=fault_probe,
                    trusted_completion_sentinel=sentinel_path,
                    registered_session_id=session_id,
                )
        else:
            _run_registered_sudo(
                [
                    str(_STRICT_PRIMITIVES["python"]),
                    *_ROOT_PYTHON_ARGUMENTS,
                    "-c",
                    _OUTER_OWNER_SENTINEL_SOURCE,
                    str(sentinel_path),
                    nonce,
                    str(os.getuid()),
                ],
                session_id=session_id,
                trusted_fault_probe=fault_probe,
            )
        raise AssertionError("strict outer owner fault probe unexpectedly passed")
    except BaseException as error:
        print(
            f"strict outer owner fault probe failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1
    finally:
        if pause_descriptor >= 0:
            try:
                os.close(pause_descriptor)
            except OSError:
                pass
        if registry is not None:
            try:
                close_trusted_isolation_chains(registry)
            except BaseException as error:
                print(
                    "strict outer owner registry close failed: "
                    f"{type(error).__name__}: {error}",
                    file=sys.stderr,
                )


def _assert_outer_owner_sentinel(path: Path, nonce: str) -> None:
    try:
        metadata = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise AssertionError("strict outer owner sentinel is unreadable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or data != f"armed:{nonce}".encode("ascii")
    ):
        raise AssertionError("strict outer owner sentinel was executed or replaced")


def _probe_independent_outer_owner_fault(
    boundary: str,
    selected_signal: int,
    *,
    candidate_root: Path,
    candidate_sha: str,
) -> None:
    if (
        boundary not in _OUTER_OWNER_FAULT_BOUNDARIES
        or selected_signal not in (signal.SIGKILL, signal.SIGSTOP)
        or not candidate_root.is_absolute()
        or re.fullmatch(r"[0-9a-f]{40}", candidate_sha) is None
    ):
        raise AssertionError("strict outer owner fault case is malformed")
    parent_session = _active_strict_session()
    parent_registry_root = parent_session.get("root")
    if not isinstance(parent_registry_root, Path):
        raise AssertionError("strict parent registry root is malformed")
    realm = _strict_realm()
    lock = realm.get("lock")
    lock_descriptor = (
        lock.fileno()
        if lock is not None and hasattr(lock, "fileno")
        else realm.get("inherited_lock_fd")
    )
    if type(lock_descriptor) is not int:
        raise AssertionError("strict outer owner realm lock is unavailable")
    nonce = uuid.uuid4().hex
    session_id = uuid.uuid4().hex
    temporary = tempfile.TemporaryDirectory(
        prefix="required-ci-outer-owner-probe-"
    )
    control_root = Path(temporary.name).resolve(strict=True)
    ack_path = control_root / "fault-ack.json"
    sentinel_path = control_root / "sudo-sentinel"
    _write_single_link_file(
        sentinel_path, f"armed:{nonce}".encode("ascii"), 0o600
    )
    bootstrap_read_fd = -1
    bootstrap_write_fd = -1
    pause_read_fd = -1
    pause_write_fd = -1
    owner_pidfd: int | None = None
    registry_descriptor: int | None = None
    outer_pidfd: int | None = None
    watchdog_pidfd: int | None = None
    root_active_pidfds: list[int] = []
    process: subprocess.Popen[bytes] | None = None
    stdout_file: IO[bytes] | None = None
    stderr_file: IO[bytes] | None = None
    registry_root: Path | None = None
    registry_identity: tuple[int, int] | None = None
    probe_completed = False
    try:
        bootstrap_read_fd, bootstrap_write_fd = os.pipe2(os.O_CLOEXEC)
        pause_read_fd, pause_write_fd = os.pipe2(os.O_CLOEXEC)
        environment = _minimal_supervisor_environment()
        environment.update(
            {
                ISOLATION_MODE_ENV: STRICT_ISOLATION_MODE,
                _ISOLATION_UID_ENV: str(realm["uid"]),
                _ISOLATION_GID_ENV: str(realm["gid"]),
                _ISOLATION_LOCK_FD_ENV: str(lock_descriptor),
                CANDIDATE_ROOT_ENV: str(candidate_root),
                CANDIDATE_SHA_ENV: candidate_sha,
            }
        )
        if any(
            key in environment
            for key in (
                _ISOLATION_REGISTRY_ENV,
                _ISOLATION_REGISTRY_TOKEN_ENV,
                _ISOLATION_WATCHDOG_TOKEN_ENV,
            )
        ):
            raise AssertionError("strict outer owner inherited recovery state")
        stdout_file = tempfile.TemporaryFile()
        stderr_file = tempfile.TemporaryFile()
        process = subprocess.Popen(
            [
                str(_STRICT_PRIMITIVES["python"]),
                *_ROOT_PYTHON_ARGUMENTS,
                str(_TRUSTED_SUPPORT_PATH),
                "--outer-owner-fault-probe",
                nonce,
                boundary,
                str(ack_path),
                session_id,
                str(bootstrap_read_fd),
                str(pause_read_fd),
                str(sentinel_path),
            ],
            cwd=str(_TRUSTED_CHECKOUT_ROOT),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            pass_fds=(lock_descriptor, bootstrap_read_fd, pause_read_fd),
            start_new_session=True,
        )
        os.close(bootstrap_read_fd)
        bootstrap_read_fd = -1
        os.close(pause_read_fd)
        pause_read_fd = -1
        owner_pidfd = os.pidfd_open(process.pid, 0)
        owner_identity = _process_identity(Path("/proc") / str(process.pid))
        if (
            owner_identity is None
            or owner_identity[0] != owner_identity[3]
            or owner_identity[0] != owner_identity[4]
            or owner_identity[5] != (os.getuid(),) * 4
        ):
            raise AssertionError("strict outer owner identity is invalid")
        if os.write(bootstrap_write_fd, b"G") != 1:
            raise AssertionError("strict outer owner bootstrap release was incomplete")
        os.close(bootstrap_write_fd)
        bootstrap_write_fd = -1
        ack = _wait_outer_owner_fault_ack(
            ack_path,
            process,
            boundary=boundary,
            selected_signal=selected_signal,
            stdout_file=stdout_file,
            stderr_file=stderr_file,
            timeout_seconds=(
                _STRICT_WATCHDOG_TIMEOUT_SECONDS
                if boundary != "after-target-active"
                else _STRICT_WATCHDOG_TIMEOUT_SECONDS
                + (CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS * 3)
            ),
        )
        (
            registry_root,
            registry_identity,
            outer,
            watchdog,
            target_uid,
            root_active_identities,
        ) = _validate_outer_owner_fault_ack(
            ack,
            nonce=nonce,
            boundary=boundary,
            expected_session_id=session_id,
            owner_identity=owner_identity,
            parent_registry_root=parent_registry_root,
        )
        registry_descriptor = os.open(
            registry_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        registry_metadata = os.fstat(registry_descriptor)
        if (
            (registry_metadata.st_dev, registry_metadata.st_ino)
            != registry_identity
        ):
            raise AssertionError("strict outer owner registry descriptor changed")
        outer_pidfd = os.pidfd_open(outer[0], 0)
        watchdog_pidfd = os.pidfd_open(watchdog[0], 0)
        if (
            _registered_process_binding(
                _process_identity(Path("/proc") / str(outer[0]))
                or (0, 0, 0, 0, 0, (0, 0, 0, 0))
            )
            != list(outer)
            or _registered_process_binding(
                _process_identity(Path("/proc") / str(watchdog[0]))
                or (0, 0, 0, 0, 0, (0, 0, 0, 0))
            )
            != list(watchdog)
        ):
            raise AssertionError("strict outer owner process pidfd binding changed")
        for index, identity in enumerate(root_active_identities):
            descriptor = os.pidfd_open(identity[0], 0)
            root_active_pidfds.append(descriptor)
            if (
                _process_identity(Path("/proc") / str(identity[0]))
                != identity
            ):
                raise AssertionError(
                    "strict outer owner root-active pidfd binding changed "
                    f"at index {index}"
                )
        _assert_outer_owner_sentinel(sentinel_path, nonce)
        _signal_process_pidfd(owner_pidfd, selected_signal)
        process.wait(
            timeout=(
                _STRICT_WATCHDOG_TIMEOUT_SECONDS
                + (CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS * 3)
            )
        )
        if process.returncode != -signal.SIGKILL:
            raise AssertionError(
                "strict outer owner was not terminated by an exact SIGKILL"
            )
        _wait_process_pidfd_terminal(
            owner_pidfd,
            timeout_seconds=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS,
            description="owner",
        )
        os.close(pause_write_fd)
        pause_write_fd = -1
        _wait_exact_registry_root_absent(
            registry_root,
            registry_identity,
            timeout_seconds=(
                _STRICT_WATCHDOG_TIMEOUT_SECONDS
                + (CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS * 3)
            ),
            bound_descriptor=registry_descriptor,
        )
        _wait_outer_owner_session_quiescent(
            outer,
            timeout_seconds=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS,
        )
        _stable_uid_zero(target_uid)
        _wait_process_pidfd_terminal(
            outer_pidfd,
            timeout_seconds=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS,
            description="outer anchor",
        )
        _wait_process_pidfd_terminal(
            watchdog_pidfd,
            timeout_seconds=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS,
            description="watchdog",
        )
        for index, descriptor in enumerate(root_active_pidfds):
            _wait_process_pidfd_terminal(
                descriptor,
                timeout_seconds=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS,
                description="root-active process " + str(index),
            )
        _assert_outer_owner_sentinel(sentinel_path, nonce)
        stdout = _read_registered_bounded_file(
            stdout_file, "outer owner stdout", 4096
        )
        stderr = _read_registered_bounded_file(
            stderr_file, "outer owner stderr", 4096
        )
        if stdout or stderr:
            raise AssertionError("strict outer owner fault probe wrote output")
        probe_completed = True
    finally:
        for descriptor_name, descriptor in (
            ("bootstrap read", bootstrap_read_fd),
            ("bootstrap write", bootstrap_write_fd),
            ("pause read", pause_read_fd),
            ("pause write", pause_write_fd),
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    if probe_completed:
                        raise AssertionError(
                            f"strict outer owner {descriptor_name} close failed"
                        )
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                if owner_pidfd is not None:
                    _signal_process_pidfd(owner_pidfd, signal.SIGKILL)
                    process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
        for descriptor in (
            *root_active_pidfds,
            watchdog_pidfd,
            outer_pidfd,
            registry_descriptor,
            owner_pidfd,
        ):
            if descriptor is not None:
                os.close(descriptor)
        if stdout_file is not None:
            stdout_file.close()
        if stderr_file is not None:
            stderr_file.close()
        temporary.cleanup()


def _ensure_strict_backend() -> None:
    global _STRICT_BACKEND_VALIDATED
    strict_isolation_platform_preflight()
    _active_strict_session()
    if _STRICT_BACKEND_VALIDATED:
        return
    _strict_realm()
    _run_registered_sudo([str(_STRICT_PRIMITIVES["true"])])
    _protect_strict_checkout_boundaries()
    candidate_root = candidate_repository_root()
    candidate_sha, _ = expected_candidate_sha(candidate_root)
    for source, timeout_seconds, expect_timeout in (
        (_NORMAL_NAMESPACE_PROBE, 5.0, False),
        (_KILL_NAMESPACE_PROBE, 0.5, True),
    ):
        with _execution_snapshot(
            candidate_root, candidate_sha, probe_source=source
        ) as snapshot:
            candidate_paths = snapshot["candidate_paths"]
            runtime_root = snapshot["runtime_root"]
            if not isinstance(candidate_paths, dict) or not isinstance(runtime_root, Path):
                raise AssertionError("strict capability snapshot is malformed")
            probe_path = Path(next(iter(candidate_paths.values())))
            environment = _closed_candidate_environment(
                None, home=runtime_root, temporary_root=runtime_root
            )
            receipt = _invoke_strict_controller(
                snapshot,
                [
                    str(_STRICT_PRIMITIVES["python"]),
                    "-I",
                    "-B",
                    "-S",
                    str(probe_path),
                ],
                environment,
                runtime_root,
                b"",
                timeout_seconds=timeout_seconds,
            )
        if receipt.get("status") != "completed":
            raise AssertionError(
                f"strict candidate live capability probe failed: {receipt.get('error')}"
            )
        if receipt.get("cleanup_status") != "complete":
            raise AssertionError("strict candidate live capability cleanup is incomplete")
        if receipt.get("timed_out") is not expect_timeout:
            raise AssertionError("strict candidate live capability timeout result is wrong")
        try:
            _decode_strict_probe_output_text(receipt, "stdout_base64")
            _decode_strict_probe_output_text(receipt, "stderr_base64")
        except AssertionError as error:
            if not expect_timeout:
                raise AssertionError(
                    "strict candidate normal namespace probe failed: "
                    + _strict_normal_probe_failure_details(receipt)
                ) from error
            raise AssertionError(
                "strict candidate kill namespace probe output receipt is malformed"
            ) from error
        returncode = receipt.get("returncode")
        process_leak_observed = receipt.get("process_leak_observed")
        if type(returncode) is not int or type(process_leak_observed) is not bool:
            if expect_timeout:
                raise AssertionError(
                    "strict candidate kill namespace probe receipt is malformed"
                )
            raise AssertionError(
                "strict candidate normal namespace probe failed: "
                + _strict_normal_probe_failure_details(receipt)
            )
        if expect_timeout and returncode != -signal.SIGKILL:
            raise AssertionError(
                "strict candidate kill namespace probe receipt is malformed"
            )
        if not expect_timeout and (
            returncode != 0 or process_leak_observed is not False
        ):
            raise AssertionError(
                "strict candidate normal namespace probe failed: "
                + _strict_normal_probe_failure_details(receipt)
            )
        if _candidate_uid_inventory(int(_strict_realm()["uid"])):
            raise AssertionError("strict candidate live probe left a process")
    for fault_point in (
        "after-wrapper-popen-before-handshake-sigkill",
        "after-wrapper-popen-before-handshake-sigstop",
        "after-wrapper-bound-before-barrier-sigkill",
        "after-wrapper-bound-before-barrier-sigstop",
    ):
        with _execution_snapshot(
            candidate_root,
            candidate_sha,
            probe_source=b"raise SystemExit(0)\n",
        ) as snapshot:
            candidate_paths = snapshot["candidate_paths"]
            runtime_root = snapshot["runtime_root"]
            if not isinstance(candidate_paths, dict) or not isinstance(runtime_root, Path):
                raise AssertionError("strict fault probe snapshot is malformed")
            probe_path = Path(next(iter(candidate_paths.values())))
            environment = _closed_candidate_environment(
                None, home=runtime_root, temporary_root=runtime_root
            )
            try:
                _invoke_strict_controller(
                    snapshot,
                    [
                        str(_STRICT_PRIMITIVES["python"]),
                        "-I",
                        "-B",
                        "-S",
                        str(probe_path),
                    ],
                    environment,
                    runtime_root,
                    b"",
                    timeout_seconds=1.0,
                    trusted_fault_point=fault_point,
                    outer_timeout_seconds=0.5,
                )
            except AssertionError:
                pass
            else:
                raise AssertionError("strict root wrapper fault probe unexpectedly passed")
        if _candidate_uid_inventory(int(_strict_realm()["uid"])):
            raise AssertionError("strict root wrapper fault probe left a process")
    for boundary in (
        "after-outer-popen",
        "after-outer-bound",
        "after-root-authorized",
        "after-root-authorized-barrier",
        "after-target-active",
    ):
        for selected_signal in (signal.SIGKILL, signal.SIGSTOP):
            _probe_independent_outer_owner_fault(
                boundary,
                selected_signal,
                candidate_root=candidate_root,
                candidate_sha=candidate_sha,
            )
    _STRICT_BACKEND_VALIDATED = True


def trusted_isolation_child_environment() -> dict[str, str]:
    if not _strict_isolation_requested():
        return {}
    _active_strict_session()
    _ensure_strict_backend()
    realm = _strict_realm()
    lock = realm.get("lock")
    lock_descriptor = (
        lock.fileno()
        if lock is not None and hasattr(lock, "fileno")
        else realm.get("inherited_lock_fd")
    )
    if type(lock_descriptor) is not int:
        raise AssertionError("strict isolation parent does not hold the realm lock")
    return {
        _ISOLATION_UID_ENV: str(realm["uid"]),
        _ISOLATION_GID_ENV: str(realm["gid"]),
        _ISOLATION_LOCK_FD_ENV: str(lock_descriptor),
    }


def trusted_isolation_child_pass_fds() -> tuple[int, ...]:
    if not _strict_isolation_requested():
        return ()
    _active_strict_session()
    realm = _strict_realm()
    lock = realm.get("lock")
    lock_descriptor = (
        lock.fileno()
        if lock is not None and hasattr(lock, "fileno")
        else realm.get("inherited_lock_fd")
    )
    if type(lock_descriptor) is not int:
        raise AssertionError("strict isolation parent does not hold the realm lock")
    return (lock_descriptor,)


def assert_candidate_isolation_quiescent() -> None:
    if not _strict_isolation_requested():
        return
    target_uid = int(_strict_realm()["uid"])
    for _ in range(_STRICT_ZERO_SCAN_COUNT):
        if _candidate_uid_inventory(target_uid):
            raise AssertionError("strict candidate UID realm is not quiescent")
        time.sleep(_STRICT_ZERO_SCAN_INTERVAL_SECONDS)


def _candidate_child_resource_limits() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (
            CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES,
            CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES,
        ),
    )


def _kill_candidate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise AssertionError("candidate process group could not be reaped") from error


def _candidate_process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError as error:
        raise AssertionError("candidate process group cannot be inspected") from error
    return True


def _read_bounded_output(output_file, description: str) -> str:
    output_file.flush()
    size = output_file.tell()
    if size > CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES:
        raise AssertionError(f"candidate {description} exceeded its fixed limit")
    output_file.seek(0)
    data = output_file.read(CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES + 1)
    if len(data) != size:
        raise AssertionError(f"candidate {description} could not be read completely")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AssertionError(f"candidate {description} is not valid UTF-8") from error


def _validated_candidate_script(root: Path, script: Path) -> None:
    content_root = _candidate_content_root_for_checkout(root)
    try:
        relative_script = script.relative_to(content_root)
    except ValueError as error:
        raise AssertionError(
            "candidate subprocess script escapes the candidate content root"
        ) from error
    if relative_script not in CANDIDATE_SCRIPT_RELATIVE_PATHS:
        raise AssertionError("candidate subprocess script is not in the fixed inventory")
    if _ordinary_candidate_file(content_root, relative_script) != script:
        raise AssertionError("candidate subprocess script path is not canonical")


def _run_candidate_process(
    script: Path,
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
    writable_roots: Sequence[Path] = (),
    readable_roots: Sequence[Path] = (),
) -> subprocess.CompletedProcess[str]:
    strict_isolation_platform_preflight()
    strict = _strict_isolation_requested()
    configured_interpreter_binding: dict[str, object] | None = None
    if strict:
        _active_strict_session()
        strict_candidate_sha = os.environ.get(CANDIDATE_SHA_ENV)
        if strict_candidate_sha is None:
            raise AssertionError(
                "strict candidate isolation requires an explicit frozen candidate SHA"
            )
        _parse_candidate_sha(strict_candidate_sha, CANDIDATE_SHA_ENV)
        realm = _strict_realm()
        configured_interpreter_binding = _bind_configured_candidate_interpreter(
            int(realm["uid"]), int(realm["gid"])
        )
    root = candidate_repository_root()
    candidate_sha, require_clean = expected_candidate_sha(root)
    if strict and not require_clean:
        raise AssertionError(
            "strict candidate isolation requires an explicit frozen candidate SHA"
        )
    need_workspace = cwd is None
    before, captured_sources, captured_workspace_sources = (
        _candidate_checkout_binding_with_sources(
            root,
            candidate_sha,
            require_clean=require_clean,
            capture_workspace=need_workspace,
        )
    )
    if need_workspace and captured_workspace_sources is None:
        raise AssertionError("candidate workspace sources were not captured")
    if not need_workspace and captured_workspace_sources is not None:
        raise AssertionError("candidate workspace sources were unexpectedly captured")
    _validated_candidate_script(root, script)
    input_bytes = b"" if input_text is None else input_text.encode("utf-8")
    if len(input_bytes) > CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES:
        raise AssertionError("candidate stdin exceeds its fixed limit")
    supplied_environment = os.environ if env is None else env
    requested_home_value = None if env is None else supplied_environment.get("HOME")
    requested_home = (
        Path(requested_home_value)
        if requested_home_value is not None
        else None
    )
    if strict:
        _ensure_strict_backend()
        if requested_home is not None:
            if not requested_home.is_absolute() or requested_home.is_symlink():
                raise AssertionError("strict candidate HOME must be an absolute directory")
            requested_home = requested_home.resolve(strict=True)
        if cwd is not None:
            if not Path(cwd).is_absolute():
                raise AssertionError("strict candidate cwd must be absolute")
            _registered_fixture_root(Path(cwd))

    timed_out = False
    lingering_group = False
    returncode: int | None = None
    stdout = ""
    stderr = ""
    exact_command: list[str] = []
    expected_script_manifest = before.get("candidate_script_sha256")
    if not isinstance(expected_script_manifest, dict) or not all(
        isinstance(path, str) and isinstance(digest, str)
        for path, digest in expected_script_manifest.items()
    ):
        raise AssertionError("candidate script manifest is malformed")
    with _execution_snapshot(
        root,
        candidate_sha,
        require_clean=require_clean,
        expected_script_manifest=expected_script_manifest,
        candidate_sources=captured_sources,
        candidate_workspace_sources=captured_workspace_sources,
        materialize_workspace=need_workspace,
    ) as snapshot, _prepared_candidate_fixtures(
        Path(snapshot["controller_path"]),
        tuple(Path(path) for path in writable_roots),
        requested_home,
    ) as prepared_roots:
            safe_git_directories = _fixture_git_repositories(
                prepared_roots
                if strict
                else tuple(Path(path) for path in writable_roots)
            )
            candidate_paths = snapshot["candidate_paths"]
            runtime_root = snapshot["runtime_root"]
            workspace_root = snapshot["workspace_root"]
            if (
                not isinstance(candidate_paths, dict)
                or not isinstance(runtime_root, Path)
                or (
                    need_workspace
                    and not isinstance(workspace_root, Path)
                )
                or (not need_workspace and workspace_root is not None)
            ):
                raise AssertionError("candidate execution snapshot is malformed")
            snapshot_script = Path(candidate_paths[script.name])
            exact_command = [
                (
                    str(snapshot_script)
                    if str(value) == str(script)
                    else str(candidate_paths["required_ci_candidate.py"])
                    if str(value) == str(_TRUSTED_SUPPORT_PATH)
                    else str(value)
                )
                for value in command
            ]
            if strict:
                if not exact_command or exact_command[0] != sys.executable:
                    raise AssertionError(
                        "strict candidate command must start with the trusted interpreter selector"
                    )
                if (
                    configured_interpreter_binding is None
                    or exact_command[0]
                    != configured_interpreter_binding.get("selector")
                ):
                    raise AssertionError(
                        "strict candidate configured interpreter binding changed"
                    )
                exact_command[0] = str(
                    configured_interpreter_binding["resolved"]
                )
            child_home = runtime_root if requested_home is None else requested_home
            child_environment = _closed_candidate_environment(
                supplied_environment,
                home=child_home,
                temporary_root=runtime_root,
                safe_git_directories=safe_git_directories,
            )
            child_cwd = workspace_root if need_workspace else Path(cwd)
            if not isinstance(child_cwd, Path):
                raise AssertionError("candidate child cwd is malformed")
            if strict:
                receipt = _invoke_strict_controller(
                    snapshot,
                    exact_command,
                    child_environment,
                    child_cwd,
                    input_bytes,
                    timeout_seconds=CANDIDATE_PROCESS_TIMEOUT_SECONDS,
                    candidate_interpreter_binding=(
                        configured_interpreter_binding
                    ),
                    writable_roots=prepared_roots,
                    readable_roots=readable_roots,
                )
                if receipt.get("status") != "completed":
                    raise AssertionError(
                        "strict candidate process isolation blocked: "
                        f"{receipt.get('error')}"
                    )
                if receipt.get("cleanup_status") != "complete":
                    raise AssertionError("strict candidate process cleanup is incomplete")
                timed_out_value = receipt.get("timed_out")
                if type(timed_out_value) is not bool:
                    raise AssertionError(
                        "strict candidate timed-out receipt is malformed"
                    )
                process_leak_observed = receipt.get("process_leak_observed")
                if type(process_leak_observed) is not bool:
                    raise AssertionError(
                        "strict candidate process-leak receipt is malformed"
                    )
                timed_out = timed_out_value
                lingering_group = process_leak_observed
                returncode_value = receipt.get("returncode")
                if type(returncode_value) is not int:
                    raise AssertionError("strict candidate return code is malformed")
                returncode = returncode_value
                try:
                    stdout_bytes = base64.b64decode(
                        str(receipt["stdout_base64"]), validate=True
                    )
                    stderr_bytes = base64.b64decode(
                        str(receipt["stderr_base64"]), validate=True
                    )
                    stdout = stdout_bytes.decode("utf-8")
                    stderr = stderr_bytes.decode("utf-8")
                except (KeyError, ValueError, UnicodeDecodeError) as error:
                    raise AssertionError(
                        "strict candidate output receipt is malformed"
                    ) from error
            else:
                with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                    process = subprocess.Popen(
                        exact_command,
                        cwd=str(child_cwd),
                        env=child_environment,
                        stdin=subprocess.PIPE
                        if input_text is not None
                        else subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        start_new_session=True,
                        preexec_fn=_candidate_child_resource_limits,
                    )
                    try:
                        process.communicate(
                            input_bytes if input_text is not None else None,
                            timeout=CANDIDATE_PROCESS_TIMEOUT_SECONDS,
                        )
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        _kill_candidate_process_group(process)
                    lingering_group = _candidate_process_group_exists(process.pid)
                    if lingering_group:
                        _kill_candidate_process_group(process)
                    stdout = _read_bounded_output(stdout_file, "stdout")
                    stderr = _read_bounded_output(stderr_file, "stderr")
                    returncode = process.returncode

    after = candidate_checkout_binding(root, candidate_sha, require_clean=require_clean)
    if after != before:
        raise AssertionError("candidate checkout binding changed during subprocess")
    if timed_out:
        raise AssertionError("candidate subprocess exceeded its fixed timeout")
    if lingering_group:
        raise AssertionError("candidate subprocess left an active descendant")
    if strict and _candidate_uid_inventory(int(_strict_realm()["uid"])):
        raise AssertionError("candidate process isolation is not quiescent")
    if type(returncode) is not int:
        raise AssertionError("candidate subprocess did not produce a return code")
    return subprocess.CompletedProcess(exact_command, returncode, stdout, stderr)


def run_candidate_python(
    script: Path,
    arguments: Sequence[str] = (),
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
    writable_roots: Sequence[Path] = (),
    readable_roots: Sequence[Path] = (),
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-I", str(script), *arguments]
    return _run_candidate_process(
        script,
        command,
        cwd=cwd,
        env=env,
        input_text=input_text,
        writable_roots=writable_roots,
        readable_roots=readable_roots,
    )


def run_candidate_hook_fault_probe(
    script: Path,
    faults: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    input_text: str,
    writable_roots: Sequence[Path] = (),
) -> subprocess.CompletedProcess[str]:
    if script.name != "waited_delivery_hook_adapter.py":
        raise AssertionError("candidate hook fault probe requires the hook adapter")
    exact_faults = tuple(faults)
    if exact_faults not in _HOOK_FAULT_PROFILES:
        raise AssertionError("candidate hook fault probe has an invalid fault sequence")
    command = [
        sys.executable,
        "-I",
        "-B",
        str(_TRUSTED_SUPPORT_PATH),
        "--hook-fault-probe",
        str(script),
        ",".join(exact_faults),
    ]
    completed = _run_candidate_process(
        script,
        command,
        env=env,
        input_text=input_text,
        writable_roots=writable_roots,
    )
    return completed


def _hook_fault_probe_main(adapter_value: str, fault_value: str) -> int:
    adapter_path = Path(adapter_value)
    if (
        not adapter_path.is_absolute()
        or adapter_path.name != "waited_delivery_hook_adapter.py"
    ):
        raise AssertionError("candidate hook fault probe requires an absolute script path")
    faults = tuple(fault_value.split(","))
    if faults not in _HOOK_FAULT_PROFILES:
        raise AssertionError("candidate hook fault probe has an invalid fault sequence")
    spec = importlib.util.spec_from_file_location(
        "_required_ci_candidate_hook_adapter", adapter_path
    )
    if spec is None or spec.loader is None:
        raise AssertionError("candidate hook adapter cannot be loaded for the fault probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    observed_faults: list[str] = []

    def injected_continuation_failure(*_args, **_kwargs):
        observed_faults.append("continuation")
        raise RuntimeError("required-ci injected continuation failure")

    def injected_fallback_failure(*_args, **_kwargs):
        observed_faults.append("fallback")
        raise RuntimeError("required-ci injected fallback failure")

    def injected_last_resort_failure(*_args, **_kwargs):
        observed_faults.append("last-resort")
        raise RuntimeError("required-ci injected last-resort failure")

    def injected_diagnostic_log_failure(*_args, **_kwargs):
        observed_faults.append("diagnostic-log")
        raise RuntimeError("required-ci injected diagnostic log failure")

    original_print = print

    def injected_print(*args, **kwargs):
        message = args[0] if args else ""
        if (
            "diagnostic-stderr" in faults
            and isinstance(message, str)
            and message.startswith("waited-delivery hook diagnostics write failed:")
        ):
            observed_faults.append("diagnostic-stderr")
            raise RuntimeError("required-ci injected diagnostic stderr failure")
        if "prompt-stderr" in faults and kwargs.get("file") is sys.stderr:
            observed_faults.append("prompt-stderr")
            raise RuntimeError("required-ci injected prompt stderr failure")
        return original_print(*args, **kwargs)

    if "continuation" in faults:
        module._build_stop_continuation_prompt = injected_continuation_failure
    if "fallback" in faults:
        module._build_stop_fallback_prompt = injected_fallback_failure
    if "last-resort" in faults:
        module._build_stop_last_resort_prompt = injected_last_resort_failure
    if "diagnostic-log" in faults:
        module._append_hook_log = injected_diagnostic_log_failure
    if "diagnostic-stderr" in faults or "prompt-stderr" in faults:
        module.print = injected_print
    if "diagnostic-stderr" in faults:
        os.environ["WAITED_DELIVERY_HOOK_DEBUG"] = "1"
    original_argv = sys.argv
    try:
        sys.argv = [str(adapter_path), "stop-hook"]
        try:
            result = module.main()
        except SystemExit as error:
            raise AssertionError(
                "candidate hook adapter bypassed the trusted probe return path"
            ) from error
    finally:
        sys.argv = original_argv
    if tuple(observed_faults) != faults:
        raise AssertionError("candidate hook adapter skipped the injected fault sequence")
    if type(result) is not int:
        raise AssertionError("candidate hook adapter returned a non-integer status")
    return result


if __name__ == "__main__":
    if len(sys.argv) == 8 and sys.argv[1] == "--isolation-registry-watchdog":
        raise SystemExit(_registry_watchdog_main(sys.argv[2:]))
    if len(sys.argv) == 9 and sys.argv[1] == "--outer-owner-fault-probe":
        raise SystemExit(_outer_owner_fault_probe_main(sys.argv[2:]))
    if len(sys.argv) == 3 and sys.argv[1] == "--isolation-root-controller":
        raise SystemExit(_root_controller_main(sys.argv[2]))
    if len(sys.argv) == 5 and sys.argv[1] == "--isolation-cleanup":
        raise SystemExit(
            _root_cleanup_main(sys.argv[2], sys.argv[3], sys.argv[4])
        )
    if len(sys.argv) == 3 and sys.argv[1] == "--isolation-uid-cleanup":
        raise SystemExit(_root_uid_cleanup_main(sys.argv[2]))
    if len(sys.argv) == 14 and sys.argv[1] == "--isolation-tree":
        raise SystemExit(_root_tree_main(sys.argv[2:]))
    if len(sys.argv) == 17 and sys.argv[1] == "--isolation-seal":
        raise SystemExit(_root_seal_execution_root_main(sys.argv[2:]))
    if len(sys.argv) == 4 and sys.argv[1] == "--hook-fault-probe":
        raise SystemExit(_hook_fault_probe_main(sys.argv[2], sys.argv[3]))
    raise SystemExit("required_ci_candidate.py is a trusted support module")
