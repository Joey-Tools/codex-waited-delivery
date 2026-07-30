#!/usr/bin/env python3

"""Compatibility runner for historical waited-delivery state."""

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
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time
import unicodedata
import uuid
from collections.abc import Callable, Iterator
from typing import BinaryIO, Literal, NamedTuple, TypedDict, cast


TERMINAL_PHASE_STATUSES = {
    "passed",
    "failed",
    "blocked",
    "unavailable",
    "decision_point",
}
PHASE_STATUSES = TERMINAL_PHASE_STATUSES | {"pending", "running"}
CHILD_TERMINAL_STATUSES = {"completed", "failed", "interrupted"}
CHILD_STATUSES = CHILD_TERMINAL_STATUSES | {"pending", "running"}
DEFAULT_PHASES = [
    "tests",
    "docs_sync",
    "internal_review",
    "external_review",
]
REVIEW_PHASES = {"internal_review", "external_review"}
DEFAULT_EXTERNAL_HELPER = (
    pathlib.Path(__file__).resolve().parents[2]
    / "review-orchestration-playbook"
    / "scripts"
    / "isolated_review"
)
FALLBACK_SMOKE_PROMPT = """You are running a fallback-lane readiness smoke.

Rules:
- Do not perform a full code review.
- Do not inspect extra files unless the runtime requires it to answer.
- Reply with exactly one line.

Output contract:
- If the lane is usable and can answer, reply exactly: READY
- If the lane is blocked or unavailable, reply with a single short line starting with: BLOCKED:
"""
RUN_LOCK_NAME = ".state.lock"
STATE_FILE_NAME = "state.json"
FALLBACK_SMOKE_PROMPT_NAME = "fallback-smoke.prompt.md"
RUNS_DIR_NAME = "waited-delivery"
STATE_MAX_BYTES = 4 * 1024 * 1024
STATE_SCHEMA_VERSION = 5
FILESYSTEM_PATH_DISPLAY_MAX_BYTES = 512
FILE_MODE = 0o600
DIRECTORY_MODE = 0o700
LEGACY_DIRECTORY_MODE = 0o755
UNTRUSTED_WRITE_MASK = stat.S_IWGRP | stat.S_IWOTH
CHILD_SESSION_ID_MAX_UTF8_BYTES = 1024
CHILD_SESSION_ID_MAX_JSON_BYTES = 6 * CHILD_SESSION_ID_MAX_UTF8_BYTES + 2
PARENT_METADATA_MAX_UTF8_BYTES = 4096
PARENT_METADATA_MAX_JSON_BYTES = 6 * PARENT_METADATA_MAX_UTF8_BYTES + 2
TIMESTAMP_CAPACITY_CHARS = 64
BOUNDED_ORCHESTRATION_FIELDS = (
    (
        "child_session_id",
        CHILD_SESSION_ID_MAX_UTF8_BYTES,
        CHILD_SESSION_ID_MAX_JSON_BYTES,
        True,
    ),
    (
        "parent_session_id",
        PARENT_METADATA_MAX_UTF8_BYTES,
        PARENT_METADATA_MAX_JSON_BYTES,
        False,
    ),
    (
        "parent_turn_id",
        PARENT_METADATA_MAX_UTF8_BYTES,
        PARENT_METADATA_MAX_JSON_BYTES,
        False,
    ),
    (
        "parent_transcript_path",
        PARENT_METADATA_MAX_UTF8_BYTES,
        PARENT_METADATA_MAX_JSON_BYTES,
        False,
    ),
    (
        "permission_mode",
        PARENT_METADATA_MAX_UTF8_BYTES,
        PARENT_METADATA_MAX_JSON_BYTES,
        False,
    ),
)
SMOKE_TIMEOUT_SECONDS = 30.0
SMOKE_CLEANUP_TIMEOUT_SECONDS = 3.0
SMOKE_CAPTURE_MAX_BYTES = 256 * 1024
PROCESS_DRAIN_CHUNK_BYTES = 64 * 1024
PROCESS_POLL_INTERVAL_SECONDS = 0.02
PROC_GROUP_SCAN_MAX_ENTRIES = 131_072
PROC_GROUP_SCAN_TIMEOUT_SECONDS = 0.25
PROMPT_REFRESH_SCHEMA_VERSION = 3


class FileVersion(NamedTuple):
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int
    sha256: str


class ArtifactRead(NamedTuple):
    content: bytes
    version: FileVersion


class DirectoryIdentity(NamedTuple):
    device: int
    inode: int
    uid: int
    gid: int
    mode: int


LinuxProcessGroupState = Literal[
    "live",
    "zombie-only",
    "no-members",
    "unknown",
]


class UserError(RuntimeError):
    pass


class ArtifactMissingError(UserError):
    pass


class ArtifactUnreadableError(UserError):
    pass


class ArtifactChangedError(UserError):
    pass


class PhaseState(TypedDict):
    status: str
    summary: str
    findings: list[str]
    evidence: list[str]
    updated_at: str | None


class ReviewPolicy(TypedDict):
    external_lane: str
    fallback_lane: str
    fallback_entrypoint: str
    external_helper: str


class FallbackReadinessSmoke(TypedDict):
    enabled: bool
    status: str
    lane: str
    entrypoint: str
    prompt_file: str
    command: list[str]
    sample: str | None
    stdout: str
    stderr: str
    returncode: int | None
    updated_at: str | None


class Artifacts(TypedDict):
    state_json: str
    child_contract: str
    child_prompt: str
    parent_prompt: str
    fallback_smoke_prompt: str
    fallback_smoke_command: str


class OrchestrationState(TypedDict):
    parent_session_id: str | None
    parent_turn_id: str | None
    parent_transcript_path: str | None
    permission_mode: str | None
    child_session_id: str | None
    child_status: str
    child_started_at: str | None
    child_finished_at: str | None
    updated_at: str | None


class LegacyBoundedTextIdentity(TypedDict):
    utf8_bytes: int
    json_bytes: int
    sha256: str


class WaitedDeliveryState(TypedDict):
    schema_version: int
    run_id: str
    preparation_id: str | None
    repo_root: str
    goal: str
    created_at: str
    updated_at: str
    known_blockers: list[str]
    changed_files: list[str]
    phases_order: list[str]
    phases: dict[str, PhaseState]
    review_policy: ReviewPolicy
    fallback_readiness_smoke: FallbackReadinessSmoke
    orchestration: OrchestrationState
    legacy_bounded_text: dict[str, LegacyBoundedTextIdentity]
    artifacts: Artifacts
    overall_status: str


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _json_value_size(value: str) -> int:
    return len(json.dumps(value, ensure_ascii=True).encode("utf-8"))


def _bounded_text_identity(
    value: str,
    *,
    label: str,
    require_nonblank: bool,
) -> LegacyBoundedTextIdentity:
    if not isinstance(value, str):
        raise UserError(f"{label} must be a string")
    if require_nonblank and not value.strip():
        raise UserError(f"{label} requires a nonblank value")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise UserError(f"{label} must be valid UTF-8") from error
    return {
        "utf8_bytes": len(encoded),
        "json_bytes": _json_value_size(value),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _validate_bounded_text(
    value: str,
    *,
    label: str,
    max_utf8_bytes: int,
    max_json_bytes: int,
    require_nonblank: bool,
) -> None:
    identity = _bounded_text_identity(
        value,
        label=label,
        require_nonblank=require_nonblank,
    )
    if identity["utf8_bytes"] > max_utf8_bytes:
        raise UserError(
            f"{label} exceeds its UTF-8 byte limit "
            f"({identity['utf8_bytes']} > {max_utf8_bytes} bytes)"
        )
    if identity["json_bytes"] > max_json_bytes:
        raise UserError(
            f"{label} exceeds its JSON-encoded byte limit "
            f"({identity['json_bytes']} > {max_json_bytes} bytes)"
        )


def _validate_child_session_id(value: str, *, label: str) -> None:
    _validate_bounded_text(
        value,
        label=label,
        max_utf8_bytes=CHILD_SESSION_ID_MAX_UTF8_BYTES,
        max_json_bytes=CHILD_SESSION_ID_MAX_JSON_BYTES,
        require_nonblank=True,
    )


def _validate_parent_metadata_args(args: argparse.Namespace) -> None:
    for field in (
        "parent_session_id",
        "parent_turn_id",
        "parent_transcript_path",
        "permission_mode",
    ):
        value = getattr(args, field, None)
        if value is None:
            continue
        _validate_bounded_text(
            value,
            label=field.replace("_", "-"),
            max_utf8_bytes=PARENT_METADATA_MAX_UTF8_BYTES,
            max_json_bytes=PARENT_METADATA_MAX_JSON_BYTES,
            require_nonblank=False,
        )


def _run_json(cmd: list[str], *, cwd: pathlib.Path | None = None) -> str:
    completed = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or "unknown error"
        raise UserError(f"command failed: {' '.join(cmd)}\n{stderr}")
    return completed.stdout


def _run_bytes(cmd: list[str], *, cwd: pathlib.Path | None = None) -> bytes:
    completed = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=False,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = os.fsdecode(completed.stderr).strip() or "unknown error"
        raise UserError(f"command failed: {' '.join(cmd)}\n{stderr}")
    return completed.stdout


def _resolve_repo_root(repo_arg: str) -> pathlib.Path:
    repo_path = pathlib.Path(repo_arg).resolve()
    stdout = _run_json(
        ["git", "-C", str(repo_path), "rev-parse", "--show-toplevel"],
    )
    return pathlib.Path(stdout.strip()).resolve()


def _collect_changed_files(repo_root: pathlib.Path) -> list[str]:
    stdout = _run_bytes(
        [
            "git",
            "-C",
            str(repo_root),
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ]
    )
    changed: list[str] = []
    seen: set[str] = set()
    if not stdout:
        return changed
    if not stdout.endswith(b"\0"):
        raise UserError("git status returned an incomplete NUL-framed record")
    records = stdout[:-1].split(b"\0")
    record_index = 0
    while record_index < len(records):
        record = records[record_index]
        record_index += 1
        if len(record) < 4 or record[2:3] != b" " or not record[3:]:
            raise UserError("git status returned a malformed NUL-framed record")
        status = record[:2]
        paths = [record[3:]]
        if b"R" in status or b"C" in status:
            if record_index >= len(records) or not records[record_index]:
                raise UserError("git status returned an incomplete rename/copy record")
            paths.append(records[record_index])
            record_index += 1
        for path_bytes in paths:
            path = os.fsdecode(path_bytes)
            if path == ".codex-tmp" or path.startswith(".codex-tmp/"):
                continue
            if path not in seen:
                changed.append(path)
                seen.add(path)
    return changed


def _ensure_relative_paths(paths: list[str]) -> list[str]:
    result: list[str] = []
    for path in paths:
        candidate = pathlib.Path(path)
        if candidate.is_absolute():
            raise UserError(f"changed-file must be repo-relative: {path}")
        result.append(candidate.as_posix())
    return result


def _pair_path_display_tokens(
    tokens: list[str],
    encoded_lengths: list[int],
) -> Iterator[tuple[str, int]]:
    if len(tokens) != len(encoded_lengths):
        raise AssertionError("path display token accounting length mismatch")
    return zip(tokens, encoded_lengths)


def _display_filesystem_path(path: str) -> str:
    has_non_surrogateescape_surrogate = any(
        unicodedata.category(character) == "Cs"
        and not 0xDC80 <= ord(character) <= 0xDCFF
        for character in path
    )
    if has_non_surrogateescape_surrogate:
        identity_kind = "utf8-surrogatepass"
        identity_bytes = path.encode("utf-8", errors="surrogatepass")
    else:
        try:
            identity_bytes = os.fsencode(path)
            identity_kind = "filesystem-bytes"
        except UnicodeEncodeError:
            identity_kind = "utf8-surrogatepass"
            identity_bytes = path.encode("utf-8", errors="surrogatepass")

    tokens: list[str] = []
    last_index = len(path) - 1
    for index, character in enumerate(path):
        codepoint = ord(character)
        if character == "\\":
            token = "\\\\"
        elif character == "`":
            token = "\\x60"
        elif character == "⟦":
            token = "\\u27e6"
        elif character == "⟧":
            token = "\\u27e7"
        elif character == " " and index in {0, last_index}:
            token = "\\x20"
        elif character == "\t":
            token = "\\t"
        elif character == "\r":
            token = "\\r"
        elif character == "\n":
            token = "\\n"
        elif 0xDC80 <= codepoint <= 0xDCFF:
            token = f"\\x{codepoint - 0xDC00:02x}"
        elif unicodedata.category(character) in {
            "Cc",
            "Cf",
            "Cs",
            "Zl",
            "Zp",
        } or codepoint in {0x2028, 0x2029}:
            if codepoint <= 0x7F:
                token = f"\\x{codepoint:02x}"
            elif codepoint <= 0xFFFF:
                token = f"\\u{codepoint:04x}"
            else:
                token = f"\\U{codepoint:08x}"
        else:
            token = character
        tokens.append(token)

    encoded_lengths = [len(token.encode("utf-8")) for token in tokens]
    if sum(encoded_lengths) <= FILESYSTEM_PATH_DISPLAY_MAX_BYTES:
        return "".join(tokens)

    suffix = (
        f"⟦truncated;identity={identity_kind};bytes={len(identity_bytes)};"
        f"sha256={hashlib.sha256(identity_bytes).hexdigest()}⟧"
    )
    suffix_bytes = len(suffix.encode("utf-8"))
    available_bytes = FILESYSTEM_PATH_DISPLAY_MAX_BYTES - suffix_bytes
    displayed_tokens: list[str] = []
    displayed_bytes = 0
    for token, token_bytes in _pair_path_display_tokens(tokens, encoded_lengths):
        if displayed_bytes + token_bytes > available_bytes:
            break
        displayed_tokens.append(token)
        displayed_bytes += token_bytes
    return "".join(displayed_tokens) + suffix


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


def _lexical_absolute(path_arg: str | pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path_arg)))


def _validate_component_name(name: str, *, label: str) -> None:
    if not name or name in {".", ".."} or pathlib.PurePath(name).name != name:
        raise UserError(f"{label} must be one path component: {name!r}")


def _preflight_utf8_artifact(name: str, content: str) -> None:
    try:
        content.encode("utf-8")
    except UnicodeEncodeError as error:
        raise UserError(
            f"run artifact is not valid UTF-8 before run creation: {name}"
        ) from error


def _generate_run_id(transaction_time: str) -> str:
    return (
        f"{dt.datetime.fromisoformat(transaction_time):%Y%m%dT%H%M%SZ}-"
        f"{uuid.uuid4().hex[:8]}"
    )


def _prospective_run_directory(
    repo_root: pathlib.Path,
    run_id: str,
) -> pathlib.Path:
    _validate_component_name(run_id, label="run id")
    try:
        encoded_run_id = os.fsencode(run_id)
    except UnicodeEncodeError as error:
        raise UserError(
            "run id cannot be represented by the repository filesystem"
        ) from error
    if b"\0" in encoded_run_id:
        raise UserError("run id cannot contain a NUL byte")
    try:
        name_max = os.pathconf(repo_root, "PC_NAME_MAX")
    except (OSError, ValueError) as error:
        raise UserError(
            "repository component-length limit cannot be determined safely"
        ) from error
    if name_max >= 0 and len(encoded_run_id) > name_max:
        raise UserError(
            f"run id exceeds the repository component-length limit "
            f"({len(encoded_run_id)} > {name_max} bytes)"
        )
    return repo_root / ".codex-tmp" / RUNS_DIR_NAME / run_id


def _open_absolute_directory(path: pathlib.Path) -> int:
    if not path.is_absolute():
        raise UserError(f"directory path must be absolute: {path}")
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
    _validate_component_name(name, label="directory name")
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
            # Darwin libc can expose ENOTSUP and EOPNOTSUPP as distinct values.
            if error_number in {
                errno.ENOENT,
                getattr(errno, "ENODATA", errno.ENOENT),
                errno.ENOTSUP,
                getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
            }:
                return False
            raise UserError(f"{label} extended ACL cannot be inspected safely")
        free_result = acl_free(acl)
        if free_result != 0:
            raise UserError(f"{label} extended ACL inspection cleanup failed")
        return True
    if sys.platform.startswith("linux"):
        getxattr = getattr(os, "getxattr", None)
        if getxattr is None:
            raise UserError(
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
                raise UserError(
                    f"{label} POSIX ACL cannot be inspected safely"
                ) from error
            except (TypeError, ValueError) as error:
                raise UserError(
                    f"{label} POSIX ACL cannot be inspected descriptor-relatively"
                ) from error
            return True
        return False
    raise UserError(f"{label} ACL inspection is unsupported on platform {sys.platform}")


def _require_no_extended_acl(file_fd: int, *, label: str) -> None:
    if _descriptor_has_extended_acl(file_fd, label=label):
        raise UserError(f"{label} must not carry a named or extended ACL")


def _require_owned_nonwritable_directory(
    directory_stat: os.stat_result,
    *,
    label: str,
    directory_fd: int | None = None,
) -> DirectoryIdentity:
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise UserError(f"{label} must be a directory")
    identity = _directory_identity(directory_stat)
    if identity.uid != os.geteuid():
        raise UserError(f"{label} must be owned by the current user")
    if identity.mode & UNTRUSTED_WRITE_MASK:
        raise UserError(f"{label} must not be writable by group or other users")
    if directory_fd is not None:
        _require_no_extended_acl(directory_fd, label=label)
    return identity


def _bound_owned_directory_identity(
    parent_fd: int,
    name: str,
    directory_fd: int,
    *,
    label: str,
) -> DirectoryIdentity:
    try:
        descriptor_stat = os.fstat(directory_fd)
        named_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise UserError(f"{label} binding cannot be restated safely") from error
    descriptor_identity = _require_owned_nonwritable_directory(
        descriptor_stat,
        label=label,
        directory_fd=directory_fd,
    )
    named_identity = _require_owned_nonwritable_directory(
        named_stat,
        label=f"named {label}",
    )
    if (
        not _same_object(descriptor_stat, named_stat)
        or descriptor_identity != named_identity
    ):
        raise UserError(f"{label} identity or access policy changed")
    return descriptor_identity


def _open_owned_directory_at(parent_fd: int, name: str, *, label: str) -> int:
    try:
        directory_fd = _open_directory_at(parent_fd, name)
    except OSError as error:
        raise UserError(f"{label} cannot be opened without following links") from error
    try:
        _bound_owned_directory_identity(
            parent_fd,
            name,
            directory_fd,
            label=label,
        )
    except Exception:
        os.close(directory_fd)
        raise
    return directory_fd


def _harden_run_directory(
    runs_fd: int,
    run_name: str,
    run_fd: int,
    *,
    allow_legacy: bool,
) -> DirectoryIdentity:
    identity = _bound_owned_directory_identity(
        runs_fd,
        run_name,
        run_fd,
        label="run directory",
    )
    if identity.mode == DIRECTORY_MODE:
        return identity
    if not allow_legacy or identity.mode != LEGACY_DIRECTORY_MODE:
        raise UserError(
            "run directory must use mode 0700 or current-user legacy mode 0755"
        )
    try:
        os.fchmod(run_fd, DIRECTORY_MODE)
    except OSError as error:
        raise UserError(
            "cannot tighten current-user legacy run directory to mode 0700"
        ) from error
    hardened = _bound_owned_directory_identity(
        runs_fd,
        run_name,
        run_fd,
        label="run directory",
    )
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
    ) or hardened.mode != DIRECTORY_MODE:
        raise UserError(
            "run directory object or access policy changed while tightening legacy mode"
        )
    return hardened


def _ensure_directory_at(parent_fd: int, name: str) -> int:
    _validate_component_name(name, label="directory name")
    try:
        os.mkdir(name, DIRECTORY_MODE, dir_fd=parent_fd)
    except FileExistsError:
        pass
    directory_fd = _open_directory_at(parent_fd, name)
    try:
        descriptor_stat = os.fstat(directory_fd)
        named_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(descriptor_stat.st_mode)
            or not stat.S_ISDIR(named_stat.st_mode)
            or not _same_object(descriptor_stat, named_stat)
        ):
            raise UserError(f"run parent directory identity mismatch: {name}")
        _bound_owned_directory_identity(
            parent_fd,
            name,
            directory_fd,
            label=f"run parent directory {name}",
        )
        os.fsync(parent_fd)
        named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(named_after.st_mode) or not _same_object(
            descriptor_stat, named_after
        ):
            raise UserError(
                f"run parent directory changed while persisting its entry: {name}"
            )
        _bound_owned_directory_identity(
            parent_fd,
            name,
            directory_fd,
            label=f"run parent directory {name}",
        )
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def _run_layout(
    run_dir_arg: str | pathlib.Path,
    *,
    expected_repo_root: str | pathlib.Path | None = None,
) -> tuple[pathlib.Path, pathlib.Path, str]:
    run_dir = _lexical_absolute(run_dir_arg)
    if (
        run_dir.parent.name != RUNS_DIR_NAME
        or run_dir.parent.parent.name != ".codex-tmp"
    ):
        raise UserError(
            "run directory must be a direct child of <repo>/.codex-tmp/waited-delivery"
        )
    run_name = run_dir.name
    _validate_component_name(run_name, label="run id")
    repo_root = run_dir.parents[2]
    if expected_repo_root is not None:
        expected = _lexical_absolute(expected_repo_root)
        if repo_root != expected:
            raise UserError(
                "run directory is outside the expected repository waited-delivery root"
            )
    return run_dir, repo_root, run_name


def _open_run_directory_path(
    repo_root: pathlib.Path,
    run_name: str,
    *,
    allow_legacy_run_mode: bool = False,
) -> int:
    repo_fd = _open_absolute_directory(repo_root)
    codex_tmp_fd: int | None = None
    runs_fd: int | None = None
    try:
        _require_owned_nonwritable_directory(
            os.fstat(repo_fd),
            label="repository root",
            directory_fd=repo_fd,
        )
        codex_tmp_fd = _open_owned_directory_at(
            repo_fd,
            ".codex-tmp",
            label="run .codex-tmp parent",
        )
        runs_fd = _open_owned_directory_at(
            codex_tmp_fd,
            RUNS_DIR_NAME,
            label="waited-delivery parent",
        )
        run_fd = _open_directory_at(runs_fd, run_name)
        try:
            _harden_run_directory(
                runs_fd,
                run_name,
                run_fd,
                allow_legacy=allow_legacy_run_mode,
            )
        except Exception:
            os.close(run_fd)
            raise
        return run_fd
    finally:
        if runs_fd is not None:
            os.close(runs_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        os.close(repo_fd)


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _directory_identity(file_stat: os.stat_result) -> DirectoryIdentity:
    return DirectoryIdentity(
        device=file_stat.st_dev,
        inode=file_stat.st_ino,
        uid=file_stat.st_uid,
        gid=file_stat.st_gid,
        mode=stat.S_IMODE(file_stat.st_mode),
    )


def _verify_run_directory_identity(
    run_dir: pathlib.Path,
    repo_root: pathlib.Path,
    run_fd: int,
    *,
    expected_identity: DirectoryIdentity | None = None,
) -> None:
    current_fd = _open_run_directory_path(repo_root, run_dir.name)
    try:
        current = os.fstat(current_fd)
        pinned = os.fstat(run_fd)
        if not stat.S_ISDIR(current.st_mode) or not _same_object(current, pinned):
            raise UserError(f"run directory identity changed: {run_dir}")
        if expected_identity is not None:
            pinned_identity = _directory_identity(pinned)
            current_identity = _directory_identity(current)
            if (
                pinned_identity.device,
                pinned_identity.inode,
            ) != (
                expected_identity.device,
                expected_identity.inode,
            ):
                raise UserError(f"run directory identity changed: {run_dir}")
            if pinned_identity != expected_identity:
                raise UserError(f"run directory access identity changed: {run_dir}")
            if current_identity != expected_identity:
                raise UserError(
                    f"named run directory access identity changed: {run_dir}"
                )
    finally:
        os.close(current_fd)


def _open_run_directory(
    run_dir_arg: str | pathlib.Path,
    *,
    expected_repo_root: str | pathlib.Path | None = None,
    expected_run_identity: DirectoryIdentity | None = None,
) -> tuple[pathlib.Path, pathlib.Path, int]:
    run_dir, repo_root, run_name = _run_layout(
        run_dir_arg,
        expected_repo_root=expected_repo_root,
    )
    try:
        run_fd = _open_run_directory_path(
            repo_root,
            run_name,
            allow_legacy_run_mode=expected_run_identity is None,
        )
    except OSError as error:
        raise UserError(f"unsafe or unavailable run directory: {run_dir}") from error
    try:
        _verify_run_directory_identity(run_dir, repo_root, run_fd)
        if expected_run_identity is not None:
            actual_identity = _directory_identity(os.fstat(run_fd))
            if (
                actual_identity.device,
                actual_identity.inode,
            ) != (
                expected_run_identity.device,
                expected_run_identity.inode,
            ):
                raise UserError(
                    "run directory identity does not match the expected bridge identity"
                )
            if actual_identity != expected_run_identity:
                raise UserError(
                    "run directory access identity does not match the expected "
                    "bridge identity"
                )
    except Exception:
        os.close(run_fd)
        raise
    return run_dir, repo_root, run_fd


def _create_run_directory(
    repo_root: pathlib.Path,
    run_id: str,
) -> tuple[pathlib.Path, int]:
    run_dir = _prospective_run_directory(repo_root, run_id)
    repo_fd = _open_absolute_directory(repo_root)
    codex_tmp_fd: int | None = None
    runs_fd: int | None = None
    try:
        _require_owned_nonwritable_directory(
            os.fstat(repo_fd),
            label="repository root",
            directory_fd=repo_fd,
        )
        codex_tmp_fd = _ensure_directory_at(repo_fd, ".codex-tmp")
        runs_fd = _ensure_directory_at(codex_tmp_fd, RUNS_DIR_NAME)
        try:
            os.mkdir(run_id, DIRECTORY_MODE, dir_fd=runs_fd)
        except FileExistsError as error:
            raise UserError(
                f"run directory already exists for run id: {run_id}"
            ) from error
        run_fd = _open_directory_at(runs_fd, run_id)
        _harden_run_directory(
            runs_fd,
            run_id,
            run_fd,
            allow_legacy=False,
        )
        _verify_run_directory_identity(run_dir, repo_root, run_fd)
        os.fsync(runs_fd)
        _verify_run_directory_identity(run_dir, repo_root, run_fd)
    except OSError as error:
        raise UserError(
            "run directory parents are unsafe or unavailable for creation"
        ) from error
    finally:
        if runs_fd is not None:
            os.close(runs_fd)
        if codex_tmp_fd is not None:
            os.close(codex_tmp_fd)
        os.close(repo_fd)
    try:
        _verify_run_directory_identity(run_dir, repo_root, run_fd)
    except Exception:
        os.close(run_fd)
        raise
    return run_dir, run_fd


def _regular_file_stat(
    run_fd: int,
    name: str,
    *,
    required: bool,
) -> os.stat_result | None:
    _validate_component_name(name, label="artifact name")
    try:
        file_stat = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
    except FileNotFoundError:
        if required:
            raise UserError(f"required run artifact is missing: {name}")
        return None
    try:
        file_fd = os.open(name, _regular_open_flags(), dir_fd=run_fd)
    except OSError as error:
        raise UserError(
            f"run artifact cannot be opened without following links: {name}"
        ) from error
    try:
        descriptor_stat = os.fstat(file_fd)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or not stat.S_ISREG(descriptor_stat.st_mode)
            or not _same_object(file_stat, descriptor_stat)
        ):
            raise UserError(f"run artifact must be a regular file: {name}")
        named_access = (
            file_stat.st_uid,
            file_stat.st_gid,
            stat.S_IMODE(file_stat.st_mode),
        )
        descriptor_access = (
            descriptor_stat.st_uid,
            descriptor_stat.st_gid,
            stat.S_IMODE(descriptor_stat.st_mode),
        )
        if named_access != descriptor_access:
            raise UserError(f"run artifact identity or access policy changed: {name}")
        if descriptor_stat.st_uid != os.geteuid():
            raise UserError(f"run artifact must be owned by the current user: {name}")
        if stat.S_IMODE(descriptor_stat.st_mode) & UNTRUSTED_WRITE_MASK:
            raise UserError(
                f"run artifact must not be writable by group or other users: {name}"
            )
        _require_no_extended_acl(file_fd, label=f"run artifact {name}")
        return descriptor_stat
    finally:
        os.close(file_fd)


def _read_fd_bounded(file_fd: int, name: str, *, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    retained = 0
    while True:
        chunk = os.read(file_fd, min(65536, max_bytes + 1 - retained))
        if not chunk:
            break
        chunks.append(chunk)
        retained += len(chunk)
        if retained > max_bytes:
            raise ArtifactUnreadableError(f"run artifact exceeds byte limit: {name}")
    return b"".join(chunks)


def _read_regular_artifact(
    run_fd: int,
    name: str,
    *,
    max_bytes: int,
) -> ArtifactRead:
    _validate_component_name(name, label="artifact name")
    try:
        file_fd = os.open(name, _regular_open_flags(), dir_fd=run_fd)
    except FileNotFoundError as error:
        raise ArtifactMissingError(f"run artifact is missing: {name}") from error
    except OSError as error:
        raise ArtifactUnreadableError(
            f"cannot open run artifact without following links: {name}"
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
            raise ArtifactUnreadableError(
                f"cannot restat run artifact without following links: {name}"
            ) from error
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named_before.st_mode)
            or not _same_object(before, named_before)
        ):
            raise ArtifactUnreadableError(
                f"run artifact must be a regular file: {name}"
            )
        if before.st_uid != os.geteuid() or named_before.st_uid != os.geteuid():
            raise ArtifactUnreadableError(
                f"run artifact must be owned by the current user: {name}"
            )
        if (
            stat.S_IMODE(before.st_mode) & UNTRUSTED_WRITE_MASK
            or stat.S_IMODE(named_before.st_mode) & UNTRUSTED_WRITE_MASK
        ):
            raise ArtifactUnreadableError(
                f"run artifact must not be writable by group or other users: {name}"
            )
        _require_no_extended_acl(file_fd, label=f"run artifact {name}")
        if before.st_size > max_bytes:
            raise ArtifactUnreadableError(f"run artifact exceeds byte limit: {name}")
        expected_access = (
            before.st_uid,
            before.st_gid,
            stat.S_IMODE(before.st_mode),
        )
        first_content = _read_fd_bounded(file_fd, name, max_bytes=max_bytes)
        middle = os.fstat(file_fd)
        os.lseek(file_fd, 0, os.SEEK_SET)
        second_content = _read_fd_bounded(file_fd, name, max_bytes=max_bytes)
        after = os.fstat(file_fd)
        try:
            named_after = os.stat(
                name,
                dir_fd=run_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ArtifactUnreadableError(
                f"cannot restat run artifact without following links: {name}"
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
            raise ArtifactChangedError(
                f"run artifact identity, access, size, or content changed "
                f"while it was read: {name}"
            )
        _require_no_extended_acl(file_fd, label=f"run artifact {name}")
        return ArtifactRead(
            content=second_content,
            version=FileVersion(
                device=after.st_dev,
                inode=after.st_ino,
                uid=after.st_uid,
                gid=after.st_gid,
                mode=stat.S_IMODE(after.st_mode),
                size=after.st_size,
                sha256=hashlib.sha256(second_content).hexdigest(),
            ),
        )
    except OSError as error:
        raise ArtifactUnreadableError(
            f"cannot read stable run artifact content: {name}"
        ) from error
    finally:
        os.close(file_fd)


def _expected_artifact_version(
    run_fd: int,
    name: str,
    *,
    required: bool,
    max_bytes: int = STATE_MAX_BYTES,
) -> FileVersion | None:
    try:
        return _read_regular_artifact(
            run_fd,
            name,
            max_bytes=max_bytes,
        ).version
    except ArtifactMissingError:
        if required:
            raise UserError(f"required run artifact is missing: {name}") from None
        return None


def _validate_expected_artifact(
    run_fd: int,
    name: str,
    expected_version: FileVersion | None,
    *,
    max_bytes: int,
) -> None:
    try:
        current = _read_regular_artifact(
            run_fd,
            name,
            max_bytes=max_bytes,
        ).version
    except ArtifactMissingError:
        if expected_version is None:
            return
        raise UserError(f"run artifact is missing before update: {name}") from None
    except ArtifactChangedError:
        raise UserError(f"run artifact content changed before update: {name}") from None
    except ArtifactUnreadableError:
        raise UserError(f"run artifact is unreadable before update: {name}") from None

    if expected_version is None:
        raise UserError(f"run artifact appeared before update: {name}")
    if (current.device, current.inode) != (
        expected_version.device,
        expected_version.inode,
    ):
        raise UserError(f"run artifact was replaced before update: {name}")
    if (current.uid, current.gid, current.mode) != (
        expected_version.uid,
        expected_version.gid,
        expected_version.mode,
    ):
        raise UserError(f"run artifact access changed before update: {name}")
    if (
        current.size != expected_version.size
        or current.sha256 != expected_version.sha256
    ):
        raise UserError(f"run artifact content changed before update: {name}")


def _file_version_payload(version: FileVersion) -> dict[str, object]:
    return {
        "device": version.device,
        "inode": version.inode,
        "uid": version.uid,
        "gid": version.gid,
        "mode": version.mode,
        "size": version.size,
        "sha256": version.sha256,
    }


def _expected_file_version(
    args: argparse.Namespace,
    prefix: str,
) -> FileVersion:
    values = tuple(
        getattr(args, f"expected_{prefix}_{field}")
        for field in ("dev", "ino", "uid", "gid", "mode", "size", "sha256")
    )
    integer_values = values[:-1]
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in integer_values
    ):
        raise UserError(
            f"expected {prefix} identity fields must be supplied as nonnegative "
            f"integers"
        )
    sha256 = values[-1]
    if (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise UserError(f"expected {prefix} sha256 must be lowercase hexadecimal")
    return FileVersion(
        device=cast(int, integer_values[0]),
        inode=cast(int, integer_values[1]),
        uid=cast(int, integer_values[2]),
        gid=cast(int, integer_values[3]),
        mode=cast(int, integer_values[4]),
        size=cast(int, integer_values[5]),
        sha256=sha256,
    )


def _read_absolute_regular_artifact(
    path: pathlib.Path,
    *,
    max_bytes: int,
) -> ArtifactRead:
    if not path.is_absolute() or not path.name:
        raise ArtifactUnreadableError("absolute artifact path is required")
    try:
        parent_fd = _open_absolute_directory(path.parent)
    except OSError as error:
        raise ArtifactUnreadableError(
            f"cannot open absolute artifact parent without following links: {path}"
        ) from error
    try:
        return _read_regular_artifact(
            parent_fd,
            path.name,
            max_bytes=max_bytes,
        )
    finally:
        os.close(parent_fd)


def _fd_execution_path(file_fd: int, name: str) -> pathlib.Path:
    try:
        descriptor_stat = os.fstat(file_fd)
    except OSError as error:
        raise UserError(
            f"cannot inspect descriptor-bound compatibility artifact: {name}"
        ) from error
    for root in (pathlib.Path("/dev/fd"), pathlib.Path("/proc/self/fd")):
        candidate = root / str(file_fd)
        probe_fd: int | None = None
        try:
            probe_fd = os.open(
                candidate,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            candidate_stat = os.fstat(probe_fd)
        except OSError:
            continue
        finally:
            if probe_fd is not None:
                os.close(probe_fd)
        if _same_object(descriptor_stat, candidate_stat):
            return candidate
    raise UserError(f"cannot expose descriptor-bound compatibility artifact: {name}")


@contextlib.contextmanager
def _anonymous_smoke_prompt_pipe() -> Iterator[tuple[pathlib.Path, BinaryIO, BinaryIO]]:
    read_fd, write_fd = os.pipe()
    read_stream: BinaryIO | None = None
    write_stream: BinaryIO | None = None
    try:
        read_stream = os.fdopen(read_fd, "rb", buffering=0)
        write_stream = os.fdopen(write_fd, "wb", buffering=0)
        execution_path = _fd_execution_path(
            read_stream.fileno(),
            "fallback-smoke.prompt.md",
        )
        yield execution_path, read_stream, write_stream
    finally:
        if write_stream is None:
            try:
                os.close(write_fd)
            except OSError:
                pass
        else:
            try:
                write_stream.close()
            except OSError:
                pass
        if read_stream is None:
            try:
                os.close(read_fd)
            except OSError:
                pass
        else:
            try:
                read_stream.close()
            except OSError:
                pass


def _require_isolated_python() -> None:
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise UserError("refresh-prompts requires Python -I -B -S isolation")


def _atomic_write_regular(
    run_fd: int,
    name: str,
    content: str,
    *,
    expected_version: FileVersion | None,
    max_content_bytes: int | None = None,
) -> FileVersion:
    encoded = content.encode("utf-8")
    if max_content_bytes is not None and len(encoded) > max_content_bytes:
        raise UserError(
            f"run artifact exceeds maximum size before update: {name} "
            f"({len(encoded)} > {max_content_bytes} bytes)"
        )
    comparison_max_bytes = max(STATE_MAX_BYTES, len(encoded))
    _validate_expected_artifact(
        run_fd,
        name,
        expected_version,
        max_bytes=comparison_max_bytes,
    )
    temp_name = f".{name}.{uuid.uuid4().hex}.tmp"
    temp_fd: int | None = None
    temp_identity: DirectoryIdentity | None = None
    try:
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            FILE_MODE,
            dir_fd=run_fd,
        )
        offset = 0
        while offset < len(encoded):
            written_bytes = os.write(temp_fd, encoded[offset:])
            if written_bytes <= 0:
                raise UserError(f"failed to write temporary run artifact: {name}")
            offset += written_bytes
        os.fsync(temp_fd)
        temp_identity = _directory_identity(os.fstat(temp_fd))
        if (
            temp_identity.uid != os.geteuid()
            or temp_identity.mode & UNTRUSTED_WRITE_MASK
        ):
            raise UserError(f"temporary run artifact access policy is unsafe: {name}")
        _require_no_extended_acl(
            temp_fd,
            label=f"temporary run artifact {name}",
        )
        os.close(temp_fd)
        temp_fd = None
        _validate_expected_artifact(
            run_fd,
            name,
            expected_version,
            max_bytes=comparison_max_bytes,
        )
        os.replace(
            temp_name,
            name,
            src_dir_fd=run_fd,
            dst_dir_fd=run_fd,
        )
        os.fsync(run_fd)
        published_stat = _regular_file_stat(run_fd, name, required=True)
        if (
            published_stat is None
            or temp_identity is None
            or _directory_identity(published_stat) != temp_identity
        ):
            raise UserError(
                f"run artifact publication identity mismatch after update: {name}"
            )
        written = _read_regular_artifact(
            run_fd,
            name,
            max_bytes=max(len(encoded), 1),
        )
        if (
            written.content != encoded
            or (
                written.version.device,
                written.version.inode,
            )
            != (temp_identity.device, temp_identity.inode)
            or (
                written.version.uid,
                written.version.gid,
                written.version.mode,
            )
            != (
                temp_identity.uid,
                temp_identity.gid,
                temp_identity.mode,
            )
        ):
            raise UserError(
                f"run artifact publication identity or content mismatch "
                f"after update: {name}"
            )
        return written.version
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=run_fd)
        except FileNotFoundError:
            pass


def _bounded_text_is_oversized(
    identity: LegacyBoundedTextIdentity,
    *,
    max_utf8_bytes: int,
    max_json_bytes: int,
) -> bool:
    return (
        identity["utf8_bytes"] > max_utf8_bytes
        or identity["json_bytes"] > max_json_bytes
    )


def _validate_legacy_bounded_text_marker(
    field: str,
    raw_marker: object,
) -> LegacyBoundedTextIdentity:
    if not isinstance(raw_marker, dict) or set(raw_marker) != {
        "utf8_bytes",
        "json_bytes",
        "sha256",
    }:
        raise UserError(
            f"invalid legacy bounded-text identity for orchestration.{field}"
        )
    utf8_bytes = raw_marker.get("utf8_bytes")
    json_bytes = raw_marker.get("json_bytes")
    sha256 = raw_marker.get("sha256")
    if (
        not isinstance(utf8_bytes, int)
        or isinstance(utf8_bytes, bool)
        or utf8_bytes < 0
        or not isinstance(json_bytes, int)
        or isinstance(json_bytes, bool)
        or json_bytes < 0
        or not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise UserError(
            f"invalid legacy bounded-text identity for orchestration.{field}"
        )
    return {
        "utf8_bytes": utf8_bytes,
        "json_bytes": json_bytes,
        "sha256": sha256,
    }


def _migrate_legacy_bounded_text(
    state: WaitedDeliveryState,
    *,
    source_schema_version: int,
) -> None:
    orchestration = state.get("orchestration")
    if not isinstance(orchestration, dict):
        raise UserError("state orchestration must be an object")
    supported_fields = {field for field, *_limits in BOUNDED_ORCHESTRATION_FIELDS}
    raw_markers = state.get("legacy_bounded_text")
    if source_schema_version == STATE_SCHEMA_VERSION:
        if not isinstance(raw_markers, dict):
            raise UserError("state legacy_bounded_text must be an object")
        unknown_fields = set(raw_markers) - supported_fields
        if unknown_fields:
            raise UserError(
                "state legacy_bounded_text contains unsupported fields: "
                + ", ".join(sorted(unknown_fields))
            )
        markers = {
            field: _validate_legacy_bounded_text_marker(field, raw_marker)
            for field, raw_marker in raw_markers.items()
        }
    else:
        markers: dict[str, LegacyBoundedTextIdentity] = {}

    for (
        field,
        max_utf8_bytes,
        max_json_bytes,
        _require_nonblank,
    ) in BOUNDED_ORCHESTRATION_FIELDS:
        value = orchestration.get(field)
        if value is None:
            markers.pop(field, None)
            continue
        identity = _bounded_text_identity(
            cast(str, value),
            label=field.replace("_", "-"),
            require_nonblank=False,
        )
        if not _bounded_text_is_oversized(
            identity,
            max_utf8_bytes=max_utf8_bytes,
            max_json_bytes=max_json_bytes,
        ):
            markers.pop(field, None)
            continue
        if source_schema_version < STATE_SCHEMA_VERSION:
            markers[field] = identity
        elif markers.get(field) != identity:
            raise UserError(
                f"oversized orchestration.{field} changed outside its "
                "grandfathered legacy identity"
            )

    state["schema_version"] = STATE_SCHEMA_VERSION
    state["legacy_bounded_text"] = markers


def _validate_bounded_text_for_save(state: WaitedDeliveryState) -> None:
    if state.get("schema_version") != STATE_SCHEMA_VERSION:
        raise UserError(
            f"state must use schema {STATE_SCHEMA_VERSION} before publication"
        )
    markers = state.get("legacy_bounded_text")
    if not isinstance(markers, dict):
        raise UserError("state legacy_bounded_text must be an object")
    supported_fields = {field for field, *_limits in BOUNDED_ORCHESTRATION_FIELDS}
    unknown_fields = set(markers) - supported_fields
    if unknown_fields:
        raise UserError(
            "state legacy_bounded_text contains unsupported fields: "
            + ", ".join(sorted(unknown_fields))
        )
    orchestration = state["orchestration"]
    for (
        field,
        max_utf8_bytes,
        max_json_bytes,
        require_nonblank,
    ) in BOUNDED_ORCHESTRATION_FIELDS:
        value = orchestration[field]
        if value is None:
            markers.pop(field, None)
            continue
        label = field.replace("_", "-")
        identity = _bounded_text_identity(
            value,
            label=label,
            require_nonblank=require_nonblank,
        )
        if not _bounded_text_is_oversized(
            identity,
            max_utf8_bytes=max_utf8_bytes,
            max_json_bytes=max_json_bytes,
        ):
            markers.pop(field, None)
            continue
        raw_marker = markers.get(field)
        marker = (
            _validate_legacy_bounded_text_marker(field, raw_marker)
            if raw_marker is not None
            else None
        )
        if marker == identity:
            continue
        _validate_bounded_text(
            value,
            label=label,
            max_utf8_bytes=max_utf8_bytes,
            max_json_bytes=max_json_bytes,
            require_nonblank=require_nonblank,
        )


def _load_state_from_fd(
    run_dir: pathlib.Path,
    repo_root: pathlib.Path,
    run_fd: int,
) -> tuple[WaitedDeliveryState, FileVersion]:
    artifact = _read_regular_artifact(
        run_fd,
        STATE_FILE_NAME,
        max_bytes=STATE_MAX_BYTES,
    )
    try:
        payload = json.loads(artifact.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UserError(
            f"invalid state payload: {run_dir / STATE_FILE_NAME}"
        ) from error
    if not isinstance(payload, dict):
        raise UserError(f"invalid state payload: {run_dir / STATE_FILE_NAME}")
    state = cast(WaitedDeliveryState, payload)
    schema_version = state.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version < 1
        or schema_version > STATE_SCHEMA_VERSION
    ):
        raise UserError(f"unsupported state schema: {run_dir / STATE_FILE_NAME}")
    state.setdefault("preparation_id", None)
    if state.get("repo_root") != str(repo_root):
        raise UserError(
            "state repo_root does not exactly match the run directory repository"
        )
    orchestration = state["orchestration"]
    orchestration.setdefault("parent_session_id", None)
    orchestration.setdefault("parent_turn_id", None)
    orchestration.setdefault("parent_transcript_path", None)
    orchestration.setdefault("permission_mode", None)
    _migrate_legacy_bounded_text(
        state,
        source_schema_version=schema_version,
    )
    return state, artifact.version


def _state_requires_terminal_capacity(state: WaitedDeliveryState) -> bool:
    orchestration = state["orchestration"]
    if orchestration["child_status"] not in CHILD_TERMINAL_STATUSES:
        return True
    if _non_terminal_phase_names(state):
        return True
    return state["overall_status"] != _overall_status(state["phases"])


def _larger_json_capacity_value(
    current: str | None,
    reserved: str,
) -> str:
    if isinstance(current, str) and _json_value_size(current) > _json_value_size(
        reserved
    ):
        return current
    return reserved


def _terminal_capacity_projection(
    state: WaitedDeliveryState,
    *,
    transaction_time: str,
) -> WaitedDeliveryState:
    projected = copy.deepcopy(state)
    orchestration = projected["orchestration"]
    maximum_id = "\x01" * CHILD_SESSION_ID_MAX_UTF8_BYTES
    maximum_parent_metadata = "\x01" * PARENT_METADATA_MAX_UTF8_BYTES
    maximum_timestamp = "0" * TIMESTAMP_CAPACITY_CHARS
    if not orchestration["child_session_id"]:
        orchestration["child_session_id"] = maximum_id
    if not orchestration["child_started_at"]:
        orchestration["child_started_at"] = maximum_timestamp
    for field in (
        "parent_session_id",
        "parent_turn_id",
        "parent_transcript_path",
        "permission_mode",
    ):
        orchestration[field] = _larger_json_capacity_value(
            orchestration[field],
            maximum_parent_metadata,
        )
    if orchestration["child_status"] not in CHILD_TERMINAL_STATUSES:
        orchestration["child_status"] = "interrupted"
    if not orchestration["child_finished_at"]:
        orchestration["child_finished_at"] = maximum_timestamp
    orchestration["updated_at"] = _larger_json_capacity_value(
        transaction_time,
        maximum_timestamp,
    )
    for phase_name in projected["phases_order"]:
        phase = projected["phases"][phase_name]
        if phase["status"] not in TERMINAL_PHASE_STATUSES:
            phase["status"] = "decision_point"
            phase["updated_at"] = _larger_json_capacity_value(
                transaction_time,
                maximum_timestamp,
            )
    projected["overall_status"] = _overall_status(projected["phases"])
    projected["updated_at"] = _larger_json_capacity_value(
        transaction_time,
        maximum_timestamp,
    )
    return projected


def _serialize_state_for_save(
    state: WaitedDeliveryState,
    *,
    transaction_time: str,
    context: str,
) -> str:
    _validate_bounded_text_for_save(state)
    state["updated_at"] = transaction_time
    state_json = json.dumps(state, indent=2, sort_keys=True) + "\n"
    encoded_size = len(state_json.encode("utf-8"))
    if encoded_size > STATE_MAX_BYTES:
        raise UserError(
            f"{context} exceeds the state byte limit before artifact publication "
            f"({encoded_size} > {STATE_MAX_BYTES} bytes); the existing state and "
            "terminal artifacts remain unchanged. Reduce nonessential summaries, "
            "findings, evidence, smoke output, or blocker text and retry."
        )
    if _state_requires_terminal_capacity(state):
        projected = _terminal_capacity_projection(
            state,
            transaction_time=transaction_time,
        )
        projected_size = len(
            (json.dumps(projected, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )
        if projected_size > STATE_MAX_BYTES:
            raise UserError(
                f"{context} would consume reserved terminal capacity "
                f"({projected_size} > {STATE_MAX_BYTES} projected bytes); the "
                "existing state and terminal artifacts remain unchanged. Reduce "
                "nonessential summaries, findings, evidence, smoke output, or "
                "blocker text and retry."
            )
    return state_json


def _save_state(
    run_dir: pathlib.Path,
    repo_root: pathlib.Path,
    run_fd: int,
    state: WaitedDeliveryState,
    expected_state_version: FileVersion,
    *,
    transaction_time: str | None = None,
    context: str = "state update",
) -> FileVersion:
    _verify_run_directory_identity(run_dir, repo_root, run_fd)
    state_json = _serialize_state_for_save(
        state,
        transaction_time=transaction_time or _utc_now(),
        context=context,
    )
    written_version = _atomic_write_regular(
        run_fd,
        STATE_FILE_NAME,
        state_json,
        expected_version=expected_state_version,
        max_content_bytes=STATE_MAX_BYTES,
    )
    _verify_run_directory_identity(run_dir, repo_root, run_fd)
    return written_version


@contextlib.contextmanager
def _open_run_lock_descriptor(
    run_fd: int,
) -> Iterator[tuple[int, DirectoryIdentity]]:
    try:
        lock_fd = os.open(
            RUN_LOCK_NAME,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            FILE_MODE,
            dir_fd=run_fd,
        )
    except OSError as error:
        raise UserError("cannot open run lock without following links") from error
    try:
        lock_stat = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_stat.st_mode):
            raise UserError("run lock must be a regular file")
        if lock_stat.st_uid != os.geteuid():
            raise UserError("run lock must be owned by the current user")
        if stat.S_IMODE(lock_stat.st_mode) & UNTRUSTED_WRITE_MASK:
            raise UserError("run lock must not be writable by group or other users")
        _require_no_extended_acl(lock_fd, label="run lock")
        yield lock_fd, _directory_identity(lock_stat)
    finally:
        os.close(lock_fd)


@contextlib.contextmanager
def _acquired_run_lock(
    run_fd: int,
    lock_fd: int,
    expected_lock_identity: DirectoryIdentity,
) -> Iterator[None]:
    current_lock = os.fstat(lock_fd)
    if (
        not stat.S_ISREG(current_lock.st_mode)
        or _directory_identity(current_lock) != expected_lock_identity
    ):
        raise UserError("run lock descriptor identity changed before acquisition")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        named_lock = _regular_file_stat(run_fd, RUN_LOCK_NAME, required=True)
        if (
            named_lock is None
            or _directory_identity(named_lock) != expected_lock_identity
        ):
            raise UserError("run lock was replaced before acquisition")
        yield
        named_lock = _regular_file_stat(run_fd, RUN_LOCK_NAME, required=True)
        if (
            named_lock is None
            or _directory_identity(named_lock) != expected_lock_identity
            or _directory_identity(os.fstat(lock_fd)) != expected_lock_identity
        ):
            raise UserError("run lock was replaced while held")
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def _run_lock(run_fd: int) -> Iterator[None]:
    with _open_run_lock_descriptor(run_fd) as (
        lock_fd,
        lock_identity,
    ):
        with _acquired_run_lock(run_fd, lock_fd, lock_identity):
            yield


@contextlib.contextmanager
def _locked_run_state(
    run_dir_arg: str | pathlib.Path,
    *,
    expected_repo_root: str | pathlib.Path | None = None,
    expected_run_identity: DirectoryIdentity | None = None,
) -> Iterator[tuple[pathlib.Path, pathlib.Path, int, WaitedDeliveryState, FileVersion]]:
    run_dir, repo_root, run_fd = _open_run_directory(
        run_dir_arg,
        expected_repo_root=expected_repo_root,
        expected_run_identity=expected_run_identity,
    )
    opened_run_identity = _directory_identity(os.fstat(run_fd))
    try:
        with _run_lock(run_fd):
            _verify_run_directory_identity(
                run_dir,
                repo_root,
                run_fd,
                expected_identity=opened_run_identity,
            )
            state, state_version = _load_state_from_fd(
                run_dir,
                repo_root,
                run_fd,
            )
            for prompt_name in ("child-prompt.md", "parent-prompt.md"):
                _read_regular_artifact(
                    run_fd,
                    prompt_name,
                    max_bytes=STATE_MAX_BYTES,
                )
            yield run_dir, repo_root, run_fd, state, state_version
            _verify_run_directory_identity(
                run_dir,
                repo_root,
                run_fd,
                expected_identity=opened_run_identity,
            )
    finally:
        os.close(run_fd)


def _phase_template() -> PhaseState:
    return {
        "status": "pending",
        "summary": "",
        "findings": [],
        "evidence": [],
        "updated_at": None,
    }


def _orchestration_template(
    *,
    parent_session_id: str | None = None,
    parent_turn_id: str | None = None,
    parent_transcript_path: str | None = None,
    permission_mode: str | None = None,
) -> OrchestrationState:
    return {
        "parent_session_id": parent_session_id,
        "parent_turn_id": parent_turn_id,
        "parent_transcript_path": parent_transcript_path,
        "permission_mode": permission_mode,
        "child_session_id": None,
        "child_status": "pending",
        "child_started_at": None,
        "child_finished_at": None,
        "updated_at": None,
    }


def _build_child_contract(state: WaitedDeliveryState) -> str:
    review_policy = state["review_policy"]
    fallback = state["fallback_readiness_smoke"]
    lines = [
        "# Waited Delivery Child Contract",
        "",
        f"- Run ID: `{state['run_id']}`",
        f"- Repo: `{state['repo_root']}`",
        f"- Goal: {state['goal']}",
        "",
        "## Required Phases",
    ]
    for phase in state["phases_order"]:
        lines.append(f"- `{phase}`")

    lines.extend(
        [
            "",
            "## Review Policy",
            "- Implementation boundary: the main session completes implementation before spawning the child.",
            "- Child review boundary: the child owns tests, docs sync, and verification of the already-implemented change; it must not mark `internal_review` or `external_review` as passed.",
            "- Parent review boundary: after the child returns, the parent must form an authorized, committed, clean/frozen `base_sha..head_sha` before starting review.",
            "- Dirty or untracked implementation state cannot count as reviewed.",
            "- Runner enforcement: `record-phase` rejects a review `passed` result before the child is terminal, while implementation state is dirty/untracked, or when nonblank terminal review evidence is missing.",
            "- Named internal single review: the parent directly launches exactly one fresh/clear-context Codex `reviewer` agent.",
            "- Reviewer context: load `$review-orchestration-playbook` plus applicable `AGENTS.md` and repository guidance.",
            "- Reviewer workspace: discover the fixed diff and necessary nearby context with tools inside the clean/frozen workspace.",
            "- Reviewer handoff: do not precompute or paste the full diff into the prompt.",
            "- Helper role: `isolated_review` is low-level compatibility/diagnostic tooling only; it cannot start, satisfy, substitute for, or count as the named internal single review.",
            f"- Primary external-review lane: `{review_policy['external_lane']}`",
            f"- Fallback lane: `{review_policy['fallback_lane']}`",
            f"- Fallback entrypoint: `{review_policy['fallback_entrypoint']}`",
            f"- Fallback readiness smoke enabled: `{str(fallback['enabled']).lower()}`",
        ]
    )

    blockers = state["known_blockers"]
    if blockers:
        lines.extend(["", "## Known Blockers"])
        for blocker in blockers:
            lines.append(f"- {blocker}")

    changed_files = state["changed_files"]
    if changed_files:
        lines.extend(["", "## Changed Files"])
        for path in changed_files:
            lines.append(f"- `{_display_filesystem_path(path)}`")

    lines.extend(
        [
            "",
            "## Guardrails",
            "- Spawn no additional delivery children for this run.",
            "- Treat fallback readiness smoke as lane-availability evidence only, not as external-review coverage.",
            "- Keep external fallback-readiness smoke separate from the named internal single review; it never adds or replaces an internal reviewer.",
            "- Convert any reviewer stall into a terminal result such as `blocked`, `unavailable`, or `decision_point` after bounded retries.",
            "- Return control as soon as a gate reaches the earliest decisive stopping point.",
        ]
    )

    return "\n".join(lines) + "\n"


def _shell_command(args: list[str]) -> str:
    return " ".join(shlex.quote(arg) for arg in args)


def _runner_command(
    *args: str,
    runner_path: pathlib.Path | None = None,
) -> str:
    published_path = runner_path or pathlib.Path(__file__).resolve()
    return _shell_command([sys.executable, str(published_path), *args])


def _smoke_command_argv(state: WaitedDeliveryState) -> list[str]:
    smoke = state["fallback_readiness_smoke"]
    helper = pathlib.Path(state["review_policy"]["external_helper"])
    return [
        str(helper),
        "--repo",
        state["repo_root"],
        "--lane",
        smoke["lane"],
        "--entrypoint",
        smoke["entrypoint"],
        "--prompt-file",
        smoke["prompt_file"],
        "--",
        "{prompt_text}",
    ]


def _build_child_prompt(
    run_dir: pathlib.Path,
    state: WaitedDeliveryState,
    *,
    runner_path: pathlib.Path | None = None,
) -> str:
    smoke = state["fallback_readiness_smoke"]
    lines = [
        "# Waited Delivery Child Prompt",
        "",
        f"- Run directory: `{run_dir}`",
        f"- Contract: `{state['artifacts']['child_contract']}`",
        f"- State file: `{state['artifacts']['state_json']}`",
        "",
        "Use the runner as the delivery control plane for this run.",
        "",
        "Required sequence:",
        f"1. Read `{state['artifacts']['child_contract']}` before doing finish-line work.",
    ]
    if smoke["enabled"]:
        lines.append(
            "2. If an early fallback-lane readiness probe is useful, run this narrow smoke first:"
        )
        lines.append(
            f"   `{_runner_command('run-fallback-smoke', '--run-dir', str(run_dir), runner_path=runner_path)}`"
        )
    else:
        lines.append("2. Fallback readiness smoke is disabled for this run.")
    lines.extend(
        [
            "3. For each child-owned delivery phase, mark it `running` before work begins:",
            f"   `{_runner_command('begin-phase', '--run-dir', str(run_dir), '--phase', '<phase>', runner_path=runner_path)}`",
            "4. As soon as a phase reaches a terminal result, persist it with `record-phase`:",
            f"   `{_runner_command('record-phase', '--run-dir', str(run_dir), '--phase', '<phase>', '--status', 'passed', '--summary', '<summary>', runner_path=runner_path)}`",
            "5. Do not mark `internal_review` or `external_review` as passed. The parent owns review after you return.",
            "6. If you stop early after a decisive failure or decision point, close untouched downstream phases before returning:",
            f"   `{_runner_command('close-open-phases', '--run-dir', str(run_dir), '--status', 'blocked', '--summary', '<why downstream phases were not run>', runner_path=runner_path)}`",
            "7. Do not call `finalize` from the child. The parent owns review and reconciliation after `wait` returns.",
            "8. Return a concise terminal summary for the parent that matches the persisted child-owned phase states.",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_parent_prompt(
    run_dir: pathlib.Path,
    state: WaitedDeliveryState,
    *,
    runner_path: pathlib.Path | None = None,
) -> str:
    lines = [
        "# Waited Delivery Parent Prompt",
        "",
        "You are the main session for a waited-delivery run.",
        "",
        "Required sequence:",
        f"1. Spawn exactly one delivery child for this run and give it `{state['artifacts']['child_prompt']}` as the bounded handoff payload.",
        f"2. As soon as the child session ID is known, persist it with: `{_runner_command('attach-child', '--run-dir', str(run_dir), '--child-session-id', '<child_session_id>', runner_path=runner_path)}`",
        "3. Immediately wait for that child. Do not summarize early and do not continue unrelated work while the child is active.",
        "4. When `wait` returns, inspect the child result and persist its terminal status before starting review:",
        f"   `{_runner_command('finish-child', '--run-dir', str(run_dir), '--child-status', '<completed|failed|interrupted>', '--child-session-id', '<child_session_id>', runner_path=runner_path)}`",
        "5. Do not claim review coverage while implementation changes remain dirty or untracked. When authorized, form a committed clean/frozen `base_sha..head_sha`; otherwise record `blocked` or `decision_point`.",
        "6. Named internal single review means directly launching exactly one fresh/clear-context Codex `reviewer` agent. Require it to load `$review-orchestration-playbook` plus applicable `AGENTS.md` and repository guidance.",
        "7. Give the reviewer only the goal, workspace path, immutable refs, focus, evidence budget, and output contract. Do not precompute or paste a full diff; the reviewer discovers the fixed diff and nearby context with tools inside the clean/frozen workspace.",
        "8. `isolated_review` is low-level compatibility/diagnostic tooling only. It cannot start, satisfy, substitute for, or count as the named internal single review; its lifecycle does not add a reviewer.",
        "9. Persist the named Codex artifact only as `internal_review`. Run `external_review` separately only when required, and never reuse the internal artifact for it. A fallback-readiness smoke is availability evidence only and never review coverage.",
        f"10. Reconcile the run with: `{_runner_command('reconcile-parent', '--run-dir', str(run_dir), '--child-status', '<completed|failed|interrupted>', '--child-session-id', '<child_session_id>', runner_path=runner_path)}`",
        "11. Read the resulting `summary.md` and only then give the user the consolidated finish-line result.",
        "",
        "Guardrails:",
        "- Do not spawn additional delivery children for this run.",
        "- Do not call `finalize` directly from the parent when `reconcile-parent` is available.",
        "- If the user explicitly interrupts or materially redirects the run, record that through the terminal child status instead of pretending the old run completed cleanly.",
    ]
    return "\n".join(lines) + "\n"


def _write_current_prompts(
    run_dir: pathlib.Path,
    run_fd: int,
    state: WaitedDeliveryState,
    *,
    require_existing: bool,
    runner_path: pathlib.Path | None = None,
) -> tuple[pathlib.Path, FileVersion, pathlib.Path, FileVersion]:
    child_prompt_path = run_dir / "child-prompt.md"
    parent_prompt_path = run_dir / "parent-prompt.md"
    state["artifacts"]["child_prompt"] = str(child_prompt_path)
    state["artifacts"]["parent_prompt"] = str(parent_prompt_path)
    child_prompt_version = _expected_artifact_version(
        run_fd,
        child_prompt_path.name,
        required=require_existing,
    )
    parent_prompt_version = _expected_artifact_version(
        run_fd,
        parent_prompt_path.name,
        required=require_existing,
    )
    child_published_version = _atomic_write_regular(
        run_fd,
        child_prompt_path.name,
        _build_child_prompt(
            run_dir,
            state,
            runner_path=runner_path,
        ),
        expected_version=child_prompt_version,
    )
    parent_published_version = _atomic_write_regular(
        run_fd,
        parent_prompt_path.name,
        _build_parent_prompt(
            run_dir,
            state,
            runner_path=runner_path,
        ),
        expected_version=parent_prompt_version,
    )
    return (
        child_prompt_path,
        child_published_version,
        parent_prompt_path,
        parent_published_version,
    )


def _non_terminal_phase_names(state: WaitedDeliveryState) -> list[str]:
    return [
        phase_name
        for phase_name in state["phases_order"]
        if state["phases"][phase_name]["status"] not in TERMINAL_PHASE_STATUSES
    ]


def _prepare(args: argparse.Namespace) -> int:
    _validate_parent_metadata_args(args)
    repo_root = _resolve_repo_root(args.repo)
    changed_files = (
        _ensure_relative_paths(args.changed_file)
        if args.changed_file
        else _collect_changed_files(repo_root)
    )
    initial_transaction_time = _utc_now()
    run_id = (
        args.run_id
        if args.run_id is not None
        else _generate_run_id(initial_transaction_time)
    )
    run_dir = _prospective_run_directory(repo_root, run_id)
    preparation_id = args.preparation_id
    preparation_lease_fd = args.preparation_lease_fd
    if (preparation_id is None) != (preparation_lease_fd is None):
        raise UserError(
            "preparation id and inherited preparation lease fd must be supplied together"
        )
    if preparation_id is not None:
        _validate_component_name(preparation_id, label="preparation id")
        assert preparation_lease_fd is not None
        if preparation_lease_fd < 0:
            raise UserError("preparation lease fd must be nonnegative")
        try:
            lease_stat = os.fstat(preparation_lease_fd)
        except OSError as error:
            raise UserError("preparation lease fd is not open") from error
        if (
            not stat.S_ISREG(lease_stat.st_mode)
            or lease_stat.st_uid != os.geteuid()
            or stat.S_IMODE(lease_stat.st_mode) != FILE_MODE
        ):
            raise UserError(
                "preparation lease fd must be an owner-private regular file"
            )
    phases_order = args.phase or list(DEFAULT_PHASES)
    if "internal_review" not in phases_order:
        raise UserError("phase order must include the required internal_review phase")

    state_path = run_dir / "state.json"
    contract_path = run_dir / "child-contract.md"
    child_prompt_path = run_dir / "child-prompt.md"
    parent_prompt_path = run_dir / "parent-prompt.md"
    smoke_prompt_path = run_dir / FALLBACK_SMOKE_PROMPT_NAME
    smoke_command_path = run_dir / "fallback-smoke.command.txt"
    state: WaitedDeliveryState = {
        "schema_version": STATE_SCHEMA_VERSION,
        "run_id": run_id,
        "preparation_id": preparation_id,
        "repo_root": str(repo_root),
        "goal": args.goal,
        "created_at": initial_transaction_time,
        "updated_at": initial_transaction_time,
        "known_blockers": list(args.known_blocker),
        "changed_files": changed_files,
        "phases_order": phases_order,
        "phases": {phase: _phase_template() for phase in phases_order},
        "review_policy": {
            "external_lane": args.external_lane,
            "fallback_lane": args.fallback_lane,
            "fallback_entrypoint": args.fallback_entrypoint,
            "external_helper": str(pathlib.Path(args.external_helper).resolve()),
        },
        "fallback_readiness_smoke": {
            "enabled": not args.no_fallback_smoke,
            "status": "pending",
            "lane": args.fallback_lane,
            "entrypoint": args.fallback_entrypoint,
            "prompt_file": str(smoke_prompt_path),
            "command": [],
            "sample": None,
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "updated_at": None,
        },
        "orchestration": _orchestration_template(
            parent_session_id=args.parent_session_id,
            parent_turn_id=args.parent_turn_id,
            parent_transcript_path=args.parent_transcript_path,
            permission_mode=args.permission_mode,
        ),
        "legacy_bounded_text": {},
        "artifacts": {
            "state_json": str(state_path),
            "child_contract": str(contract_path),
            "child_prompt": str(child_prompt_path),
            "parent_prompt": str(parent_prompt_path),
            "fallback_smoke_prompt": str(smoke_prompt_path),
            "fallback_smoke_command": str(smoke_command_path),
        },
        "overall_status": "pending",
    }
    state["fallback_readiness_smoke"]["command"] = _smoke_command_argv(state)
    initial_state_json = _serialize_state_for_save(
        state,
        transaction_time=initial_transaction_time,
        context="initial state",
    )
    initial_artifacts = {
        smoke_prompt_path.name: FALLBACK_SMOKE_PROMPT,
        contract_path.name: _build_child_contract(state),
        child_prompt_path.name: _build_child_prompt(run_dir, state),
        parent_prompt_path.name: _build_parent_prompt(run_dir, state),
        smoke_command_path.name: (
            _shell_command(state["fallback_readiness_smoke"]["command"]) + "\n"
        ),
        state_path.name: initial_state_json,
    }
    for artifact_name, artifact_content in initial_artifacts.items():
        _preflight_utf8_artifact(artifact_name, artifact_content)

    run_dir, run_fd = _create_run_directory(repo_root, run_id)
    try:
        with _run_lock(run_fd):
            _atomic_write_regular(
                run_fd,
                smoke_prompt_path.name,
                initial_artifacts[smoke_prompt_path.name],
                expected_version=None,
            )
            _atomic_write_regular(
                run_fd,
                contract_path.name,
                initial_artifacts[contract_path.name],
                expected_version=None,
            )
            _atomic_write_regular(
                run_fd,
                child_prompt_path.name,
                initial_artifacts[child_prompt_path.name],
                expected_version=None,
            )
            _atomic_write_regular(
                run_fd,
                parent_prompt_path.name,
                initial_artifacts[parent_prompt_path.name],
                expected_version=None,
            )
            _atomic_write_regular(
                run_fd,
                smoke_command_path.name,
                initial_artifacts[smoke_command_path.name],
                expected_version=None,
            )
            _atomic_write_regular(
                run_fd,
                state_path.name,
                initial_artifacts[state_path.name],
                expected_version=None,
                max_content_bytes=STATE_MAX_BYTES,
            )
            _verify_run_directory_identity(run_dir, repo_root, run_fd)
    finally:
        os.close(run_fd)

    if args.json:
        print(
            json.dumps(
                {
                    "run_dir": str(run_dir),
                    "preparation_id": state["preparation_id"],
                    "preparation_lease_inherited": (preparation_lease_fd is not None),
                    "state_json": state["artifacts"]["state_json"],
                    "child_contract": state["artifacts"]["child_contract"],
                    "child_prompt": state["artifacts"]["child_prompt"],
                    "parent_prompt": state["artifacts"]["parent_prompt"],
                    "fallback_smoke_prompt": state["artifacts"][
                        "fallback_smoke_prompt"
                    ],
                    "fallback_smoke_command": state["artifacts"][
                        "fallback_smoke_command"
                    ],
                }
            )
        )
    else:
        print(run_dir)
    return 0


def _refresh_prompts(args: argparse.Namespace) -> int:
    _require_isolated_python()
    expected_identity_values = (
        getattr(args, "expected_run_dev", None),
        getattr(args, "expected_run_ino", None),
        getattr(args, "expected_run_uid", None),
        getattr(args, "expected_run_gid", None),
        getattr(args, "expected_run_mode", None),
    )
    if any(value is not None for value in expected_identity_values) and not all(
        value is not None for value in expected_identity_values
    ):
        raise UserError(
            "expected run device, inode, uid, gid, and mode must be supplied together"
        )
    expected_run_identity = None
    if all(value is not None for value in expected_identity_values):
        expected_run_identity = DirectoryIdentity(
            device=cast(int, expected_identity_values[0]),
            inode=cast(int, expected_identity_values[1]),
            uid=cast(int, expected_identity_values[2]),
            gid=cast(int, expected_identity_values[3]),
            mode=cast(int, expected_identity_values[4]),
        )
    expected_bridge_version = _expected_file_version(args, "bridge")
    expected_runner_version = _expected_file_version(args, "runner")
    runner_source = globals().get("_WAITED_DELIVERY_BOUND_RUNNER_SOURCE")
    if not isinstance(runner_source, bytes):
        raise UserError("refresh-prompts requires anonymous-pipe-bound runner source")
    compiled_bridge_path = pathlib.Path(args.compiled_bridge_path)
    compiled_runner_path = pathlib.Path(args.compiled_runner_path)
    runner_path = pathlib.Path(args.published_runner_path)
    for label, path in (
        ("compiled bridge", compiled_bridge_path),
        ("compiled runner", compiled_runner_path),
        ("published runner", runner_path),
    ):
        if (
            not path.is_absolute()
            or not path.name
            or pathlib.PurePath(path.name).name != path.name
        ):
            raise UserError(f"{label} path must be an absolute file path")
    if compiled_runner_path != pathlib.Path(os.path.abspath(__file__)):
        raise UserError(
            "compatibility runner compile filename does not match the loaded code"
        )
    if compiled_runner_path != runner_path:
        raise UserError("compiled and published compatibility runner paths must match")
    if (
        len(runner_source) != expected_runner_version.size
        or hashlib.sha256(runner_source).hexdigest() != expected_runner_version.sha256
    ):
        raise UserError("bound compatibility runner source content changed")
    bridge_version = expected_bridge_version
    runner_version = expected_runner_version
    with _locked_run_state(
        args.run_dir,
        expected_repo_root=args.expected_repo_root,
        expected_run_identity=expected_run_identity,
    ) as (run_dir, repo_root, run_fd, state, state_version):
        run_identity = _directory_identity(os.fstat(run_fd))
        if (
            len(runner_source) != expected_runner_version.size
            or hashlib.sha256(runner_source).hexdigest()
            != expected_runner_version.sha256
        ):
            raise UserError(
                "bound compatibility runner source content changed before writes"
            )
        transaction_time = _utc_now()
        candidate = copy.deepcopy(state)
        candidate["artifacts"]["child_prompt"] = str(run_dir / "child-prompt.md")
        candidate["artifacts"]["parent_prompt"] = str(run_dir / "parent-prompt.md")
        _serialize_state_for_save(
            candidate,
            transaction_time=transaction_time,
            context="prompt refresh state",
        )
        (
            child_prompt_path,
            child_prompt_version,
            parent_prompt_path,
            parent_prompt_version,
        ) = _write_current_prompts(
            run_dir,
            run_fd,
            candidate,
            require_existing=True,
            runner_path=runner_path,
        )
        _save_state(
            run_dir,
            repo_root,
            run_fd,
            candidate,
            state_version,
            transaction_time=transaction_time,
            context="prompt refresh state",
        )
    if args.json:
        print(
            json.dumps(
                {
                    "refresh_schema_version": PROMPT_REFRESH_SCHEMA_VERSION,
                    "python_isolated": True,
                    "bridge_source_transport": "anonymous-pipe-memory",
                    "runner_source_transport": "anonymous-pipe-memory",
                    "bridge_source_reopenable": False,
                    "runner_source_reopenable": False,
                    "run_dir": str(run_dir),
                    "runner_path": str(runner_path),
                    "compiled_bridge_path": str(compiled_bridge_path),
                    "bridge_version": _file_version_payload(bridge_version),
                    "compiled_runner_path": str(compiled_runner_path),
                    "runner_version": _file_version_payload(runner_version),
                    "child_prompt": str(child_prompt_path),
                    "child_prompt_version": _file_version_payload(child_prompt_version),
                    "parent_prompt": str(parent_prompt_path),
                    "parent_prompt_version": _file_version_payload(
                        parent_prompt_version
                    ),
                    "run_dev": run_identity.device,
                    "run_ino": run_identity.inode,
                    "run_uid": run_identity.uid,
                    "run_gid": run_identity.gid,
                    "run_mode": run_identity.mode,
                }
            )
        )
    else:
        print(parent_prompt_path)
    return 0


def _attach_child(args: argparse.Namespace) -> int:
    if not args.child_session_id.strip():
        raise UserError("attach-child requires a nonblank child session id")
    _validate_child_session_id(
        args.child_session_id,
        label="attach-child child-session-id",
    )
    _validate_parent_metadata_args(args)
    with _locked_run_state(args.run_dir) as (
        run_dir,
        repo_root,
        run_fd,
        state,
        state_version,
    ):
        orchestration = state["orchestration"]
        if (
            orchestration["child_status"] != "pending"
            or orchestration["child_session_id"]
        ):
            raise UserError(
                "cannot attach child after child orchestration has already started"
            )
        transaction_time = _utc_now()
        orchestration["child_session_id"] = args.child_session_id
        orchestration["child_status"] = "running"
        orchestration["child_started_at"] = transaction_time
        orchestration["updated_at"] = transaction_time
        if args.parent_session_id:
            orchestration["parent_session_id"] = args.parent_session_id
        if args.parent_turn_id:
            orchestration["parent_turn_id"] = args.parent_turn_id
        if args.parent_transcript_path:
            orchestration["parent_transcript_path"] = args.parent_transcript_path
        if args.permission_mode:
            orchestration["permission_mode"] = args.permission_mode
        _save_state(
            run_dir,
            repo_root,
            run_fd,
            state,
            state_version,
            transaction_time=transaction_time,
            context="child attachment",
        )
    return 0


def _bind_parent(args: argparse.Namespace) -> int:
    _validate_parent_metadata_args(args)
    with _locked_run_state(args.run_dir) as (
        run_dir,
        repo_root,
        run_fd,
        state,
        state_version,
    ):
        if (
            not args.parent_session_id
            and not args.parent_turn_id
            and not args.parent_transcript_path
            and not args.permission_mode
        ):
            raise UserError("bind-parent requires at least one parent metadata field")
        orchestration = state["orchestration"]
        if args.parent_session_id:
            orchestration["parent_session_id"] = args.parent_session_id
        if args.parent_turn_id:
            orchestration["parent_turn_id"] = args.parent_turn_id
        if args.parent_transcript_path:
            orchestration["parent_transcript_path"] = args.parent_transcript_path
        if args.permission_mode:
            orchestration["permission_mode"] = args.permission_mode
        orchestration["updated_at"] = _utc_now()
        _save_state(run_dir, repo_root, run_fd, state, state_version)
    return 0


def _begin_phase(args: argparse.Namespace) -> int:
    with _locked_run_state(args.run_dir) as (
        run_dir,
        repo_root,
        run_fd,
        state,
        state_version,
    ):
        phases = state["phases"]
        if args.phase not in phases:
            raise UserError(f"unknown phase: {args.phase}")
        phase = phases[args.phase]
        phase["status"] = "running"
        phase["summary"] = args.summary or ""
        phase["findings"] = []
        phase["evidence"] = []
        phase["updated_at"] = _utc_now()
        _save_state(run_dir, repo_root, run_fd, state, state_version)
    return 0


def _validate_review_pass(state: WaitedDeliveryState, evidence: list[str]) -> None:
    orchestration = state["orchestration"]
    if orchestration["child_status"] not in CHILD_TERMINAL_STATUSES:
        raise UserError("cannot record a passed review before the child is terminal")
    child_session_id = orchestration["child_session_id"]
    if not isinstance(child_session_id, str) or not child_session_id.strip():
        raise UserError(
            "cannot record a passed review without a nonblank attached child session id"
        )
    changed_files = _collect_changed_files(pathlib.Path(state["repo_root"]))
    if changed_files:
        sample = ", ".join(_display_filesystem_path(path) for path in changed_files[:5])
        suffix = "" if len(changed_files) <= 5 else ", ..."
        raise UserError(
            "cannot record a passed review while implementation state is "
            f"dirty or untracked: {sample}{suffix}"
        )
    if not any(item.strip() for item in evidence):
        raise UserError(
            "cannot record a passed review without nonblank terminal reviewer evidence"
        )


def _validate_passed_reviews(state: WaitedDeliveryState) -> None:
    if "internal_review" not in state["phases"]:
        raise UserError(
            "waited-delivery state is missing the required internal_review phase"
        )
    for phase_name in REVIEW_PHASES:
        phase = state["phases"].get(phase_name)
        if phase is not None and phase["status"] == "passed":
            _validate_review_pass(state, phase["evidence"])


def _record_phase(args: argparse.Namespace) -> int:
    with _locked_run_state(args.run_dir) as (
        run_dir,
        repo_root,
        run_fd,
        state,
        state_version,
    ):
        phases = state["phases"]
        if args.phase not in phases:
            raise UserError(f"unknown phase: {args.phase}")
        if args.status not in PHASE_STATUSES:
            raise UserError(f"unsupported status: {args.status}")
        if args.phase in REVIEW_PHASES and args.status == "passed":
            _validate_review_pass(state, list(args.evidence))
        phase = phases[args.phase]
        phase["status"] = args.status
        phase["summary"] = args.summary or ""
        phase["findings"] = list(args.finding)
        phase["evidence"] = list(args.evidence)
        phase["updated_at"] = _utc_now()
        _save_state(run_dir, repo_root, run_fd, state, state_version)
    return 0


def _close_open_phases(args: argparse.Namespace) -> int:
    with _locked_run_state(args.run_dir) as (
        run_dir,
        repo_root,
        run_fd,
        state,
        state_version,
    ):
        if args.status not in TERMINAL_PHASE_STATUSES:
            raise UserError(
                f"close-open-phases requires a terminal status: {args.status}"
            )
        findings = list(args.finding)
        evidence = list(args.evidence)
        if args.status == "passed" and any(
            phase_name in REVIEW_PHASES
            and state["phases"][phase_name]["status"] not in TERMINAL_PHASE_STATUSES
            for phase_name in state["phases_order"]
        ):
            raise UserError(
                "close-open-phases cannot mark review phases passed; record each "
                "review phase with its own terminal evidence"
            )
        updated = False
        for phase_name in state["phases_order"]:
            phase = state["phases"][phase_name]
            if phase["status"] in TERMINAL_PHASE_STATUSES:
                continue
            phase["status"] = args.status
            phase["summary"] = args.summary or ""
            phase["findings"] = findings.copy()
            phase["evidence"] = evidence.copy()
            phase["updated_at"] = _utc_now()
            updated = True
        if updated:
            _save_state(run_dir, repo_root, run_fd, state, state_version)
    return 0


def _transition_child_terminal(
    state: WaitedDeliveryState,
    *,
    child_status: str,
    child_session_id: str | None,
    transaction_time: str,
) -> None:
    if child_status not in CHILD_TERMINAL_STATUSES:
        raise UserError(f"unsupported child status: {child_status}")
    if not child_session_id or not child_session_id.strip():
        raise UserError(
            "child terminal transition requires a nonblank child session id"
        )
    orchestration = state["orchestration"]
    attached_id = orchestration["child_session_id"]
    if not attached_id:
        raise UserError(
            "cannot finish child before attach-child records its session id"
        )
    if child_session_id != attached_id:
        raise UserError(
            "child session id does not match the attached child: "
            f"expected {attached_id}, got {child_session_id}"
        )
    current_status = orchestration["child_status"]
    if current_status == "running":
        orchestration["child_status"] = child_status
        orchestration["child_finished_at"] = transaction_time
        orchestration["updated_at"] = transaction_time
    elif current_status in CHILD_TERMINAL_STATUSES:
        if current_status != child_status:
            raise UserError(
                "child terminal status does not match the recorded status: "
                f"expected {current_status}, got {child_status}"
            )
        if not orchestration["child_finished_at"]:
            orchestration["child_finished_at"] = transaction_time
            orchestration["updated_at"] = transaction_time
    else:
        raise UserError(
            "cannot finish child before attach-child transitions it to running"
        )


def _finish_child(args: argparse.Namespace) -> int:
    with _locked_run_state(args.run_dir) as (
        run_dir,
        repo_root,
        run_fd,
        state,
        state_version,
    ):
        transaction_time = _utc_now()
        candidate = copy.deepcopy(state)
        _transition_child_terminal(
            candidate,
            child_status=args.child_status,
            child_session_id=args.child_session_id,
            transaction_time=transaction_time,
        )
        _serialize_state_for_save(
            candidate,
            transaction_time=transaction_time,
            context="child terminal transition",
        )
        _save_state(
            run_dir,
            repo_root,
            run_fd,
            candidate,
            state_version,
            transaction_time=transaction_time,
            context="child terminal transition",
        )
    return 0


class _CaptureLimitExceeded(Exception):
    pass


class _DeferredSmokeTermination(BaseException):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


class _SmokeSignalTransaction:
    """Defer one terminal signal until the launched process group is gone."""

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
                "fallback readiness smoke signal supervision requires POSIX "
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

    def __enter__(self) -> _SmokeSignalTransaction:
        pthread_sigmask, _sigpending, _sigwait = self._signal_runtime()
        candidates = self._candidate_signals()
        try:
            self._entry_mask = {
                int(value)
                for value in pthread_sigmask(signal.SIG_BLOCK, set(candidates))
            }
        except (OSError, ValueError) as error:
            raise UserError(
                f"cannot block smoke supervision signals before launch: {error}"
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
                f"cannot restore smoke supervision entry signal mask: {error}"
            ) from error
        return self

    def raise_if_pending(self) -> None:
        if self._pending_signal is None or self._raised:
            return
        self._raised = True
        raise _DeferredSmokeTermination(self._pending_signal)

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
                    f"cannot inspect pending smoke supervision signals: {error}"
                ) from error
            if not pending:
                return
            try:
                signum = int(sigwait(pending))
            except (OSError, ValueError) as error:
                raise UserError(
                    f"cannot consume pending smoke supervision signal: {error}"
                ) from error
            if signum not in pending:
                raise UserError(
                    "smoke supervision sigwait returned an unrequested signal"
                )
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
                f"cannot block smoke supervision signals during cleanup: {error}"
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
                    _DeferredSmokeTermination,
                ):
                    print(
                        "note: smoke cleanup raised "
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
                    f"cannot restore smoke supervision terminal signal mask: {error}"
                ) from error

        return isinstance(exc, _DeferredSmokeTermination)


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
    max_entries: int = PROC_GROUP_SCAN_MAX_ENTRIES,
) -> LinuxProcessGroupState:
    if deadline is None:
        deadline = time.monotonic() + PROC_GROUP_SCAN_TIMEOUT_SECONDS
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


def _process_group_exists(
    pgid: int,
    *,
    proc_root: pathlib.Path = pathlib.Path("/proc"),
    platform: str = sys.platform,
) -> bool:
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
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_group_is_addressable(pgid: int) -> bool:
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


def _drain_process_output_once(
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    timeout: float,
    capture: bool,
    max_capture_bytes: int,
) -> None:
    for key, _mask in selector.select(timeout):
        try:
            chunk = os.read(key.fd, PROCESS_DRAIN_CHUNK_BYTES)
        except BlockingIOError:
            continue
        if not chunk:
            selector.unregister(key.fd)
            continue
        if not capture:
            continue
        retained = sum(len(value) for value in captures.values())
        if retained + len(chunk) > max_capture_bytes:
            raise _CaptureLimitExceeded
        captures[cast(str, key.data)].extend(chunk)


def _service_smoke_io_once(
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
        if key.data == "prompt-input":
            if not (mask & selectors.EVENT_WRITE):
                continue
            try:
                written = os.write(
                    key.fd,
                    input_bytes[
                        input_offset : input_offset + PROCESS_DRAIN_CHUNK_BYTES
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
                cast(BinaryIO, key.fileobj).close()
            continue
        try:
            chunk = os.read(key.fd, PROCESS_DRAIN_CHUNK_BYTES)
        except BlockingIOError:
            continue
        if not chunk:
            selector.unregister(key.fd)
            continue
        retained = sum(len(value) for value in captures.values())
        if retained + len(chunk) > max_capture_bytes:
            raise _CaptureLimitExceeded
        captures[cast(str, key.data)].extend(chunk)
    return input_offset, input_rejected


def _close_smoke_input(
    selector: selectors.BaseSelector,
    input_stream: BinaryIO | None,
) -> None:
    if input_stream is None:
        return
    if not input_stream.closed:
        try:
            selector.unregister(input_stream)
        except (KeyError, ValueError, OSError):
            pass
        try:
            input_stream.close()
        except OSError:
            pass


def _cleanup_smoke_process(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    captures: dict[str, bytearray],
    *,
    cleanup_timeout: float,
    max_capture_bytes: int,
) -> None:
    _kill_process_group(process.pid)
    deadline = time.monotonic() + cleanup_timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        _drain_process_output_once(
            selector,
            captures,
            timeout=min(PROCESS_POLL_INTERVAL_SECONDS, max(0.0, remaining)),
            capture=False,
            max_capture_bytes=max_capture_bytes,
        )
        returncode = process.poll()
        if (
            returncode is not None
            and not _process_group_is_addressable(process.pid)
            and not selector.get_map()
        ):
            return
    reasons: list[str] = []
    if process.poll() is None:
        reasons.append("failed to reap smoke process")
    if _process_group_is_addressable(process.pid):
        reasons.append("failed to prove smoke process-group disappearance")
    if selector.get_map():
        reasons.append("failed to drain smoke process pipes")
    raise UserError("; ".join(reasons) or "smoke process cleanup timed out")


def _run_bounded_smoke_process(
    command: list[str],
    *,
    cwd: pathlib.Path,
    child_read_streams: tuple[BinaryIO, ...] = (),
    input_stream: BinaryIO | None = None,
    input_bytes: bytes | None = None,
    timeout: float = SMOKE_TIMEOUT_SECONDS,
    cleanup_timeout: float = SMOKE_CLEANUP_TIMEOUT_SECONDS,
    max_capture_bytes: int = SMOKE_CAPTURE_MAX_BYTES,
    pre_spawn_check: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    if not command or not all(isinstance(argument, str) for argument in command):
        raise UserError("fallback readiness smoke command must be a nonempty argv")
    child_read_fds: list[int] = []
    for child_read_stream in child_read_streams:
        try:
            child_read_fd = child_read_stream.fileno()
        except (AttributeError, OSError, ValueError) as error:
            raise UserError(
                "fallback readiness smoke child reader must be an open file object"
            ) from error
        try:
            child_read_metadata = os.fstat(child_read_fd)
            child_read_access = fcntl.fcntl(child_read_fd, fcntl.F_GETFL) & os.O_ACCMODE
        except OSError as error:
            raise UserError(
                "fallback readiness smoke child reader cannot be verified"
            ) from error
        if (
            not stat.S_ISFIFO(child_read_metadata.st_mode)
            or child_read_access != os.O_RDONLY
        ):
            raise UserError(
                "fallback readiness smoke child reader must be an anonymous-pipe reader"
            )
        child_read_fds.append(child_read_fd)
    if len(child_read_fds) != len(set(child_read_fds)):
        raise UserError("fallback readiness smoke child readers must be distinct")
    pass_fds = tuple(child_read_fds)
    if (input_stream is None) != (input_bytes is None):
        raise UserError(
            "fallback readiness smoke input_stream and input_bytes must be supplied "
            "together"
        )
    if input_bytes is not None and not isinstance(input_bytes, bytes):
        raise UserError("fallback readiness smoke input must be bytes")
    if input_stream is not None:
        try:
            input_stream_fd = input_stream.fileno()
        except (AttributeError, OSError, ValueError) as error:
            raise UserError(
                "fallback readiness smoke input stream must be an open file object"
            ) from error
        try:
            input_metadata = os.fstat(input_stream_fd)
            input_access = fcntl.fcntl(input_stream_fd, fcntl.F_GETFL) & os.O_ACCMODE
        except OSError as error:
            raise UserError(
                "fallback readiness smoke input stream cannot be verified"
            ) from error
        if not stat.S_ISFIFO(input_metadata.st_mode) or input_access != os.O_WRONLY:
            raise UserError(
                "fallback readiness smoke input stream must be an anonymous-pipe writer"
            )
        if input_stream_fd in pass_fds:
            raise UserError(
                "fallback readiness smoke input stream must remain parent-private"
            )
        if len(cast(bytes, input_bytes)) > STATE_MAX_BYTES:
            raise UserError(
                f"fallback readiness smoke input exceeds {STATE_MAX_BYTES} bytes"
            )
    if timeout <= 0 or cleanup_timeout <= 0 or max_capture_bytes <= 0:
        raise UserError("fallback readiness smoke bounds must be positive")
    signal_transaction = _SmokeSignalTransaction()
    completed: subprocess.CompletedProcess[str] | None = None
    with signal_transaction:
        completed = _run_bounded_smoke_process_supervised(
            command,
            cwd=cwd,
            pass_fds=pass_fds,
            child_read_streams=child_read_streams,
            input_stream=input_stream,
            input_bytes=input_bytes,
            timeout=timeout,
            cleanup_timeout=cleanup_timeout,
            max_capture_bytes=max_capture_bytes,
            signal_transaction=signal_transaction,
            pre_spawn_check=pre_spawn_check,
        )
    if signal_transaction.pending_signal is not None:
        signum = signal_transaction.pending_signal
        return subprocess.CompletedProcess(
            command,
            128 + signum,
            stdout="" if completed is None else completed.stdout,
            stderr=(
                f"BLOCKED: smoke interrupted by {signal.Signals(signum).name} "
                "after process-group cleanup\n"
            ),
        )
    if completed is None:
        raise UserError("smoke process completed without a result")
    return completed


def _run_bounded_smoke_process_supervised(
    command: list[str],
    *,
    cwd: pathlib.Path,
    pass_fds: tuple[int, ...],
    child_read_streams: tuple[BinaryIO, ...],
    input_stream: BinaryIO | None,
    input_bytes: bytes | None,
    timeout: float,
    cleanup_timeout: float,
    max_capture_bytes: int,
    signal_transaction: _SmokeSignalTransaction,
    pre_spawn_check: Callable[[], None] | None,
) -> subprocess.CompletedProcess[str]:
    try:
        selector = selectors.DefaultSelector()
    except OSError as error:
        raise UserError(
            f"cannot initialize fallback readiness smoke selector: {error}"
        ) from error
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    failure: tuple[int, str] | None = None
    cleanup_complete = False
    input_offset = 0
    input_rejected = False
    try:
        signal_transaction.raise_if_pending()
        if pre_spawn_check is not None:
            pre_spawn_check()
        signal_transaction.raise_if_pending()
        try:
            process = subprocess.Popen(
                command,
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=pass_fds,
                start_new_session=True,
            )
        except OSError as error:
            raise UserError(
                f"cannot start fallback readiness smoke: {error}"
            ) from error
        try:
            for child_read_stream in child_read_streams:
                try:
                    child_read_stream.close()
                except OSError as error:
                    raise UserError(
                        "cannot close parent fallback-smoke prompt reader after "
                        "process launch"
                    ) from error
            if process.stdout is None or process.stderr is None:
                raise UserError("smoke process pipes were not created")
            for name, stream in (
                ("stdout", process.stdout),
                ("stderr", process.stderr),
            ):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream.fileno(), selectors.EVENT_READ, name)
            if input_bytes is not None:
                if input_stream is None:
                    raise UserError("smoke prompt input pipe was not supplied")
                if input_bytes:
                    os.set_blocking(input_stream.fileno(), False)
                    selector.register(
                        input_stream,
                        selectors.EVENT_WRITE,
                        "prompt-input",
                    )
                else:
                    _close_smoke_input(selector, input_stream)
            signal_transaction.raise_if_pending()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                signal_transaction.raise_if_pending()
                remaining = deadline - time.monotonic()
                try:
                    input_offset, rejected_now = _service_smoke_io_once(
                        selector,
                        captures,
                        input_bytes=b"" if input_bytes is None else input_bytes,
                        input_offset=input_offset,
                        timeout=min(
                            PROCESS_POLL_INTERVAL_SECONDS,
                            max(0.0, remaining),
                        ),
                        max_capture_bytes=max_capture_bytes,
                    )
                    input_rejected = input_rejected or rejected_now
                except _CaptureLimitExceeded:
                    failure = (
                        125,
                        f"BLOCKED: smoke output exceeded {max_capture_bytes} bytes",
                    )
                    break
                if (
                    input_bytes is not None
                    and input_rejected
                    and input_offset != len(input_bytes)
                ):
                    failure = (
                        126,
                        "BLOCKED: smoke rejected its prompt stream before complete "
                        "delivery",
                    )
                    break
                signal_transaction.raise_if_pending()
                returncode = process.poll()
                if returncode is None:
                    continue
                if input_bytes is not None and input_offset != len(input_bytes):
                    failure = (
                        126,
                        "BLOCKED: smoke rejected its prompt stream before complete "
                        "delivery",
                    )
                    break
                if _process_group_exists(process.pid):
                    failure = (
                        126,
                        "BLOCKED: smoke left a live descendant in its process group",
                    )
                    break
                if not selector.get_map():
                    break
            else:
                failure = (
                    124,
                    f"BLOCKED: smoke exceeded {timeout:g} second hard timeout",
                )

            if failure is not None:
                _close_smoke_input(selector, input_stream)
                _cleanup_smoke_process(
                    process,
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

            returncode = process.poll()
            if returncode is None:
                raise UserError("smoke process reached an impossible terminal state")
            return subprocess.CompletedProcess(
                command,
                returncode,
                stdout=captures["stdout"].decode("utf-8", errors="replace"),
                stderr=captures["stderr"].decode("utf-8", errors="replace"),
            )
        except BaseException:
            if not cleanup_complete:
                _close_smoke_input(selector, input_stream)
                _cleanup_smoke_process(
                    process,
                    selector,
                    captures,
                    cleanup_timeout=cleanup_timeout,
                    max_capture_bytes=max_capture_bytes,
                )
            raise
        finally:
            _close_smoke_input(selector, input_stream)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
    finally:
        _close_smoke_input(selector, input_stream)
        selector.close()


def _classify_smoke(
    stdout: str, stderr: str, returncode: int
) -> tuple[str, str | None]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if returncode != 0:
        err_lines = [line.strip() for line in stderr.splitlines() if line.strip()]
        blocked = next(
            (
                line
                for line in reversed((*lines, *err_lines))
                if line.startswith("BLOCKED:")
            ),
            None,
        )
        if blocked:
            return "blocked", blocked
        return "blocked", f"BLOCKED: process exited with code {returncode}"
    if lines and lines[-1] == "READY":
        return "passed", "READY"
    blocked = next((line for line in lines if line.startswith("BLOCKED:")), None)
    if blocked:
        return "blocked", blocked
    sample = lines[-1] if lines else None
    return "decision_point", sample


def _run_fallback_smoke(args: argparse.Namespace) -> int:
    run_dir, repo_root, run_fd = _open_run_directory(args.run_dir)
    run_identity = _directory_identity(os.fstat(run_fd))
    try:
        with _open_run_lock_descriptor(run_fd) as (
            lock_fd,
            lock_identity,
        ):
            with contextlib.ExitStack() as smoke_pipe_stack:
                with _acquired_run_lock(run_fd, lock_fd, lock_identity):
                    _verify_run_directory_identity(
                        run_dir,
                        repo_root,
                        run_fd,
                        expected_identity=run_identity,
                    )
                    state, snapshot_state_version = _load_state_from_fd(
                        run_dir,
                        repo_root,
                        run_fd,
                    )
                    protected_artifact_versions = {
                        STATE_FILE_NAME: snapshot_state_version,
                    }
                    for artifact_field, artifact_name in (
                        ("child_prompt", "child-prompt.md"),
                        ("parent_prompt", "parent-prompt.md"),
                    ):
                        if state["artifacts"][artifact_field] != str(
                            run_dir / artifact_name
                        ):
                            raise UserError(
                                f"{artifact_name} path does not match the "
                                "descriptor-bound run artifact"
                            )
                        protected_artifact_versions[artifact_name] = (
                            _read_regular_artifact(
                                run_fd,
                                artifact_name,
                                max_bytes=STATE_MAX_BYTES,
                            ).version
                        )
                    snapshot_smoke = copy.deepcopy(state["fallback_readiness_smoke"])
                    if not snapshot_smoke["enabled"]:
                        raise UserError(
                            "fallback readiness smoke is disabled for this run"
                        )
                    expected_prompt_path = run_dir / FALLBACK_SMOKE_PROMPT_NAME
                    if snapshot_smoke["prompt_file"] != str(
                        expected_prompt_path
                    ) or state["artifacts"]["fallback_smoke_prompt"] != str(
                        expected_prompt_path
                    ):
                        raise UserError(
                            "fallback readiness smoke prompt path does not match "
                            "the descriptor-bound run artifact"
                        )
                    command = list(snapshot_smoke["command"])
                    prompt_indexes = [
                        index
                        for index, argument in enumerate(command)
                        if argument == "--prompt-file"
                    ]
                    if (
                        len(prompt_indexes) != 1
                        or prompt_indexes[0] + 1 >= len(command)
                        or command[prompt_indexes[0] + 1] != str(expected_prompt_path)
                    ):
                        raise UserError(
                            "fallback readiness smoke command does not bind the "
                            "expected prompt artifact"
                        )
                    prompt_artifact = _read_regular_artifact(
                        run_fd,
                        FALLBACK_SMOKE_PROMPT_NAME,
                        max_bytes=STATE_MAX_BYTES,
                    )
                    protected_artifact_versions[FALLBACK_SMOKE_PROMPT_NAME] = (
                        prompt_artifact.version
                    )
                    (
                        prompt_execution_path,
                        prompt_read_stream,
                        prompt_write_stream,
                    ) = smoke_pipe_stack.enter_context(_anonymous_smoke_prompt_pipe())
                    command[prompt_indexes[0] + 1] = str(prompt_execution_path)
                    smoke_cwd = pathlib.Path(state["repo_root"])

                def pre_spawn_check() -> None:
                    _verify_run_directory_identity(
                        run_dir,
                        repo_root,
                        run_fd,
                        expected_identity=run_identity,
                    )
                    current_lock = _regular_file_stat(
                        run_fd,
                        RUN_LOCK_NAME,
                        required=True,
                    )
                    if (
                        current_lock is None
                        or _directory_identity(current_lock) != lock_identity
                        or _directory_identity(os.fstat(lock_fd)) != lock_identity
                    ):
                        raise UserError(
                            "run lock identity or access policy changed before "
                            "fallback process start"
                        )
                    for (
                        artifact_name,
                        artifact_version,
                    ) in protected_artifact_versions.items():
                        _validate_expected_artifact(
                            run_fd,
                            artifact_name,
                            artifact_version,
                            max_bytes=STATE_MAX_BYTES,
                        )

                completed = _run_bounded_smoke_process(
                    command,
                    cwd=smoke_cwd,
                    child_read_streams=(prompt_read_stream,),
                    input_stream=prompt_write_stream,
                    input_bytes=prompt_artifact.content,
                    pre_spawn_check=pre_spawn_check,
                )
                status, sample = _classify_smoke(
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    returncode=completed.returncode,
                )
                smoke_pipe_stack.close()
                with _acquired_run_lock(run_fd, lock_fd, lock_identity):
                    _verify_run_directory_identity(
                        run_dir,
                        repo_root,
                        run_fd,
                        expected_identity=run_identity,
                    )
                    latest_state, latest_state_version = _load_state_from_fd(
                        run_dir,
                        repo_root,
                        run_fd,
                    )
                    latest_smoke = latest_state["fallback_readiness_smoke"]
                    if (
                        latest_state_version != snapshot_state_version
                        and latest_smoke != snapshot_smoke
                    ):
                        raise UserError(
                            "fallback readiness smoke state changed while the "
                            "command was running"
                        )
                    latest_smoke["status"] = status
                    latest_smoke["sample"] = sample
                    latest_smoke["stdout"] = completed.stdout
                    latest_smoke["stderr"] = completed.stderr
                    latest_smoke["returncode"] = completed.returncode
                    latest_smoke["updated_at"] = _utc_now()
                    _save_state(
                        run_dir,
                        repo_root,
                        run_fd,
                        latest_state,
                        latest_state_version,
                    )
                    _verify_run_directory_identity(
                        run_dir,
                        repo_root,
                        run_fd,
                        expected_identity=run_identity,
                    )
    finally:
        os.close(run_fd)
    if sample:
        print(sample)
    return 0 if status == "passed" else 1


def _overall_status(phases: dict[str, PhaseState]) -> str:
    statuses = [phase["status"] for phase in phases.values()]
    if any(status == "failed" for status in statuses):
        return "failed"
    if any(status == "decision_point" for status in statuses):
        return "decision_point"
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if any(status == "unavailable" for status in statuses):
        return "unavailable"
    if statuses and all(status == "passed" for status in statuses):
        return "passed"
    if any(status == "running" for status in statuses):
        return "running"
    return "pending"


def _build_summary(
    state: WaitedDeliveryState,
    *,
    require_terminal: bool,
) -> str:
    non_terminal = _non_terminal_phase_names(state)
    if require_terminal and non_terminal:
        raise UserError(
            "cannot finalize before all phases reach terminal status: "
            + ", ".join(non_terminal)
        )
    orchestration = state["orchestration"]
    if (
        require_terminal
        and orchestration["child_status"] not in CHILD_TERMINAL_STATUSES
    ):
        raise UserError(
            "cannot finalize before child reaches terminal status: "
            f"{orchestration['child_status']}"
        )
    child_session_id = orchestration["child_session_id"]
    if orchestration["child_status"] in CHILD_TERMINAL_STATUSES and (
        not isinstance(child_session_id, str) or not child_session_id.strip()
    ):
        raise UserError(
            "cannot finalize a terminal run without a nonblank attached child session id"
        )
    _validate_passed_reviews(state)
    overall_status = _overall_status(state["phases"])
    state["overall_status"] = overall_status
    lines = [
        "# Waited Delivery Summary",
        "",
        f"- Run ID: `{state['run_id']}`",
        f"- Overall status: `{overall_status}`",
        "",
        "## Phases",
    ]
    for phase_name in state["phases_order"]:
        phase = state["phases"][phase_name]
        summary = phase["summary"] or "no summary"
        lines.append(f"- `{phase_name}`: `{phase['status']}` - {summary}")
    lines.extend(
        [
            "",
            "## Orchestration",
            f"- Parent session: `{orchestration['parent_session_id'] or 'unknown'}`",
            f"- Parent turn: `{orchestration['parent_turn_id'] or 'unknown'}`",
            f"- Parent transcript: `{orchestration['parent_transcript_path'] or 'unknown'}`",
            f"- Permission mode: `{orchestration['permission_mode'] or 'unknown'}`",
            f"- Child session: `{orchestration['child_session_id'] or 'unknown'}`",
            f"- Child status: `{orchestration['child_status']}`",
        ]
    )
    smoke = state["fallback_readiness_smoke"]
    lines.extend(
        [
            "",
            "## Fallback Readiness Smoke",
            f"- Enabled: `{str(smoke['enabled']).lower()}`",
            f"- Status: `{smoke['status']}`",
        ]
    )
    if smoke["sample"]:
        lines.append(f"- Sample: `{smoke['sample']}`")
    return "\n".join(lines) + "\n"


def _publish_summary(
    run_dir: pathlib.Path,
    run_fd: int,
    content: str,
) -> pathlib.Path:
    summary_path = run_dir / "summary.md"
    summary_version = _expected_artifact_version(
        run_fd,
        summary_path.name,
        required=False,
    )
    _atomic_write_regular(
        run_fd,
        summary_path.name,
        content,
        expected_version=summary_version,
    )
    return summary_path


def _finalize(args: argparse.Namespace) -> int:
    with _locked_run_state(args.run_dir) as (
        run_dir,
        repo_root,
        run_fd,
        state,
        state_version,
    ):
        transaction_time = _utc_now()
        candidate = copy.deepcopy(state)
        summary_content = _build_summary(
            candidate,
            require_terminal=args.require_terminal,
        )
        _serialize_state_for_save(
            candidate,
            transaction_time=transaction_time,
            context="finalized state",
        )
        summary_path = _publish_summary(run_dir, run_fd, summary_content)
        _save_state(
            run_dir,
            repo_root,
            run_fd,
            candidate,
            state_version,
            transaction_time=transaction_time,
            context="finalized state",
        )
    print(summary_path)
    return 0


def _reconcile_parent(args: argparse.Namespace) -> int:
    with _locked_run_state(args.run_dir) as (
        run_dir,
        repo_root,
        run_fd,
        state,
        state_version,
    ):
        transaction_time = _utc_now()
        candidate = copy.deepcopy(state)
        _transition_child_terminal(
            candidate,
            child_status=args.child_status,
            child_session_id=args.child_session_id,
            transaction_time=transaction_time,
        )
        orchestration = candidate["orchestration"]
        summary_content = _build_summary(
            candidate,
            require_terminal=True,
        )
        _serialize_state_for_save(
            candidate,
            transaction_time=transaction_time,
            context="terminal reconciliation",
        )
        summary_path = _publish_summary(run_dir, run_fd, summary_content)
        _save_state(
            run_dir,
            repo_root,
            run_fd,
            candidate,
            state_version,
            transaction_time=transaction_time,
            context="terminal reconciliation",
        )
        state = candidate
    if args.json:
        print(
            json.dumps(
                {
                    "summary_path": str(summary_path),
                    "overall_status": state["overall_status"],
                    "child_status": orchestration["child_status"],
                    "child_session_id": orchestration["child_session_id"],
                }
            )
        )
    else:
        print(summary_path)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare and track deterministic waited-delivery runs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument(
        "--repo", required=True, help="Git repo root or path inside the repo."
    )
    prepare.add_argument(
        "--goal", required=True, help="Short delivery goal for the current run."
    )
    prepare.add_argument("--run-id", help="Optional explicit run identifier.")
    prepare.add_argument(
        "--preparation-id",
        help="Optional stable adapter preparation transaction identifier.",
    )
    prepare.add_argument(
        "--preparation-lease-fd",
        type=int,
        help="Inherited adapter preparation lease descriptor.",
    )
    prepare.add_argument(
        "--json",
        action="store_true",
        help="Print the prepared run/artifact paths as JSON.",
    )
    prepare.add_argument(
        "--parent-session-id", help="Optional parent session identifier."
    )
    prepare.add_argument("--parent-turn-id", help="Optional parent turn identifier.")
    prepare.add_argument(
        "--parent-transcript-path",
        help="Optional parent transcript/rollout path from an outer hook or adapter.",
    )
    prepare.add_argument(
        "--permission-mode",
        help="Optional parent permission mode from an outer hook or adapter.",
    )
    prepare.add_argument(
        "--phase",
        action="append",
        help="Override phase order; every override must include internal_review.",
    )
    prepare.add_argument(
        "--changed-file",
        action="append",
        default=[],
        help="Repo-relative changed file.",
    )
    prepare.add_argument(
        "--known-blocker", action="append", default=[], help="Known blocker to record."
    )
    prepare.add_argument("--external-lane", default="bounded-semantic")
    prepare.add_argument("--fallback-lane", default="baseline")
    prepare.add_argument("--fallback-entrypoint", default="gh-copilot")
    prepare.add_argument(
        "--external-helper",
        default=str(DEFAULT_EXTERNAL_HELPER),
        help="Path to the external review helper used for readiness smoke.",
    )
    prepare.add_argument(
        "--no-fallback-smoke",
        action="store_true",
        help="Disable fallback readiness smoke artifacts for this run.",
    )
    prepare.set_defaults(func=_prepare)

    attach_child = subparsers.add_parser("attach-child")
    attach_child.add_argument("--run-dir", required=True)
    attach_child.add_argument("--child-session-id", required=True)
    attach_child.add_argument("--parent-session-id")
    attach_child.add_argument("--parent-turn-id")
    attach_child.add_argument("--parent-transcript-path")
    attach_child.add_argument("--permission-mode")
    attach_child.set_defaults(func=_attach_child)

    bind_parent = subparsers.add_parser("bind-parent")
    bind_parent.add_argument("--run-dir", required=True)
    bind_parent.add_argument("--parent-session-id")
    bind_parent.add_argument("--parent-turn-id")
    bind_parent.add_argument("--parent-transcript-path")
    bind_parent.add_argument("--permission-mode")
    bind_parent.set_defaults(func=_bind_parent)

    refresh_prompts = subparsers.add_parser("refresh-prompts")
    refresh_prompts.add_argument("--run-dir", required=True)
    refresh_prompts.add_argument(
        "--compiled-bridge-path",
        required=True,
        help="Canonical compile filename used for the in-memory bridge source.",
    )
    refresh_prompts.add_argument(
        "--compiled-runner-path",
        required=True,
        help="Canonical compile filename used for the in-memory runner source.",
    )
    refresh_prompts.add_argument(
        "--published-runner-path",
        required=True,
        help="Canonical runner path to publish in regenerated prompts.",
    )
    refresh_prompts.add_argument(
        "--expected-repo-root",
        help=(
            "Require the run to be a direct no-symlink descendant of this exact "
            "repository root."
        ),
    )
    refresh_prompts.add_argument(
        "--expected-run-dev",
        type=int,
        help="Require the run directory to have this device identity.",
    )
    refresh_prompts.add_argument(
        "--expected-run-ino",
        type=int,
        help="Require the run directory to have this inode identity.",
    )
    refresh_prompts.add_argument(
        "--expected-run-uid",
        type=int,
        help="Require the run directory to have this owner identity.",
    )
    refresh_prompts.add_argument(
        "--expected-run-gid",
        type=int,
        help="Require the run directory to have this group identity.",
    )
    refresh_prompts.add_argument(
        "--expected-run-mode",
        type=int,
        help="Require the run directory to have this exact POSIX mode.",
    )
    refresh_prompts.add_argument(
        "--expected-bridge-dev",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-bridge-ino",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-bridge-uid",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-bridge-gid",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-bridge-mode",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-bridge-size",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument("--expected-bridge-sha256", required=True)
    refresh_prompts.add_argument(
        "--expected-runner-dev",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-runner-ino",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-runner-uid",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-runner-gid",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-runner-mode",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument(
        "--expected-runner-size",
        type=int,
        required=True,
    )
    refresh_prompts.add_argument("--expected-runner-sha256", required=True)
    refresh_prompts.add_argument(
        "--json",
        action="store_true",
        help="Print the refreshed prompt and runner paths as JSON.",
    )
    refresh_prompts.set_defaults(func=_refresh_prompts)

    begin_phase = subparsers.add_parser("begin-phase")
    begin_phase.add_argument("--run-dir", required=True)
    begin_phase.add_argument("--phase", required=True)
    begin_phase.add_argument("--summary", default="")
    begin_phase.set_defaults(func=_begin_phase)

    record_phase = subparsers.add_parser("record-phase")
    record_phase.add_argument("--run-dir", required=True)
    record_phase.add_argument("--phase", required=True)
    record_phase.add_argument("--status", required=True)
    record_phase.add_argument("--summary", default="")
    record_phase.add_argument("--finding", action="append", default=[])
    record_phase.add_argument("--evidence", action="append", default=[])
    record_phase.set_defaults(func=_record_phase)

    close_open = subparsers.add_parser("close-open-phases")
    close_open.add_argument("--run-dir", required=True)
    close_open.add_argument("--status", required=True)
    close_open.add_argument("--summary", default="")
    close_open.add_argument("--finding", action="append", default=[])
    close_open.add_argument("--evidence", action="append", default=[])
    close_open.set_defaults(func=_close_open_phases)

    run_smoke = subparsers.add_parser("run-fallback-smoke")
    run_smoke.add_argument("--run-dir", required=True)
    run_smoke.set_defaults(func=_run_fallback_smoke)

    finish_child = subparsers.add_parser("finish-child")
    finish_child.add_argument("--run-dir", required=True)
    finish_child.add_argument("--child-status", required=True)
    finish_child.add_argument("--child-session-id", required=True)
    finish_child.set_defaults(func=_finish_child)

    reconcile_parent = subparsers.add_parser("reconcile-parent")
    reconcile_parent.add_argument("--run-dir", required=True)
    reconcile_parent.add_argument("--child-status", required=True)
    reconcile_parent.add_argument("--child-session-id", required=True)
    reconcile_parent.add_argument(
        "--json",
        action="store_true",
        help="Print summary/result fields as JSON instead of only the summary path.",
    )
    reconcile_parent.set_defaults(func=_reconcile_parent)

    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--run-dir", required=True)
    finalize.add_argument(
        "--require-terminal",
        action="store_true",
        help="Fail unless the child and all phases already reached terminal status.",
    )
    finalize.set_defaults(func=_finalize)

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except UserError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
