#!/usr/bin/env python3

"""Explicit-only hook compatibility for historical waited-delivery runs."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import stat
import subprocess
import sys
import traceback
import uuid
from typing import NamedTuple, TypedDict, cast


BRIDGE_PATH = pathlib.Path(__file__).resolve().with_name("waited_delivery_bridge.py")
RUNNER_PATH = BRIDGE_PATH.with_name("waited_delivery_runner.py")
INDEX_SCHEMA_VERSION = 1
CURRENT_THREAD_ENV = "CODEX_THREAD_ID"
HOOK_DEBUG_ENV = "WAITED_DELIVERY_HOOK_DEBUG"
HOOK_COMMANDS = {"user-prompt-submit-hook", "stop-hook"}
HOOK_ENABLE_FLAG = "--enable-compat-hook"
NON_HOOK_COMMANDS = {
    "prepare-active-run",
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
RUNS_DIR_NAME = "waited-delivery"
STATE_MAX_BYTES = 4 * 1024 * 1024
PROMPT_REFRESH_SCHEMA_VERSION = 1


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


class StopArtifactRead(NamedTuple):
    content: bytes
    version: StopArtifactVersion


class RefreshedPrompts(NamedTuple):
    child_prompt: pathlib.Path
    child_version: StopArtifactVersion
    parent_prompt: pathlib.Path
    parent_version: StopArtifactVersion


class SessionRecord(TypedDict):
    session_id: str
    cwd: str
    transcript_path: str | None
    permission_mode: str | None
    last_prompt: str | None
    run_dir: str | None
    status: str
    updated_at: str | None


class AdapterIndex(TypedDict):
    schema_version: int
    latest_session_id: str | None
    updated_at: str | None
    sessions: dict[str, SessionRecord]


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _shell_command(args: list[str]) -> str:
    return " ".join(shlex.quote(arg) for arg in args)


def _run(
    cmd: list[str], *, cwd: pathlib.Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )


def _bridge_command(*args: str) -> list[str]:
    return [sys.executable, str(BRIDGE_PATH), *args]


def _run_bridge_json(*args: str) -> dict[str, object]:
    completed = _run(_bridge_command(*args))
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


def _run_bridge_passthrough(*args: str) -> int:
    completed = _run(_bridge_command(*args))
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
    return _adapter_dir(repo_root) / "index.json"


def _index_template() -> AdapterIndex:
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "latest_session_id": None,
        "updated_at": None,
        "sessions": {},
    }


def _load_index(repo_root: pathlib.Path) -> tuple[pathlib.Path, AdapterIndex]:
    path = _index_path(repo_root)
    if not path.is_file():
        return path, _index_template()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise UserError(f"invalid adapter index: {path}")
    payload.setdefault("schema_version", INDEX_SCHEMA_VERSION)
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
    return path, cast(AdapterIndex, payload)


def _save_index(path: pathlib.Path, index: AdapterIndex) -> None:
    index["updated_at"] = _utc_now()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


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


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _run_directory_identity(file_stat: os.stat_result) -> RunDirectoryIdentity:
    return RunDirectoryIdentity(
        device=file_stat.st_dev,
        inode=file_stat.st_ino,
        uid=file_stat.st_uid,
        gid=file_stat.st_gid,
        mode=stat.S_IMODE(file_stat.st_mode),
    )


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
        codex_tmp_fd = _open_directory_at(repo_fd, ".codex-tmp")
        runs_fd = _open_directory_at(codex_tmp_fd, RUNS_DIR_NAME)
        return _open_directory_at(runs_fd, run_name)
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
        return _read_stop_regular_artifact(
            parent_fd,
            path.name,
            max_bytes=max_bytes,
        )
    finally:
        os.close(parent_fd)


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
    if pinned_identity.uid != os.geteuid() or pinned_identity.mode != 0o700:
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


def _load_run_state(run_dir_str: str) -> dict[str, object] | None:
    state_path = pathlib.Path(run_dir_str).resolve() / "state.json"
    if not state_path.is_file():
        return None
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return None
    return cast(dict[str, object], payload)


def _refresh_recovery_prompts(
    run_dir: pathlib.Path,
    repo_root: pathlib.Path,
    run_identity: RunDirectoryIdentity,
) -> RefreshedPrompts:
    expected_runner = _read_stop_absolute_regular_artifact(
        RUNNER_PATH,
        max_bytes=STATE_MAX_BYTES,
    ).version
    payload = _run_bridge_json(
        "refresh-prompts-live",
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
        "--expected-runner-dev",
        str(expected_runner.device),
        "--expected-runner-ino",
        str(expected_runner.inode),
        "--expected-runner-uid",
        str(expected_runner.uid),
        "--expected-runner-gid",
        str(expected_runner.gid),
        "--expected-runner-mode",
        str(expected_runner.mode),
        "--expected-runner-size",
        str(expected_runner.size),
        "--expected-runner-sha256",
        expected_runner.sha256,
    )
    if payload.get("refresh_schema_version") != PROMPT_REFRESH_SCHEMA_VERSION:
        raise RunSafetyError(
            "refresh-prompts-live returned an unsupported refresh schema"
        )
    expected_paths = {
        "runner_path": RUNNER_PATH,
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
    runner_version = _stop_artifact_version_from_payload(payload, "runner_version")
    child_version = _stop_artifact_version_from_payload(
        payload,
        "child_prompt_version",
    )
    parent_version = _stop_artifact_version_from_payload(
        payload,
        "parent_prompt_version",
    )
    actual_runner = _read_stop_absolute_regular_artifact(
        RUNNER_PATH,
        max_bytes=STATE_MAX_BYTES,
    ).version
    _validate_expected_stop_artifact(
        "waited_delivery_runner.py",
        runner_version,
        expected_runner,
    )
    _validate_expected_stop_artifact(
        "waited_delivery_runner.py",
        actual_runner,
        runner_version,
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
    }
    index["sessions"][session_id] = record
    index["latest_session_id"] = session_id
    return record


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
        index_path, index = _load_index(repo_root)
        prompt = payload.get("prompt")
        transcript_value = payload.get("transcript_path")
        permission_value = payload.get("permission_mode")
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
        _save_index(index_path, index)
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


def _handle_pinned_stop_run(
    *,
    payload: dict[str, object],
    repo_root: pathlib.Path,
    index_path: pathlib.Path,
    index: AdapterIndex,
    record: SessionRecord,
    run_dir: pathlib.Path,
    state: dict[str, object],
    run_identity: RunDirectoryIdentity,
    run_fd: int,
) -> int:
    if _run_is_terminal(state):
        record["run_dir"] = None
        record["status"] = "completed"
        record["updated_at"] = _utc_now()
        _save_index(index_path, index)
        return _success_hook_response()
    if payload.get("stop_hook_active"):
        return _success_hook_response()
    record["updated_at"] = _utc_now()
    _save_index(index_path, index)
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
    try:
        payload = json.load(sys.stdin)
        cwd = payload.get("cwd")
        session_id = payload.get("session_id")
        if not isinstance(cwd, str) or not isinstance(session_id, str):
            return _success_hook_response()
        repo_root = _resolve_repo_root(cwd, strict=False)
        if repo_root is None:
            return _success_hook_response()
        index_path, index = _load_index(repo_root)
        record = index["sessions"].get(session_id)
        if record is None or not record["run_dir"]:
            return _success_hook_response()
        try:
            run_dir, state, run_identity, run_fd = _load_stop_run_state(
                repo_root,
                record["run_dir"],
            )
        except RunSafetyError as error:
            return _block_unsafe_stop(error, payload)
        try:
            return _handle_pinned_stop_run(
                payload=payload,
                repo_root=repo_root,
                index_path=index_path,
                index=index,
                record=record,
                run_dir=run_dir,
                state=state,
                run_identity=run_identity,
                run_fd=run_fd,
            )
        finally:
            os.close(run_fd)
    except Exception as error:
        setattr(error, "hook_command", "stop-hook")
        setattr(error, "hook_payload", payload)
        return _fail_open_hook_response(error)


def _prepare_active_run(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    index_path, index = _load_index(repo_root)
    record = _resolve_session_record(
        index,
        repo_root=repo_root,
        session_id=args.session_id,
        transcript_path=args.transcript_path,
        prompt_text=args.prompt_text,
        host_session_id=_current_thread_session_id(),
    )
    if record["run_dir"]:
        state = _load_run_state(record["run_dir"])
        if state is not None and not _run_is_terminal(state):
            raise UserError(
                f"session {record['session_id']} already has an active waited-delivery run: {record['run_dir']}"
            )
    bridge_args = [
        "prepare-live",
        "--repo",
        str(repo_root),
        "--goal",
        args.goal,
        "--parent-session-id",
        record["session_id"],
    ]
    if record["transcript_path"]:
        bridge_args.extend(["--parent-transcript-path", record["transcript_path"]])
    if record["permission_mode"]:
        bridge_args.extend(["--permission-mode", record["permission_mode"]])
    if args.run_id:
        bridge_args.extend(["--run-id", args.run_id])
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
    payload = _run_bridge_json(*bridge_args)
    run_dir = payload.get("run_dir")
    if not isinstance(run_dir, str) or not run_dir:
        raise UserError("prepare-live did not return run_dir")
    record["run_dir"] = run_dir
    record["status"] = "active"
    record["updated_at"] = _utc_now()
    index["latest_session_id"] = record["session_id"]
    _save_index(index_path, index)
    print(json.dumps(payload))
    return 0


def _attach_child_active_run(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    index_path, index = _load_index(repo_root)
    record = _resolve_session_record(
        index,
        repo_root=repo_root,
        session_id=args.session_id,
        run_dir=args.run_dir,
    )
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
        _save_index(index_path, index)
    return exit_code


def _finish_child_active_run(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    index_path, index = _load_index(repo_root)
    record = _resolve_session_record(
        index,
        repo_root=repo_root,
        session_id=args.session_id,
        run_dir=args.run_dir,
    )
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
        _save_index(index_path, index)
    return exit_code


def _reconcile_active_run(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    index_path, index = _load_index(repo_root)
    record = _resolve_session_record(
        index,
        repo_root=repo_root,
        session_id=args.session_id,
        run_dir=args.run_dir,
    )
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
    state = _load_run_state(args.run_dir)
    if state is not None and _run_is_terminal(state):
        record["run_dir"] = None
        record["status"] = "completed"
    else:
        record["run_dir"] = args.run_dir
        record["status"] = "active"
    record["updated_at"] = _utc_now()
    index["latest_session_id"] = record["session_id"]
    _save_index(index_path, index)
    print(json.dumps(payload))
    return 0


def _show_index(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo, strict=True)
    assert repo_root is not None
    _, index = _load_index(repo_root)
    print(json.dumps(index, indent=2, sort_keys=True))
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
