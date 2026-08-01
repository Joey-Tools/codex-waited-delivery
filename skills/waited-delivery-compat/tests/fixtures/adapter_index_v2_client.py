#!/usr/bin/env python3

"""Frozen schema-v2 adapter-index reader/writer compatibility fixture."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import uuid


INDEX_SCHEMA_VERSION = 2
PREPARATION_STATUSES = {"preparing", "recovery_required"}


def _template() -> dict[str, object]:
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "latest_session_id": None,
        "updated_at": None,
        "sessions": {},
    }


def _decode(path: pathlib.Path) -> dict[str, object]:
    if not path.exists():
        return _template()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("invalid adapter index")
    schema_version = payload.get("schema_version", 1)
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in {1, INDEX_SCHEMA_VERSION}
    ):
        raise RuntimeError("unsupported adapter index schema")
    payload["schema_version"] = INDEX_SCHEMA_VERSION
    sessions = payload.setdefault("sessions", {})
    if not isinstance(sessions, dict):
        raise RuntimeError("invalid adapter sessions")
    return payload


def _save(path: pathlib.Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    content = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            encoded = content.encode("utf-8")
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise RuntimeError("schema-v2 index write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _observe(args: argparse.Namespace) -> None:
    payload = _decode(args.index)
    sessions = payload["sessions"]
    assert isinstance(sessions, dict)
    existing = sessions.get(args.session_id)
    if existing is not None and not isinstance(existing, dict):
        raise RuntimeError("invalid adapter session record")
    run_dir = existing.get("run_dir") if existing else None
    if existing and existing.get("status") in PREPARATION_STATUSES:
        status = existing["status"]
    else:
        status = "active" if run_dir else "observed"
    sessions[args.session_id] = {
        "session_id": args.session_id,
        "cwd": args.cwd,
        "transcript_path": None,
        "permission_mode": None,
        "last_prompt": args.prompt,
        "run_dir": run_dir,
        "status": status,
        "updated_at": args.started_at,
        "preparation_id": existing.get("preparation_id") if existing else None,
        "preparation_run_id": (
            existing.get("preparation_run_id") if existing else None
        ),
        "preparation_lease_path": (
            existing.get("preparation_lease_path") if existing else None
        ),
        "preparation_started_at": (
            existing.get("preparation_started_at") if existing else None
        ),
        "preparation_reason": (
            existing.get("preparation_reason") if existing else None
        ),
    }
    payload["latest_session_id"] = args.session_id
    payload["updated_at"] = args.started_at
    _save(args.index, payload)


def _seed_preparing(args: argparse.Namespace) -> None:
    payload = _decode(args.index)
    sessions = payload["sessions"]
    assert isinstance(sessions, dict)
    sessions[args.session_id] = {
        "session_id": args.session_id,
        "cwd": args.cwd,
        "transcript_path": None,
        "permission_mode": None,
        "last_prompt": None,
        "run_dir": args.run_dir,
        "status": "preparing",
        "updated_at": args.started_at,
        "preparation_id": args.preparation_id,
        "preparation_run_id": args.run_id,
        "preparation_lease_path": args.lease_path,
        "preparation_started_at": args.started_at,
        "preparation_reason": None,
    }
    payload["latest_session_id"] = args.session_id
    payload["updated_at"] = args.started_at
    _save(args.index, payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("observe", "seed-preparing"))
    parser.add_argument("--index", type=pathlib.Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--prompt")
    parser.add_argument("--run-dir")
    parser.add_argument("--run-id")
    parser.add_argument("--preparation-id")
    parser.add_argument("--lease-path")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.action == "observe":
            _observe(args)
        else:
            for field in ("run_dir", "run_id", "preparation_id", "lease_path"):
                if not getattr(args, field):
                    raise RuntimeError(
                        f"seed-preparing requires --{field.replace('_', '-')}"
                    )
            _seed_preparing(args)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
