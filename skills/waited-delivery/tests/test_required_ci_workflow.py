from __future__ import annotations

import ast
import base64
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import io
import importlib.util
import inspect
from pathlib import Path
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import time
import unittest
import uuid
from collections.abc import Iterator, Mapping
from unittest import mock


TRUSTED_CANDIDATE_SUPPORT_PATH = Path(__file__).resolve(strict=True).with_name(
    "required_ci_candidate.py"
)
try:
    TRUSTED_CANDIDATE_SUPPORT_SOURCE = TRUSTED_CANDIDATE_SUPPORT_PATH.read_bytes()
except OSError as error:
    raise AssertionError("trusted candidate support cannot be read") from error
TRUSTED_CANDIDATE_SUPPORT_SHA256 = hashlib.sha256(
    TRUSTED_CANDIDATE_SUPPORT_SOURCE
).hexdigest()


def _load_trusted_candidate_support():
    spec = importlib.util.spec_from_file_location(
        "required_ci_candidate", TRUSTED_CANDIDATE_SUPPORT_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("trusted candidate support cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_CANDIDATE_SUPPORT = _load_trusted_candidate_support()


def distribution_contract_context(
    skill_root: Path,
) -> tuple[Path, Path, Path, str]:
    if skill_root.parts[-3:] == ("personal_codex", "skills", "waited-delivery"):
        checkout_root = skill_root.parents[2]
        content_relative_root = Path("personal_codex")
        return (
            checkout_root,
            checkout_root / content_relative_root,
            content_relative_root,
            "private",
        )
    if skill_root.parts[-2:] == ("skills", "waited-delivery"):
        checkout_root = skill_root.parents[1]
        return checkout_root, checkout_root, Path(), "canonical"
    raise AssertionError(f"unsupported waited-delivery skill layout: {skill_root}")


SKILL_ROOT = Path(__file__).resolve().parents[1]
(
    TRUSTED_REPO_ROOT,
    TRUSTED_CONTENT_ROOT,
    TRUSTED_CONTENT_RELATIVE_ROOT,
    DISTRIBUTION_PROFILE,
) = distribution_contract_context(SKILL_ROOT)
EXPECTED_REPOSITORY = "Joey-Tools/codex-waited-delivery"
EXPECTED_TEST_TIMEOUT_MINUTES = "37"
TRUSTED_REPOSITORY_GUARD_TIMEOUT_MINUTES = 1
TRUSTED_CANDIDATE_CHECKOUT_TIMEOUT_MINUTES = 3
TRUSTED_SOURCE_CHECKOUT_TIMEOUT_MINUTES = 3
TRUSTED_PYTHON_SETUP_TIMEOUT_MINUTES = 3
STRICT_RUNTIME_HARDENING_TIMEOUT_MINUTES = 2
TRUSTED_COMPILE_TIMEOUT_MINUTES = 2
TRUSTED_STRUCTURE_TIMEOUT_MINUTES = 3
TRUSTED_TEST_STEP_TIMEOUT_MINUTES = 15
REQUIRED_CI_CANDIDATE_ROOT_ENV = _CANDIDATE_SUPPORT.CANDIDATE_ROOT_ENV
REQUIRED_CI_CANDIDATE_SHA_ENV = _CANDIDATE_SUPPORT.CANDIDATE_SHA_ENV
REQUIRED_CI_ISOLATION_MODE_ENV = "REQUIRED_CI_ISOLATION_MODE"
REQUIRED_CI_ISOLATION_MODE = "sudo-setpriv-v1"
CANDIDATE_TESTS_RELATIVE_PATH = Path("skills/waited-delivery/tests")


def distribution_content_root(checkout_root: Path) -> Path:
    return checkout_root / TRUSTED_CONTENT_RELATIVE_ROOT


def distribution_tests_root(checkout_root: Path) -> Path:
    return distribution_content_root(checkout_root) / CANDIDATE_TESTS_RELATIVE_PATH


TRUSTED_PRE_SUPERVISOR_TIMEOUT_MINUTES = (
    TRUSTED_REPOSITORY_GUARD_TIMEOUT_MINUTES
    + TRUSTED_CANDIDATE_CHECKOUT_TIMEOUT_MINUTES
    + TRUSTED_SOURCE_CHECKOUT_TIMEOUT_MINUTES
    + TRUSTED_PYTHON_SETUP_TIMEOUT_MINUTES
    + STRICT_RUNTIME_HARDENING_TIMEOUT_MINUTES
    + TRUSTED_COMPILE_TIMEOUT_MINUTES
    + TRUSTED_STRUCTURE_TIMEOUT_MINUTES
)
TRUSTED_TEST_SUITE_TIMEOUT_SECONDS = 10 * 60
TRUSTED_TEST_CLEANUP_RESERVE_SECONDS = 2 * 60
TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS = (
    TRUSTED_TEST_SUITE_TIMEOUT_SECONDS + TRUSTED_TEST_CLEANUP_RESERVE_SECONDS
)
TRUSTED_TEST_STEP_RUNNER_MARGIN_SECONDS = 3 * 60
TRUSTED_JOB_RUNNER_MARGIN_MINUTES = 5
TRUSTED_TEST_MINIMUM_CHILD_TIMEOUT_SECONDS = 1
TRUSTED_TEST_CHILD_REAP_TIMEOUT_SECONDS = 5
TRUSTED_REPOSITORY_FILE_SIZE_LIMIT_BYTES = 2 * 1024 * 1024
TRUSTED_WORKFLOW_INVENTORY_LIMIT = 256
TRUSTED_WORKFLOW_TOTAL_SIZE_LIMIT_BYTES = 16 * 1024 * 1024
TRUSTED_TEST_CHILD_SUCCESS_EXIT = 73
TRUSTED_TEST_RECEIPT_SCHEMA_VERSION = 3
TRUSTED_TEST_RECEIPT_SENTINEL = "REQUIRED_CI_TRUSTED_TESTS_COMPLETED:"
TRUSTED_STRUCTURE_VALIDATOR_FLAG = "--validate-required-ci-structure"
TRUSTED_TEST_SUPERVISOR_FLAG = "--run-trusted-tests"
TRUSTED_TEST_CHILD_FLAG = "--run-trusted-test-suite"
CI_STRICT_RUNTIME_LIVE_FLAG = "--run-strict-runtime-live-test"
CI_STRICT_RUNTIME_LIVE_TEST_METHOD = (
    "test_strict_target_access_policy_blocks_snapshot_write_and_control_read"
)
CI_STRICT_RUNTIME_LIVE_SENTINEL = "REQUIRED_CI_STRICT_RUNTIME_LIVE_COMPLETED:"
TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV = "REQUIRED_CI_SUPERVISOR_DEADLINE"
LOCAL_SUPERVISOR_ISOLATION_ENV = (
    REQUIRED_CI_ISOLATION_MODE_ENV,
    "REQUIRED_CI_INTERNAL_ISOLATION_UID",
    "REQUIRED_CI_INTERNAL_ISOLATION_GID",
    "REQUIRED_CI_INTERNAL_ISOLATION_LOCK_FD",
    "REQUIRED_CI_INTERNAL_ISOLATION_REGISTRY",
    "REQUIRED_CI_INTERNAL_ISOLATION_REGISTRY_TOKEN",
)
CI_STRICT_RUNTIME_LIVE_FORBIDDEN_ENV = (
    REQUIRED_CI_CANDIDATE_ROOT_ENV,
    TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV,
    *LOCAL_SUPERVISOR_ISOLATION_ENV[1:],
    "REQUIRED_CI_INTERNAL_ISOLATION_WATCHDOG_TOKEN",
)


@contextlib.contextmanager
def _local_nonstrict_supervisor_environment() -> Iterator[None]:
    previous = {
        key: os.environ[key]
        for key in LOCAL_SUPERVISOR_ISOLATION_ENV
        if key in os.environ
    }
    try:
        for key in LOCAL_SUPERVISOR_ISOLATION_ENV:
            os.environ.pop(key, None)
        yield
    finally:
        for key in LOCAL_SUPERVISOR_ISOLATION_ENV:
            os.environ.pop(key, None)
        os.environ.update(previous)


def _snapshot_permission_probe_is_meaningful() -> bool:
    mode = os.environ.get(REQUIRED_CI_ISOLATION_MODE_ENV)
    if mode is not None and mode != REQUIRED_CI_ISOLATION_MODE:
        raise AssertionError(
            f"{REQUIRED_CI_ISOLATION_MODE_ENV} must be exactly "
            f"{REQUIRED_CI_ISOLATION_MODE!r}"
        )
    return mode == REQUIRED_CI_ISOLATION_MODE or os.geteuid() != 0


REPOSITORY_GUARD = (
    "      - name: Reject unexpected repository\n"
    f"        if: ${{{{ github.repository != '{EXPECTED_REPOSITORY}' }}}}\n"
    f"        timeout-minutes: {TRUSTED_REPOSITORY_GUARD_TIMEOUT_MINUTES}\n"
    "        run: exit 1"
)
CANDIDATE_CHECKOUT_INPUTS = {
    "repository": EXPECTED_REPOSITORY,
    "ref": "${{ github.sha }}",
    "path": ".candidate",
    "persist-credentials": "false",
}
TRUSTED_CHECKOUT_INPUTS = {
    "repository": "${{ job.workflow_repository }}",
    "ref": "${{ job.workflow_sha }}",
    "path": ".required-ci",
    "persist-credentials": "false",
}
TRUSTED_VALIDATOR_ENV = {
    REQUIRED_CI_CANDIDATE_ROOT_ENV: "${{ github.workspace }}/.candidate",
    REQUIRED_CI_CANDIDATE_SHA_ENV: "${{ github.sha }}",
}
TRUSTED_RUNTIME_ENV = {
    **TRUSTED_VALIDATOR_ENV,
    REQUIRED_CI_ISOLATION_MODE_ENV: REQUIRED_CI_ISOLATION_MODE,
}
CANDIDATE_COMPILE_COMMAND = (
    'python3 -I -X pycache_prefix="$RUNNER_TEMP/required-ci-pycache" '
    '-m py_compile "$GITHUB_WORKSPACE/.candidate/skills/waited-delivery/scripts/'
    'waited_delivery_bridge.py" "$GITHUB_WORKSPACE/.candidate/skills/'
    'waited-delivery/scripts/waited_delivery_hook_adapter.py" '
    '"$GITHUB_WORKSPACE/.candidate/skills/waited-delivery/scripts/'
    'waited_delivery_runner.py"'
)
TRUSTED_VALIDATOR_COMMAND = (
    'python3 -I "$GITHUB_WORKSPACE/.required-ci/skills/waited-delivery/tests/'
    f'test_required_ci_workflow.py" {TRUSTED_STRUCTURE_VALIDATOR_FLAG}'
)
TRUSTED_TEST_SUPERVISOR_LAUNCHER_SOURCE = (
    "import os,sys,time; environment=os.environ.copy(); "
    f'environment["{TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV}"]='
    f'f"{{time.monotonic()+{TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS}:.9f}}"; '
    "os.execve(sys.executable,[sys.executable,\"-I\",\"-B\",\"-S\","
    'environment["GITHUB_WORKSPACE"]+"/.required-ci/skills/waited-delivery/'
    f'tests/test_required_ci_workflow.py","{TRUSTED_TEST_SUPERVISOR_FLAG}"],'
    "environment)"
)
TRUSTED_TEST_SUPERVISOR_COMMAND = (
    "python3 -I -B -S -c '"
    f"{TRUSTED_TEST_SUPERVISOR_LAUNCHER_SOURCE}"
    "'"
)
README_COMPILE_COMMAND = (
    "python3 -I -B -c 'import sys; from pathlib import Path; "
    'paths=sorted(Path("skills/waited-delivery/scripts").glob("*.py")); '
    'sys.exit("no candidate Python helpers found") if not paths else None; '
    '[compile(path.read_bytes(), str(path), "exec") for path in paths]'
    "'"
)
README_DISCOVERY_COMMAND = (
    "python3 -I -m unittest discover -s skills/waited-delivery/tests"
)
STRICT_RUNTIME_HARDENING_COMMAND = (
    'if [[ ! "$pythonLocation" =~ '
    "^/opt/hostedtoolcache/Python/"
    "[0-9]+\\.[0-9]+\\.[0-9]+/x64$ ]]; then\n"
    '  echo "unexpected configured Python location: '
    '$pythonLocation" >&2\n'
    "  exit 1\n"
    "fi\n"
    'python_version_dir="${pythonLocation%/*}"\n'
    'python_family_dir="${python_version_dir%/*}"\n'
    "for path in \\\n"
    "  /usr/share/zoneinfo \\\n"
    '  "$pythonLocation" \\\n'
    "  /usr/share \\\n"
    "  /opt \\\n"
    "  /opt/hostedtoolcache \\\n"
    '  "$python_family_dir" \\\n'
    '  "$python_version_dir"\n'
    "do\n"
    '  if [[ ! -d "$path" || -L "$path" ]]; then\n'
    '    echo "unsafe strict runtime path: $path" >&2\n'
    "    exit 1\n"
    "  fi\n"
    "done\n"
    "acl_tool=/usr/bin/setfacl\n"
    'if [[ ! -f "$acl_tool" || -L "$acl_tool" || ! -x "$acl_tool" ]]; then\n'
    '  echo "trusted setfacl is unavailable" >&2\n'
    "  exit 1\n"
    "fi\n"
    "unset POSIXLY_CORRECT\n"
    'sudo "$acl_tool" --recursive --physical --remove-all --remove-default -- '
    '/usr/share/zoneinfo "$pythonLocation"\n'
    'sudo "$acl_tool" --remove-all --remove-default -- \\\n'
    "  /usr/share \\\n"
    "  /opt \\\n"
    "  /opt/hostedtoolcache \\\n"
    '  "$python_family_dir" \\\n'
    '  "$python_version_dir"\n'
    'sudo chmod -R a-w -- /usr/share/zoneinfo "$pythonLocation"\n'
    "sudo chmod a-w -- \\\n"
    "  /usr/share \\\n"
    "  /opt \\\n"
    "  /opt/hostedtoolcache \\\n"
    '  "$python_family_dir" \\\n'
    '  "$python_version_dir"'
)
CI_STRICT_RUNTIME_HARDENING_STEP = (
    "      - name: Harden strict live runtime roots\n"
    f"        timeout-minutes: {STRICT_RUNTIME_HARDENING_TIMEOUT_MINUTES}\n"
    "        run: |\n"
    + "".join(
        f"          {line}\n"
        for line in STRICT_RUNTIME_HARDENING_COMMAND.splitlines()
    )
)
CI_STRICT_RUNTIME_LIVE_JOB = (
    "  strict-live:\n"
    "    runs-on: ubuntu-24.04\n"
    "    timeout-minutes: 25\n"
    "    steps:\n"
    "      - name: Check out strict live candidate\n"
    "        uses: actions/checkout@v4\n"
    "        timeout-minutes: 3\n"
    "        with:\n"
    "          persist-credentials: false\n"
    "      - name: Set up configured Python for strict live evidence\n"
    "        uses: actions/setup-python@v5\n"
    "        timeout-minutes: 3\n"
    "        with:\n"
    '          python-version: "3.x"\n'
    f"{CI_STRICT_RUNTIME_HARDENING_STEP}"
    "      - name: Run strict target credential live test\n"
    "        timeout-minutes: 15\n"
    "        env:\n"
    "          REQUIRED_CI_CANDIDATE_SHA: ${{ github.sha }}\n"
    "          REQUIRED_CI_ISOLATION_MODE: sudo-setpriv-v1\n"
    "        run: |\n"
    "          python3 -I -B -S skills/waited-delivery/tests/"
    "test_required_ci_workflow.py --run-strict-runtime-live-test\n"
)
CANDIDATE_CHECKOUT_STEP = (
    "      - name: Check out candidate\n"
    "        uses: actions/checkout@v4\n"
    f"        timeout-minutes: {TRUSTED_CANDIDATE_CHECKOUT_TIMEOUT_MINUTES}\n"
    "        with:\n"
    f"          repository: {EXPECTED_REPOSITORY}\n"
    "          ref: ${{ github.sha }}\n"
    "          path: .candidate\n"
    "          persist-credentials: false\n"
)
TRUSTED_CHECKOUT_STEP = (
    "      - name: Check out trusted Required CI source\n"
    "        uses: actions/checkout@v4\n"
    f"        timeout-minutes: {TRUSTED_SOURCE_CHECKOUT_TIMEOUT_MINUTES}\n"
    "        with:\n"
    "          # GitHub.com job workflow identity pins this reusable leaf's own source.\n"
    "          repository: ${{ job.workflow_repository }}\n"
    "          ref: ${{ job.workflow_sha }}\n"
    "          path: .required-ci\n"
    "          persist-credentials: false\n"
)
PYTHON_SETUP_STEP = (
    "      - uses: actions/setup-python@v5\n"
    f"        timeout-minutes: {TRUSTED_PYTHON_SETUP_TIMEOUT_MINUTES}\n"
    "        with:\n"
    '          python-version: "3.x"\n'
)
TRUSTED_TEST_SUPERVISOR_STEP = (
    "      - name: Run trusted Required CI tests\n"
    f"        timeout-minutes: {TRUSTED_TEST_STEP_TIMEOUT_MINUTES}\n"
    "        working-directory: ${{ github.workspace }}/.candidate\n"
    "        env:\n"
    "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
    "          REQUIRED_CI_CANDIDATE_SHA: ${{ github.sha }}\n"
    "          REQUIRED_CI_ISOLATION_MODE: sudo-setpriv-v1\n"
    "        run: |\n"
    f"          {TRUSTED_TEST_SUPERVISOR_COMMAND}\n"
)
REQUIRED_EXECUTION_STEPS = (
    f"{CI_STRICT_RUNTIME_HARDENING_STEP}"
    "      - name: Compile candidate Python helpers\n"
    f"        timeout-minutes: {TRUSTED_COMPILE_TIMEOUT_MINUTES}\n"
    "        run: |\n"
    f"          {CANDIDATE_COMPILE_COMMAND}\n"
    "      - name: Validate Required CI structure\n"
    f"        timeout-minutes: {TRUSTED_STRUCTURE_TIMEOUT_MINUTES}\n"
    "        env:\n"
    "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
    "          REQUIRED_CI_CANDIDATE_SHA: ${{ github.sha }}\n"
    "        run: |\n"
    f"          {TRUSTED_VALIDATOR_COMMAND}\n"
    f"{TRUSTED_TEST_SUPERVISOR_STEP}"
)


def _trusted_required_ci_cli_mode() -> str | None:
    if sys.argv[1:] == [TRUSTED_STRUCTURE_VALIDATOR_FLAG]:
        return "structure"
    if sys.argv[1:] == [TRUSTED_TEST_SUPERVISOR_FLAG]:
        return "supervisor"
    if len(sys.argv) == 3 and sys.argv[1] == TRUSTED_TEST_CHILD_FLAG:
        return "child"
    return None


def required_ci_repository_root(trusted_repo_root: Path) -> Path:
    cli_mode = _trusted_required_ci_cli_mode()
    candidate_root_value = os.environ.get(REQUIRED_CI_CANDIDATE_ROOT_ENV)
    candidate_sha_value = os.environ.get(REQUIRED_CI_CANDIDATE_SHA_ENV)
    if cli_mode is not None and (
        candidate_root_value is None or candidate_sha_value is None
    ):
        raise AssertionError(
            "trusted Required CI entry requires candidate root and SHA together"
        )
    if cli_mode is not None:
        github_sha_value = os.environ.get("GITHUB_SHA")
        if github_sha_value is None:
            raise AssertionError(
                "trusted Required CI entry requires the GitHub candidate SHA binding"
            )
        candidate_sha = _CANDIDATE_SUPPORT._parse_candidate_sha(
            candidate_sha_value, REQUIRED_CI_CANDIDATE_SHA_ENV
        )
        github_sha = _CANDIDATE_SUPPORT._parse_candidate_sha(
            github_sha_value, "GITHUB_SHA"
        )
        if candidate_sha != github_sha:
            raise AssertionError("candidate SHA must equal GITHUB_SHA")
    if candidate_root_value is None:
        if trusted_repo_root.name == ".required-ci":
            raise AssertionError(
                f"{REQUIRED_CI_CANDIDATE_ROOT_ENV} is required in the trusted "
                "checkout"
            )
        return trusted_repo_root
    candidate_root = Path(candidate_root_value)
    if not candidate_root.is_absolute() or candidate_root.name != ".candidate":
        raise AssertionError(
            f"{REQUIRED_CI_CANDIDATE_ROOT_ENV} must be an absolute .candidate path"
        )
    try:
        canonical_trusted_root = trusted_repo_root.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            "trusted Required CI checkout must be an existing directory"
        ) from error
    if (
        not trusted_repo_root.is_absolute()
        or trusted_repo_root.is_symlink()
        or canonical_trusted_root != trusted_repo_root
        or not canonical_trusted_root.is_dir()
    ):
        raise AssertionError(
            "trusted Required CI checkout must be an absolute canonical directory"
        )
    github_workspace_value = os.environ.get("GITHUB_WORKSPACE")
    if cli_mode is not None and github_workspace_value is None:
        raise AssertionError(
            "trusted Required CI entry requires the GitHub workspace binding"
        )
    if github_workspace_value is None:
        mandated_candidate_root = canonical_trusted_root.parent / ".candidate"
    else:
        github_workspace = Path(github_workspace_value)
        if not github_workspace.is_absolute() or github_workspace.is_symlink():
            raise AssertionError(
                "GITHUB_WORKSPACE must be an absolute canonical directory"
            )
        try:
            canonical_workspace = github_workspace.resolve(strict=True)
        except OSError as error:
            raise AssertionError("GITHUB_WORKSPACE is unreadable") from error
        mandated_trusted_root = canonical_workspace / ".required-ci"
        mandated_candidate_root = canonical_workspace / ".candidate"
        if (
            canonical_workspace != github_workspace
            or not canonical_workspace.is_dir()
            or canonical_trusted_root != mandated_trusted_root
        ):
            raise AssertionError(
                "trusted checkout must be the mandated .required-ci directory "
                "in the GitHub workspace"
            )
    if candidate_root != mandated_candidate_root:
        raise AssertionError(
            f"{REQUIRED_CI_CANDIDATE_ROOT_ENV} must select the mandated "
            "candidate checkout beside the trusted checkout"
        )
    if candidate_root.is_symlink():
        raise AssertionError(
            f"{REQUIRED_CI_CANDIDATE_ROOT_ENV} must not select a symlink"
        )
    try:
        resolved = candidate_root.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            f"{REQUIRED_CI_CANDIDATE_ROOT_ENV} must select an existing directory"
        ) from error
    if resolved != mandated_candidate_root or not resolved.is_dir():
        raise AssertionError(
            f"{REQUIRED_CI_CANDIDATE_ROOT_ENV} must select the canonical "
            "mandated candidate checkout"
        )
    return resolved


def _trusted_test_child_invocation() -> bool:
    return _trusted_required_ci_cli_mode() == "child"


REPO_ROOT = (
    TRUSTED_REPO_ROOT
    if _trusted_test_child_invocation()
    else required_ci_repository_root(TRUSTED_REPO_ROOT)
)


def _direct_test_inventory(repo_root: Path, description: str) -> list[dict[str, object]]:
    if not repo_root.is_absolute() or repo_root.is_symlink():
        raise AssertionError(f"{description} repository root must be absolute and real")
    try:
        resolved_repo_root = repo_root.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            f"{description} repository root must be an existing directory"
        ) from error
    if not resolved_repo_root.is_dir():
        raise AssertionError(f"{description} repository root must be a directory")
    if resolved_repo_root != repo_root:
        raise AssertionError(f"{description} repository root must not use symlinks")

    tests_root = distribution_tests_root(resolved_repo_root)
    if tests_root.is_symlink():
        raise AssertionError(f"{description} test root must not be a symlink")
    try:
        resolved_tests_root = tests_root.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            f"{description} expected test inventory root is missing"
        ) from error
    if not resolved_tests_root.is_dir():
        raise AssertionError(
            f"{description} expected test inventory root must be a directory"
        )
    if resolved_tests_root != tests_root:
        raise AssertionError(f"{description} test root escapes the repository")

    try:
        entries = sorted(resolved_tests_root.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise AssertionError(
            f"{description} expected test inventory cannot be enumerated"
        ) from error
    modules = [
        entry
        for entry in entries
        if entry.name.startswith("test_") and entry.suffix == ".py"
    ]
    if not modules:
        raise AssertionError(f"{description} expected test inventory must not be empty")

    inventory: list[dict[str, object]] = []
    for module_path in modules:
        if module_path.is_symlink() or not module_path.is_file():
            raise AssertionError(
                f"{description} test module {module_path.name!r} must be an ordinary file"
            )
        inventory.append(
            {
                "module": module_path.name,
                "test_ids": _static_test_ids(module_path, description),
            }
        )
    return inventory


def _static_test_ids(module_path: Path, description: str) -> list[str]:
    try:
        source = module_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise AssertionError(
            f"{description} test module {module_path.name!r} cannot be read as UTF-8"
        ) from error
    try:
        tree = ast.parse(source, filename=str(module_path))
    except SyntaxError as error:
        raise AssertionError(
            f"{description} test module {module_path.name!r} is not valid Python"
        ) from error

    test_ids: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "load_tests":
                raise AssertionError(
                    f"{description} test module {module_path.name!r} uses an "
                    "unsupported load_tests hook"
                )
            if node.name.startswith("test_"):
                raise AssertionError(
                    f"{description} test module {module_path.name!r} uses an "
                    "unsupported module-level test"
                )
        if not isinstance(node, ast.ClassDef):
            continue
        test_methods = [
            child
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test_")
        ]
        if not test_methods:
            continue
        direct_test_case = (
            len(node.bases) == 1
            and isinstance(node.bases[0], ast.Attribute)
            and isinstance(node.bases[0].value, ast.Name)
            and node.bases[0].value.id == "unittest"
            and node.bases[0].attr == "TestCase"
            and not node.keywords
        )
        if not direct_test_case:
            raise AssertionError(
                f"{description} test class {node.name!r} in {module_path.name!r} "
                "must directly extend unittest.TestCase"
            )
        if node.decorator_list:
            raise AssertionError(
                f"{description} test class {node.name!r} in {module_path.name!r} "
                "must not use decorators"
            )
        for method in test_methods:
            if isinstance(method, ast.AsyncFunctionDef):
                raise AssertionError(
                    f"{description} test {node.name}.{method.name} must be synchronous"
                )
            if method.decorator_list:
                raise AssertionError(
                    f"{description} test {node.name}.{method.name} must not use "
                    "decorators"
                )
            test_ids.append(f"{node.name}.{method.name}")

    if not test_ids:
        raise AssertionError(
            f"{description} test module {module_path.name!r} has no static tests"
        )
    if len(test_ids) != len(set(test_ids)):
        raise AssertionError(
            f"{description} test module {module_path.name!r} has duplicate test IDs"
        )
    return sorted(test_ids)


def _inventory_lookup(inventory: list[dict[str, object]]) -> dict[str, list[str]]:
    lookup: dict[str, list[str]] = {}
    for entry in inventory:
        module = entry.get("module")
        test_ids = entry.get("test_ids")
        if type(module) is not str or type(test_ids) is not list:
            raise AssertionError("test inventory entry has an invalid shape")
        if module in lookup or any(type(test_id) is not str for test_id in test_ids):
            raise AssertionError("test inventory entry is duplicated or malformed")
        lookup[module] = test_ids
    return lookup


def _require_expected_test_inventory(
    expected_inventory: list[dict[str, object]],
    candidate_inventory: list[dict[str, object]],
) -> None:
    expected = _inventory_lookup(expected_inventory)
    candidate = _inventory_lookup(candidate_inventory)
    missing: list[str] = []
    for module, expected_test_ids in expected.items():
        candidate_test_ids = candidate.get(module)
        if candidate_test_ids is None:
            missing.append(module)
            continue
        missing.extend(
            f"{module}::{test_id}"
            for test_id in expected_test_ids
            if test_id not in candidate_test_ids
        )
    if missing:
        raise AssertionError(
            "candidate expected test inventory is incomplete: " + ", ".join(missing)
        )


def _inventory_test_ids(inventory: list[dict[str, object]]) -> list[str]:
    test_ids: list[str] = []
    for module_filename, module_test_ids in _inventory_lookup(inventory).items():
        module_name = Path(module_filename).stem
        test_ids.extend(f"{module_name}.{test_id}" for test_id in module_test_ids)
    if not test_ids or len(test_ids) != len(set(test_ids)):
        raise AssertionError("trusted expected test inventory is empty or duplicated")
    return sorted(test_ids)


def _suite_test_ids(suite: unittest.TestSuite) -> list[str]:
    test_ids: list[str] = []
    pending: list[unittest.TestSuite | unittest.TestCase] = [suite]
    while pending:
        item = pending.pop()
        if isinstance(item, unittest.TestSuite):
            pending.extend(reversed(list(item)))
            continue
        test_id = item.id()
        if type(test_id) is not str:
            raise AssertionError("loaded trusted test ID is malformed")
        test_ids.append(test_id)
    if len(test_ids) != len(set(test_ids)):
        raise AssertionError("loaded trusted test inventory contains duplicates")
    return sorted(test_ids)


def _assert_candidate_absent_from_sys_path(candidate_root: Path) -> None:
    resolved_candidate_root = candidate_root.resolve(strict=True)
    for entry in sys.path:
        if type(entry) is not str:
            raise AssertionError("trusted test sys.path contains a non-string entry")
        path = Path.cwd() if entry == "" else Path(entry)
        try:
            resolved_entry = path.resolve(strict=False)
        except OSError as error:
            raise AssertionError("trusted test sys.path cannot be resolved") from error
        if (
            resolved_entry == resolved_candidate_root
            or resolved_candidate_root in resolved_entry.parents
        ):
            raise AssertionError("candidate checkout must not appear on trusted sys.path")


def _trusted_test_source_manifest(repo_root: Path) -> dict[str, str]:
    resolved_repo_root = repo_root.resolve(strict=True)
    tests_root = distribution_tests_root(resolved_repo_root)
    support_path = tests_root / "required_ci_candidate.py"
    paths = sorted(tests_root.glob("test_*.py")) + [support_path]
    manifest: dict[str, str] = {}
    for path in paths:
        try:
            path.lstat()
            resolved = path.resolve(strict=True)
            source = path.read_bytes()
        except OSError as error:
            raise AssertionError("trusted test source cannot be read") from error
        if not path.is_file() or path.is_symlink() or resolved != path:
            raise AssertionError("trusted test source must be an ordinary file")
        relative = path.relative_to(resolved_repo_root).as_posix()
        manifest[relative] = hashlib.sha256(source).hexdigest()
    if len(manifest) != len(paths):
        raise AssertionError("trusted test source inventory is duplicated")
    support_relative = (
        TRUSTED_CONTENT_RELATIVE_ROOT
        / CANDIDATE_TESTS_RELATIVE_PATH
        / "required_ci_candidate.py"
    ).as_posix()
    if manifest[support_relative] != TRUSTED_CANDIDATE_SUPPORT_SHA256:
        raise AssertionError("trusted candidate support does not match loaded bytes")
    return manifest


def _trusted_test_suite_receipt(
    trusted_repo_root: Path, candidate_root: Path
) -> dict[str, object]:
    _CANDIDATE_SUPPORT.strict_isolation_platform_preflight()
    trusted_inventory = _direct_test_inventory(trusted_repo_root, "trusted")
    trusted_source_sha256 = _trusted_test_source_manifest(trusted_repo_root)
    expected_test_ids = _inventory_test_ids(trusted_inventory)
    trusted_tests_root = (
        distribution_tests_root(trusted_repo_root.resolve(strict=True))
    )
    _assert_candidate_absent_from_sys_path(candidate_root)
    candidate_sha, require_clean = _CANDIDATE_SUPPORT.expected_candidate_sha(
        candidate_root
    )
    candidate_binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
        candidate_root,
        candidate_sha,
        require_clean=require_clean,
    )

    loader = unittest.TestLoader()
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    runner_output = io.StringIO()
    with contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(
        captured_stderr
    ):
        suite = loader.discover(
            start_dir=str(trusted_tests_root),
            pattern="test_*.py",
            top_level_dir=str(trusted_tests_root),
        )
        if loader.errors:
            raise AssertionError("trusted test loader reported errors")
        _assert_candidate_absent_from_sys_path(candidate_root)
        loaded_test_ids = _suite_test_ids(suite)
        if loaded_test_ids != expected_test_ids:
            raise AssertionError(
                "loaded trusted test inventory does not match static inventory"
            )
        result = unittest.TextTestRunner(
            stream=runner_output, verbosity=0
        ).run(suite)
    _assert_candidate_absent_from_sys_path(candidate_root)

    result_counts = {
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }
    if (
        result.testsRun != len(expected_test_ids)
        or not result.wasSuccessful()
        or any(result_counts.values())
    ):
        details = _bounded_failure_text(
            runner_output.getvalue()
            + captured_stdout.getvalue()
            + captured_stderr.getvalue()
        )
        raise AssertionError(f"trusted test suite did not complete exactly: {details}")
    if _direct_test_inventory(trusted_repo_root, "trusted") != trusted_inventory:
        raise AssertionError("trusted expected test inventory changed during execution")
    if _trusted_test_source_manifest(trusted_repo_root) != trusted_source_sha256:
        raise AssertionError("trusted test source changed during execution")
    final_candidate_binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
        candidate_root,
        candidate_sha,
        require_clean=require_clean,
    )
    if final_candidate_binding != candidate_binding:
        raise AssertionError("candidate checkout binding changed during trusted tests")
    return {
        "schema_version": TRUSTED_TEST_RECEIPT_SCHEMA_VERSION,
        "status": "completed",
        **candidate_binding,
        "trusted_inventory": trusted_inventory,
        "trusted_source_sha256": trusted_source_sha256,
        "expected_test_count": len(expected_test_ids),
        "executed_test_count": result.testsRun,
        **result_counts,
    }


_bounded_failure_text = _CANDIDATE_SUPPORT._bounded_failure_text


def _validated_trusted_child_receipt(
    completed: subprocess.CompletedProcess[str],
    trusted_inventory: list[dict[str, object]],
    trusted_source_sha256: dict[str, str],
    candidate_binding: dict[str, object],
) -> dict[str, object]:
    if completed.returncode != TRUSTED_TEST_CHILD_SUCCESS_EXIT:
        details = _bounded_failure_text(completed.stderr or completed.stdout)
        raise AssertionError(
            "trusted Required CI tests did not complete under the isolated child "
            f"(exit {completed.returncode}): {details}"
        )
    if completed.stderr:
        raise AssertionError("trusted Required CI child wrote unexpected stderr")
    expected_test_count = len(_inventory_test_ids(trusted_inventory))
    expected_receipt = {
        "schema_version": TRUSTED_TEST_RECEIPT_SCHEMA_VERSION,
        "status": "completed",
        **candidate_binding,
        "trusted_inventory": trusted_inventory,
        "trusted_source_sha256": trusted_source_sha256,
        "expected_test_count": expected_test_count,
        "executed_test_count": expected_test_count,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }
    canonical_receipt = json.dumps(
        expected_receipt, sort_keys=True, separators=(",", ":")
    )
    expected_stdout = f"{TRUSTED_TEST_RECEIPT_SENTINEL}{canonical_receipt}\n"
    if completed.stdout != expected_stdout:
        raise AssertionError(
            "trusted Required CI child returned a malformed completion receipt"
        )
    try:
        receipt = json.loads(completed.stdout[len(TRUSTED_TEST_RECEIPT_SENTINEL) :])
    except (json.JSONDecodeError, TypeError) as error:
        raise AssertionError(
            "trusted Required CI child returned a malformed completion receipt"
        ) from error
    if receipt != expected_receipt:
        raise AssertionError(
            "trusted Required CI child completion receipt is not exact"
        )
    return receipt


def _close_and_verify_trusted_isolation(
    isolation_chain_registry: Mapping[str, object],
) -> None:
    cleanup_failures: list[str] = []
    try:
        _CANDIDATE_SUPPORT.close_trusted_isolation_chains(
            isolation_chain_registry
        )
    except BaseException as error:
        cleanup_failures.append(f"registry cleanup: {error}")
    try:
        _CANDIDATE_SUPPORT.assert_candidate_isolation_quiescent()
    except BaseException as error:
        cleanup_failures.append(f"candidate UID proof: {error}")
    if cleanup_failures:
        raise AssertionError(
            "trusted isolation cleanup was incomplete: "
            + "; ".join(cleanup_failures)
        )


def _validated_trusted_test_supervisor_deadline(value: float) -> float:
    if type(value) is not float or not math.isfinite(value):
        raise AssertionError("trusted test supervisor deadline is invalid")
    return value


def _trusted_test_supervisor_deadline_from_environment() -> float:
    encoded = os.environ.pop(TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV, None)
    if (
        encoded is None
        or len(encoded) > 32
        or re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{9}", encoded) is None
    ):
        raise AssertionError(
            "trusted test supervisor launcher deadline is missing or malformed"
        )
    deadline = _validated_trusted_test_supervisor_deadline(float(encoded))
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AssertionError("trusted test supervisor launcher deadline has expired")
    if remaining > TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS + 0.001:
        raise AssertionError(
            "trusted test supervisor launcher deadline exceeds the fixed budget"
        )
    return deadline


def _require_trusted_test_cleanup_reserve(
    supervisor_deadline: float, description: str
) -> None:
    remaining = supervisor_deadline - time.monotonic()
    required = (
        TRUSTED_TEST_CLEANUP_RESERVE_SECONDS
        + TRUSTED_TEST_MINIMUM_CHILD_TIMEOUT_SECONDS
    )
    if remaining < required:
        raise AssertionError(
            "trusted Required CI supervisor has insufficient budget "
            f"{description}"
        )


def _remaining_trusted_test_child_timeout(supervisor_deadline: float) -> float:
    remaining = (
        supervisor_deadline
        - time.monotonic()
        - TRUSTED_TEST_CLEANUP_RESERVE_SECONDS
    )
    timeout = min(float(TRUSTED_TEST_SUITE_TIMEOUT_SECONDS), remaining)
    if timeout < TRUSTED_TEST_MINIMUM_CHILD_TIMEOUT_SECONDS:
        raise AssertionError(
            "trusted Required CI supervisor has insufficient budget before child launch"
        )
    return timeout


def _terminate_trusted_test_child(process: subprocess.Popen[str]) -> None:
    failures: list[str] = []
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except BaseException as error:
        failures.append(
            "process-group signal: "
            + _bounded_failure_text(f"{type(error).__name__}: {error}")
        )
    try:
        process.communicate(timeout=TRUSTED_TEST_CHILD_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        failures.append(
            "direct child reap timeout: "
            + _bounded_failure_text(f"{type(error).__name__}: {error}")
        )
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except BaseException as kill_error:
            failures.append(
                "direct child signal: "
                + _bounded_failure_text(
                    f"{type(kill_error).__name__}: {kill_error}"
                )
            )
        try:
            process.communicate(timeout=TRUSTED_TEST_CHILD_REAP_TIMEOUT_SECONDS)
        except BaseException as reap_error:
            failures.append(
                "direct child final reap: "
                + _bounded_failure_text(
                    f"{type(reap_error).__name__}: {reap_error}"
                )
            )
    except BaseException as error:
        failures.append(
            "direct child reap: "
            + _bounded_failure_text(f"{type(error).__name__}: {error}")
        )
    if process.poll() is None:
        failures.append("direct child is still active")
    if failures:
        raise AssertionError(
            "trusted test child cleanup was incomplete: " + "; ".join(failures)
        )


def _run_trusted_test_child(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    pass_fds: tuple[int, ...],
    supervisor_deadline: float,
) -> subprocess.CompletedProcess[str]:
    _remaining_trusted_test_child_timeout(supervisor_deadline)
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            pass_fds=pass_fds,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except OSError as error:
        raise AssertionError("trusted Required CI child could not be started") from error
    try:
        child_timeout = _remaining_trusted_test_child_timeout(supervisor_deadline)
    except BaseException:
        _terminate_trusted_test_child(process)
        raise
    try:
        stdout, stderr = process.communicate(timeout=child_timeout)
    except subprocess.TimeoutExpired:
        _terminate_trusted_test_child(process)
        raise
    except BaseException:
        _terminate_trusted_test_child(process)
        raise
    return subprocess.CompletedProcess(
        command,
        process.returncode,
        stdout,
        stderr,
    )


def supervise_trusted_required_ci_tests(
    trusted_repo_root: Path,
    candidate_root: Path,
    *,
    supervisor_deadline: float,
) -> dict[str, object]:
    supervisor_deadline = _validated_trusted_test_supervisor_deadline(
        supervisor_deadline
    )
    _require_trusted_test_cleanup_reserve(
        supervisor_deadline, "before platform preflight"
    )
    _CANDIDATE_SUPPORT.strict_isolation_platform_preflight()
    try:
        canonical_trusted_root = trusted_repo_root.resolve(strict=True)
        canonical_candidate_root = candidate_root.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            "trusted supervisor split roots are unreadable"
        ) from error
    if (
        trusted_repo_root.is_symlink()
        or candidate_root.is_symlink()
        or canonical_trusted_root != trusted_repo_root
        or canonical_candidate_root != candidate_root
        or canonical_trusted_root.name != ".required-ci"
        or canonical_candidate_root.name != ".candidate"
        or canonical_trusted_root.parent != canonical_candidate_root.parent
    ):
        raise AssertionError(
            "trusted supervisor requires canonical sibling split roots"
        )
    split_workspace_root = canonical_trusted_root.parent
    _assert_candidate_absent_from_sys_path(candidate_root)
    trusted_inventory = _direct_test_inventory(trusted_repo_root, "trusted")
    trusted_source_sha256 = _trusted_test_source_manifest(trusted_repo_root)
    candidate_static_inventory = _direct_test_inventory(candidate_root, "candidate")
    _require_expected_test_inventory(trusted_inventory, candidate_static_inventory)
    candidate_sha, require_clean = _CANDIDATE_SUPPORT.expected_candidate_sha(
        candidate_root
    )
    candidate_binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
        candidate_root,
        candidate_sha,
        require_clean=require_clean,
    )

    child_environment = os.environ.copy()
    child_environment.pop("PYTHONHOME", None)
    child_environment.pop("PYTHONPATH", None)
    child_environment.pop(TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV, None)
    child_environment[REQUIRED_CI_CANDIDATE_ROOT_ENV] = str(
        candidate_root.resolve(strict=True)
    )
    child_environment[REQUIRED_CI_CANDIDATE_SHA_ENV] = candidate_sha
    child_environment["GITHUB_SHA"] = candidate_sha
    child_environment["GITHUB_WORKSPACE"] = str(split_workspace_root)
    _require_trusted_test_cleanup_reserve(
        supervisor_deadline, "before isolation registry acquisition"
    )
    isolation_chain_registry = (
        _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()
    )
    try:
        registry_environment = isolation_chain_registry["environment"]
        if not isinstance(registry_environment, dict):
            raise AssertionError("trusted isolation chain registry is malformed")
        child_environment.update(registry_environment)
        child_environment.update(
            _CANDIDATE_SUPPORT.trusted_isolation_child_environment()
        )
        child_environment.pop(TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV, None)
        isolation_pass_fds = (
            _CANDIDATE_SUPPORT.trusted_isolation_child_pass_fds()
        )
        trusted_supervisor = Path(__file__).resolve(strict=True)
        try:
            trusted_supervisor_source = trusted_supervisor.read_bytes()
        except OSError as error:
            raise AssertionError(
                "trusted candidate test supervisor cannot be read"
            ) from error
        try:
            completed = _run_trusted_test_child(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-S",
                    str(trusted_supervisor),
                    TRUSTED_TEST_CHILD_FLAG,
                    str(trusted_repo_root.resolve(strict=True)),
                ],
                cwd=trusted_repo_root.resolve(strict=True),
                environment=child_environment,
                pass_fds=isolation_pass_fds,
                supervisor_deadline=supervisor_deadline,
            )
        except subprocess.TimeoutExpired as error:
            raise AssertionError(
                "trusted Required CI tests did not complete before the fixed timeout"
            ) from error
    finally:
        _close_and_verify_trusted_isolation(isolation_chain_registry)
    receipt = _validated_trusted_child_receipt(
        completed,
        trusted_inventory,
        trusted_source_sha256,
        candidate_binding,
    )

    try:
        final_supervisor_source = trusted_supervisor.read_bytes()
    except OSError as error:
        raise AssertionError(
            "trusted candidate test supervisor became unreadable"
        ) from error
    if final_supervisor_source != trusted_supervisor_source:
        raise AssertionError("trusted candidate test supervisor changed")
    if _direct_test_inventory(trusted_repo_root, "trusted") != trusted_inventory:
        raise AssertionError("trusted expected test inventory changed during execution")
    if _trusted_test_source_manifest(trusted_repo_root) != trusted_source_sha256:
        raise AssertionError("trusted test source changed during execution")
    if (
        _direct_test_inventory(candidate_root, "candidate")
        != candidate_static_inventory
    ):
        raise AssertionError("candidate static test inventory changed during execution")
    final_candidate_binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
        candidate_root,
        candidate_sha,
        require_clean=require_clean,
    )
    if final_candidate_binding != candidate_binding:
        raise AssertionError("candidate checkout binding changed during supervision")
    return receipt


def _require_strict_workflow_mode() -> None:
    if os.environ.get(REQUIRED_CI_ISOLATION_MODE_ENV) != REQUIRED_CI_ISOLATION_MODE:
        raise AssertionError(
            "trusted Required CI functional mode requires exact strict isolation"
        )


def _strict_runtime_live_candidate_binding(
) -> tuple[Path, str, dict[str, object]]:
    _require_strict_workflow_mode()
    if DISTRIBUTION_PROFILE != "canonical":
        raise AssertionError(
            "strict runtime live evidence requires the canonical repository layout"
        )
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "Linux"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise AssertionError(
            "strict runtime live evidence requires a GitHub-hosted Linux runner"
        )
    inherited = [
        name for name in CI_STRICT_RUNTIME_LIVE_FORBIDDEN_ENV if name in os.environ
    ]
    if inherited:
        raise AssertionError(
            "strict runtime live evidence requires a fresh owner environment"
        )
    if (
        _CANDIDATE_SUPPORT._STRICT_SESSION is not None
        or _CANDIDATE_SUPPORT._STRICT_REALM is not None
        or _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED is not False
    ):
        raise AssertionError(
            "strict runtime live evidence requires fresh isolation state"
        )
    workspace_value = os.environ.get("GITHUB_WORKSPACE")
    if workspace_value is None:
        raise AssertionError(
            "strict runtime live evidence requires the GitHub workspace binding"
        )
    workspace = Path(workspace_value)
    try:
        canonical_workspace = workspace.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            "strict runtime live GitHub workspace is unreadable"
        ) from error
    if (
        not workspace.is_absolute()
        or workspace.is_symlink()
        or canonical_workspace != workspace
        or canonical_workspace != REPO_ROOT
        or TRUSTED_REPO_ROOT != REPO_ROOT
    ):
        raise AssertionError(
            "strict runtime live evidence requires the canonical checkout root"
        )
    candidate_sha_value = os.environ.get(REQUIRED_CI_CANDIDATE_SHA_ENV)
    github_sha_value = os.environ.get("GITHUB_SHA")
    if candidate_sha_value is None or github_sha_value is None:
        raise AssertionError(
            "strict runtime live evidence requires the GitHub candidate SHA binding"
        )
    candidate_sha = _CANDIDATE_SUPPORT._parse_candidate_sha(
        candidate_sha_value, REQUIRED_CI_CANDIDATE_SHA_ENV
    )
    github_sha = _CANDIDATE_SUPPORT._parse_candidate_sha(
        github_sha_value, "GITHUB_SHA"
    )
    if candidate_sha != github_sha:
        raise AssertionError(
            "strict runtime live candidate SHA must equal GITHUB_SHA"
        )
    expected_sha, require_clean = _CANDIDATE_SUPPORT.expected_candidate_sha(
        REPO_ROOT
    )
    if expected_sha != candidate_sha or require_clean is not True:
        raise AssertionError(
            "strict runtime live candidate authority is not frozen"
        )
    binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
        REPO_ROOT,
        candidate_sha,
        require_clean=True,
    )
    return REPO_ROOT, candidate_sha, binding


def _strict_runtime_live_owner_realm(
    registry: Mapping[str, object],
) -> dict[str, object]:
    if (
        not isinstance(registry, dict)
        or registry.get("inherited") is not False
        or registry.get("watchdog_authorized") is not False
        or registry.get("closed") is not False
        or not isinstance(registry.get("root"), Path)
        or not isinstance(registry.get("watchdog_process"), subprocess.Popen)
        or type(registry.get("watchdog_pidfd")) is not int
        or _CANDIDATE_SUPPORT._active_strict_session() is not registry
    ):
        raise AssertionError(
            "strict runtime live isolation registry is not an exact owner session"
        )
    realm = _CANDIDATE_SUPPORT._strict_realm()
    lock = realm.get("lock") if isinstance(realm, dict) else None
    try:
        lock_descriptor = lock.fileno()
    except (AttributeError, OSError, ValueError) as error:
        raise AssertionError(
            "strict runtime live owner identity lock is unavailable"
        ) from error
    if (
        type(lock_descriptor) is not int
        or lock_descriptor < 0
        or realm.get("inherited_lock_fd") is not None
        or type(realm.get("uid")) is not int
        or realm.get("uid") != realm.get("gid")
        or realm.get("uid") != registry.get("target_uid")
    ):
        raise AssertionError(
            "strict runtime live owner identity realm is malformed"
        )
    return realm


def _strict_runtime_live_main() -> int:
    runner_output = io.StringIO()
    try:
        candidate_root, candidate_sha, candidate_binding = (
            _strict_runtime_live_candidate_binding()
        )
        backend_validated = False
        realm: dict[str, object] | None = None
        result: unittest.TestResult | None = None
        registry = _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()
        try:
            realm = _strict_runtime_live_owner_realm(registry)
            suite = unittest.TestSuite(
                [
                    TrustedCandidateTestSupervisorRegressionTests(
                        CI_STRICT_RUNTIME_LIVE_TEST_METHOD
                    )
                ]
            )
            result = unittest.TextTestRunner(
                stream=runner_output,
                verbosity=2,
            ).run(suite)
            backend_validated = (
                _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED is True
            )
        finally:
            _close_and_verify_trusted_isolation(registry)
        final_binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
            candidate_root,
            candidate_sha,
            require_clean=True,
        )
        if final_binding != candidate_binding:
            raise AssertionError(
                "strict runtime live candidate binding changed during execution"
            )
        if _CANDIDATE_SUPPORT._STRICT_SESSION is not None:
            raise AssertionError(
                "strict runtime live owner registry remained active after cleanup"
            )
        if result is None or realm is None:
            raise AssertionError("strict runtime live test did not run")
        if (
            result.testsRun != 1
            or result.failures
            or result.errors
            or result.skipped
            or result.expectedFailures
            or result.unexpectedSuccesses
            or not result.wasSuccessful()
            or not backend_validated
        ):
            raise AssertionError(
                "strict runtime live test did not complete exactly once without "
                "failures or skips: "
                + _bounded_failure_text(runner_output.getvalue())
            )
        receipt = {
            "schema_version": 1,
            "status": "completed",
            "candidate_sha": candidate_sha,
            "configured_python": str(Path(sys.executable).resolve(strict=True)),
            "configured_version": list(sys.version_info[:3]),
            "target_gid": int(realm["gid"]),
            "target_uid": int(realm["uid"]),
            "test": (
                "TrustedCandidateTestSupervisorRegressionTests."
                + CI_STRICT_RUNTIME_LIVE_TEST_METHOD
            ),
            "tests_run": 1,
        }
    except BaseException as error:
        message = _bounded_failure_text(f"{type(error).__name__}: {error}")
        print(f"strict runtime live evidence failed: {message}", file=sys.stderr)
        return 1
    print(
        CI_STRICT_RUNTIME_LIVE_SENTINEL
        + json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    )
    return 0


def _trusted_test_child_main(trusted_repo_root_value: str) -> int:
    try:
        if os.environ.get(REQUIRED_CI_ISOLATION_MODE_ENV) is not None:
            _require_strict_workflow_mode()
        trusted_repo_root = Path(trusted_repo_root_value)
        if (
            not trusted_repo_root.is_absolute()
            or trusted_repo_root.name != ".required-ci"
            or trusted_repo_root.is_symlink()
        ):
            raise AssertionError("trusted test root must be an absolute .required-ci path")
        try:
            canonical_trusted_root = trusted_repo_root.resolve(strict=True)
        except OSError as error:
            raise AssertionError("trusted test root is unreadable") from error
        if canonical_trusted_root != trusted_repo_root:
            raise AssertionError("trusted test root must be canonical")
        candidate_root = required_ci_repository_root(canonical_trusted_root)
        receipt = _trusted_test_suite_receipt(
            canonical_trusted_root, candidate_root
        )
    except BaseException as error:
        message = _bounded_failure_text(f"{type(error).__name__}: {error}")
        print(f"trusted Required CI child failed: {message}", file=sys.stderr)
        return 1
    canonical_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    print(f"{TRUSTED_TEST_RECEIPT_SENTINEL}{canonical_receipt}")
    return TRUSTED_TEST_CHILD_SUCCESS_EXIT


def _trusted_test_supervisor_main() -> int:
    try:
        _require_strict_workflow_mode()
        supervisor_deadline = _trusted_test_supervisor_deadline_from_environment()
        receipt = supervise_trusted_required_ci_tests(
            TRUSTED_REPO_ROOT,
            REPO_ROOT,
            supervisor_deadline=supervisor_deadline,
        )
    except BaseException as error:
        message = _bounded_failure_text(f"{type(error).__name__}: {error}")
        print(f"trusted Required CI test supervisor failed: {message}", file=sys.stderr)
        return 1
    canonical_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    print(f"{TRUSTED_TEST_RECEIPT_SENTINEL}{canonical_receipt}")
    return 0


def top_level_job_ids(workflow: str) -> list[str]:
    _, jobs = _workflow_job_blocks(workflow)
    return [job_id for job_id, _ in jobs]


_PLAIN_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
_BLOCK_SCALAR = re.compile(r"[|>](?:[1-9][+-]?|[+-][1-9]?)?\Z")


def _strip_yaml_comment(line: str, line_number: int) -> str:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        character = line[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif quote == "'":
            if character == quote:
                if index + 1 < len(line) and line[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif character in ("'", '"'):
            quote = character
        elif character == "#" and (index == 0 or line[index - 1].isspace()):
            break
        index += 1
    if quote is not None or escaped:
        raise AssertionError(f"unclosed quoted scalar on line {line_number}")
    return line[:index].rstrip()


def _mapping_pair(fragment: str, line_number: int) -> tuple[str, str]:
    quote: str | None = None
    escaped = False
    flow_stack: list[str] = []
    unseparated_colon = False
    for index, character in enumerate(fragment):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                if index + 1 < len(fragment) and fragment[index + 1] == quote:
                    continue
                quote = None
            continue
        if character in ("'", '"'):
            quote = character
        elif character in "[{":
            flow_stack.append(character)
        elif character in "]}":
            if not flow_stack or "[{"["]}".index(character)] != flow_stack.pop():
                raise AssertionError(f"malformed flow shape on line {line_number}")
        elif character == ":" and not flow_stack:
            if index + 1 < len(fragment) and fragment[index + 1] not in " \t":
                unseparated_colon = True
                continue
            key = fragment[:index].strip()
            if not _PLAIN_KEY.fullmatch(key):
                raise AssertionError(
                    f"unsupported or malformed mapping key on line {line_number}"
                )
            return key, fragment[index + 1 :].strip()
    if flow_stack:
        raise AssertionError(f"unclosed flow shape on line {line_number}")
    if unseparated_colon:
        raise AssertionError(
            "block mapping separator must be followed by whitespace or line end "
            f"on line {line_number}"
        )
    raise AssertionError(f"expected a mapping entry on line {line_number}")


def _plain_scalar(value: str, line_number: int) -> str:
    if not value:
        raise AssertionError(f"missing scalar value on line {line_number}")
    if value[0] == "!":
        raise AssertionError(
            f"explicit YAML tags are unsupported on line {line_number}"
        )
    if value[0] == "'":
        if len(value) < 2 or value[-1] != "'":
            raise AssertionError(f"unclosed quoted scalar on line {line_number}")
        return value[1:-1].replace("''", "'")
    if value[0] == '"':
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as error:
            raise AssertionError(
                f"malformed quoted scalar on line {line_number}"
            ) from error
        if not isinstance(decoded, str):
            raise AssertionError(f"expected a string scalar on line {line_number}")
        return decoded
    if value[0] in "[{|>":
        raise AssertionError(f"unsupported scalar shape on line {line_number}")
    return value


def _validate_flow_value(value: str, line_number: int) -> None:
    if not value or value[0] not in "[{":
        return
    quote: str | None = None
    escaped = False
    stack: list[str] = []
    for index, character in enumerate(value):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    continue
                quote = None
            continue
        if character in ("'", '"'):
            quote = character
        elif character in "[{":
            stack.append(character)
        elif character in "]}":
            if not stack or "[{"["]}".index(character)] != stack.pop():
                raise AssertionError(f"malformed flow shape on line {line_number}")
            if not stack and value[index + 1 :].strip():
                raise AssertionError(f"malformed flow shape on line {line_number}")
    if quote is not None or escaped or stack:
        raise AssertionError(f"unclosed flow shape on line {line_number}")


def _structural_yaml_lines(
    workflow: str,
) -> tuple[list[str], list[tuple[int, int, str]]]:
    lines = workflow.splitlines()
    structural: list[tuple[int, int, str]] = []
    block_key_indent: int | None = None
    for index, raw_line in enumerate(lines):
        prefix_length = len(raw_line) - len(raw_line.lstrip(" \t"))
        prefix = raw_line[:prefix_length]
        if "\t" in prefix:
            raise AssertionError(f"tab indentation on line {index + 1}")
        indent = len(prefix)
        if block_key_indent is not None:
            if not raw_line.strip() or indent > block_key_indent:
                continue
            block_key_indent = None
        content = _strip_yaml_comment(raw_line[indent:], index + 1)
        if not content:
            continue
        structural.append((index, indent, content))
        mapping_fragment = content[2:].lstrip() if content.startswith("- ") else content
        try:
            _, value = _mapping_pair(mapping_fragment, index + 1)
        except AssertionError:
            continue
        _validate_flow_value(value, index + 1)
        if _BLOCK_SCALAR.fullmatch(value):
            block_key_indent = indent + (2 if content.startswith("- ") else 0)
    return lines, structural


def _mapping_blocks(
    entries: list[tuple[int, int, str]], context: str
) -> list[tuple[str, str, int, list[tuple[int, int, str]]]]:
    if not entries:
        return []
    mapping_indent = min(entry[1] for entry in entries)
    starts = [
        index for index, entry in enumerate(entries) if entry[1] == mapping_indent
    ]
    if not starts or starts[0] != 0:
        raise AssertionError(f"malformed {context} indentation")
    blocks: list[tuple[str, str, int, list[tuple[int, int, str]]]] = []
    seen: set[str] = set()
    for block_number, start in enumerate(starts):
        end = starts[block_number + 1] if block_number + 1 < len(starts) else len(entries)
        block = entries[start:end]
        line_index, _, content = block[0]
        if content.startswith("- "):
            raise AssertionError(
                f"unsupported sequence in {context} on line {line_index + 1}"
            )
        key, value = _mapping_pair(content, line_index + 1)
        if key in seen:
            raise AssertionError(
                f"duplicate {context} key {key!r} on line {line_index + 1}"
            )
        seen.add(key)
        blocks.append((key, value, line_index + 1, block))
    return blocks


def _top_level_blocks(
    workflow: str,
) -> tuple[
    list[str],
    dict[str, tuple[str, int, list[tuple[int, int, str]]]],
]:
    lines, structural = _structural_yaml_lines(workflow)
    top_starts = [
        index for index, entry in enumerate(structural) if entry[1] == 0
    ]
    if not top_starts or top_starts[0] != 0:
        raise AssertionError("workflow must start with a supported top-level mapping")
    blocks: dict[str, tuple[str, int, list[tuple[int, int, str]]]] = {}
    for block_number, start in enumerate(top_starts):
        end = (
            top_starts[block_number + 1]
            if block_number + 1 < len(top_starts)
            else len(structural)
        )
        line_index, _, content = structural[start]
        _reject_yaml_indirection(content, line_index + 1)
        key, value = _mapping_pair(content, line_index + 1)
        if key in blocks:
            raise AssertionError(
                f"duplicate top-level key {key!r} on line {line_index + 1}"
            )
        child_entries = structural[start + 1 : end]
        for child_line, _, child_content in child_entries:
            _reject_yaml_indirection(child_content, child_line + 1)
        blocks[key] = (value, line_index + 1, child_entries)
    return lines, blocks


def _workflow_job_blocks(
    workflow: str,
) -> tuple[list[str], list[tuple[str, list[tuple[int, int, str]]]]]:
    lines, top_level = _top_level_blocks(workflow)
    if "jobs" not in top_level:
        raise AssertionError("workflow must contain a jobs mapping")
    jobs_value, jobs_line, jobs_entries = top_level["jobs"]
    if jobs_value:
        raise AssertionError(f"jobs must use a block mapping on line {jobs_line}")
    job_blocks = _mapping_blocks(jobs_entries, "job")
    if not job_blocks:
        raise AssertionError("jobs mapping must not be empty")
    jobs: list[tuple[str, list[tuple[int, int, str]]]] = []
    for job_id, job_value, line_number, block in job_blocks:
        if job_value:
            raise AssertionError(
                f"job must use a block mapping on line {line_number}"
            )
        jobs.append((job_id, block))
    return lines, jobs


def _validate_permissions(
    workflow: str, jobs: list[tuple[str, list[tuple[int, int, str]]]]
) -> None:
    _, top_level = _top_level_blocks(workflow)
    if "permissions" not in top_level:
        raise AssertionError("workflow must declare top-level permissions")
    permissions_value, permissions_line, permissions_entries = top_level[
        "permissions"
    ]
    if permissions_value:
        raise AssertionError(
            f"permissions must use a block mapping on line {permissions_line}"
        )
    permission_blocks = _mapping_blocks(
        permissions_entries, "top-level permission"
    )
    if len(permission_blocks) != 1:
        raise AssertionError("top-level permissions must contain only contents: read")
    key, value, line_number, block = permission_blocks[0]
    if len(block) != 1 or key != "contents" or value != "read":
        raise AssertionError(
            f"top-level permissions must contain only contents: read on line {line_number}"
        )

    for job_id, job_entries in jobs:
        properties = _mapping_blocks(job_entries[1:], f"job {job_id!r} property")
        if any(key == "permissions" for key, _, _, _ in properties):
            raise AssertionError(
                f"job {job_id!r} must not override top-level permissions"
            )


def _validate_workflow_envelope(workflow: str) -> None:
    _, top_level = _top_level_blocks(workflow)
    if list(top_level) != ["name", "on", "permissions", "jobs"]:
        raise AssertionError(
            "workflow top-level keys must be exactly name, on, permissions, "
            "and jobs in order"
        )
    name_value, name_line, name_entries = top_level["name"]
    if name_entries or _plain_scalar(name_value, name_line) != "Required CI":
        raise AssertionError("workflow name must be exactly 'Required CI'")

    trigger_value, trigger_line, trigger_entries = top_level["on"]
    if trigger_value:
        raise AssertionError(
            f"workflow trigger must use a block mapping on line {trigger_line}"
        )
    triggers = _mapping_blocks(trigger_entries, "workflow trigger")
    if len(triggers) != 1:
        raise AssertionError("workflow must declare only the workflow_call trigger")
    key, value, _, block = triggers[0]
    if key != "workflow_call" or value or len(block) != 1:
        raise AssertionError("workflow_call must be the only empty trigger")


def _reject_yaml_indirection(content: str, line_number: int) -> None:
    unquoted = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(content):
        character = content[index]
        if quote == '"':
            unquoted.append(" ")
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif quote == "'":
            unquoted.append(" ")
            if character == quote:
                if index + 1 < len(content) and content[index + 1] == quote:
                    unquoted.append(" ")
                    index += 1
                else:
                    quote = None
        elif character in ("'", '"'):
            quote = character
            unquoted.append(" ")
        else:
            unquoted.append(character)
        index += 1
    projected = "".join(unquoted)
    has_node_indirection = False
    for index, character in enumerate(projected):
        if character not in "&*":
            continue
        prefix = projected[:index].rstrip()
        if not prefix or prefix[-1] in ":,[]{}?-":
            has_node_indirection = True
            break
    if has_node_indirection or re.search(
        r"(?:^|[-\s,{])<<\s*:", projected
    ):
        raise AssertionError(
            f"YAML anchors, aliases, and merge keys are unsupported on line {line_number}"
        )


_REQUIRED_CI_LOCAL_CALLS = frozenset(
    (
        "./.github/workflows/required-ci.yml",
        "$/.github/workflows/required-ci.yml",
    )
)
_REQUIRED_CI_REMOTE_REPOSITORY_PREFIX = f"{EXPECTED_REPOSITORY}/"
_REQUIRED_CI_REMOTE_WORKFLOW_PREFIX = ".github/workflows/required-ci.yml@"


def _is_required_ci_call_target(uses: str) -> bool:
    if uses in _REQUIRED_CI_LOCAL_CALLS:
        return True
    repository_prefix = uses[: len(_REQUIRED_CI_REMOTE_REPOSITORY_PREFIX)]
    if (
        repository_prefix.casefold()
        != _REQUIRED_CI_REMOTE_REPOSITORY_PREFIX.casefold()
    ):
        return False
    workflow_ref = uses[len(_REQUIRED_CI_REMOTE_REPOSITORY_PREFIX) :]
    return (
        workflow_ref.startswith(_REQUIRED_CI_REMOTE_WORKFLOW_PREFIX)
        and len(workflow_ref) > len(_REQUIRED_CI_REMOTE_WORKFLOW_PREFIX)
    )


def _workflow_job_uses_values(workflow: str) -> list[tuple[int, str]]:
    _, jobs = _workflow_job_blocks(workflow)
    uses_values: list[tuple[int, str]] = []
    for job_id, job_entries in jobs:
        properties = _mapping_blocks(job_entries[1:], f"job {job_id!r} property")
        for key, value, line_number, block in properties:
            if key != "uses":
                continue
            if len(block) != 1:
                raise AssertionError(
                    f"job {job_id!r} uses must be a scalar on line {line_number}"
                )
            uses_values.append((line_number, _plain_scalar(value, line_number)))
    return uses_values


def _required_ci_callers_in_workflow_sources(
    workflow_sources: Mapping[Path, bytes],
) -> list[tuple[Path, int, str]]:
    canonical_leaf = Path(".github/workflows/required-ci.yml")
    callers: list[tuple[Path, int, str]] = []
    for relative_path in sorted(workflow_sources):
        if relative_path == canonical_leaf:
            continue
        try:
            workflow = workflow_sources[relative_path].decode("utf-8")
        except UnicodeDecodeError as error:
            raise AssertionError(
                f"candidate workflow is not UTF-8: {relative_path}"
            ) from error
        for line_number, uses in _workflow_job_uses_values(workflow):
            if _is_required_ci_call_target(uses):
                callers.append((relative_path, line_number, uses))
    return callers


def required_ci_callers_in_repository(
    repo_root: Path,
) -> list[tuple[Path, int, str]]:
    workflows_root = repo_root / ".github/workflows"
    canonical_leaf = workflows_root / "required-ci.yml"
    workflow_paths = sorted(
        {
            *workflows_root.rglob("*.yml"),
            *workflows_root.rglob("*.yaml"),
        }
    )
    workflow_sources: dict[Path, bytes] = {}
    for workflow_path in workflow_paths:
        if workflow_path == canonical_leaf or not workflow_path.is_file():
            continue
        try:
            source = workflow_path.read_bytes()
        except OSError as error:
            raise AssertionError(
                f"candidate workflow is unreadable: {workflow_path}"
            ) from error
        workflow_sources[workflow_path.relative_to(repo_root)] = source
    return _required_ci_callers_in_workflow_sources(workflow_sources)


def _checkout_from_step(entries: list[tuple[int, int, str]], step_indent: int) -> bool:
    first_index, _, first_content = entries[0]
    if not first_content.startswith("- "):
        raise AssertionError(f"malformed step on line {first_index + 1}")
    fragment = first_content[2:].lstrip()
    if not fragment or fragment[0] in "[{":
        raise AssertionError(f"unsupported step shape on line {first_index + 1}")
    root_indent = step_indent + 2
    root_entries = [(first_index, fragment)]
    for line_index, indent, content in entries[1:]:
        if step_indent < indent < root_indent:
            raise AssertionError(f"malformed step indentation on line {line_index + 1}")
        if indent == root_indent:
            if content.startswith("- "):
                raise AssertionError(f"malformed step mapping on line {line_index + 1}")
            root_entries.append((line_index, content))

    values: dict[str, tuple[str, int]] = {}
    for line_index, entry in root_entries:
        key, value = _mapping_pair(entry, line_index + 1)
        if key in values:
            raise AssertionError(f"duplicate step key {key!r} on line {line_index + 1}")
        values[key] = (value, line_index + 1)
    if "uses" not in values:
        return False
    uses_value, line_number = values["uses"]
    action = _plain_scalar(uses_value, line_number)
    checkout_prefix = "actions/checkout@"
    folded_action = action.casefold()
    if not folded_action.startswith(checkout_prefix):
        if checkout_prefix in folded_action:
            raise AssertionError(
                f"ambiguous checkout action scalar on line {line_number}"
            )
        return False
    if len(action) == len(checkout_prefix):
        raise AssertionError(f"checkout action is missing a ref on line {line_number}")
    return True


def _step_properties(
    entries: list[tuple[int, int, str]], step_indent: int
) -> dict[str, tuple[str, int, list[tuple[int, int, str]]]]:
    first_index, _, first_content = entries[0]
    if not first_content.startswith("- "):
        raise AssertionError(f"malformed step on line {first_index + 1}")
    fragment = first_content[2:].lstrip()
    if not fragment or fragment[0] in "[{":
        raise AssertionError(f"unsupported step shape on line {first_index + 1}")
    root_indent = step_indent + 2
    synthetic_entries = [(first_index, root_indent, fragment), *entries[1:]]
    properties = _mapping_blocks(synthetic_entries, "step")
    return {
        key: (value, line_number, block)
        for key, value, line_number, block in properties
    }


def _validate_checkout_inputs(
    entries: list[tuple[int, int, str]],
    step_indent: int,
    expected: dict[str, str],
) -> None:
    properties = _step_properties(entries, step_indent)
    if "with" not in properties:
        raise AssertionError("checkout step must declare a with mapping")
    with_value, with_line, with_block = properties["with"]
    if with_value:
        raise AssertionError(
            f"checkout with must use a block mapping on line {with_line}"
        )
    input_blocks = _mapping_blocks(with_block[1:], "checkout input")
    actual: dict[str, str] = {}
    for key, value, line_number, block in input_blocks:
        if len(block) != 1:
            raise AssertionError(
                f"checkout input {key!r} must be a scalar on line {line_number}"
            )
        _plain_scalar(value, line_number)
        actual[key] = value
    if actual != expected or list(actual) != list(expected):
        raise AssertionError(
            "checkout inputs must be exactly the required ordered mapping"
        )


def _validate_repository_guard(
    entries: list[tuple[int, int, str]], step_indent: int
) -> None:
    properties = _step_properties(entries, step_indent)
    expected = {
        "name": "Reject unexpected repository",
        "if": f"${{{{ github.repository != '{EXPECTED_REPOSITORY}' }}}}",
        "timeout-minutes": str(TRUSTED_REPOSITORY_GUARD_TIMEOUT_MINUTES),
        "run": "exit 1",
    }
    actual: dict[str, str] = {}
    for key, (value, line_number, block) in properties.items():
        if len(block) != 1:
            raise AssertionError(
                f"repository guard {key!r} must be a scalar on line {line_number}"
            )
        _plain_scalar(value, line_number)
        actual[key] = value
    if actual != expected:
        raise AssertionError(
            "each checkout must be immediately preceded by the exact repository guard"
        )


def _step_blocks(
    steps_property: list[tuple[int, int, str]], job_id: str
) -> tuple[int, list[list[tuple[int, int, str]]]]:
    if len(steps_property) < 2:
        raise AssertionError(f"job {job_id!r} steps block must not be empty")
    entries = steps_property[1:]
    step_indent = min(entry[1] for entry in entries)
    starts = [
        index for index, entry in enumerate(entries) if entry[1] == step_indent
    ]
    if not starts or starts[0] != 0:
        raise AssertionError(f"malformed steps indentation in job {job_id!r}")
    blocks: list[list[tuple[int, int, str]]] = []
    for step_number, start in enumerate(starts):
        end = starts[step_number + 1] if step_number + 1 < len(starts) else len(entries)
        block = entries[start:end]
        if not block[0][2].startswith("- "):
            raise AssertionError(
                f"steps must use a block sequence on line {block[0][0] + 1}"
            )
        blocks.append(block)
    return step_indent, blocks


def _require_step_properties(
    entries: list[tuple[int, int, str]],
    step_indent: int,
    expected_keys: list[str],
    description: str,
) -> dict[str, tuple[str, int, list[tuple[int, int, str]]]]:
    properties = _step_properties(entries, step_indent)
    if list(properties) != expected_keys:
        raise AssertionError(
            f"{description} properties must be exactly {expected_keys!r} in order"
        )
    return properties


def _require_scalar(
    property_entry: tuple[str, int, list[tuple[int, int, str]]],
    expected: str,
    description: str,
) -> None:
    value, line_number, block = property_entry
    if len(block) != 1 or _plain_scalar(value, line_number) != expected:
        raise AssertionError(
            f"{description} must equal {expected!r} on line {line_number}"
        )


def _require_exact_timeout(
    property_entry: tuple[str, int, list[tuple[int, int, str]]],
    expected_minutes: int,
    description: str,
) -> None:
    value, line_number, block = property_entry
    if len(block) != 1 or value != str(expected_minutes):
        raise AssertionError(
            f"{description} must be the exact unquoted integer literal "
            f"{expected_minutes} on line {line_number}"
        )


def _require_exact_mapping(
    property_entry: tuple[str, int, list[tuple[int, int, str]]],
    expected: dict[str, str],
    description: str,
) -> None:
    value, line_number, block = property_entry
    if value:
        raise AssertionError(
            f"{description} must use a block mapping on line {line_number}"
        )
    entries = _mapping_blocks(block[1:], description)
    actual: dict[str, str] = {}
    for key, entry_value, entry_line, entry_block in entries:
        if len(entry_block) != 1:
            raise AssertionError(
                f"{description} key {key!r} must be a scalar on line {entry_line}"
            )
        actual[key] = _plain_scalar(entry_value, entry_line)
    if actual != expected or list(actual) != list(expected):
        raise AssertionError(f"{description} must equal the required mapping")


def _require_run_block(
    lines: list[str],
    property_entry: tuple[str, int, list[tuple[int, int, str]]],
    expected_command: str,
    description: str,
) -> None:
    value, line_number, block = property_entry
    if value != "|" or len(block) != 1:
        raise AssertionError(
            f"{description} must use a literal block scalar on line {line_number}"
        )
    header = lines[line_number - 1]
    header_indent = len(header) - len(header.lstrip(" "))
    body: list[str] = []
    for raw_line in lines[line_number:]:
        if raw_line:
            indent = len(raw_line) - len(raw_line.lstrip(" "))
            if indent <= header_indent:
                break
        body.append(raw_line)
    expected_body = [
        " " * (header_indent + 2) + line
        for line in expected_command.splitlines()
    ]
    if body != expected_body:
        raise AssertionError(
            f"{description} must contain exactly the required command"
        )


def _validate_test_job(
    lines: list[str], job_entries: list[tuple[int, int, str]]
) -> None:
    properties = _mapping_blocks(job_entries[1:], "job 'test' property")
    if [key for key, _, _, _ in properties] != [
        "runs-on",
        "timeout-minutes",
        "steps",
    ]:
        raise AssertionError(
            "test job properties must be exactly runs-on, timeout-minutes, "
            "and steps in order"
        )
    runs_key, runs_value, runs_line, runs_block = properties[0]
    if runs_key != "runs-on" or len(runs_block) != 1:
        raise AssertionError("test job runner must be a scalar")
    if _plain_scalar(runs_value, runs_line) != "ubuntu-latest":
        raise AssertionError("test job must run on ubuntu-latest")

    timeout_key, timeout_value, timeout_line, timeout_block = properties[1]
    if (
        timeout_key != "timeout-minutes"
        or len(timeout_block) != 1
        or timeout_value != EXPECTED_TEST_TIMEOUT_MINUTES
    ):
        raise AssertionError(
            "test job timeout-minutes must be the exact unquoted integer literal "
            f"{EXPECTED_TEST_TIMEOUT_MINUTES} on line {timeout_line}"
        )

    steps_key, steps_value, steps_line, steps_property = properties[2]
    if steps_key != "steps" or steps_value:
        raise AssertionError(
            f"test job steps must use a block sequence on line {steps_line}"
        )
    step_indent, steps = _step_blocks(steps_property, "test")
    if len(steps) != 8:
        raise AssertionError("test job must contain exactly the eight required steps")

    guard = _require_step_properties(
        steps[0],
        step_indent,
        ["name", "if", "timeout-minutes", "run"],
        "repository guard",
    )
    _require_scalar(guard["name"], "Reject unexpected repository", "guard name")
    _require_scalar(
        guard["if"],
        f"${{{{ github.repository != '{EXPECTED_REPOSITORY}' }}}}",
        "guard condition",
    )
    _require_exact_timeout(
        guard["timeout-minutes"],
        TRUSTED_REPOSITORY_GUARD_TIMEOUT_MINUTES,
        "repository guard timeout",
    )
    _require_scalar(guard["run"], "exit 1", "guard command")

    candidate_checkout = _require_step_properties(
        steps[1],
        step_indent,
        ["name", "uses", "timeout-minutes", "with"],
        "candidate checkout step",
    )
    _require_scalar(
        candidate_checkout["name"], "Check out candidate", "candidate checkout name"
    )
    _require_scalar(
        candidate_checkout["uses"], "actions/checkout@v4", "candidate checkout action"
    )
    _require_exact_timeout(
        candidate_checkout["timeout-minutes"],
        TRUSTED_CANDIDATE_CHECKOUT_TIMEOUT_MINUTES,
        "candidate checkout timeout",
    )
    _require_exact_mapping(
        candidate_checkout["with"],
        CANDIDATE_CHECKOUT_INPUTS,
        "candidate checkout inputs",
    )

    trusted_checkout = _require_step_properties(
        steps[2],
        step_indent,
        ["name", "uses", "timeout-minutes", "with"],
        "trusted checkout step",
    )
    _require_scalar(
        trusted_checkout["name"],
        "Check out trusted Required CI source",
        "trusted checkout name",
    )
    _require_scalar(
        trusted_checkout["uses"],
        "actions/checkout@v4",
        "trusted checkout action",
    )
    _require_exact_timeout(
        trusted_checkout["timeout-minutes"],
        TRUSTED_SOURCE_CHECKOUT_TIMEOUT_MINUTES,
        "trusted checkout timeout",
    )
    _require_exact_mapping(
        trusted_checkout["with"],
        TRUSTED_CHECKOUT_INPUTS,
        "trusted checkout inputs",
    )

    setup = _require_step_properties(
        steps[3],
        step_indent,
        ["uses", "timeout-minutes", "with"],
        "Python setup step",
    )
    _require_scalar(setup["uses"], "actions/setup-python@v5", "Python setup action")
    _require_exact_timeout(
        setup["timeout-minutes"],
        TRUSTED_PYTHON_SETUP_TIMEOUT_MINUTES,
        "Python setup timeout",
    )
    _require_exact_mapping(
        setup["with"], {"python-version": "3.x"}, "Python setup inputs"
    )

    hardening_step = _require_step_properties(
        steps[4],
        step_indent,
        ["name", "timeout-minutes", "run"],
        "strict runtime hardening step",
    )
    _require_scalar(
        hardening_step["name"],
        "Harden strict live runtime roots",
        "strict runtime hardening step name",
    )
    _require_exact_timeout(
        hardening_step["timeout-minutes"],
        STRICT_RUNTIME_HARDENING_TIMEOUT_MINUTES,
        "strict runtime hardening timeout",
    )
    _require_run_block(
        lines,
        hardening_step["run"],
        STRICT_RUNTIME_HARDENING_COMMAND,
        "strict runtime hardening command",
    )

    compile_step = _require_step_properties(
        steps[5],
        step_indent,
        ["name", "timeout-minutes", "run"],
        "compile step",
    )
    _require_scalar(
        compile_step["name"],
        "Compile candidate Python helpers",
        "compile step name",
    )
    _require_exact_timeout(
        compile_step["timeout-minutes"],
        TRUSTED_COMPILE_TIMEOUT_MINUTES,
        "compile step timeout",
    )
    _require_run_block(
        lines,
        compile_step["run"],
        CANDIDATE_COMPILE_COMMAND,
        "compile step command",
    )

    validator_step = _require_step_properties(
        steps[6],
        step_indent,
        ["name", "timeout-minutes", "env", "run"],
        "validator step",
    )
    _require_scalar(
        validator_step["name"],
        "Validate Required CI structure",
        "validator step name",
    )
    _require_exact_timeout(
        validator_step["timeout-minutes"],
        TRUSTED_STRUCTURE_TIMEOUT_MINUTES,
        "validator step timeout",
    )
    _require_exact_mapping(
        validator_step["env"], TRUSTED_VALIDATOR_ENV, "validator environment"
    )
    _require_run_block(
        lines,
        validator_step["run"],
        TRUSTED_VALIDATOR_COMMAND,
        "validator step command",
    )

    test_step = _require_step_properties(
        steps[7],
        step_indent,
        ["name", "timeout-minutes", "working-directory", "env", "run"],
        "test step",
    )
    _require_scalar(
        test_step["name"],
        "Run trusted Required CI tests",
        "test step name",
    )
    _require_exact_timeout(
        test_step["timeout-minutes"],
        TRUSTED_TEST_STEP_TIMEOUT_MINUTES,
        "test step timeout",
    )
    _require_scalar(
        test_step["working-directory"],
        "${{ github.workspace }}/.candidate",
        "test supervisor working directory",
    )
    _require_exact_mapping(
        test_step["env"], TRUSTED_RUNTIME_ENV, "test supervisor environment"
    )
    _require_run_block(
        lines,
        test_step["run"],
        TRUSTED_TEST_SUPERVISOR_COMMAND,
        "test supervisor command",
    )


def checkout_steps(workflow: str, *, validate_contract: bool = False) -> list[str]:
    lines, structural = _structural_yaml_lines(workflow)
    jobs_entries = [
        entry for entry in structural if entry[1] == 0 and entry[2] == "jobs:"
    ]
    if len(jobs_entries) != 1:
        raise AssertionError(
            "workflow must contain exactly one block-style jobs mapping"
        )
    jobs_position = structural.index(jobs_entries[0])
    jobs_block: list[tuple[int, int, str]] = []
    for entry in structural[jobs_position + 1 :]:
        if entry[1] == 0:
            break
        _reject_yaml_indirection(entry[2], entry[0] + 1)
        jobs_block.append(entry)
    if not jobs_block:
        raise AssertionError("jobs mapping must not be empty")

    job_indent = min(entry[1] for entry in jobs_block)
    job_starts = [
        index for index, entry in enumerate(jobs_block) if entry[1] == job_indent
    ]
    checkouts: list[str] = []
    for job_number, start in enumerate(job_starts):
        end = (
            job_starts[job_number + 1]
            if job_number + 1 < len(job_starts)
            else len(jobs_block)
        )
        job_entries = jobs_block[start:end]
        job_line, _, job_content = job_entries[0]
        _, job_value = _mapping_pair(job_content, job_line + 1)
        if job_value:
            raise AssertionError(f"job must use a block mapping on line {job_line + 1}")
        child_entries = job_entries[1:]
        if not child_entries:
            continue
        property_indent = min(entry[1] for entry in child_entries)
        steps_positions = []
        for index, entry in enumerate(child_entries):
            if entry[1] != property_indent:
                continue
            key, value = _mapping_pair(entry[2], entry[0] + 1)
            if key == "steps":
                steps_positions.append((index, value))
        if len(steps_positions) > 1:
            raise AssertionError(
                f"duplicate steps mapping in job on line {job_line + 1}"
            )
        if not steps_positions:
            continue
        steps_start, steps_value = steps_positions[0]
        if steps_value == "[]":
            continue
        if steps_value:
            raise AssertionError(
                f"steps must use a block sequence on line {child_entries[steps_start][0] + 1}"
            )
        steps_line_indent = child_entries[steps_start][1]
        steps_block: list[tuple[int, int, str]] = []
        for entry in child_entries[steps_start + 1 :]:
            if entry[1] <= steps_line_indent:
                break
            steps_block.append(entry)
        if not steps_block:
            raise AssertionError(
                f"steps block must not be empty on line {child_entries[steps_start][0] + 1}"
            )
        step_indent = min(entry[1] for entry in steps_block)
        step_starts = [
            index for index, entry in enumerate(steps_block) if entry[1] == step_indent
        ]
        for step_number, step_start in enumerate(step_starts):
            step_end = (
                step_starts[step_number + 1]
                if step_number + 1 < len(step_starts)
                else len(steps_block)
            )
            step_entries = steps_block[step_start:step_end]
            if not _checkout_from_step(step_entries, step_indent):
                continue
            if validate_contract:
                expected_checkouts = (
                    CANDIDATE_CHECKOUT_INPUTS,
                    TRUSTED_CHECKOUT_INPUTS,
                )
                checkout_number = len(checkouts)
                if checkout_number >= len(expected_checkouts):
                    raise AssertionError("workflow contains an unexpected checkout")
                _validate_checkout_inputs(
                    step_entries,
                    step_indent,
                    expected_checkouts[checkout_number],
                )
                if checkout_number == 0 and step_number == 0:
                    raise AssertionError(
                        "checkout step is missing its repository guard"
                    )
                if checkout_number == 0:
                    guard_start = step_starts[step_number - 1]
                    guard_end = step_start
                    _validate_repository_guard(
                        steps_block[guard_start:guard_end], step_indent
                    )
            raw_start = step_entries[0][0]
            raw_end = (
                steps_block[step_end][0]
                if step_end < len(steps_block)
                else (
                    child_entries[steps_start + 1 + len(steps_block)][0]
                    if steps_start + 1 + len(steps_block) < len(child_entries)
                    else (job_entries[-1][0] + 1)
                )
            )
            checkouts.append("\n".join(lines[raw_start:raw_end]))
    return checkouts


def validate_required_workflow(workflow: str) -> list[str]:
    lines, jobs = _workflow_job_blocks(workflow)
    if [job_id for job_id, _ in jobs] != ["test"]:
        raise AssertionError("workflow must contain exactly the test job")
    _validate_permissions(workflow, jobs)
    _validate_test_job(lines, jobs[0][1])
    _validate_workflow_envelope(workflow)
    checkouts = checkout_steps(workflow, validate_contract=True)
    if len(checkouts) != 2:
        raise AssertionError("workflow must contain exactly two checkout steps")
    return checkouts


def _read_bound_repository_file(
    repo_root: Path,
    relative_path: Path,
    description: str,
) -> bytes:
    if (
        not repo_root.is_absolute()
        or relative_path.is_absolute()
        or not relative_path.parts
        or ".." in relative_path.parts
    ):
        raise AssertionError(f"{description} path binding changed")
    try:
        initial_root_metadata = repo_root.lstat()
        canonical_root = repo_root.resolve(strict=True)
    except OSError as error:
        raise AssertionError(f"{description} repository root is unreadable") from error
    if (
        not stat.S_ISDIR(initial_root_metadata.st_mode)
        or canonical_root != repo_root
    ):
        raise AssertionError(f"{description} path binding changed")
    if canonical_root.anchor != os.path.sep:
        raise AssertionError(f"{description} path binding changed")
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
    try:
        with contextlib.ExitStack() as descriptor_stack:
            initial_root_identity = (
                initial_root_metadata.st_dev,
                initial_root_metadata.st_ino,
            )
            anchor_descriptor = os.open(canonical_root.anchor, directory_flags)
            descriptor_stack.callback(os.close, anchor_descriptor)
            anchor_metadata = os.fstat(anchor_descriptor)
            if not stat.S_ISDIR(anchor_metadata.st_mode):
                raise AssertionError(f"{description} path binding changed")

            directory_bindings: list[
                tuple[int, str, int, tuple[int, int]]
            ] = []
            parent_descriptor = anchor_descriptor
            directory_components = (
                *canonical_root.parts[1:],
                *relative_path.parts[:-1],
            )
            absolute_component_count = len(canonical_root.parts) - 1
            repository_chain_descriptor = (
                anchor_descriptor if absolute_component_count == 0 else None
            )
            for component_index, component in enumerate(directory_components):
                component_metadata = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if not stat.S_ISDIR(component_metadata.st_mode):
                    raise AssertionError(f"{description} path binding changed")
                try:
                    component_descriptor = os.open(
                        component,
                        directory_flags,
                        dir_fd=parent_descriptor,
                    )
                except FileNotFoundError as error:
                    raise AssertionError(
                        f"{description} disappeared during binding"
                    ) from error
                except OSError as error:
                    if error.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise AssertionError(
                            f"{description} path binding changed during binding"
                        ) from error
                    raise AssertionError(
                        f"{description} is unreadable during binding"
                    ) from error
                descriptor_stack.callback(os.close, component_descriptor)
                opened_component = os.fstat(component_descriptor)
                component_identity = (
                    component_metadata.st_dev,
                    component_metadata.st_ino,
                )
                if (
                    not stat.S_ISDIR(opened_component.st_mode)
                    or (opened_component.st_dev, opened_component.st_ino)
                    != component_identity
                ):
                    raise AssertionError(
                        f"{description} path binding changed during binding"
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
                if component_index == absolute_component_count - 1:
                    if component_identity != initial_root_identity:
                        raise AssertionError(
                            f"{description} path binding changed"
                        )
                    repository_chain_descriptor = component_descriptor

            if repository_chain_descriptor is None:
                raise AssertionError(f"{description} path binding changed")

            leaf_name = relative_path.parts[-1]
            path_metadata = os.stat(
                leaf_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(path_metadata.st_mode)
                or path_metadata.st_nlink != 1
                or path_metadata.st_size < 0
                or path_metadata.st_size
                > TRUSTED_REPOSITORY_FILE_SIZE_LIMIT_BYTES
            ):
                raise AssertionError(f"{description} path binding changed")
            try:
                descriptor = os.open(
                    leaf_name,
                    file_flags,
                    dir_fd=parent_descriptor,
                )
            except FileNotFoundError as error:
                raise AssertionError(
                    f"{description} disappeared during binding"
                ) from error
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise AssertionError(
                        f"{description} path binding changed during binding"
                    ) from error
                raise AssertionError(
                    f"{description} is unreadable during binding"
                ) from error
            descriptor_stack.callback(os.close, descriptor)
            opened = os.fstat(descriptor)
            opened_identity = (opened.st_dev, opened.st_ino)
            path_identity = (path_metadata.st_dev, path_metadata.st_ino)
            if (
                opened_identity != path_identity
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise AssertionError(
                    f"{description} object changed or was replaced during binding"
                )
            if opened.st_nlink != 1:
                raise AssertionError(
                    f"{description} access policy changed during binding"
                )
            if (
                opened.st_size != path_metadata.st_size
                or opened.st_size > TRUSTED_REPOSITORY_FILE_SIZE_LIMIT_BYTES
            ):
                raise AssertionError(
                    f"{description} content stability changed during binding"
                )

            def read_once() -> bytes:
                chunks: list[bytes] = []
                remaining = opened.st_size + 1
                while remaining > 0:
                    chunk = os.read(descriptor, min(remaining, 64 * 1024))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                return b"".join(chunks)

            first = read_once()
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = read_once()
            try:
                revalidated = os.fstat(descriptor)
                revalidated_path = os.stat(
                    leaf_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )

                final_anchor = os.fstat(anchor_descriptor)
                final_chain_root = os.fstat(repository_chain_descriptor)
                if (
                    not stat.S_ISDIR(final_anchor.st_mode)
                    or (final_anchor.st_dev, final_anchor.st_ino)
                    != (anchor_metadata.st_dev, anchor_metadata.st_ino)
                    or not stat.S_ISDIR(final_chain_root.st_mode)
                    or (final_chain_root.st_dev, final_chain_root.st_ino)
                    != initial_root_identity
                ):
                    raise AssertionError(
                        f"{description} path binding changed during revalidation"
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
                            f"{description} path binding changed during "
                            "revalidation"
                        )
            except FileNotFoundError as error:
                raise AssertionError(
                    f"{description} disappeared during revalidation"
                ) from error
            except OSError as error:
                raise AssertionError(
                    f"{description} is unreadable during revalidation"
                ) from error

            if (
                (revalidated.st_dev, revalidated.st_ino)
                != opened_identity
                or not stat.S_ISREG(revalidated.st_mode)
            ):
                raise AssertionError(
                    f"{description} object changed or was replaced during "
                    "revalidation"
                )
            if revalidated.st_nlink != 1:
                raise AssertionError(
                    f"{description} access policy changed during revalidation"
                )
            if (
                first != second
                or len(first) != opened.st_size
                or revalidated.st_size != opened.st_size
            ):
                raise AssertionError(
                    f"{description} content stability changed during revalidation"
                )
            if (
                (revalidated_path.st_dev, revalidated_path.st_ino)
                != opened_identity
                or not stat.S_ISREG(revalidated_path.st_mode)
            ):
                raise AssertionError(
                    f"{description} object changed or was replaced during "
                    "revalidation"
                )
            if revalidated_path.st_nlink != 1:
                raise AssertionError(
                    f"{description} access policy changed during revalidation"
                )
            if revalidated_path.st_size != opened.st_size:
                raise AssertionError(
                    f"{description} content stability changed during revalidation"
                )
    except FileNotFoundError as error:
        raise AssertionError(f"{description} is missing") from error
    except OSError as error:
        raise AssertionError(f"{description} is unreadable") from error
    return first


def _frozen_candidate_file_bytes(
    repo_root: Path,
    candidate_sha: str,
    relative_path: Path,
) -> bytes:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise AssertionError("frozen candidate path must be repository-relative")
    object_spec = f"{candidate_sha}:{relative_path.as_posix()}"
    size_output = _CANDIDATE_SUPPORT._run_candidate_git(
        repo_root,
        "cat-file",
        "-s",
        object_spec,
        output_limit=128,
    )
    try:
        size_text = size_output.decode("ascii")
        size = int(size_text[:-1] if size_text.endswith("\n") else size_text)
    except (UnicodeDecodeError, ValueError) as error:
        raise AssertionError(
            f"frozen candidate size is malformed: {relative_path}"
        ) from error
    if size < 0 or size > TRUSTED_REPOSITORY_FILE_SIZE_LIMIT_BYTES:
        raise AssertionError(
            f"frozen candidate file exceeds its size limit: {relative_path}"
        )
    source = _CANDIDATE_SUPPORT._run_candidate_git(
        repo_root,
        "cat-file",
        "blob",
        object_spec,
        output_limit=TRUSTED_REPOSITORY_FILE_SIZE_LIMIT_BYTES,
    )
    if len(source) != size:
        raise AssertionError(
            f"frozen candidate file size changed: {relative_path}"
        )
    return source


def _frozen_candidate_workflow_sources(
    repo_root: Path, candidate_sha: str
) -> dict[Path, bytes]:
    tree_output = _CANDIDATE_SUPPORT._run_candidate_git(
        repo_root,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        candidate_sha,
        "--",
        ".github/workflows",
        output_limit=TRUSTED_REPOSITORY_FILE_SIZE_LIMIT_BYTES,
    )
    workflow_paths: list[Path] = []
    for raw_entry in tree_output.split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        fields = metadata.split(b" ")
        if separator != b"\t" or len(fields) != 3:
            raise AssertionError("frozen candidate workflow tree is malformed")
        mode, object_type, object_id = fields
        try:
            relative_path = Path(raw_path.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise AssertionError(
                "frozen candidate workflow path is not UTF-8"
            ) from error
        if relative_path.suffix not in (".yml", ".yaml"):
            continue
        if (
            mode not in (b"100644", b"100755")
            or object_type != b"blob"
            or re.fullmatch(rb"[0-9a-f]{40}", object_id) is None
            or relative_path.is_absolute()
            or relative_path.parts[:2] != (".github", "workflows")
            or ".." in relative_path.parts
        ):
            raise AssertionError(
                f"frozen candidate workflow object is unsafe: {relative_path}"
            )
        workflow_paths.append(relative_path)
    if len(workflow_paths) > TRUSTED_WORKFLOW_INVENTORY_LIMIT:
        raise AssertionError("frozen candidate workflow inventory is too large")
    sources: dict[Path, bytes] = {}
    total_size = 0
    for relative_path in sorted(workflow_paths):
        source = _frozen_candidate_file_bytes(
            repo_root, candidate_sha, relative_path
        )
        total_size += len(source)
        if total_size > TRUSTED_WORKFLOW_TOTAL_SIZE_LIMIT_BYTES:
            raise AssertionError("frozen candidate workflows exceed their total limit")
        sources[relative_path] = source
    return sources


def validate_required_ci_repository(
    repo_root: Path,
    *,
    candidate_sha: str | None = None,
) -> list[str]:
    workflow_relative_path = Path(".github/workflows/required-ci.yml")
    try:
        workflow_source = _read_bound_repository_file(
            repo_root,
            workflow_relative_path,
            "candidate required-ci.yml",
        )
        workflow = workflow_source.decode("utf-8")
    except UnicodeError as error:
        raise AssertionError("candidate required-ci.yml cannot be read") from error
    support_relative_path = (
        TRUSTED_CONTENT_RELATIVE_ROOT
        / "skills/waited-delivery/tests/required_ci_candidate.py"
    )
    support_source = _read_bound_repository_file(
        repo_root,
        support_relative_path,
        "candidate trusted support",
    )
    frozen_workflows: dict[Path, bytes] | None = None
    if candidate_sha is not None:
        candidate_sha = _CANDIDATE_SUPPORT._parse_candidate_sha(
            candidate_sha, "candidate SHA"
        )
        frozen_workflows = _frozen_candidate_workflow_sources(
            repo_root, candidate_sha
        )
        frozen_workflow_source = frozen_workflows.get(workflow_relative_path)
        if frozen_workflow_source is None:
            raise AssertionError(
                "frozen candidate commit is missing required-ci.yml"
            )
        frozen_support_source = _frozen_candidate_file_bytes(
            repo_root, candidate_sha, support_relative_path
        )
        if workflow_source != frozen_workflow_source:
            raise AssertionError(
                "candidate required-ci.yml does not match the frozen commit"
            )
        if support_source != frozen_support_source:
            raise AssertionError(
                "candidate trusted support does not match the frozen commit"
            )
    if support_source != TRUSTED_CANDIDATE_SUPPORT_SOURCE:
        raise AssertionError(
            "candidate trusted support must match the Required CI source"
        )
    checkouts = validate_required_workflow(workflow)
    callers = (
        required_ci_callers_in_repository(repo_root)
        if frozen_workflows is None
        else _required_ci_callers_in_workflow_sources(frozen_workflows)
    )
    if callers:
        raise AssertionError(
            "candidate repository must not contain another Required CI caller"
        )
    return checkouts


def _trusted_structure_validator_main() -> int:
    candidate_sha, require_clean = _CANDIDATE_SUPPORT.expected_candidate_sha(
        REPO_ROOT
    )
    if not require_clean:
        raise AssertionError(
            "trusted structure validation requires an explicit frozen candidate SHA"
        )
    before = _CANDIDATE_SUPPORT.candidate_checkout_binding(
        REPO_ROOT, candidate_sha, require_clean=True
    )
    validate_required_ci_repository(REPO_ROOT, candidate_sha=candidate_sha)
    after = _CANDIDATE_SUPPORT.candidate_checkout_binding(
        REPO_ROOT, candidate_sha, require_clean=True
    )
    if after != before:
        raise AssertionError(
            "candidate checkout binding changed during structure validation"
        )
    return 0


class MappingPairParsingTests(unittest.TestCase):
    def test_block_mapping_separator_requires_whitespace_or_line_end(self) -> None:
        with self.assertRaisesRegex(AssertionError, "mapping separator"):
            _mapping_pair("name:Required CI", 1)

    def test_colons_after_the_mapping_separator_remain_scalar_content(self) -> None:
        fixtures = {
            "plain value": ("run: echo key:value", ("run", "echo key:value")),
            "quoted value": ('name: "Required: CI"', ("name", '"Required: CI"')),
            "trailing comment": (
                _strip_yaml_comment("name: Required CI # expected name", 1),
                ("name", "Required CI"),
            ),
            "line end": ("jobs:", ("jobs", "")),
        }

        for name, (fragment, expected) in fixtures.items():
            with self.subTest(name=name):
                self.assertEqual(_mapping_pair(fragment, 1), expected)


class CheckoutStepParsingTests(unittest.TestCase):
    def test_unsafe_named_checkout_is_enumerated_for_contract_rejection(self) -> None:
        workflow = (
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            f"          repository: {EXPECTED_REPOSITORY}\n"
            "          ref: ${{ github.sha }}\n"
            "          persist-credentials: false\n"
            "      - name: Unsafe named checkout\n"
            "        uses: actions/checkout@v4\n"
            "        with:\n"
            "          repository: attacker/example\n"
        )

        checkout = checkout_steps(workflow)

        self.assertEqual(len(checkout), 2)
        self.assertIn(f"repository: {EXPECTED_REPOSITORY}", checkout[0])
        self.assertNotIn(f"repository: {EXPECTED_REPOSITORY}", checkout[1])

    def test_named_quoted_and_case_variant_checkouts_are_enumerated(self) -> None:
        workflow = (
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - name: Named checkout\n"
            "        uses: 'actions/checkout@v4'\n"
            "      - name: Case variant\n"
            '        uses: "Actions/Checkout@v4"\n'
        )

        checkout = checkout_steps(workflow)

        self.assertEqual(len(checkout), 2)
        self.assertIn("name: Named checkout", checkout[0])
        self.assertIn("name: Case variant", checkout[1])

    def test_checkout_text_outside_a_step_uses_key_is_ignored(self) -> None:
        workflow = (
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - name: actions/checkout@v4 is only a label\n"
            "        run: |\n"
            "          echo '- uses: actions/checkout@v4'\n"
            "      - uses: actions/checkout-extra@v4\n"
            "      - uses: example/action@v1\n"
            "        with:\n"
            "          uses: actions/checkout@v4\n"
            "      - name: Checkout after block scalar\n"
            "        uses: actions/checkout@v4\n"
        )

        checkout = checkout_steps(workflow)

        self.assertEqual(len(checkout), 1)
        self.assertIn("name: Checkout after block scalar", checkout[0])

    def test_duplicate_step_uses_key_fails_closed(self) -> None:
        workflow = (
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - uses: example/action@v1\n"
            "        uses: actions/checkout@v4\n"
        )

        with self.assertRaisesRegex(AssertionError, "duplicate step key 'uses'"):
            checkout_steps(workflow)

    def test_yaml_indirection_fails_closed(self) -> None:
        fixtures = {
            "anchor": (
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - &checkout\n"
                "        uses: actions/checkout@v4\n"
            ),
            "alias": ("jobs:\n  test:\n    steps:\n      - *checkout\n"),
            "merge": (
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - name: Merged checkout\n"
                "        <<: *checkout\n"
            ),
            "punctuated anchor and alias": (
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - name: &checkout.action actions/checkout@v4\n"
                "        uses: *checkout.action\n"
                "        with:\n"
                "          repository: attacker/example\n"
            ),
        }

        for name, workflow in fixtures.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(AssertionError, "anchors, aliases"):
                    checkout_steps(workflow)

    def test_plain_scalar_operators_are_not_yaml_indirection(self) -> None:
        workflow = (
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - name: Ordinary operators\n"
            "        run: echo a*b && true\n"
            "      - uses: actions/checkout@v4\n"
        )

        checkout = checkout_steps(workflow)

        self.assertEqual(len(checkout), 1)

    def test_unclosed_or_flow_step_shapes_fail_closed(self) -> None:
        fixtures = {
            "unclosed quote": (
                'jobs:\n  test:\n    steps:\n      - uses: "actions/checkout@v4\n'
            ),
            "unclosed flow": (
                "jobs:\n  test:\n    steps:\n      - {uses: actions/checkout@v4\n"
            ),
            "closed flow": (
                "jobs:\n  test:\n    steps:\n      - {uses: actions/checkout@v4}\n"
            ),
            "unclosed nested flow": (
                "jobs:\n  test:\n    steps:\n      - name: Invalid flow\n"
                "        run: [echo\n"
            ),
            "tagged checkout scalar": (
                "jobs:\n  test:\n    steps:\n      - uses: !!str actions/checkout@v4\n"
            ),
        }

        for name, workflow in fixtures.items():
            with self.subTest(name=name):
                with self.assertRaises(AssertionError):
                    checkout_steps(workflow)


class WorkflowHardeningRegressionTests(unittest.TestCase):
    def test_ordinary_ci_has_exact_strict_runtime_live_job(self) -> None:
        if DISTRIBUTION_PROFILE == "private":
            self.skipTest(
                "repository-only CI workflow is not packaged in the private "
                "skill-only distribution"
            )
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertTrue(
            workflow.startswith(
                "name: CI\n\non:\n  pull_request:\n  push:\n"
                "    branches:\n      - master\n\n"
                "permissions:\n  contents: read\n"
            )
        )
        self.assertNotIn("pull_request_target", workflow)
        self.assertEqual(workflow.count("permissions:"), 1)
        self.assertEqual(workflow.count("permissions:\n  contents: read\n"), 1)
        self.assertEqual(top_level_job_ids(workflow), ["test", "strict-live"])
        self.assertEqual(workflow.count(CI_STRICT_RUNTIME_LIVE_JOB), 1)
        self.assertTrue(workflow.endswith(CI_STRICT_RUNTIME_LIVE_JOB))
        self.assertEqual(
            CI_STRICT_RUNTIME_LIVE_JOB.count(
                "          persist-credentials: false\n"
            ),
            1,
        )
        for forbidden in (
            "secrets:",
            "actions/cache",
            "actions/upload-artifact",
            "actions/download-artifact",
            "continue-on-error:",
            "        if:",
        ):
            self.assertNotIn(forbidden, CI_STRICT_RUNTIME_LIVE_JOB)

    def test_strict_runtime_live_hardens_only_bound_runtime_roots(self) -> None:
        if DISTRIBUTION_PROFILE == "private":
            self.skipTest(
                "repository-only CI workflow is not packaged in the private "
                "skill-only distribution"
            )
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        required_workflow = (
            REPO_ROOT / ".github/workflows/required-ci.yml"
        ).read_text(encoding="utf-8")

        setup_marker = (
            "      - name: Set up configured Python for strict live evidence\n"
        )
        run_marker = "      - name: Run strict target credential live test\n"
        self.assertEqual(workflow.count(CI_STRICT_RUNTIME_HARDENING_STEP), 1)
        self.assertLess(
            workflow.index(setup_marker),
            workflow.index(CI_STRICT_RUNTIME_HARDENING_STEP),
        )
        self.assertLess(
            workflow.index(CI_STRICT_RUNTIME_HARDENING_STEP),
            workflow.index(run_marker),
        )
        self.assertEqual(
            required_workflow.count(CI_STRICT_RUNTIME_HARDENING_STEP), 1
        )
        self.assertLess(
            required_workflow.index(PYTHON_SETUP_STEP),
            required_workflow.index(CI_STRICT_RUNTIME_HARDENING_STEP),
        )
        self.assertLess(
            required_workflow.index(CI_STRICT_RUNTIME_HARDENING_STEP),
            required_workflow.index(
                "      - name: Compile candidate Python helpers\n"
            ),
        )
        self.assertIn(
            r"^/opt/hostedtoolcache/Python/"
            r"[0-9]+\.[0-9]+\.[0-9]+/x64$",
            CI_STRICT_RUNTIME_HARDENING_STEP,
        )
        for unsafe_location in (
            "/opt/hostedtoolcache/Python/../..",
            "/opt/hostedtoolcache/Python/3.14.7/..",
            "/opt/hostedtoolcache/Python/.hidden/x64",
        ):
            with self.subTest(unsafe_location=unsafe_location):
                self.assertIsNone(
                    re.fullmatch(
                        r"/opt/hostedtoolcache/Python/"
                        r"[0-9]+\.[0-9]+\.[0-9]+/x64",
                        unsafe_location,
                    )
                )
        self.assertIn(
            'acl_tool=/usr/bin/setfacl',
            CI_STRICT_RUNTIME_HARDENING_STEP,
        )
        self.assertIn("unset POSIXLY_CORRECT", CI_STRICT_RUNTIME_HARDENING_STEP)
        self.assertIn(
            'if [[ ! -f "$acl_tool" || -L "$acl_tool" || '
            '! -x "$acl_tool" ]]; then',
            CI_STRICT_RUNTIME_HARDENING_STEP,
        )
        recursive_acl_command = (
            'sudo "$acl_tool" --recursive --physical --remove-all '
            "--remove-default -- "
            '/usr/share/zoneinfo "$pythonLocation"'
        )
        ancestor_acl_command = (
            'sudo "$acl_tool" --remove-all --remove-default -- \\\n'
            "  /usr/share \\\n"
            "  /opt \\\n"
            "  /opt/hostedtoolcache \\\n"
            '  "$python_family_dir" \\\n'
            '  "$python_version_dir"'
        )
        self.assertIn(recursive_acl_command, STRICT_RUNTIME_HARDENING_COMMAND)
        self.assertIn(ancestor_acl_command, STRICT_RUNTIME_HARDENING_COMMAND)
        self.assertLess(
            STRICT_RUNTIME_HARDENING_COMMAND.index(recursive_acl_command),
            STRICT_RUNTIME_HARDENING_COMMAND.index(
                'sudo chmod -R a-w -- /usr/share/zoneinfo "$pythonLocation"'
            ),
        )
        self.assertLess(
            STRICT_RUNTIME_HARDENING_COMMAND.index(ancestor_acl_command),
            STRICT_RUNTIME_HARDENING_COMMAND.index("sudo chmod a-w --"),
        )
        self.assertIn(
            'sudo chmod -R a-w -- /usr/share/zoneinfo "$pythonLocation"',
            CI_STRICT_RUNTIME_HARDENING_STEP,
        )
        self.assertNotIn(
            "sudo chmod -R a-w -- /usr/share ",
            CI_STRICT_RUNTIME_HARDENING_STEP,
        )
        self.assertNotIn(
            "sudo chmod -R a-w -- /opt ",
            CI_STRICT_RUNTIME_HARDENING_STEP,
        )
        for path in (
            "/usr/share/zoneinfo",
            '"$pythonLocation"',
            "/usr/share",
            "/opt",
            "/opt/hostedtoolcache",
            '"$python_family_dir"',
            '"$python_version_dir"',
        ):
            with self.subTest(path=path):
                self.assertIn(path, CI_STRICT_RUNTIME_HARDENING_STEP)

    def test_checkout_inputs_cannot_be_smuggled_through_the_step_name(self) -> None:
        for style in ("|", ">-"):
            with self.subTest(style=style):
                workflow = (
                    "permissions:\n"
                    "  contents: read\n"
                    "jobs:\n"
                    "  test:\n"
                    "    steps:\n"
                    f"{REPOSITORY_GUARD}\n"
                    "      - uses: actions/checkout@v4\n"
                    f"        name: {style}\n"
                    f"          repository: {EXPECTED_REPOSITORY}\n"
                    "          ref: ${{ github.sha }}\n"
                    "          persist-credentials: false\n"
                    "        with:\n"
                    "          repository: attacker/example\n"
                    "          ref: refs/heads/main\n"
                    "          persist-credentials: true\n"
                )

                with self.assertRaises(AssertionError):
                    validate_required_workflow(workflow)

    def test_checkout_input_mapping_shapes_fail_closed(self) -> None:
        variants = {
            "duplicate": (
                f"          repository: {EXPECTED_REPOSITORY}\n"
                "          repository: attacker/example\n"
                "          ref: ${{ github.sha }}\n"
                "          persist-credentials: false\n"
            ),
            "unsupported key": (
                f"          repository: {EXPECTED_REPOSITORY}\n"
                "          ref: ${{ github.sha }}\n"
                "          persist-credentials: false\n"
                "          path: source\n"
            ),
            "alias": "        with: *checkout-inputs\n",
            "tag": "        with: !!map\n",
            "flow": (
                "        with: {repository: Joey-Tools/codex-waited-delivery, "
                "ref: '${{ github.sha }}', persist-credentials: false}\n"
            ),
            "block scalar": "        with: |\n          repository: ignored\n",
        }

        for name, value in variants.items():
            with self.subTest(name=name):
                with_mapping = (
                    value if value.startswith("        with:") else "        with:\n" + value
                )
                workflow = (
                    "permissions:\n"
                    "  contents: read\n"
                    "jobs:\n"
                    "  test:\n"
                    "    steps:\n"
                    f"{REPOSITORY_GUARD}\n"
                    "      - uses: actions/checkout@v4\n"
                    f"{with_mapping}"
                )

                with self.assertRaises(AssertionError):
                    validate_required_workflow(workflow)

    def test_job_level_permission_overrides_fail_closed(self) -> None:
        variants = {
            "scalar": "    permissions: write-all\n",
            "flow": "    permissions: {contents: write}\n",
            "quoted key": '    "permissions": write-all\n',
        }

        for name, override in variants.items():
            with self.subTest(name=name):
                workflow = (
                    "permissions:\n"
                    "  contents: read\n"
                    "jobs:\n"
                    "  test:\n"
                    f"{override}"
                    "    steps:\n"
                    f"{REPOSITORY_GUARD}\n"
                    "      - uses: actions/checkout@v4\n"
                    "        with:\n"
                    f"          repository: {EXPECTED_REPOSITORY}\n"
                    "          ref: ${{ github.sha }}\n"
                    "          persist-credentials: false\n"
                )

                with self.assertRaises(AssertionError):
                    validate_required_workflow(workflow)

    def test_top_level_permissions_are_an_exact_read_only_mapping(self) -> None:
        variants = {
            "scalar": "permissions: read-all\n",
            "flow": "permissions: {contents: read}\n",
            "extra scope": "permissions:\n  contents: read\n  actions: read\n",
            "quoted duplicate": (
                "permissions:\n  contents: read\n\"permissions\": write-all\n"
            ),
        }

        for name, permissions in variants.items():
            with self.subTest(name=name):
                workflow = (
                    f"{permissions}"
                    "jobs:\n"
                    "  test:\n"
                    "    steps:\n"
                    f"{REPOSITORY_GUARD}\n"
                    "      - uses: actions/checkout@v4\n"
                    "        with:\n"
                    f"          repository: {EXPECTED_REPOSITORY}\n"
                    "          ref: ${{ github.sha }}\n"
                    "          persist-credentials: false\n"
                )

                with self.assertRaises(AssertionError):
                    validate_required_workflow(workflow)

    def test_inline_comment_cannot_hide_an_extra_job(self) -> None:
        workflow = (
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            f"{REPOSITORY_GUARD}\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            f"          repository: {EXPECTED_REPOSITORY}\n"
            "          ref: ${{ github.sha }}\n"
            "          persist-credentials: false\n"
            "  release: # hidden from the raw-line parser\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo publish\n"
        )

        with self.assertRaises(AssertionError):
            validate_required_workflow(workflow)

    def test_comments_and_ordinary_strings_do_not_create_structure(self) -> None:
        workflow = (
            'name: "permissions: write-all # ordinary text"\n'
            "on:\n"
            "  workflow_call:\n"
            "permissions:\n"
            "  contents: read\n"
            "# jobs:\n"
            "#   release:\n"
            "jobs:\n"
            "  # release: this remains a comment\n"
            "  test: # the only real job\n"
            "    runs-on: ubuntu-latest\n"
            f"    timeout-minutes: {EXPECTED_TEST_TIMEOUT_MINUTES}\n"
            "    steps:\n"
            f"{REPOSITORY_GUARD}\n"
            f"{CANDIDATE_CHECKOUT_STEP}"
            f"{TRUSTED_CHECKOUT_STEP}"
            f"{PYTHON_SETUP_STEP}"
            f"{REQUIRED_EXECUTION_STEPS}"
        )

        self.assertEqual(top_level_job_ids(workflow), ["test"])
        required_name_workflow = workflow.replace(
            'name: "permissions: write-all # ordinary text"\n',
            'name: "Required CI"\n',
            1,
        )
        self.assertEqual(len(validate_required_workflow(required_name_workflow)), 2)


class RequiredJobExecutionRegressionTests(unittest.TestCase):
    @staticmethod
    def required_workflow(
        *,
        job_properties: str = "",
        runner: str = "ubuntu-latest",
        timeout_minutes: str | None = EXPECTED_TEST_TIMEOUT_MINUTES,
        trailing_steps: str = REQUIRED_EXECUTION_STEPS,
    ) -> str:
        timeout_line = (
            ""
            if timeout_minutes is None
            else f"    timeout-minutes: {timeout_minutes}\n"
        )
        return (
            "name: Required CI\n"
            "on:\n"
            "  workflow_call:\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  test:\n"
            f"{job_properties}"
            f"    runs-on: {runner}\n"
            f"{timeout_line}"
            "    steps:\n"
            f"{REPOSITORY_GUARD}\n"
            f"{CANDIDATE_CHECKOUT_STEP}"
            f"{TRUSTED_CHECKOUT_STEP}"
            f"{PYTHON_SETUP_STEP}"
            f"{trailing_steps}"
        )

    def test_test_job_requires_the_exact_literal_timeout(self) -> None:
        trailing_steps = REQUIRED_EXECUTION_STEPS
        valid_workflow = self.required_workflow(trailing_steps=trailing_steps)
        self.assertEqual(len(validate_required_workflow(valid_workflow)), 2)

        invalid_timeouts = {
            "missing": None,
            "zero": "0",
            "noninteger word": "ten",
            "noninteger decimal": "10.5",
            "quoted integer": f'"{EXPECTED_TEST_TIMEOUT_MINUTES}"',
            "expression": "${{ vars.REQUIRED_CI_TIMEOUT_MINUTES }}",
            "over GitHub maximum": "361",
            "different positive integer": "36",
        }
        for name, timeout_minutes in invalid_timeouts.items():
            with self.subTest(name=name):
                with self.assertRaises(AssertionError):
                    validate_required_workflow(
                        self.required_workflow(
                            timeout_minutes=timeout_minutes,
                            trailing_steps=trailing_steps,
                        )
                    )

    def test_runtime_hardening_acl_commands_are_exact_and_fail_closed(
        self,
    ) -> None:
        workflow = self.required_workflow()
        mutations = {
            "ambient setfacl": workflow.replace(
                "acl_tool=/usr/bin/setfacl", "acl_tool=setfacl", 1
            ),
            "missing recursive access ACL removal": workflow.replace(
                "--recursive --physical --remove-all --remove-default",
                "--recursive --physical --remove-default",
                1,
            ),
            "missing recursive default ACL removal": workflow.replace(
                "--recursive --physical --remove-all --remove-default",
                "--recursive --physical --remove-all",
                1,
            ),
            "missing ancestor access ACL removal": workflow.replace(
                'sudo "$acl_tool" --remove-all --remove-default',
                'sudo "$acl_tool" --remove-default',
                1,
            ),
            "missing ancestor default ACL removal": workflow.replace(
                'sudo "$acl_tool" --remove-all --remove-default',
                'sudo "$acl_tool" --remove-all',
                1,
            ),
            "missing trusted tool preflight": workflow.replace(
                '          if [[ ! -f "$acl_tool" || -L "$acl_tool" || '
                '! -x "$acl_tool" ]]; then\n'
                '            echo "trusted setfacl is unavailable" >&2\n'
                "            exit 1\n"
                "          fi\n",
                "",
                1,
            ),
            "POSIX mode is not cleared": workflow.replace(
                "unset POSIXLY_CORRECT\n", "", 1
            ),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutated, workflow)
                with self.assertRaisesRegex(
                    AssertionError, "strict runtime hardening command"
                ):
                    validate_required_workflow(mutated)

    def test_every_required_step_has_an_exact_literal_timeout(self) -> None:
        workflow = self.required_workflow()
        step_contracts = (
            (
                "repository guard",
                "      - name: Reject unexpected repository\n",
                "      - name: Check out candidate\n",
                TRUSTED_REPOSITORY_GUARD_TIMEOUT_MINUTES,
            ),
            (
                "candidate checkout",
                "      - name: Check out candidate\n",
                "      - name: Check out trusted Required CI source\n",
                TRUSTED_CANDIDATE_CHECKOUT_TIMEOUT_MINUTES,
            ),
            (
                "trusted checkout",
                "      - name: Check out trusted Required CI source\n",
                "      - uses: actions/setup-python@v5\n",
                TRUSTED_SOURCE_CHECKOUT_TIMEOUT_MINUTES,
            ),
            (
                "Python setup",
                "      - uses: actions/setup-python@v5\n",
                "      - name: Harden strict live runtime roots\n",
                TRUSTED_PYTHON_SETUP_TIMEOUT_MINUTES,
            ),
            (
                "strict runtime hardening",
                "      - name: Harden strict live runtime roots\n",
                "      - name: Compile candidate Python helpers\n",
                STRICT_RUNTIME_HARDENING_TIMEOUT_MINUTES,
            ),
            (
                "compile",
                "      - name: Compile candidate Python helpers\n",
                "      - name: Validate Required CI structure\n",
                TRUSTED_COMPILE_TIMEOUT_MINUTES,
            ),
            (
                "structure",
                "      - name: Validate Required CI structure\n",
                "      - name: Run trusted Required CI tests\n",
                TRUSTED_STRUCTURE_TIMEOUT_MINUTES,
            ),
            (
                "trusted tests",
                "      - name: Run trusted Required CI tests\n",
                None,
                TRUSTED_TEST_STEP_TIMEOUT_MINUTES,
            ),
        )
        for description, marker, next_marker, expected in step_contracts:
            start = workflow.index(marker)
            end = len(workflow) if next_marker is None else workflow.index(
                next_marker, start + len(marker)
            )
            block = workflow[start:end]
            timeout_line = f"        timeout-minutes: {expected}\n"
            self.assertEqual(block.count(timeout_line), 1)
            variants = {
                "missing": "",
                "zero": "        timeout-minutes: 0\n",
                "quoted": f'        timeout-minutes: "{expected}"\n',
                "expression": (
                    "        timeout-minutes: "
                    "${{ vars.REQUIRED_CI_STEP_TIMEOUT }}\n"
                ),
                "wrong": f"        timeout-minutes: {expected + 1}\n",
            }
            for variant, replacement in variants.items():
                with self.subTest(step=description, variant=variant):
                    mutated_block = block.replace(timeout_line, replacement, 1)
                    mutated = workflow[:start] + mutated_block + workflow[end:]
                    with self.assertRaisesRegex(AssertionError, "timeout|properties"):
                        validate_required_workflow(mutated)

    def test_test_job_cannot_be_skipped_or_suppress_errors(self) -> None:
        fixtures = {
            "job condition": "    if: false\n",
            "job error suppression": "    continue-on-error: true\n",
            "unrelated job property": "    name: Hidden wrapper\n",
        }

        for name, job_properties in fixtures.items():
            with self.subTest(name=name):
                with self.assertRaises(AssertionError):
                    validate_required_workflow(
                        self.required_workflow(job_properties=job_properties)
                    )

    def test_candidate_and_trusted_checkouts_are_exact_and_ordered(self) -> None:
        workflow = self.required_workflow()
        fixtures = {
            "missing trusted checkout": workflow.replace(
                TRUSTED_CHECKOUT_STEP, "", 1
            ),
            "trusted repository follows candidate context": workflow.replace(
                "          repository: ${{ job.workflow_repository }}\n",
                f"          repository: {EXPECTED_REPOSITORY}\n",
                1,
            ),
            "trusted ref follows candidate context": workflow.replace(
                "          ref: ${{ job.workflow_sha }}\n",
                "          ref: ${{ github.sha }}\n",
                1,
            ),
            "trusted checkout path is relaxed": workflow.replace(
                "          path: .required-ci\n",
                "          path: .trusted\n",
                1,
            ),
            "candidate checkout path is missing": workflow.replace(
                "          path: .candidate\n", "", 1
            ),
            "candidate credentials are persisted": workflow.replace(
                "          persist-credentials: false\n",
                "          persist-credentials: true\n",
                1,
            ),
            "checkout order is reversed": workflow.replace(
                CANDIDATE_CHECKOUT_STEP + TRUSTED_CHECKOUT_STEP,
                TRUSTED_CHECKOUT_STEP + CANDIDATE_CHECKOUT_STEP,
                1,
            ),
        }

        for name, fixture in fixtures.items():
            with self.subTest(name=name):
                self.assertNotEqual(fixture, workflow)
                with self.assertRaises(AssertionError):
                    validate_required_workflow(fixture)

    def test_python_invocations_are_isolated_and_bound_to_exact_roots(self) -> None:
        workflow = self.required_workflow()
        candidate_validator_command = (
            'python3 -I "$GITHUB_WORKSPACE/.candidate/skills/waited-delivery/'
            f'tests/test_required_ci_workflow.py" {TRUSTED_STRUCTURE_VALIDATOR_FLAG}'
        )
        fixtures = {
            "compile lacks isolated mode": workflow.replace(
                CANDIDATE_COMPILE_COMMAND,
                CANDIDATE_COMPILE_COMMAND.replace("python3 -I", "python3", 1),
                1,
            ),
            "compile uses a relative candidate path": workflow.replace(
                CANDIDATE_COMPILE_COMMAND,
                "python3 -I -m py_compile skills/waited-delivery/scripts/*.py",
                1,
            ),
            "validator lacks isolated mode": workflow.replace(
                TRUSTED_VALIDATOR_COMMAND,
                TRUSTED_VALIDATOR_COMMAND.replace("python3 -I", "python3", 1),
                1,
            ),
            "validator runs candidate copy": workflow.replace(
                TRUSTED_VALIDATOR_COMMAND, candidate_validator_command, 1
            ),
            "validator uses relative path": workflow.replace(
                TRUSTED_VALIDATOR_COMMAND,
                "python3 -I skills/waited-delivery/tests/test_required_ci_workflow.py "
                f"{TRUSTED_STRUCTURE_VALIDATOR_FLAG}",
                1,
            ),
            "validator candidate root env is missing": workflow.replace(
                "        env:\n"
                "          REQUIRED_CI_CANDIDATE_ROOT: "
                "${{ github.workspace }}/.candidate\n",
                "",
                1,
            ),
            "validator candidate root env is relaxed": workflow.replace(
                "${{ github.workspace }}/.candidate",
                "${{ github.workspace }}",
                1,
            ),
            "validator candidate SHA env is missing": workflow.replace(
                "          REQUIRED_CI_CANDIDATE_SHA: ${{ github.sha }}\n",
                "",
                1,
            ),
            "validator candidate SHA env is relaxed": workflow.replace(
                "          REQUIRED_CI_CANDIDATE_SHA: ${{ github.sha }}\n",
                "          REQUIRED_CI_CANDIDATE_SHA: ${{ job.workflow_sha }}\n",
                1,
            ),
            "validator isolation mode is unexpectedly enabled": workflow.replace(
                "          REQUIRED_CI_CANDIDATE_SHA: ${{ github.sha }}\n",
                "          REQUIRED_CI_CANDIDATE_SHA: ${{ github.sha }}\n"
                "          REQUIRED_CI_ISOLATION_MODE: sudo-setpriv-v1\n",
                1,
            ),
            "validator environment has an extra key": workflow.replace(
                "          REQUIRED_CI_CANDIDATE_ROOT: "
                "${{ github.workspace }}/.candidate\n",
                "          REQUIRED_CI_CANDIDATE_ROOT: "
                "${{ github.workspace }}/.candidate\n"
                "          PYTHONPATH: ${{ github.workspace }}/.candidate\n",
                1,
            ),
            "functional supervisor lacks isolated mode": workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                TRUSTED_TEST_SUPERVISOR_COMMAND.replace(
                    "python3 -I", "python3", 1
                ),
                1,
            ),
            "functional supervisor uses a relative path": workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                "python3 -I skills/waited-delivery/tests/"
                "test_required_ci_workflow.py --run-trusted-tests",
                1,
            ),
            "functional supervisor candidate cwd is missing": workflow.replace(
                "        working-directory: "
                "${{ github.workspace }}/.candidate\n",
                "",
                1,
            ),
            "functional supervisor runs from trusted checkout": workflow.replace(
                "        working-directory: "
                "${{ github.workspace }}/.candidate\n",
                "        working-directory: "
                "${{ github.workspace }}/.required-ci\n",
                1,
            ),
        }

        for name, fixture in fixtures.items():
            with self.subTest(name=name):
                self.assertNotEqual(fixture, workflow)
                with self.assertRaises(AssertionError):
                    validate_required_workflow(fixture)

    def test_functional_tests_are_owned_by_the_trusted_supervisor(self) -> None:
        secure_workflow = self.required_workflow()

        self.assertEqual(len(validate_required_workflow(secure_workflow)), 2)

        fixtures = {
            "candidate copy owns the supervisor": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                TRUSTED_TEST_SUPERVISOR_COMMAND.replace(
                    'environment["GITHUB_WORKSPACE"]+"/.required-ci/',
                    'environment["GITHUB_WORKSPACE"]+"/.candidate/',
                    1,
                ),
                1,
            ),
            "supervisor lacks isolated mode": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                TRUSTED_TEST_SUPERVISOR_COMMAND.replace(
                    "python3 -I", "python3", 1
                ),
                1,
            ),
            "supervisor flag is missing": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                TRUSTED_TEST_SUPERVISOR_COMMAND.replace(
                    ',"--run-trusted-tests"', "", 1
                ),
                1,
            ),
            "supervisor deadline uses wall clock": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                TRUSTED_TEST_SUPERVISOR_COMMAND.replace(
                    "time.monotonic()", "time.time()", 1
                ),
                1,
            ),
            "supervisor deadline is extended": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                TRUSTED_TEST_SUPERVISOR_COMMAND.replace("+720", "+721", 1),
                1,
            ),
            "supervisor launcher does not exec": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                TRUSTED_TEST_SUPERVISOR_COMMAND.replace(
                    "os.execve", "os.spawnve", 1
                ),
                1,
            ),
            "supervisor launcher has a second shell action": (
                secure_workflow.replace(
                    TRUSTED_TEST_SUPERVISOR_COMMAND,
                    TRUSTED_TEST_SUPERVISOR_COMMAND + "\n          echo unexpected",
                    1,
                )
            ),
            "candidate root environment is missing": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_STEP,
                TRUSTED_TEST_SUPERVISOR_STEP.replace(
                    "        env:\n"
                    "          REQUIRED_CI_CANDIDATE_ROOT: "
                    "${{ github.workspace }}/.candidate\n",
                    "",
                    1,
                ),
                1,
            ),
            "candidate root environment is relaxed": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_STEP,
                TRUSTED_TEST_SUPERVISOR_STEP.replace(
                    "${{ github.workspace }}/.candidate",
                    "${{ github.workspace }}",
                    1,
                ),
                1,
            ),
            "candidate SHA environment is missing": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_STEP,
                TRUSTED_TEST_SUPERVISOR_STEP.replace(
                    "          REQUIRED_CI_CANDIDATE_SHA: ${{ github.sha }}\n",
                    "",
                    1,
                ),
                1,
            ),
            "candidate SHA environment is relaxed": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_STEP,
                TRUSTED_TEST_SUPERVISOR_STEP.replace(
                    "          REQUIRED_CI_CANDIDATE_SHA: ${{ github.sha }}\n",
                    "          REQUIRED_CI_CANDIDATE_SHA: ${{ job.workflow_sha }}\n",
                    1,
                ),
                1,
            ),
            "candidate isolation mode is missing": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_STEP,
                TRUSTED_TEST_SUPERVISOR_STEP.replace(
                    "          REQUIRED_CI_ISOLATION_MODE: sudo-setpriv-v1\n",
                    "",
                    1,
                ),
                1,
            ),
            "candidate isolation mode is relaxed": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_STEP,
                TRUSTED_TEST_SUPERVISOR_STEP.replace(
                    "          REQUIRED_CI_ISOLATION_MODE: sudo-setpriv-v1\n",
                    "          REQUIRED_CI_ISOLATION_MODE: local\n",
                    1,
                ),
                1,
            ),
            "candidate root environment adds PYTHONPATH": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_STEP,
                TRUSTED_TEST_SUPERVISOR_STEP.replace(
                    "          REQUIRED_CI_CANDIDATE_ROOT: "
                    "${{ github.workspace }}/.candidate\n",
                    "          REQUIRED_CI_CANDIDATE_ROOT: "
                    "${{ github.workspace }}/.candidate\n"
                    "          PYTHONPATH: ${{ github.workspace }}/.candidate\n",
                    1,
                ),
                1,
            ),
            "candidate discovery bypasses the supervisor": secure_workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                'python3 -I -m unittest discover -s "$GITHUB_WORKSPACE/'
                '.candidate/skills/waited-delivery/tests"',
                1,
            ),
        }

        for name, fixture in fixtures.items():
            with self.subTest(name=name):
                self.assertNotEqual(fixture, secure_workflow)
                with self.assertRaises(AssertionError):
                    validate_required_workflow(fixture)

    def test_candidate_validator_deletion_or_replacement_cannot_bypass_trust(
        self,
    ) -> None:
        secure_workflow = self.required_workflow()
        candidate_validator_command = (
            'python3 -I "$GITHUB_WORKSPACE/.candidate/skills/waited-delivery/'
            f'tests/test_required_ci_workflow.py" {TRUSTED_STRUCTURE_VALIDATOR_FLAG}'
        )
        insecure_workflow = secure_workflow.replace(
            TRUSTED_VALIDATOR_COMMAND, candidate_validator_command, 1
        )
        self.assertNotEqual(insecure_workflow, secure_workflow)

        for state in ("deleted", "replaced"):
            with self.subTest(state=state):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    candidate_root = (
                        Path(temporary_directory).resolve(strict=True) / ".candidate"
                    )
                    workflow_path = (
                        candidate_root / ".github/workflows/required-ci.yml"
                    )
                    workflow_path.parent.mkdir(parents=True)
                    workflow_path.write_text(secure_workflow, encoding="utf-8")
                    candidate_validator = (
                        candidate_root
                        / "skills/waited-delivery/tests/"
                        "test_required_ci_workflow.py"
                    )
                    candidate_validator.parent.mkdir(parents=True)
                    shutil.copyfile(
                        TRUSTED_CANDIDATE_SUPPORT_PATH,
                        candidate_validator.parent / "required_ci_candidate.py",
                    )
                    if state == "replaced":
                        candidate_validator.write_text(
                            "raise SystemExit(0)\n", encoding="utf-8"
                        )

                    self.assertEqual(
                        len(validate_required_ci_repository(candidate_root)), 2
                    )
                    workflow_path.write_text(
                        insecure_workflow, encoding="utf-8"
                    )
                    with self.assertRaises(AssertionError):
                        validate_required_ci_repository(candidate_root)

    def test_candidate_support_missing_replacement_or_symlink_fails_closed(
        self,
    ) -> None:
        secure_workflow = self.required_workflow()
        for state in ("missing", "replaced", "symlink"):
            with self.subTest(state=state):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    candidate_root = (
                        Path(temporary_directory).resolve(strict=True) / ".candidate"
                    )
                    workflow_path = (
                        candidate_root / ".github/workflows/required-ci.yml"
                    )
                    workflow_path.parent.mkdir(parents=True)
                    workflow_path.write_text(secure_workflow, encoding="utf-8")
                    support_path = (
                        candidate_root
                        / "skills/waited-delivery/tests/required_ci_candidate.py"
                    )
                    support_path.parent.mkdir(parents=True)
                    if state == "replaced":
                        support_path.write_text("raise SystemExit(0)\n", encoding="utf-8")
                    elif state == "symlink":
                        support_path.symlink_to(TRUSTED_CANDIDATE_SUPPORT_PATH)

                    with self.assertRaisesRegex(
                        AssertionError, "trusted candidate support|trusted support"
                    ):
                        validate_required_ci_repository(candidate_root)

    def test_candidate_workflow_rejects_symlinked_ancestor_directories(
        self,
    ) -> None:
        secure_workflow = self.required_workflow()
        for ancestor in (".github", ".github/workflows"):
            with self.subTest(ancestor=ancestor):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory).resolve(strict=True)
                    candidate_root = root / ".candidate"
                    outside_root = root / "outside"
                    candidate_root.mkdir()
                    outside_workflows = outside_root / "workflows"
                    outside_workflows.mkdir(parents=True)
                    (outside_workflows / "required-ci.yml").write_text(
                        secure_workflow, encoding="utf-8"
                    )
                    if ancestor == ".github":
                        (candidate_root / ".github").symlink_to(
                            outside_root, target_is_directory=True
                        )
                    else:
                        github_root = candidate_root / ".github"
                        github_root.mkdir()
                        (github_root / "workflows").symlink_to(
                            outside_workflows, target_is_directory=True
                        )
                    support_path = (
                        candidate_root
                        / "skills/waited-delivery/tests/required_ci_candidate.py"
                    )
                    support_path.parent.mkdir(parents=True)
                    shutil.copyfile(TRUSTED_CANDIDATE_SUPPORT_PATH, support_path)

                    with self.assertRaisesRegex(
                        AssertionError, "required-ci.yml path binding"
                    ):
                        validate_required_ci_repository(candidate_root)

    def test_candidate_support_rejects_symlinked_ancestor_directories(
        self,
    ) -> None:
        secure_workflow = self.required_workflow()
        for ancestor in ("skills", "skills/waited-delivery/tests"):
            with self.subTest(ancestor=ancestor), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory).resolve(strict=True)
                candidate_root = root / ".candidate"
                candidate_root.mkdir()
                workflow_path = (
                    candidate_root / ".github/workflows/required-ci.yml"
                )
                workflow_path.parent.mkdir(parents=True)
                workflow_path.write_text(secure_workflow, encoding="utf-8")
                outside_root = root / "outside"
                if ancestor == "skills":
                    outside_support = (
                        outside_root
                        / "waited-delivery/tests/required_ci_candidate.py"
                    )
                    outside_support.parent.mkdir(parents=True)
                    (candidate_root / "skills").symlink_to(
                        outside_root, target_is_directory=True
                    )
                else:
                    outside_support = outside_root / "required_ci_candidate.py"
                    outside_support.parent.mkdir(parents=True)
                    tests_parent = candidate_root / "skills/waited-delivery"
                    tests_parent.mkdir(parents=True)
                    (tests_parent / "tests").symlink_to(
                        outside_root, target_is_directory=True
                    )
                outside_support.write_bytes(TRUSTED_CANDIDATE_SUPPORT_SOURCE)

                with self.assertRaisesRegex(
                    AssertionError, "trusted support path binding"
                ):
                    validate_required_ci_repository(candidate_root)

    def test_bound_repository_reader_rejects_open_window_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            detached = path.with_name("detached.yml")
            replacement = path.with_name("replacement.yml")
            replacement.write_bytes(b"replacement\n")
            original_open = os.open
            replaced = False

            def replace_before_open(
                selected_path: object, flags: int, *args: object, **kwargs: object
            ) -> int:
                nonlocal replaced
                selected = Path(selected_path)
                if not replaced and (
                    selected == path
                    or (selected == Path(path.name) and "dir_fd" in kwargs)
                ):
                    path.rename(detached)
                    replacement.rename(path)
                    replaced = True
                return original_open(selected_path, flags, *args, **kwargs)

            with mock.patch.object(os, "open", side_effect=replace_before_open):
                with self.assertRaisesRegex(
                    AssertionError,
                    "object changed or was replaced during binding",
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertEqual(detached.read_bytes(), b"original\n")
            self.assertEqual(path.read_bytes(), b"replacement\n")

    def test_bound_repository_reader_never_blocks_on_fifo_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            detached = path.with_name("detached.yml")
            original_open = os.open
            guard_descriptor: int | None = None
            leaf_open_flags: int | None = None
            replaced = False

            def replace_with_fifo_before_open(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal guard_descriptor, leaf_open_flags, replaced
                if (
                    not replaced
                    and Path(selected_path) == Path(path.name)
                    and "dir_fd" in kwargs
                ):
                    path.rename(detached)
                    os.mkfifo(path)
                    guard_descriptor = original_open(
                        path, os.O_RDWR | os.O_NONBLOCK
                    )
                    leaf_open_flags = flags
                    replaced = True
                return original_open(selected_path, flags, *args, **kwargs)

            try:
                with mock.patch.object(
                    os, "open", side_effect=replace_with_fifo_before_open
                ):
                    with self.assertRaisesRegex(
                        AssertionError,
                        "object changed or was replaced during binding",
                    ):
                        _read_bound_repository_file(
                            root, relative_path, "probe"
                        )
            finally:
                if guard_descriptor is not None:
                    os.close(guard_descriptor)

            self.assertTrue(replaced, "the FIFO replacement fixture must execute")
            self.assertIsNotNone(leaf_open_flags)
            assert leaf_open_flags is not None
            self.assertTrue(
                leaf_open_flags & os.O_NONBLOCK,
                "leaf open must not block on a special-file replacement",
            )
            self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))
            self.assertEqual(detached.read_bytes(), b"original\n")

    def test_bound_repository_reader_rejects_ancestor_symlink_open_race(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            github_root = root / ".github"
            detached_github_root = root / "detached-github"
            original_open = os.open
            swapped = False

            def swap_ancestor_before_open(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal swapped
                selected = Path(selected_path)
                if not swapped and (
                    selected == path
                    or (selected == Path(path.name) and "dir_fd" in kwargs)
                ):
                    github_root.rename(detached_github_root)
                    github_root.symlink_to(
                        detached_github_root, target_is_directory=True
                    )
                    swapped = True
                return original_open(selected_path, flags, *args, **kwargs)

            with mock.patch.object(os, "open", side_effect=swap_ancestor_before_open):
                with self.assertRaisesRegex(
                    AssertionError, "path binding changed"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertTrue(swapped, "the ancestor race fixture must execute")
            self.assertTrue(github_root.is_symlink())
            self.assertEqual(path.read_bytes(), b"original\n")

    def test_bound_repository_reader_rejects_repository_root_symlink_open_race(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory).resolve(strict=True)
            root = workspace / "candidate-root"
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            detached_root = workspace / "detached-candidate-root"
            original_open = os.open
            swapped = False

            def swap_root_before_open(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal swapped
                if (
                    not swapped
                    and Path(selected_path) == Path(root.name)
                    and "dir_fd" in kwargs
                ):
                    root.rename(detached_root)
                    root.symlink_to(detached_root, target_is_directory=True)
                    swapped = True
                return original_open(selected_path, flags, *args, **kwargs)

            with mock.patch.object(os, "open", side_effect=swap_root_before_open):
                with self.assertRaisesRegex(
                    AssertionError, "path binding changed during binding"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertTrue(swapped, "the root race fixture must execute")
            self.assertTrue(root.is_symlink())
            self.assertEqual(path.read_bytes(), b"original\n")

    def test_bound_repository_reader_rejects_whole_root_swap_before_anchor_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory).resolve(strict=True)
            root = workspace / "candidate-root"
            replacement_root = workspace / "replacement-candidate-root"
            detached_root = workspace / "detached-candidate-root"
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            replacement_path = replacement_root / relative_path
            path.parent.mkdir(parents=True)
            replacement_path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            replacement_path.write_bytes(b"decoy\n")
            original_open = os.open
            swapped = False

            def swap_root_before_anchor_open(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal swapped
                if (
                    not swapped
                    and Path(selected_path) == Path(root.anchor)
                    and "dir_fd" not in kwargs
                ):
                    root.rename(detached_root)
                    replacement_root.rename(root)
                    swapped = True
                return original_open(selected_path, flags, *args, **kwargs)

            with mock.patch.object(
                os, "open", side_effect=swap_root_before_anchor_open
            ):
                with self.assertRaisesRegex(
                    AssertionError, "path binding changed"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertTrue(swapped, "the whole-root race fixture must execute")
            self.assertEqual(path.read_bytes(), b"decoy\n")
            self.assertEqual(
                (detached_root / relative_path).read_bytes(), b"original\n"
            )

    def test_bound_repository_reader_never_opens_absolute_root_through_symlink(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            container = Path(temporary_directory).resolve(strict=True)
            workspace = container / "workspace"
            root = workspace / "candidate-root"
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            detached_workspace = container / "detached-workspace"
            original_open = os.open
            transient_symlink_followed = False

            def restore_ancestor_after_absolute_open(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal transient_symlink_followed
                if (
                    not transient_symlink_followed
                    and Path(selected_path) == root
                    and "dir_fd" not in kwargs
                ):
                    workspace.rename(detached_workspace)
                    workspace.symlink_to(
                        detached_workspace, target_is_directory=True
                    )
                    try:
                        descriptor = original_open(
                            selected_path, flags, *args, **kwargs
                        )
                        transient_symlink_followed = True
                    finally:
                        workspace.unlink()
                        detached_workspace.rename(workspace)
                    return descriptor
                return original_open(selected_path, flags, *args, **kwargs)

            with mock.patch.object(
                os, "open", side_effect=restore_ancestor_after_absolute_open
            ):
                source = _read_bound_repository_file(
                    root, relative_path, "probe"
                )

            self.assertFalse(
                transient_symlink_followed,
                "repository files must be reached only through the no-follow "
                "component chain",
            )
            self.assertEqual(source, b"original\n")
            self.assertFalse(workspace.is_symlink())

    def test_bound_repository_reader_allows_benign_sibling_directory_churn(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            sibling = path.parent / "benign-child"
            original_open = os.open
            churned = False

            def add_sibling_before_open(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal churned
                selected = Path(selected_path)
                if not churned and (
                    selected == path
                    or (selected == Path(path.name) and "dir_fd" in kwargs)
                ):
                    sibling.mkdir()
                    churned = True
                return original_open(selected_path, flags, *args, **kwargs)

            with mock.patch.object(os, "open", side_effect=add_sibling_before_open):
                source = _read_bound_repository_file(
                    root, relative_path, "probe"
                )

            self.assertTrue(churned, "the benign churn fixture must execute")
            self.assertEqual(source, b"original\n")
            self.assertTrue(sibling.is_dir())

    def test_bound_repository_reader_rejects_same_inode_content_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"first\n")
            original_lseek = os.lseek
            changed = False

            def mutate_before_second_read(
                descriptor: int, offset: int, whence: int
            ) -> int:
                nonlocal changed
                result = original_lseek(descriptor, offset, whence)
                if not changed:
                    path.write_bytes(b"other\n")
                    changed = True
                return result

            with mock.patch.object(os, "lseek", side_effect=mutate_before_second_read):
                with self.assertRaisesRegex(
                    AssertionError, "content stability changed"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

    def test_bound_repository_reader_rejects_final_same_inode_size_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"first\n")
            original_stat = os.stat
            leaf_stats = 0
            changed = False

            def mutate_before_final_path_stat(
                selected_path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal changed, leaf_stats
                if (
                    Path(selected_path) == Path(path.name)
                    and "dir_fd" in kwargs
                ):
                    leaf_stats += 1
                    if leaf_stats == 2:
                        path.write_bytes(b"longer\n")
                        changed = True
                return original_stat(selected_path, *args, **kwargs)

            with mock.patch.object(
                os, "stat", side_effect=mutate_before_final_path_stat
            ):
                with self.assertRaisesRegex(
                    AssertionError, "content stability changed"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertTrue(changed, "the final-size fixture must execute")
            self.assertEqual(path.read_bytes(), b"longer\n")

    def test_bound_repository_reader_reports_leaf_disappearance_during_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            original_open = os.open
            removed = False

            def remove_leaf_before_open(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal removed
                if (
                    not removed
                    and Path(selected_path) == Path(path.name)
                    and "dir_fd" in kwargs
                ):
                    path.unlink()
                    removed = True
                return original_open(selected_path, flags, *args, **kwargs)

            with mock.patch.object(os, "open", side_effect=remove_leaf_before_open):
                with self.assertRaisesRegex(
                    AssertionError, "disappeared during binding"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertTrue(removed, "the binding disappearance fixture must execute")
            self.assertFalse(path.exists())

    def test_bound_repository_reader_reports_initial_leaf_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            (root / relative_path).parent.mkdir(parents=True)

            with self.assertRaisesRegex(AssertionError, r"^probe is missing$"):
                _read_bound_repository_file(root, relative_path, "probe")

    def test_bound_repository_reader_reports_final_leaf_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"first\n")
            replacement = path.with_name("replacement.yml")
            detached = path.with_name("detached.yml")
            replacement.write_bytes(b"other\n")
            original_stat = os.stat
            leaf_stats = 0
            replaced = False

            def replace_before_final_path_stat(
                selected_path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal leaf_stats, replaced
                if (
                    Path(selected_path) == Path(path.name)
                    and "dir_fd" in kwargs
                ):
                    leaf_stats += 1
                    if leaf_stats == 2:
                        path.rename(detached)
                        replacement.rename(path)
                        replaced = True
                return original_stat(selected_path, *args, **kwargs)

            with mock.patch.object(
                os, "stat", side_effect=replace_before_final_path_stat
            ):
                with self.assertRaisesRegex(
                    AssertionError, "object changed or was replaced during revalidation"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertTrue(replaced, "the final replacement fixture must execute")
            self.assertEqual(path.read_bytes(), b"other\n")
            self.assertEqual(detached.read_bytes(), b"first\n")

    def test_bound_repository_reader_reports_final_leaf_disappearance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            original_stat = os.stat
            leaf_stats = 0

            def lose_leaf_during_revalidation(
                selected_path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal leaf_stats
                if (
                    Path(selected_path) == Path(path.name)
                    and "dir_fd" in kwargs
                ):
                    leaf_stats += 1
                    if leaf_stats == 2:
                        raise FileNotFoundError(errno.ENOENT, "injected")
                return original_stat(selected_path, *args, **kwargs)

            with mock.patch.object(
                os, "stat", side_effect=lose_leaf_during_revalidation
            ):
                with self.assertRaisesRegex(
                    AssertionError, "disappeared during revalidation"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertEqual(leaf_stats, 2)

    def test_bound_repository_reader_reports_final_ancestor_disappearance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            original_stat = os.stat
            github_stats = 0

            def lose_ancestor_during_revalidation(
                selected_path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal github_stats
                if (
                    Path(selected_path) == Path(".github")
                    and "dir_fd" in kwargs
                ):
                    github_stats += 1
                    if github_stats == 2:
                        raise FileNotFoundError(errno.ENOENT, "injected")
                return original_stat(selected_path, *args, **kwargs)

            with mock.patch.object(
                os, "stat", side_effect=lose_ancestor_during_revalidation
            ):
                with self.assertRaisesRegex(
                    AssertionError, "disappeared during revalidation"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertEqual(github_stats, 2)

    def test_bound_repository_reader_reports_final_revalidation_unreadable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            original_stat = os.stat
            leaf_stats = 0

            def deny_leaf_revalidation(
                selected_path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal leaf_stats
                if (
                    Path(selected_path) == Path(path.name)
                    and "dir_fd" in kwargs
                ):
                    leaf_stats += 1
                    if leaf_stats == 2:
                        raise PermissionError(errno.EACCES, "injected")
                return original_stat(selected_path, *args, **kwargs)

            with mock.patch.object(
                os, "stat", side_effect=deny_leaf_revalidation
            ):
                with self.assertRaisesRegex(
                    AssertionError, "unreadable during revalidation"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertEqual(leaf_stats, 2)

    def test_bound_repository_reader_reports_final_hardlink_policy_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            relative_path = Path(".github/workflows/probe.yml")
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original\n")
            alias = path.with_name("alias.yml")
            original_stat = os.stat
            leaf_stats = 0
            linked = False

            def link_before_final_path_stat(
                selected_path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal leaf_stats, linked
                if (
                    Path(selected_path) == Path(path.name)
                    and "dir_fd" in kwargs
                ):
                    leaf_stats += 1
                    if leaf_stats == 2:
                        os.link(path, alias)
                        linked = True
                return original_stat(selected_path, *args, **kwargs)

            with mock.patch.object(
                os, "stat", side_effect=link_before_final_path_stat
            ):
                with self.assertRaisesRegex(
                    AssertionError, "access policy changed during revalidation"
                ):
                    _read_bound_repository_file(root, relative_path, "probe")

            self.assertTrue(linked, "the hardlink policy fixture must execute")
            self.assertEqual(path.stat().st_ino, alias.stat().st_ino)
            self.assertEqual(path.stat().st_nlink, 2)

    def test_runner_text_in_a_fake_node_does_not_satisfy_the_contract(self) -> None:
        workflow = self.required_workflow(
            job_properties=(
                "    env:\n"
                "      REQUIRED_RUNNER_TEXT: ubuntu-latest\n"
            ),
            runner="windows-latest",
        )

        with self.assertRaises(AssertionError):
            validate_required_workflow(workflow)

    def test_commands_must_be_bound_to_the_intended_run_steps(self) -> None:
        fixtures = {
            "name smuggling": (
                "      - name: |\n"
                "          Compile candidate Python helpers\n"
                f"          {CANDIDATE_COMPILE_COMMAND}\n"
                "        run: true\n"
                "      - name: |\n"
                "          Validate Required CI structure\n"
                f"          {TRUSTED_VALIDATOR_COMMAND}\n"
                "        env:\n"
                "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
                "        run: true\n"
                "      - name: |\n"
                "          Run trusted Required CI tests\n"
                f"          {TRUSTED_TEST_SUPERVISOR_COMMAND}\n"
                "        env:\n"
                "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
                "        run: true\n"
            ),
            "swapped run steps": (
                "      - name: Compile candidate Python helpers\n"
                "        run: |\n"
                f"          {TRUSTED_TEST_SUPERVISOR_COMMAND}\n"
                "      - name: Validate Required CI structure\n"
                "        env:\n"
                "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
                "        run: |\n"
                f"          {TRUSTED_VALIDATOR_COMMAND}\n"
                "      - name: Run trusted Required CI tests\n"
                "        env:\n"
                "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
                "        run: |\n"
                f"          {CANDIDATE_COMPILE_COMMAND}\n"
            ),
        }

        for name, trailing_steps in fixtures.items():
            with self.subTest(name=name):
                with self.assertRaises(AssertionError):
                    validate_required_workflow(
                        self.required_workflow(trailing_steps=trailing_steps)
                    )

    def test_commands_cannot_run_in_suppressed_steps(self) -> None:
        workflow = self.required_workflow(
            trailing_steps=(
                "      - name: Compile candidate Python helpers\n"
                "        if: false\n"
                "        run: |\n"
                f"          {CANDIDATE_COMPILE_COMMAND}\n"
                "      - name: Validate Required CI structure\n"
                "        env:\n"
                "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
                "        run: |\n"
                f"          {TRUSTED_VALIDATOR_COMMAND}\n"
                "      - name: Run trusted Required CI tests\n"
                "        continue-on-error: true\n"
                "        env:\n"
                "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
                "        run: |\n"
                f"          {TRUSTED_TEST_SUPERVISOR_COMMAND}\n"
            )
        )

        with self.assertRaises(AssertionError):
            validate_required_workflow(workflow)

    def test_workflow_level_execution_overrides_fail_closed(self) -> None:
        variants = {
            "custom shell swallows failures": (
                "defaults:\n"
                "  run:\n"
                "    shell: bash {0} || true\n"
            ),
            "path override selects another interpreter": (
                "env:\n"
                "  PATH: ./untrusted-bin:/usr/bin:/bin\n"
            ),
        }

        for name, override in variants.items():
            with self.subTest(name=name):
                workflow = self.required_workflow(
                    trailing_steps=REQUIRED_EXECUTION_STEPS
                ).replace("permissions:\n", f"{override}permissions:\n", 1)

                with self.assertRaises(AssertionError):
                    validate_required_workflow(workflow)

    def test_workflow_call_is_the_only_trigger(self) -> None:
        workflow = self.required_workflow(
            trailing_steps=REQUIRED_EXECUTION_STEPS
        ).replace("  workflow_call:\n", "  workflow_call:\n  push:\n", 1)

        with self.assertRaises(AssertionError):
            validate_required_workflow(workflow)


class IsolatedPythonInvocationRegressionTests(unittest.TestCase):
    def test_bounded_failure_text_preserves_head_and_terminal_cause(self) -> None:
        self.assertIs(
            _bounded_failure_text,
            _CANDIDATE_SUPPORT._bounded_failure_text,
        )
        value = (
            "::warning title=forged::head\n"
            "Traceback (most recent call last):\n"
            + "H" * 2500
            + "MIDDLE-DETAIL-MUST-BE-DROPPED"
            + "T" * 2500
            + "\n   ::stop-commands::forged-token\r"
            + "\x00\x1b[31m\u2028\u2029\u202e\u200d\ud800\U000e0001"
            + "AssertionError: terminal-cause\x7f"
        )

        bounded = _bounded_failure_text(value)

        self.assertLessEqual(len(bounded), 2000)
        self.assertTrue(bounded.startswith("\\::warning title=forged::head"))
        self.assertIn("...[middle truncated]...", bounded)
        self.assertNotIn("MIDDLE-DETAIL-MUST-BE-DROPPED", bounded)
        self.assertTrue(
            bounded.endswith(
                "\\x1b[31m\\u2028\\u2029\\u202e\\u200d\\ud800"
                "\\U000e0001"
                "AssertionError: terminal-cause\\x7f"
            )
        )
        self.assertTrue(
            all(
                not line.lstrip().startswith("::")
                for line in bounded.split("\n")
            )
        )
        self.assertFalse(
            any(
                character in bounded
                for character in (
                    "\x00",
                    "\r",
                    "\x1b",
                    "\x7f",
                    "\u2028",
                    "\u2029",
                    "\u202e",
                    "\u200d",
                    "\ud800",
                    "\U000e0001",
                )
            )
        )
        self.assertIn("   \\::stop-commands::forged-token\\x0d", bounded)
        self.assertEqual(_bounded_failure_text(bounded), bounded)

    def test_isolated_unittest_ignores_candidate_root_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate_root = Path(temporary_directory) / ".candidate"
            tests_root = candidate_root / "tests"
            tests_root.mkdir(parents=True)
            shadow_marker = candidate_root / "shadow-imported"
            (candidate_root / "unittest.py").write_text(
                'open("shadow-imported", "w", encoding="utf-8").write("used")\n',
                encoding="utf-8",
            )
            (tests_root / "test_failure.py").write_text(
                "import unittest\n\n"
                "class IntentionalFailure(unittest.TestCase):\n"
                "    def test_failure(self):\n"
                '        self.fail("real discovery ran")\n',
                encoding="utf-8",
            )
            common_arguments = [
                "-m",
                "unittest",
                "discover",
                "-s",
                str(tests_root),
            ]

            shadowed = subprocess.run(
                [sys.executable, *common_arguments],
                cwd=candidate_root,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(shadowed.returncode, 0)
            self.assertTrue(shadow_marker.is_file())
            shadow_marker.unlink()

            isolated = subprocess.run(
                [sys.executable, "-I", *common_arguments],
                cwd=candidate_root,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertNotEqual(isolated.returncode, 0)
            self.assertIn("real discovery ran", isolated.stderr)
            self.assertFalse(shadow_marker.exists())


class TrustedCandidateTestSupervisorRegressionTests(unittest.TestCase):
    @staticmethod
    def root_command_config(**updates: object) -> dict[str, object]:
        config: dict[str, object] = {
            "uid": 60000,
            "gid": 60000,
            "environment": {},
            "candidate_argv": ["/usr/bin/python3", "-I", "/probe.py"],
            "candidate_interpreter": None,
            "trusted_root": "/trusted",
            "trusted_sentinel": "/trusted/sentinel",
            "host_mount_namespace": "mnt:[101]",
            "host_ipc_namespace": "ipc:[102]",
            "host_network_namespace": "net:[103]",
            "writable_roots": [
                {
                    "path": "/execution",
                    "device": 1,
                    "inode": 2,
                    "host_mount_id": 3,
                }
            ],
            "read_roots": [
                {
                    "schema_version": 1,
                    "purpose": "system-library",
                    "kind": "directory",
                    "path": "/runtime",
                    "target_uid": 60000,
                    "target_gid": 60000,
                    "components": [
                        {
                            "path": "/",
                            "kind": "directory",
                            "device": 10,
                            "inode": 11,
                            "uid": 0,
                            "gid": 0,
                            "permissions": 0o755,
                        },
                        {
                            "path": "/runtime",
                            "kind": "directory",
                            "device": 12,
                            "inode": 13,
                            "uid": 0,
                            "gid": 0,
                            "permissions": 0o755,
                        },
                    ],
                    "host_mount_id": 4,
                }
            ],
        }
        config.update(updates)
        return config

    @staticmethod
    @contextlib.contextmanager
    def root_command_mount_contract() -> Iterator[None]:
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_revalidate_strict_writable_root_bindings",
            side_effect=lambda value: value,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_revalidate_strict_host_read_root_bindings",
            side_effect=lambda value: value,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_host_namespace_identity",
            side_effect=lambda namespace: {
                "mnt": "mnt:[101]",
                "ipc": "ipc:[102]",
                "net": "net:[103]",
            }[namespace],
        ):
            yield

    @staticmethod
    def close_retained_acquisition_descriptors() -> None:
        session = _CANDIDATE_SUPPORT._STRICT_SESSION
        if not isinstance(session, dict):
            return
        for name in ("acquisition_root_fd", "acquisition_parent_fd"):
            descriptor = session.get(name)
            if type(descriptor) is int:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @staticmethod
    def write_test_module(repo_root: Path, name: str, content: str) -> None:
        path = (
            distribution_content_root(repo_root)
            / "skills/waited-delivery/tests"
            / name
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    @staticmethod
    def required_module(*, body: str = "        pass\n") -> str:
        return (
            "import unittest\n\n"
            "class RequiredTests(unittest.TestCase):\n"
            "    def test_one(self):\n"
            f"{body}"
            "    def test_two(self):\n"
            "        pass\n"
        )

    def test_strict_live_binding_requires_exact_fresh_github_checkout(
        self,
    ) -> None:
        candidate_sha = "a" * 40
        binding = {"candidate_sha": candidate_sha}
        with tempfile.TemporaryDirectory() as temporary_directory:
            repo_root = Path(temporary_directory).resolve(strict=True)
            environment = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_SHA": candidate_sha,
                "GITHUB_WORKSPACE": str(repo_root),
                REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                REQUIRED_CI_ISOLATION_MODE_ENV: REQUIRED_CI_ISOLATION_MODE,
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
            }
            with mock.patch.dict(
                os.environ, environment, clear=True
            ), mock.patch.object(
                sys.modules[__name__], "DISTRIBUTION_PROFILE", "canonical"
            ), mock.patch.object(
                sys.modules[__name__], "REPO_ROOT", repo_root
            ), mock.patch.object(
                sys.modules[__name__], "TRUSTED_REPO_ROOT", repo_root
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "_STRICT_SESSION", None
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "_STRICT_REALM", None
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "_STRICT_BACKEND_VALIDATED", False
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "expected_candidate_sha",
                return_value=(candidate_sha, True),
            ) as expected_sha, mock.patch.object(
                _CANDIDATE_SUPPORT,
                "candidate_checkout_binding",
                return_value=binding,
            ) as checkout_binding:
                self.assertEqual(
                    _strict_runtime_live_candidate_binding(),
                    (repo_root, candidate_sha, binding),
                )

                os.environ[
                    "REQUIRED_CI_INTERNAL_ISOLATION_WATCHDOG_TOKEN"
                ] = "b" * 32
                with self.assertRaisesRegex(
                    AssertionError, "fresh owner environment"
                ):
                    _strict_runtime_live_candidate_binding()

        expected_sha.assert_called_once_with(repo_root)
        checkout_binding.assert_called_once_with(
            repo_root, candidate_sha, require_clean=True
        )

    def test_strict_live_entry_runs_exact_fixture_and_closes_before_receipt(
        self,
    ) -> None:
        candidate_root = Path("/candidate")
        candidate_sha = "a" * 40
        binding = {"candidate_sha": candidate_sha}
        process = mock.Mock(spec=subprocess.Popen)
        lock = mock.Mock()
        lock.fileno.return_value = 19
        realm = {"uid": 60000, "gid": 60000, "lock": lock}
        registry = {
            "closed": False,
            "inherited": False,
            "root": Path("/registry"),
            "target_uid": 60000,
            "watchdog_authorized": False,
            "watchdog_pidfd": 23,
            "watchdog_process": process,
        }
        events: list[str] = []

        def acquire_registry() -> dict[str, object]:
            events.append("registry")
            _CANDIDATE_SUPPORT._STRICT_SESSION = registry
            return registry

        def run_exact_fixture() -> None:
            events.append("test")
            _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = True

        def cleanup(selected: Mapping[str, object]) -> None:
            self.assertIs(selected, registry)
            events.append("cleanup")
            _CANDIDATE_SUPPORT._STRICT_SESSION = None

        def final_binding(*_args: object, **_kwargs: object) -> dict[str, object]:
            events.append("rebind")
            return binding

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            sys.modules[__name__],
            "_strict_runtime_live_candidate_binding",
            side_effect=lambda: (
                events.append("binding")
                or (candidate_root, candidate_sha, binding)
            ),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "trusted_isolation_chain_registry",
            side_effect=acquire_registry,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_active_strict_session",
            side_effect=lambda: events.append("active") or registry,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_realm",
            side_effect=lambda: events.append("realm") or realm,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "candidate_checkout_binding",
            side_effect=final_binding,
        ), mock.patch.object(
            sys.modules[__name__],
            "_close_and_verify_trusted_isolation",
            side_effect=cleanup,
        ), mock.patch.object(
            type(self),
            CI_STRICT_RUNTIME_LIVE_TEST_METHOD,
            side_effect=run_exact_fixture,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_SESSION", None
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_BACKEND_VALIDATED", False
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(_strict_runtime_live_main(), 0)

        self.assertEqual(
            events,
            ["binding", "registry", "active", "realm", "test", "cleanup", "rebind"],
        )
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(stdout.getvalue().startswith(CI_STRICT_RUNTIME_LIVE_SENTINEL))
        receipt = json.loads(
            stdout.getvalue()[len(CI_STRICT_RUNTIME_LIVE_SENTINEL) :]
        )
        self.assertEqual(
            receipt,
            {
                "schema_version": 1,
                "status": "completed",
                "candidate_sha": candidate_sha,
                "configured_python": str(
                    Path(sys.executable).resolve(strict=True)
                ),
                "configured_version": list(sys.version_info[:3]),
                "target_gid": 60000,
                "target_uid": 60000,
                "test": (
                    "TrustedCandidateTestSupervisorRegressionTests."
                    + CI_STRICT_RUNTIME_LIVE_TEST_METHOD
                ),
                "tests_run": 1,
            },
        )
        live_source = inspect.getsource(_strict_runtime_live_main)
        after_acquire = live_source.split(
            "registry = _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()",
            1,
        )[1]
        self.assertTrue(after_acquire.lstrip().startswith("try:"))

    def test_strict_live_entry_rejects_skip_after_cleanup(self) -> None:
        candidate_root = Path("/candidate")
        candidate_sha = "a" * 40
        binding = {"candidate_sha": candidate_sha}
        process = mock.Mock(spec=subprocess.Popen)
        lock = mock.Mock()
        lock.fileno.return_value = 19
        realm = {"uid": 60000, "gid": 60000, "lock": lock}
        registry = {
            "closed": False,
            "inherited": False,
            "root": Path("/registry"),
            "target_uid": 60000,
            "watchdog_authorized": False,
            "watchdog_pidfd": 23,
            "watchdog_process": process,
        }
        cleanup_calls: list[Mapping[str, object]] = []

        def skip_fixture() -> None:
            _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = True
            raise unittest.SkipTest("injected live skip")

        def cleanup(selected: Mapping[str, object]) -> None:
            cleanup_calls.append(selected)
            _CANDIDATE_SUPPORT._STRICT_SESSION = None

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            sys.modules[__name__],
            "_strict_runtime_live_candidate_binding",
            return_value=(candidate_root, candidate_sha, binding),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "trusted_isolation_chain_registry",
            side_effect=lambda: setattr(
                _CANDIDATE_SUPPORT, "_STRICT_SESSION", registry
            )
            or registry,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_active_strict_session",
            return_value=registry,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_strict_realm", return_value=realm
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "candidate_checkout_binding",
            return_value=binding,
        ), mock.patch.object(
            sys.modules[__name__],
            "_close_and_verify_trusted_isolation",
            side_effect=cleanup,
        ), mock.patch.object(
            type(self),
            CI_STRICT_RUNTIME_LIVE_TEST_METHOD,
            side_effect=skip_fixture,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_SESSION", None
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_BACKEND_VALIDATED", False
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(_strict_runtime_live_main(), 1)

        self.assertEqual(cleanup_calls, [registry])
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("did not complete exactly once", stderr.getvalue())

    def test_strict_live_entry_rejects_failure_after_cleanup(self) -> None:
        candidate_sha = "a" * 40
        binding = {"candidate_sha": candidate_sha}
        registry: dict[str, object] = {}
        realm = {"uid": 60000, "gid": 60000}
        terminal_failure = (
            "strict candidate normal namespace probe failed: "
            + _CANDIDATE_SUPPORT._strict_normal_probe_failure_details(
                {
                    "status": "completed",
                    "cleanup_status": "complete",
                    "timed_out": False,
                    "returncode": 127,
                    "process_leak_observed": False,
                    "stdout_base64": base64.b64encode(
                        b"::warning title=forged::probe-output\n"
                    ).decode("ascii"),
                    "stderr_base64": base64.b64encode(
                        (
                            ("MIDDLE-DETAIL-" * 400)
                            + "\n  ::add-mask::forged-secret\r"
                            + "\x1b[31m\u2028\u2029\u202e\u200d"
                            + "terminal-cause\x7f"
                        ).encode("utf-8")
                    ).decode("ascii"),
                }
            )
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            sys.modules[__name__],
            "_strict_runtime_live_candidate_binding",
            return_value=(Path("/candidate"), candidate_sha, binding),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "trusted_isolation_chain_registry",
            return_value=registry,
        ), mock.patch.object(
            sys.modules[__name__],
            "_strict_runtime_live_owner_realm",
            return_value=realm,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "candidate_checkout_binding",
            return_value=binding,
        ), mock.patch.object(
            sys.modules[__name__], "_close_and_verify_trusted_isolation"
        ) as cleanup, mock.patch.object(
            type(self),
            CI_STRICT_RUNTIME_LIVE_TEST_METHOD,
            side_effect=AssertionError(terminal_failure),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_SESSION", None
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_BACKEND_VALIDATED", True
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(_strict_runtime_live_main(), 1)

        cleanup.assert_called_once_with(registry)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("did not complete exactly once", stderr.getvalue())
        self.assertIn("...[middle truncated]...", stderr.getvalue())
        self.assertIn('"returncode":127', stderr.getvalue())
        self.assertIn('"process_leak_observed":false', stderr.getvalue())
        self.assertIn("terminal-cause", stderr.getvalue())
        self.assertTrue(
            all(
                not line.lstrip().startswith("::")
                for line in stderr.getvalue().split("\n")
            )
        )
        self.assertFalse(
            any(
                character in stderr.getvalue()
                for character in (
                    "\r",
                    "\x1b",
                    "\x7f",
                    "\u2028",
                    "\u2029",
                    "\u202e",
                    "\u200d",
                    "\ud800",
                    "\U000e0001",
                )
            )
        )

    def test_strict_live_entry_rejects_a_test_that_never_reaches_the_backend(
        self,
    ) -> None:
        candidate_sha = "a" * 40
        binding = {"candidate_sha": candidate_sha}
        registry: dict[str, object] = {}
        realm = {"uid": 60000, "gid": 60000}
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            sys.modules[__name__],
            "_strict_runtime_live_candidate_binding",
            return_value=(Path("/candidate"), candidate_sha, binding),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "trusted_isolation_chain_registry",
            return_value=registry,
        ), mock.patch.object(
            sys.modules[__name__],
            "_strict_runtime_live_owner_realm",
            return_value=realm,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "candidate_checkout_binding",
            return_value=binding,
        ), mock.patch.object(
            sys.modules[__name__], "_close_and_verify_trusted_isolation"
        ) as cleanup, mock.patch.object(
            type(self), CI_STRICT_RUNTIME_LIVE_TEST_METHOD, return_value=None
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_SESSION", None
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_BACKEND_VALIDATED", False
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(_strict_runtime_live_main(), 1)

        cleanup.assert_called_once_with(registry)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("did not complete exactly once", stderr.getvalue())

    def test_strict_live_entry_rejects_final_binding_or_session_drift(
        self,
    ) -> None:
        candidate_sha = "a" * 40
        binding = {"candidate_sha": candidate_sha}
        cases = {
            "binding changed": (
                {"candidate_sha": "b" * 40},
                None,
                "binding changed",
            ),
            "session remained": (
                binding,
                {"closed": False},
                "registry remained active",
            ),
        }
        for name, (final_binding, final_session, expected_error) in cases.items():
            with self.subTest(name=name):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with mock.patch.object(
                    sys.modules[__name__],
                    "_strict_runtime_live_candidate_binding",
                    return_value=(Path("/candidate"), candidate_sha, binding),
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "trusted_isolation_chain_registry",
                    return_value={},
                ), mock.patch.object(
                    sys.modules[__name__],
                    "_strict_runtime_live_owner_realm",
                    return_value={"uid": 60000, "gid": 60000},
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "candidate_checkout_binding",
                    return_value=final_binding,
                ), mock.patch.object(
                    sys.modules[__name__], "_close_and_verify_trusted_isolation"
                ), mock.patch.object(
                    type(self),
                    CI_STRICT_RUNTIME_LIVE_TEST_METHOD,
                    return_value=None,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_STRICT_SESSION", final_session
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_STRICT_BACKEND_VALIDATED", True
                ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                    stderr
                ):
                    self.assertEqual(_strict_runtime_live_main(), 1)

                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(expected_error, stderr.getvalue())

    def prepare_roots(self, temporary_directory: str) -> tuple[Path, Path]:
        root = Path(temporary_directory).resolve(strict=True)
        trusted_root = root / ".required-ci"
        candidate_root = root / ".candidate"
        self.write_test_module(
            trusted_root,
            "test_required.py",
            self.required_module(),
        )
        (
            distribution_content_root(candidate_root)
            / "skills/waited-delivery/tests"
        ).mkdir(parents=True)
        trusted_support = distribution_tests_root(trusted_root) / (
            "required_ci_candidate.py"
        )
        shutil.copyfile(TRUSTED_CANDIDATE_SUPPORT_PATH, trusted_support)
        scripts_root = (
            distribution_content_root(candidate_root)
            / "skills/waited-delivery/scripts"
        )
        scripts_root.mkdir(parents=True)
        for relative_path in _CANDIDATE_SUPPORT.CANDIDATE_SCRIPT_RELATIVE_PATHS:
            (distribution_content_root(candidate_root) / relative_path).write_text(
                "pass\n", encoding="utf-8"
            )
        return trusted_root, candidate_root

    def prepare_structure_cli_split(
        self, temporary_directory: str
    ) -> tuple[Path, Path, str]:
        trusted_root, candidate_root = self.prepare_roots(temporary_directory)
        trusted_test_path = (
            distribution_tests_root(trusted_root)
            / "test_required_ci_workflow.py"
        )
        shutil.copyfile(Path(__file__).resolve(strict=True), trusted_test_path)
        candidate_support_path = (
            distribution_tests_root(candidate_root)
            / "required_ci_candidate.py"
        )
        shutil.copyfile(TRUSTED_CANDIDATE_SUPPORT_PATH, candidate_support_path)
        workflow_path = candidate_root / ".github/workflows/required-ci.yml"
        workflow_path.parent.mkdir(parents=True)
        workflow_path.write_text(
            RequiredJobExecutionRegressionTests().required_workflow(),
            encoding="utf-8",
        )
        candidate_sha = self.initialize_candidate_checkout(candidate_root)
        return trusted_root, candidate_root, candidate_sha

    @staticmethod
    def load_candidate_support(path: Path, module_name: str):
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise AssertionError("candidate support fixture cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

    def prepare_private_candidate_checkout(
        self, root: Path
    ) -> tuple[Path, Path]:
        checkout_root = root.resolve(strict=True)
        content_root = checkout_root / "personal_codex"
        support_path = (
            content_root
            / "skills/waited-delivery/tests/required_ci_candidate.py"
        )
        support_path.parent.mkdir(parents=True)
        shutil.copyfile(TRUSTED_CANDIDATE_SUPPORT_PATH, support_path)
        for relative_path in _CANDIDATE_SUPPORT.CANDIDATE_SCRIPT_RELATIVE_PATHS:
            script_path = content_root / relative_path
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("pass\n", encoding="utf-8")
        return content_root, support_path

    def initialize_candidate_checkout(self, candidate_root: Path) -> str:
        commands = (
            [
                _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                "-C",
                str(candidate_root),
                "init",
                "--object-format=sha1",
            ],
            [
                _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                "-C",
                str(candidate_root),
                "add",
                "--all",
            ],
            [
                _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                "-C",
                str(candidate_root),
                "-c",
                "user.name=Required CI Test",
                "-c",
                "user.email=required-ci@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "candidate fixture",
            ],
        )
        for command in commands:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if completed.returncode != 0:
                raise AssertionError(completed.stderr)
        completed = subprocess.run(
            [
                _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                "-C",
                str(candidate_root),
                "rev-parse",
                "--verify",
                "HEAD^{commit}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        candidate_sha = completed.stdout.strip()
        self.assertRegex(candidate_sha, r"\A[0-9a-f]{40}\Z")
        return candidate_sha

    @staticmethod
    def candidate_workspace_archive_fixture(
        candidate_root: Path, candidate_sha: str
    ) -> tuple[
        str,
        dict[Path, tuple[str, int, bool]],
        bytes,
    ]:
        object_format = _CANDIDATE_SUPPORT._run_candidate_git(
            candidate_root,
            "rev-parse",
            "--show-object-format",
            output_limit=32,
        ).decode("ascii")
        object_format = (
            object_format[:-1]
            if object_format.endswith("\n")
            else object_format
        )
        tree_output = _CANDIDATE_SUPPORT._run_candidate_git(
            candidate_root,
            "ls-tree",
            "-r",
            "-z",
            "-l",
            "--full-tree",
            candidate_sha,
            output_limit=_CANDIDATE_SUPPORT.CANDIDATE_GIT_OUTPUT_LIMIT_BYTES,
        )
        inventory = _CANDIDATE_SUPPORT._candidate_workspace_tree_inventory(
            tree_output, object_format
        )
        archive_output = _CANDIDATE_SUPPORT._run_candidate_git(
            candidate_root,
            "-c",
            "tar.umask=0022",
            "archive",
            "--format=tar",
            candidate_sha,
            output_limit=_CANDIDATE_SUPPORT.CANDIDATE_WORKSPACE_ARCHIVE_LIMIT_BYTES,
        )
        return object_format, inventory, archive_output

    @staticmethod
    def mutate_tar_header(
        archive_output: bytes,
        header_offset: int,
        start: int,
        stop: int,
        replacement: bytes,
    ) -> bytes:
        if len(replacement) != stop - start:
            raise AssertionError("tar fixture replacement has the wrong width")
        mutated = bytearray(archive_output)
        header = bytearray(mutated[header_offset : header_offset + 512])
        if len(header) != 512:
            raise AssertionError("tar fixture header is truncated")
        header[start:stop] = replacement
        header[148:156] = b" " * 8
        checksum = sum(header)
        encoded_checksum = f"{checksum:07o}\0".encode("ascii")
        if len(encoded_checksum) != 8:
            raise AssertionError("tar fixture checksum is out of range")
        header[148:156] = encoded_checksum
        mutated[header_offset : header_offset + 512] = header
        return bytes(mutated)

    def test_private_local_binding_uses_git_checkout_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            checkout_root = Path(temporary_directory).resolve(strict=True)
            _, support_path = self.prepare_private_candidate_checkout(checkout_root)
            candidate_sha = self.initialize_candidate_checkout(checkout_root)
            support = self.load_candidate_support(
                support_path, "required_ci_candidate_private_local"
            )
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop(REQUIRED_CI_CANDIDATE_ROOT_ENV, None)
                os.environ.pop(REQUIRED_CI_CANDIDATE_SHA_ENV, None)
                os.environ.pop(REQUIRED_CI_ISOLATION_MODE_ENV, None)
                self.assertEqual(
                    support.candidate_repository_root(), checkout_root
                )
                binding = support.candidate_checkout_binding(
                    checkout_root, candidate_sha, require_clean=False
                )

        self.assertEqual(binding["candidate_root"], str(checkout_root))
        self.assertEqual(binding["candidate_distribution_profile"], "private")
        self.assertEqual(
            sorted(binding["candidate_script_sha256"]),
            sorted(
                f"personal_codex/{path.as_posix()}"
                for path in support.CANDIDATE_SCRIPT_RELATIVE_PATHS
            ),
        )

    def test_private_required_ci_binding_uses_distribution_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            trusted_root = root / ".trusted-required-ci"
            candidate_root = root / ".candidate"
            trusted_root.mkdir()
            candidate_root.mkdir()
            _, support_path = self.prepare_private_candidate_checkout(trusted_root)
            self.prepare_private_candidate_checkout(candidate_root)
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            support = self.load_candidate_support(
                support_path, "required_ci_candidate_private_split"
            )
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ):
                os.environ.pop(REQUIRED_CI_ISOLATION_MODE_ENV, None)
                binding = support.candidate_checkout_binding(
                    candidate_root, candidate_sha, require_clean=True
                )
                adapter = support.candidate_script(
                    "waited_delivery_hook_adapter.py"
                )

        self.assertEqual(binding["candidate_root"], str(candidate_root))
        self.assertEqual(binding["candidate_distribution_profile"], "private")
        self.assertEqual(
            adapter,
            candidate_root
            / "personal_codex/skills/waited-delivery/scripts/"
            "waited_delivery_hook_adapter.py",
        )

    def test_strict_primitive_accepts_an_immutable_root_owned_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "python3.12"
            target.write_text("binary", encoding="utf-8")
            link = root / "python3"
            link.symlink_to(target.name)
            root_owned_file = mock.Mock(
                st_mode=stat.S_IFREG | 0o755,
                st_uid=0,
            )
            root_owned_directory = mock.Mock(
                st_mode=stat.S_IFDIR | 0o755,
                st_uid=0,
            )
            root_owned_symlink = mock.Mock(
                st_mode=stat.S_IFLNK | 0o777,
                st_uid=0,
            )

            def fake_lstat(selected: Path):
                selected_path = Path(selected)
                if selected_path.name == link.name:
                    return root_owned_symlink
                if selected_path.name == target.name:
                    return root_owned_file
                return root_owned_directory

            with mock.patch.object(
                Path, "lstat", autospec=True, side_effect=fake_lstat
            ), mock.patch.object(Path, "stat", return_value=root_owned_file):
                _CANDIDATE_SUPPORT._validate_strict_primitive(
                    link, "Noble Python symlink"
                )

    def test_candidate_environment_never_trusts_every_git_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            environment = _CANDIDATE_SUPPORT._closed_candidate_environment(
                {}, home=root, temporary_root=root
            )

        self.assertNotIn("*", environment.values())

    def test_candidate_environment_resolves_the_bound_git_without_a_platform_shim(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            environment = _CANDIDATE_SUPPORT._closed_candidate_environment(
                {}, home=root, temporary_root=root
            )

        selected = shutil.which("git", path=environment["PATH"])
        self.assertIsNotNone(selected)
        self.assertEqual(
            Path(str(selected)).resolve(strict=True),
            Path(_CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE),
        )

    def test_candidate_git_binding_rejects_object_and_access_policy_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            tool_root = root / "tool"
            bin_root = tool_root / "bin"
            bin_root.mkdir(parents=True)
            executable = bin_root / "git"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            binding = _CANDIDATE_SUPPORT._capture_trusted_git_binding(
                executable
            )
            self.assertEqual(
                _CANDIDATE_SUPPORT._revalidate_trusted_git_binding(binding),
                executable,
            )

            executable.chmod(0o644)
            with self.assertRaisesRegex(AssertionError, "not executable"):
                _CANDIDATE_SUPPORT._revalidate_trusted_git_binding(binding)
            executable.chmod(0o755)

            replaced = bin_root / "git.replaced"
            executable.rename(replaced)
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            with self.assertRaisesRegex(AssertionError, "object identity changed"):
                _CANDIDATE_SUPPORT._revalidate_trusted_git_binding(binding)
            executable.unlink()
            replaced.rename(executable)

            old_tool_root = root / "tool.old"
            tool_root.rename(old_tool_root)
            shutil.copytree(old_tool_root, tool_root)
            with self.assertRaisesRegex(AssertionError, "object identity changed"):
                _CANDIDATE_SUPPORT._revalidate_trusted_git_binding(binding)

            with self.assertRaisesRegex(AssertionError, "not absolute"):
                _CANDIDATE_SUPPORT._capture_trusted_git_binding(
                    Path("relative/git")
                )
            with self.assertRaisesRegex(AssertionError, "unsafe object type"):
                _CANDIDATE_SUPPORT._capture_trusted_git_binding(tool_root)

    def test_strict_non_linux_preflight_runs_before_git_or_candidate_popen(
        self,
    ) -> None:
        with mock.patch.dict(
            os.environ,
            {REQUIRED_CI_ISOLATION_MODE_ENV: REQUIRED_CI_ISOLATION_MODE},
            clear=False,
        ), mock.patch.object(sys, "platform", "darwin"), mock.patch.object(
            subprocess, "run"
        ) as run_process, mock.patch.object(
            subprocess, "Popen"
        ) as popen_process:
            with self.assertRaisesRegex(
                AssertionError, "requires Linux procfs before any subprocess"
            ):
                _CANDIDATE_SUPPORT.run_candidate_python(
                    _CANDIDATE_SUPPORT.candidate_script(
                        "waited_delivery_runner.py"
                    )
                )

        run_process.assert_not_called()
        popen_process.assert_not_called()

    def test_pidfd_syscall_probe_fails_before_any_subprocess(self) -> None:
        previous_validated = _CANDIDATE_SUPPORT._STRICT_PLATFORM_VALIDATED
        _CANDIDATE_SUPPORT._STRICT_PLATFORM_VALIDATED = False
        try:
            with mock.patch.dict(
                os.environ,
                {REQUIRED_CI_ISOLATION_MODE_ENV: REQUIRED_CI_ISOLATION_MODE},
                clear=False,
            ), mock.patch.object(sys, "platform", "linux"), mock.patch.object(
                Path, "is_file", return_value=True
            ), mock.patch.object(
                os,
                "pidfd_open",
                side_effect=PermissionError("injected pidfd denial"),
                create=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.signal, "pidfd_send_signal", create=True
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "_validate_strict_primitive"
            ) as validate_primitive, mock.patch.object(
                subprocess, "run"
            ) as run_process, mock.patch.object(
                subprocess, "Popen"
            ) as popen_process:
                with self.assertRaisesRegex(
                    AssertionError, "cannot use pidfd signaling"
                ):
                    _CANDIDATE_SUPPORT.strict_isolation_platform_preflight()
        finally:
            _CANDIDATE_SUPPORT._STRICT_PLATFORM_VALIDATED = previous_validated

        validate_primitive.assert_not_called()
        run_process.assert_not_called()
        popen_process.assert_not_called()

    def test_root_controller_reprobes_pidfd_before_first_child_popen(self) -> None:
        source = inspect.getsource(_CANDIDATE_SUPPORT._root_controller_main)

        self.assertLess(
            source.index("_probe_pidfd_capability()"),
            source.index("subprocess.Popen("),
        )

    def test_root_controller_cleanup_is_mandatory_on_every_exit(self) -> None:
        controller_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_controller_main
        )
        outer_source = inspect.getsource(
            _CANDIDATE_SUPPORT._invoke_strict_controller
        )
        registered_source = inspect.getsource(
            _CANDIDATE_SUPPORT._run_registered_sudo_under_gate
        )
        cleanup_source = inspect.getsource(
            _CANDIDATE_SUPPORT._invoke_registered_session_cleanup
        )
        self.assertIn("finally:", controller_source)
        self.assertIn("_root_close_candidate_realm", controller_source)
        self.assertIn("_run_registered_sudo", outer_source)
        self.assertIn("finally:", registered_source)
        self.assertIn("_recover_registered_entry", registered_source)
        self.assertIn("recovery_broker=True", cleanup_source)
        self.assertIn("--isolation-cleanup", cleanup_source)

    def test_sudo_monitor_topology_uses_a_root_identity_handshake(self) -> None:
        binder_source = inspect.getsource(
            _CANDIDATE_SUPPORT._bind_root_controller_parent
        )
        controller_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_controller_main
        )
        outer_source = inspect.getsource(
            _CANDIDATE_SUPPORT._invoke_strict_controller
        )
        cleanup_source = inspect.getsource(
            _CANDIDATE_SUPPORT._invoke_registered_session_cleanup
        )
        cleanup_main_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_cleanup_main
        )

        self.assertNotIn("expected_parent_pid", binder_source)
        self.assertNotIn("expected_parent_value", controller_source)
        self.assertIn("_write_root_controller_handshake", controller_source)
        self.assertIn('config.get("handshake_path")', controller_source)
        self.assertIn('"handshake_path"', outer_source)
        self.assertIn("_run_registered_sudo", outer_source)
        self.assertIn("str(entry_path)", cleanup_source)
        self.assertIn("_root_close_registered_host_session", cleanup_main_source)
        self.assertIn("_root_close_candidate_realm", cleanup_main_source)

    def test_root_cleanup_signals_only_validated_pidfds(self) -> None:
        candidate_signal_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_signal_identity
        )
        root_signal_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_signal_host_identity
        )

        for source in (candidate_signal_source, root_signal_source):
            self.assertIn("os.pidfd_open", source)
            self.assertIn("signal.pidfd_send_signal", source)
            self.assertNotIn("os.kill(", source)

    def test_trusted_parent_holds_the_candidate_realm_through_child_exit(
        self,
    ) -> None:
        supervisor_source = inspect.getsource(
            supervise_trusted_required_ci_tests
        )
        close_source = inspect.getsource(
            _close_and_verify_trusted_isolation
        )

        self.assertIn("trusted_isolation_child_environment", supervisor_source)
        self.assertIn("pass_fds=", supervisor_source)
        self.assertIn("finally:", supervisor_source)
        self.assertIn("_close_and_verify_trusted_isolation", supervisor_source)
        self.assertIn("assert_candidate_isolation_quiescent", close_source)

    def test_registry_watchdog_replays_on_owner_eof_or_heartbeat_timeout(
        self,
    ) -> None:
        token = "c" * 32
        registry_token = "d" * 32
        identity = (123, 456, 123, 123, 123, (os.getuid(),) * 4)
        session = {
            "environment": {
                _CANDIDATE_SUPPORT._ISOLATION_REGISTRY_ENV: "/tmp/entries",
                _CANDIDATE_SUPPORT._ISOLATION_REGISTRY_TOKEN_ENV: registry_token,
            },
            "watchdog_authorized": True,
        }
        for failure_mode in ("eof", "timeout"):
            with self.subTest(failure_mode=failure_mode):
                input_stream = mock.Mock()
                input_stream.fileno.return_value = 42
                readable = ([42], [], []) if failure_mode == "eof" else ([], [], [])
                read_result = b"" if failure_mode == "eof" else b"unused"
                captured = io.StringIO()
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "strict_isolation_platform_preflight",
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_active_strict_session",
                    return_value=session,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_process_identity",
                    return_value=identity,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_root_signal_host_identity"
                ) as signal_parent, mock.patch.object(
                    _CANDIDATE_SUPPORT, "_watchdog_close_runner_clients"
                ) as close_clients, mock.patch.object(
                    _CANDIDATE_SUPPORT, "close_trusted_isolation_chains"
                ) as close_registry, mock.patch.object(
                    _CANDIDATE_SUPPORT.select,
                    "select",
                    return_value=readable,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT.os,
                    "read",
                    return_value=read_result,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT.sys, "stdin", input_stream
                ), contextlib.redirect_stdout(captured):
                    returncode = _CANDIDATE_SUPPORT._registry_watchdog_main(
                        ("123", "456", "123", "123", token)
                    )

                self.assertEqual(returncode, 0, captured.getvalue())
                signal_parent.assert_called_once_with(
                    identity, _CANDIDATE_SUPPORT.signal.SIGKILL
                )
                close_clients.assert_called_once_with(
                    Path("/tmp/entries"), registry_token
                )
                close_registry.assert_called_once_with(session)
                self.assertIn(
                    f"{_CANDIDATE_SUPPORT._WATCHDOG_RESULT_PREFIX}",
                    captured.getvalue(),
                )

    def test_watchdog_ready_broken_pipe_replays_after_bootstrap_acceptance(
        self,
    ) -> None:
        root = Path("/tmp/required-ci-watchdog-ready-broken-fixture")
        token = "a" * 32
        owner = (61001, 777, 42, 61001, 61001, (os.getuid(),) * 4)
        session = {
            "watchdog_authorized": True,
            "environment": {
                _CANDIDATE_SUPPORT._ISOLATION_REGISTRY_ENV: str(root),
                _CANDIDATE_SUPPORT._ISOLATION_REGISTRY_TOKEN_ENV: token,
            },
        }
        gate_read_fd, gate_write_fd = os.pipe()
        os.write(gate_write_fd, b"G")
        os.close(gate_write_fd)
        printed = mock.Mock(
            side_effect=(BrokenPipeError("injected READY loss"), None)
        )
        try:
            with mock.patch.object(
                _CANDIDATE_SUPPORT, "strict_isolation_platform_preflight"
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_active_strict_session",
                return_value=session,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_process_identity",
                return_value=owner,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "_root_signal_host_identity"
            ) as signal_owner, mock.patch.object(
                _CANDIDATE_SUPPORT, "_watchdog_close_runner_clients"
            ) as close_clients, mock.patch.object(
                _CANDIDATE_SUPPORT, "close_trusted_isolation_chains"
            ) as close_registry, mock.patch.object(
                _CANDIDATE_SUPPORT, "print", printed, create=True
            ):
                returncode = _CANDIDATE_SUPPORT._registry_watchdog_main(
                    [
                        str(owner[0]),
                        str(owner[1]),
                        str(owner[3]),
                        str(owner[4]),
                        token,
                        str(gate_read_fd),
                    ]
                )
        finally:
            try:
                os.close(gate_read_fd)
            except OSError:
                pass

        self.assertEqual(returncode, 1)
        signal_owner.assert_called_once_with(owner, signal.SIGKILL)
        close_clients.assert_called_once_with(root, token)
        close_registry.assert_called_once_with(session)

    def test_registry_watchdog_is_durable_before_registry_acquisition_returns(
        self,
    ) -> None:
        acquire_source = inspect.getsource(
            _CANDIDATE_SUPPORT.trusted_isolation_chain_registry
        )
        initialize_source = inspect.getsource(
            _CANDIDATE_SUPPORT._initialize_bound_registry_acquisition
        )
        watchdog_source = inspect.getsource(
            _CANDIDATE_SUPPORT._registry_watchdog_main
        )
        watchdog_replay_source = inspect.getsource(
            _CANDIDATE_SUPPORT._registry_watchdog_replay
        )
        close_source = inspect.getsource(
            _CANDIDATE_SUPPORT.close_trusted_isolation_chains
        )

        self.assertLess(
            initialize_source.index("_start_registry_watchdog"),
            initialize_source.index("_active_strict_session"),
        )
        self.assertIn(
            "return _initialize_bound_registry_acquisition", acquire_source
        )
        self.assertIn("select.select", watchdog_source)
        self.assertIn("_STRICT_WATCHDOG_TIMEOUT_SECONDS", watchdog_source)
        self.assertIn("_registry_watchdog_replay", watchdog_source)
        self.assertIn("_watchdog_close_runner_clients", watchdog_replay_source)
        self.assertIn("close_trusted_isolation_chains(session)", watchdog_source)
        self.assertIn("_close_registry_through_watchdog", close_source)

    def test_watchdog_owner_pid_reuse_skips_signal_but_still_replays(self) -> None:
        token = "e" * 32
        registry_token = "f" * 32
        replacement = (123, 999, 123, 123, 123, (os.getuid(),) * 4)
        session = {
            "environment": {
                _CANDIDATE_SUPPORT._ISOLATION_REGISTRY_ENV: "/tmp/entries",
                _CANDIDATE_SUPPORT._ISOLATION_REGISTRY_TOKEN_ENV: registry_token,
            },
            "watchdog_authorized": True,
        }
        input_stream = mock.Mock()
        input_stream.fileno.return_value = 42
        captured = io.StringIO()
        with mock.patch.object(
            _CANDIDATE_SUPPORT, "strict_isolation_platform_preflight"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_active_strict_session",
            return_value=session,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_process_identity",
            return_value=replacement,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_root_signal_host_identity"
        ) as signal_parent, mock.patch.object(
            _CANDIDATE_SUPPORT, "_watchdog_close_runner_clients"
        ) as close_clients, mock.patch.object(
            _CANDIDATE_SUPPORT, "close_trusted_isolation_chains"
        ) as close_registry, mock.patch.object(
            _CANDIDATE_SUPPORT.select,
            "select",
            return_value=([42], [], []),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os, "read", return_value=b""
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.sys, "stdin", input_stream
        ), contextlib.redirect_stdout(captured):
            returncode = _CANDIDATE_SUPPORT._registry_watchdog_main(
                ("123", "456", "123", "123", token)
            )

        self.assertEqual(returncode, 0, captured.getvalue())
        signal_parent.assert_not_called()
        close_clients.assert_called_once_with(
            Path("/tmp/entries"), registry_token
        )
        close_registry.assert_called_once_with(session)

    def test_watchdog_owner_loss_replay_persists_until_success(self) -> None:
        parent_identity = (123, 456, 123, 123)
        session: dict[str, object] = {"root": Path("/tmp/registry")}
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_registry_watchdog_replay",
            side_effect=(
                AssertionError("injected first replay failure"),
                AssertionError("injected second replay failure"),
                None,
            ),
        ) as replay, mock.patch.object(
            _CANDIDATE_SUPPORT.time, "sleep"
        ) as sleep:
            _CANDIDATE_SUPPORT._registry_watchdog_replay_until_complete(
                parent_identity, session
            )

        self.assertEqual(replay.call_count, 3)
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [
                _CANDIDATE_SUPPORT._STRICT_WATCHDOG_REPLAY_BACKOFF_INITIAL_SECONDS,
                _CANDIDATE_SUPPORT._STRICT_WATCHDOG_REPLAY_BACKOFF_INITIAL_SECONDS
                * 2,
            ],
        )
        main_source = inspect.getsource(
            _CANDIDATE_SUPPORT._registry_watchdog_main
        )
        self.assertGreaterEqual(
            main_source.count("_registry_watchdog_replay_until_complete"), 2
        )

    def test_watchdog_pidfd_failure_reaps_gated_launch_by_eof(
        self,
    ) -> None:
        real_popen = subprocess.Popen

        class GatedFixtureProcess(real_popen):
            instances: list["GatedFixtureProcess"] = []

            def __init__(self, *args: object, **kwargs: object) -> None:
                self.pid = 62001
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.returncode: int | None = None
                self.waited = False
                self.gate_fd = os.dup(kwargs["pass_fds"][-1])
                type(self).instances.append(self)

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                self.waited = True
                if self.gate_fd >= 0:
                    os.close(self.gate_fd)
                    self.gate_fd = -1
                self.returncode = 0
                return 0

        session: dict[str, object] = {
            "controller_path": Path("/tmp/controller.py"),
            "environment": {},
            "watchdog_token": "a" * 32,
        }
        stderr = io.BytesIO()
        parent_identity = (
            os.getpid(),
            111,
            os.getpid(),
            os.getpid(),
            os.getpid(),
            (os.getuid(),) * 4,
        )
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_registry_watchdog_lock_descriptor",
            return_value=41,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os,
            "pipe2",
            side_effect=lambda _flags: os.pipe(),
            create=True,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_realm",
            return_value={"uid": 60000, "gid": 60000},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_minimal_supervisor_environment",
            return_value={},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_process_identity",
            return_value=parent_identity,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.tempfile,
            "TemporaryFile",
            return_value=stderr,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.subprocess,
            "Popen",
            GatedFixtureProcess,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os,
            "pidfd_open",
            side_effect=OSError("injected pidfd exhaustion"),
            create=True,
        ):
            with self.assertRaisesRegex(OSError, "pidfd exhaustion"):
                _CANDIDATE_SUPPORT._start_registry_watchdog(session)

        self.assertEqual(len(GatedFixtureProcess.instances), 1)
        process = GatedFixtureProcess.instances[0]
        self.assertTrue(process.waited)
        self.assertEqual(process.returncode, 0)
        self.assertTrue(stderr.closed)
        self.assertNotIn("watchdog_launch", session)
        self.assertNotIn("watchdog_process", session)

    def test_watchdog_popen_return_window_backfills_exact_launch_state(
        self,
    ) -> None:
        real_popen = subprocess.Popen

        class GatedFixtureProcess(real_popen):
            instance: "GatedFixtureProcess | None" = None

            def __init__(self, *args: object, **kwargs: object) -> None:
                self.pid = 62004
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.returncode: int | None = None
                self.waited = False
                self.gate_fd = os.dup(kwargs["pass_fds"][-1])
                type(self).instance = self

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                self.waited = True
                if self.gate_fd >= 0:
                    os.close(self.gate_fd)
                    self.gate_fd = -1
                self.returncode = 0
                return 0

        session: dict[str, object] = {
            "controller_path": Path("/tmp/controller.py"),
            "environment": {},
            "watchdog_token": "d" * 32,
        }
        stderr = io.BytesIO()
        parent_identity = (
            os.getpid(),
            111,
            os.getpid(),
            os.getpid(),
            os.getpid(),
            (os.getuid(),) * 4,
        )
        function = _CANDIDATE_SUPPORT._start_registry_watchdog
        source_lines, source_start = inspect.getsourcelines(function)
        publication_line = source_start + next(
            index
            for index, line in enumerate(source_lines)
            if 'launch["process"] = process' in line
        )

        def inject_after_popen(frame, event: str, argument):
            if (
                frame.f_code is function.__code__
                and event == "line"
                and frame.f_lineno == publication_line
            ):
                raise RuntimeError("injected post-Popen publication fault")
            return inject_after_popen

        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_registry_watchdog_lock_descriptor",
            return_value=41,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os,
            "pipe2",
            side_effect=lambda _flags: os.pipe(),
            create=True,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_realm",
            return_value={"uid": 60000, "gid": 60000},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_minimal_supervisor_environment",
            return_value={},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_process_identity",
            return_value=parent_identity,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.tempfile,
            "TemporaryFile",
            return_value=stderr,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.subprocess,
            "Popen",
            GatedFixtureProcess,
        ):
            sys.settrace(inject_after_popen)
            try:
                with self.assertRaisesRegex(
                    RuntimeError, "post-Popen publication fault"
                ):
                    function(session)
            finally:
                sys.settrace(None)

        process = GatedFixtureProcess.instance
        self.assertIsNotNone(process)
        self.assertTrue(process.waited)
        self.assertEqual(process.returncode, 0)
        self.assertTrue(stderr.closed)
        self.assertNotIn("watchdog_launch", session)

    def test_authorized_watchdog_launch_abort_uses_drain_not_owner_loss(
        self,
    ) -> None:
        real_popen = subprocess.Popen

        class AbortFixtureProcess(real_popen):
            def __init__(self) -> None:
                self.pid = 62003
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                self.returncode = 0
                return 0

        process = AbortFixtureProcess()
        identity = (
            process.pid,
            222,
            process.pid,
            process.pid,
            process.pid,
            (os.getuid(),) * 4,
        )
        launch = {
            "process": process,
            "pidfd": 42,
            "identity": identity,
            "stop_event": threading.Event(),
            "write_lock": threading.Lock(),
            "heartbeat": None,
        }
        token = "e" * 32
        result = (
            _CANDIDATE_SUPPORT._WATCHDOG_RESULT_PREFIX
            + json.dumps({"status": "complete", "token": token})
            + "\n"
        ).encode("ascii")
        with mock.patch.object(
            _CANDIDATE_SUPPORT.subprocess,
            "Popen",
            AbortFixtureProcess,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_process_identity",
            return_value=identity,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.signal,
            "pidfd_send_signal",
            create=True,
        ) as pidfd_signal, mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_read_watchdog_line",
            return_value=result,
        ):
            _CANDIDATE_SUPPORT._drain_authorized_watchdog_launch(
                launch, token
            )

        self.assertEqual(process.stdin.getvalue(), b"D\n")
        self.assertEqual(process.returncode, 0)
        pidfd_signal.assert_called_once_with(42, 0, None, 0)

    def test_watchdog_gate_release_is_monotonic_before_post_write_fault(
        self,
    ) -> None:
        real_popen = subprocess.Popen

        class GateFixtureProcess(real_popen):
            instance: "GateFixtureProcess | None" = None

            def __init__(self, *args: object, **kwargs: object) -> None:
                self.pid = 62008
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.returncode: int | None = None
                self.gate_fd = os.dup(kwargs["pass_fds"][-1])
                type(self).instance = self

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                self.returncode = 0
                return 0

        session: dict[str, object] = {
            "controller_path": Path("/tmp/controller.py"),
            "environment": {},
            "watchdog_token": "d" * 32,
        }
        stderr = io.BytesIO()
        parent_identity = (
            os.getpid(),
            111,
            os.getpid(),
            os.getpid(),
            os.getpid(),
            (os.getuid(),) * 4,
        )
        child_identity = (
            62008,
            222,
            62008,
            62008,
            62008,
            (os.getuid(),) * 4,
        )
        pidfd_read, pidfd_write = os.pipe()
        terminate_values: list[bool] = []
        function = _CANDIDATE_SUPPORT._start_registry_watchdog
        source_lines, source_start = inspect.getsourcelines(function)
        post_write_line = source_start + next(
            index
            for index, line in enumerate(source_lines)
            if "os.close(gate_write_fd)" in line
        )

        def inject_after_gate_write(frame, event: str, argument):
            if (
                frame.f_code is function.__code__
                and event == "line"
                and frame.f_lineno == post_write_line
            ):
                raise RuntimeError("injected post-gate-write fault")
            return inject_after_gate_write

        def finish_process() -> None:
            process = GateFixtureProcess.instance
            self.assertIsNotNone(process)
            if process.gate_fd >= 0:
                os.close(process.gate_fd)
                process.gate_fd = -1
            process.returncode = 0

        def drain_authorized(
            _launch: Mapping[str, object], _token: str
        ) -> None:
            finish_process()

        def retire(
            _session: dict[str, object], *, terminate: bool
        ) -> list[str]:
            terminate_values.append(terminate)
            finish_process()
            return []

        try:
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_registry_watchdog_lock_descriptor",
                return_value=41,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.os,
                "pipe2",
                side_effect=lambda _flags: os.pipe(),
                create=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_realm",
                return_value={"uid": 60000, "gid": 60000},
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_minimal_supervisor_environment",
                return_value={},
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_process_identity",
                side_effect=(parent_identity, child_identity),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.tempfile,
                "TemporaryFile",
                return_value=stderr,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.subprocess,
                "Popen",
                GateFixtureProcess,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.os,
                "pidfd_open",
                return_value=pidfd_read,
                create=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_drain_authorized_watchdog_launch",
                side_effect=drain_authorized,
            ) as drain:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_retire_registry_watchdog_handles",
                    side_effect=retire,
                ):
                    sys.settrace(inject_after_gate_write)
                    try:
                        with self.assertRaisesRegex(
                            RuntimeError, "post-gate-write fault"
                        ):
                            function(session)
                    finally:
                        sys.settrace(None)
        finally:
            os.close(pidfd_read)
            os.close(pidfd_write)
            stderr.close()

        drain.assert_called_once()
        self.assertEqual(terminate_values, [False])

    def test_watchdog_heartbeat_start_failure_stops_published_thread(
        self,
    ) -> None:
        real_popen = subprocess.Popen
        real_thread = threading.Thread

        class ReadyFixtureProcess(real_popen):
            def __init__(self, *args: object, **kwargs: object) -> None:
                self.pid = 62002
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.returncode: int | None = None
                self.gate_fd = os.dup(kwargs["pass_fds"][-1])

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                if self.gate_fd >= 0:
                    os.close(self.gate_fd)
                    self.gate_fd = -1
                self.returncode = 0
                return 0

        class FailingHeartbeat(real_thread):
            instance: "FailingHeartbeat | None" = None

            def __init__(self, *args: object, **kwargs: object) -> None:
                self.fixture_args = kwargs.get("args", ())
                self.fixture_alive = False
                self.joined = False
                type(self).instance = self

            def start(self) -> None:
                self.fixture_alive = True
                raise RuntimeError("injected heartbeat start failure")

            def is_alive(self) -> bool:
                return self.fixture_alive

            def join(self, timeout: float | None = None) -> None:
                self.joined = True
                self.fixture_alive = False

        session: dict[str, object] = {
            "controller_path": Path("/tmp/controller.py"),
            "environment": {},
            "watchdog_token": "b" * 32,
        }
        stderr = io.BytesIO()
        parent_identity = (
            os.getpid(),
            111,
            os.getpid(),
            os.getpid(),
            os.getpid(),
            (os.getuid(),) * 4,
        )
        child_identity = (
            62002,
            222,
            62002,
            62002,
            62002,
            (os.getuid(),) * 4,
        )
        pidfd_read, pidfd_write = os.pipe()
        try:
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_registry_watchdog_lock_descriptor",
                return_value=41,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.os,
                "pipe2",
                side_effect=lambda _flags: os.pipe(),
                create=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_realm",
                return_value={"uid": 60000, "gid": 60000},
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_minimal_supervisor_environment",
                return_value={},
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_process_identity",
                side_effect=(parent_identity, child_identity),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.tempfile,
                "TemporaryFile",
                return_value=stderr,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.subprocess,
                "Popen",
                ReadyFixtureProcess,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.os,
                "pidfd_open",
                return_value=pidfd_read,
                create=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_read_watchdog_line",
                return_value=(
                    f"{_CANDIDATE_SUPPORT._WATCHDOG_READY_PREFIX}"
                    f"{'b' * 32}\n"
                ).encode("ascii"),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.threading,
                "Thread",
                FailingHeartbeat,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_drain_authorized_watchdog_launch",
            ) as drain_authorized:
                with self.assertRaisesRegex(
                    RuntimeError, "heartbeat start failure"
                ):
                    _CANDIDATE_SUPPORT._start_registry_watchdog(session)
        finally:
            os.close(pidfd_write)

        heartbeat = FailingHeartbeat.instance
        self.assertIsNotNone(heartbeat)
        self.assertTrue(heartbeat.joined)
        stop_event = heartbeat.fixture_args[1]
        self.assertIsInstance(stop_event, threading.Event)
        self.assertTrue(stop_event.is_set())
        self.assertTrue(stderr.closed)
        self.assertNotIn("watchdog_launch", session)
        drain_authorized.assert_called_once()

    def test_watchdog_post_heartbeat_publication_failure_drains_authority(
        self,
    ) -> None:
        real_popen = subprocess.Popen

        class ReadyFixtureProcess(real_popen):
            def __init__(self, *args: object, **kwargs: object) -> None:
                self.pid = 62005
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.returncode: int | None = None
                self.gate_fd = os.dup(kwargs["pass_fds"][-1])

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                if self.gate_fd >= 0:
                    os.close(self.gate_fd)
                    self.gate_fd = -1
                self.returncode = 0
                return 0

        class FailingSession(dict[str, object]):
            def update(self, *args: object, **kwargs: object) -> None:
                values = dict(*args, **kwargs)
                if "watchdog_process" in values:
                    raise RuntimeError(
                        "injected post-heartbeat publication failure"
                    )
                super().update(values)

        session: dict[str, object] = FailingSession(
            {
                "controller_path": Path("/tmp/controller.py"),
                "environment": {},
                "watchdog_token": "f" * 32,
            }
        )
        stderr = io.BytesIO()
        parent_identity = (
            os.getpid(),
            111,
            os.getpid(),
            os.getpid(),
            os.getpid(),
            (os.getuid(),) * 4,
        )
        child_identity = (
            62005,
            222,
            62005,
            62005,
            62005,
            (os.getuid(),) * 4,
        )
        pidfd_read, pidfd_write = os.pipe()
        try:
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_registry_watchdog_lock_descriptor",
                return_value=41,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.os,
                "pipe2",
                side_effect=lambda _flags: os.pipe(),
                create=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_realm",
                return_value={"uid": 60000, "gid": 60000},
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_minimal_supervisor_environment",
                return_value={},
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_process_identity",
                side_effect=(parent_identity, child_identity),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.tempfile,
                "TemporaryFile",
                return_value=stderr,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.subprocess,
                "Popen",
                ReadyFixtureProcess,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.os,
                "pidfd_open",
                return_value=pidfd_read,
                create=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_read_watchdog_line",
                return_value=(
                    f"{_CANDIDATE_SUPPORT._WATCHDOG_READY_PREFIX}"
                    f"{'f' * 32}\n"
                ).encode("ascii"),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_drain_authorized_watchdog_launch",
            ) as drain_authorized:
                with self.assertRaisesRegex(
                    RuntimeError, "post-heartbeat publication failure"
                ):
                    _CANDIDATE_SUPPORT._start_registry_watchdog(session)
        finally:
            os.close(pidfd_write)

        drain_authorized.assert_called_once()
        self.assertTrue(stderr.closed)
        self.assertNotIn("watchdog_launch", session)
        self.assertNotIn("watchdog_process", session)

    def test_watchdog_partial_frame_obeys_monotonic_deadline(self) -> None:
        stream = mock.Mock()
        stream.fileno.return_value = 42
        with mock.patch.object(
            _CANDIDATE_SUPPORT.time,
            "monotonic",
            side_effect=(10.0, 10.0, 10.02),
        ) as monotonic, mock.patch.object(
            _CANDIDATE_SUPPORT.select,
            "select",
            return_value=([42], [], []),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os,
            "read",
            return_value=b"X",
        ):
            with self.assertRaisesRegex(AssertionError, "timed out"):
                _CANDIDATE_SUPPORT._read_watchdog_line(
                    stream, 0.01, "partial-frame"
                )
        self.assertEqual(monotonic.call_count, 3)

    def test_dead_watchdog_does_not_block_owner_close_recovery(self) -> None:
        root = Path("/tmp/required-ci-dead-watchdog-fixture")
        session = {
            "root": root,
            "watchdog_process": mock.Mock(),
            "watchdog_authorized": False,
            "inherited": False,
        }
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_current_strict_session_unchecked",
            return_value=session,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_active_strict_session",
            side_effect=AssertionError("injected dead watchdog health failure"),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_close_registry_through_watchdog"
        ) as close_watchdog:
            _CANDIDATE_SUPPORT.close_trusted_isolation_chains(
                {"root": root}
            )

        close_watchdog.assert_called_once_with(session)

    def test_owner_session_without_watchdog_fails_health_check(self) -> None:
        session = {
            "root": Path("/tmp/required-ci-missing-watchdog-fixture"),
            "inherited": False,
            "closed": False,
            "watchdog_authorized": False,
        }

        with self.assertRaisesRegex(
            AssertionError, "watchdog.*state|watchdog.*active"
        ):
            _CANDIDATE_SUPPORT._assert_registry_watchdog_alive(session)

        malformed = dict(session)
        malformed.pop("inherited")
        with self.assertRaisesRegex(
            AssertionError, "ownership.*malformed"
        ):
            _CANDIDATE_SUPPORT._assert_registry_watchdog_alive(malformed)

    def test_unreaped_watchdog_is_never_restarted_or_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            process = mock.Mock(spec=subprocess.Popen)
            process.poll.return_value = None
            process.stdin = mock.Mock()
            process.stdin.write.side_effect = BrokenPipeError(
                "injected watchdog control failure"
            )
            process.stdout = io.BytesIO()
            heartbeat = threading.Thread(target=lambda: None)
            heartbeat.start()
            heartbeat.join()
            session = {
                "root": root,
                "watchdog_process": process,
                "watchdog_pidfd": 42,
                "watchdog_identity": (
                    123,
                    456,
                    123,
                    123,
                    123,
                    (os.getuid(),) * 4,
                ),
                "watchdog_stderr": io.BytesIO(),
                "watchdog_stop": threading.Event(),
                "watchdog_write_lock": threading.Lock(),
                "watchdog_failures": [],
                "watchdog_heartbeat": heartbeat,
                "watchdog_closing": False,
                "watchdog_token": "a" * 32,
            }

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_retire_registry_watchdog_handles",
                return_value=["watchdog reap: injected timeout"],
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "_start_registry_watchdog"
            ) as restart:
                with self.assertRaisesRegex(
                    AssertionError, "watchdog close failed"
                ):
                    _CANDIDATE_SUPPORT._close_registry_through_watchdog(
                        session
                    )

            restart.assert_not_called()
            self.assertIs(session["watchdog_process"], process)
            self.assertEqual(session["watchdog_pidfd"], 42)

    def test_terminal_watchdog_cleanup_never_starts_unfenced_successor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            process = mock.Mock(spec=subprocess.Popen)
            process.poll.return_value = None
            process.stdin = mock.Mock()
            process.stdin.write.side_effect = BrokenPipeError(
                "injected watchdog control failure"
            )
            process.stdout = io.BytesIO()
            heartbeat = threading.Thread(target=lambda: None)
            heartbeat.start()
            heartbeat.join()
            session = {
                "root": root,
                "watchdog_process": process,
                "watchdog_pidfd": 42,
                "watchdog_identity": (
                    123,
                    456,
                    123,
                    123,
                    123,
                    (os.getuid(),) * 4,
                ),
                "watchdog_stderr": io.BytesIO(),
                "watchdog_stop": threading.Event(),
                "watchdog_write_lock": threading.Lock(),
                "watchdog_failures": [],
                "watchdog_heartbeat": heartbeat,
                "watchdog_closing": False,
                "watchdog_token": "a" * 32,
            }

            def retire(
                selected: dict[str, object], *, terminate: bool
            ) -> list[str]:
                self.assertFalse(terminate)
                for key in tuple(selected):
                    if str(key).startswith("watchdog_") and key not in (
                        "watchdog_authorized",
                        "watchdog_token",
                    ):
                        selected.pop(key, None)
                return ["watchdog stderr close: injected diagnostic"]

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_retire_registry_watchdog_handles",
                side_effect=retire,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "_start_registry_watchdog"
            ) as restart:
                with self.assertRaisesRegex(
                    AssertionError, "watchdog close failed"
                ):
                    _CANDIDATE_SUPPORT._close_registry_through_watchdog(
                        session, retry=False
                    )

            restart.assert_not_called()

    def test_owner_close_rejects_missing_watchdog_without_unfenced_restart(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            session = {
                "root": root,
                "inherited": False,
                "watchdog_authorized": False,
                "closed": False,
            }
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_current_strict_session_unchecked",
                return_value=session,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "_start_registry_watchdog"
            ) as restart, mock.patch.object(
                _CANDIDATE_SUPPORT, "_close_registry_through_watchdog"
            ) as close_watchdog, mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_close_trusted_isolation_chains_under_gate",
            ) as synchronous_close:
                with self.assertRaisesRegex(
                    AssertionError, "watchdog.*unavailable|watchdog.*missing"
                ):
                    _CANDIDATE_SUPPORT.close_trusted_isolation_chains(session)

            restart.assert_not_called()
            close_watchdog.assert_not_called()
            synchronous_close.assert_not_called()

    def test_parent_registry_exists_before_backend_or_child_environment(self) -> None:
        supervisor_source = inspect.getsource(
            supervise_trusted_required_ci_tests
        )
        backend_source = inspect.getsource(
            _CANDIDATE_SUPPORT._ensure_strict_backend
        )

        self.assertLess(
            supervisor_source.index("trusted_isolation_chain_registry"),
            supervisor_source.index("trusted_isolation_child_environment"),
        )
        self.assertLess(
            backend_source.index("_active_strict_session"),
            backend_source.index("_run_registered_sudo"),
        )

    def test_normal_namespace_probe_failure_reports_sanitized_receipt(
        self,
    ) -> None:
        candidate_stderr = (
            "probe-start\n"
            + ("H" * 2500)
            + "MIDDLE-DETAIL-MUST-BE-DROPPED"
            + ("T" * 2500)
            + "\n  ::stop-commands::forged-token\r"
            + "\x00\x1b[31m"
        ).encode("utf-8") + b"\xffAssertionError: terminal-cause\x7f"
        receipt = {
            "schema_version": 1,
            "status": "completed",
            "nonce": "a" * 32,
            "returncode": 127,
            "timed_out": False,
            "process_leak_observed": False,
            "cleanup_status": "complete",
            "stdout_base64": base64.b64encode(
                b"::warning title=forged::probe-output\n"
            ).decode("ascii"),
            "stderr_base64": base64.b64encode(candidate_stderr).decode("ascii"),
        }
        observed_cleanup_receipt = {
            **receipt,
            "returncode": 0,
            "process_leak_observed": True,
        }
        malformed_output_receipt = {
            **receipt,
            "returncode": 0,
            "process_leak_observed": False,
            "stderr_base64": "%%%not-base64%%%",
        }
        boolean_returncode_receipt = {
            **receipt,
            "returncode": False,
        }
        floating_returncode_receipt = {
            **receipt,
            "returncode": 0.0,
        }
        kill_receipt = {
            **receipt,
            "returncode": -signal.SIGKILL,
            "timed_out": True,
            "stdout_base64": base64.b64encode(b"").decode("ascii"),
            "stderr_base64": base64.b64encode(b"").decode("ascii"),
        }
        valid_normal_receipt = {
            **receipt,
            "returncode": 0,
            "stdout_base64": base64.b64encode(b"").decode("ascii"),
            "stderr_base64": base64.b64encode(b"").decode("ascii"),
        }
        selected_receipts = [receipt, kill_receipt]

        def invoke_controller_side_effect(*_args, **kwargs):
            if kwargs.get("trusted_fault_point") is not None:
                raise AssertionError("expected synthetic fault probe rejection")
            if kwargs.get("timeout_seconds") == 0.5:
                return selected_receipts[1]
            return selected_receipts[0]

        snapshot = {
            "candidate_paths": {"probe.py": Path("/snapshot/probe.py")},
            "runtime_root": Path("/snapshot/runtime"),
        }
        with mock.patch.object(
            _CANDIDATE_SUPPORT, "strict_isolation_platform_preflight"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_active_strict_session", return_value={}
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_realm",
            return_value={"uid": 60000, "gid": 60000},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_run_registered_sudo"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_protect_strict_checkout_boundaries"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "candidate_repository_root",
            return_value=Path("/candidate"),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "expected_candidate_sha",
            return_value=("b" * 40, True),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_execution_snapshot",
            return_value=contextlib.nullcontext(snapshot),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_closed_candidate_environment",
            return_value={},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_invoke_strict_controller",
            side_effect=invoke_controller_side_effect,
        ) as invoke_controller, mock.patch.object(
            _CANDIDATE_SUPPORT, "_candidate_uid_inventory", return_value=[]
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_probe_independent_outer_owner_fault"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_BACKEND_VALIDATED", False
        ):
            messages: list[str] = []
            for name, normal_receipt, selected_kill_receipt in (
                ("returncode", receipt, kill_receipt),
                ("observed-cleanup", observed_cleanup_receipt, kill_receipt),
                ("malformed-output", malformed_output_receipt, kill_receipt),
                ("boolean-returncode", boolean_returncode_receipt, kill_receipt),
                ("floating-returncode", floating_returncode_receipt, kill_receipt),
                (
                    "kill-boolean-returncode",
                    valid_normal_receipt,
                    {**kill_receipt, "returncode": False},
                ),
                (
                    "kill-floating-returncode",
                    valid_normal_receipt,
                    {**kill_receipt, "returncode": 0.0},
                ),
                (
                    "kill-wrong-integer-returncode",
                    valid_normal_receipt,
                    {**kill_receipt, "returncode": 0},
                ),
                (
                    "kill-nonboolean-leak",
                    valid_normal_receipt,
                    {**kill_receipt, "process_leak_observed": 0},
                ),
            ):
                selected_receipts[:] = [normal_receipt, selected_kill_receipt]
                _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = False
                messages.append("")
                with self.subTest(name=name):
                    with self.assertRaises(AssertionError) as raised:
                        _CANDIDATE_SUPPORT._ensure_strict_backend()
                    messages[-1] = str(raised.exception)
                    self.assertIs(
                        _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED,
                        False,
                    )

        self.assertEqual(invoke_controller.call_count, 13)
        (
            message,
            observed_message,
            malformed_message,
            boolean_message,
            floating_message,
            kill_boolean_message,
            kill_floating_message,
            kill_wrong_integer_message,
            kill_leak_message,
        ) = messages
        prefix = "strict candidate normal namespace probe failed: "
        self.assertLessEqual(len(message), len(prefix) + 2000)
        self.assertIn('"returncode":127', message)
        self.assertIn('"process_leak_observed":false', message)
        self.assertIn("\\::warning title=forged::probe-output", message)
        self.assertIn("probe-start", message)
        self.assertIn("...[middle truncated]...", message)
        self.assertNotIn("MIDDLE-DETAIL-MUST-BE-DROPPED", message)
        self.assertIn("\\xff", message)
        self.assertIn("AssertionError: terminal-cause\\x7f", message)
        self.assertTrue(
            all(
                not line.lstrip().startswith("::")
                for line in message.split("\n")
            )
        )
        self.assertFalse(
            any(
                character in message
                for character in ("\x00", "\r", "\x1b", "\x7f")
            )
        )
        self.assertIn('"returncode":0', observed_message)
        self.assertIn('"process_leak_observed":true', observed_message)
        self.assertIn('"returncode":0', malformed_message)
        self.assertIn('"process_leak_observed":false', malformed_message)
        self.assertIn("<malformed stderr_base64>", malformed_message)
        self.assertIn('"returncode":"<malformed>"', boolean_message)
        self.assertIn('"returncode":"<malformed>"', floating_message)
        for kill_message in (
            kill_boolean_message,
            kill_floating_message,
            kill_wrong_integer_message,
            kill_leak_message,
        ):
            self.assertEqual(
                kill_message,
                "strict candidate kill namespace probe receipt is malformed",
            )

    def test_supervisor_entry_consumes_the_launcher_absolute_deadline(
        self,
    ) -> None:
        captured_stdout = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {
                REQUIRED_CI_ISOLATION_MODE_ENV: REQUIRED_CI_ISOLATION_MODE,
                TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV: "700.000000000",
            },
            clear=False,
        ), mock.patch.object(
            time, "monotonic", return_value=400.0
        ) as monotonic, mock.patch.object(
            sys.modules[__name__],
            "supervise_trusted_required_ci_tests",
            return_value={"status": "completed"},
        ) as supervise, contextlib.redirect_stdout(captured_stdout):
            self.assertEqual(_trusted_test_supervisor_main(), 0)
            self.assertNotIn(TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV, os.environ)

        monotonic.assert_called_once_with()
        supervise.assert_called_once_with(
            TRUSTED_REPO_ROOT,
            REPO_ROOT,
            supervisor_deadline=700.0,
        )

    def test_launcher_deadline_rejects_noncanonical_or_extended_values(
        self,
    ) -> None:
        fixtures = {
            "missing": None,
            "whitespace": " 700.000000000",
            "exponent": "7e2",
            "nonfinite": "nan",
            "expired": "100.000000000",
            "extended": "1120.002000000",
        }
        for name, encoded in fixtures.items():
            environment = {}
            if encoded is not None:
                environment[TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV] = encoded
            with self.subTest(name=name), mock.patch.dict(
                os.environ, environment, clear=True
            ), mock.patch.object(time, "monotonic", return_value=400.0):
                with self.assertRaisesRegex(
                    AssertionError, "deadline.*missing|deadline.*malformed|expired|exceeds"
                ):
                    _trusted_test_supervisor_deadline_from_environment()
                self.assertNotIn(
                    TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV, os.environ
                )

    def test_child_timeout_deducts_preflight_time_and_cleanup_reserve(
        self,
    ) -> None:
        deadline = 820.0
        cases = {
            "full child maximum": (100.0, 600.0),
            "45 seconds spent before launch": (145.0, 555.0),
            "599 seconds spent since launcher": (699.0, 1.0),
        }
        for name, (now, expected) in cases.items():
            with self.subTest(name=name), mock.patch.object(
                time, "monotonic", return_value=now
            ):
                self.assertEqual(
                    _remaining_trusted_test_child_timeout(deadline), expected
                )

        with mock.patch.object(time, "monotonic", return_value=700.0):
            with self.assertRaisesRegex(
                AssertionError, "insufficient budget before child launch"
            ):
                _remaining_trusted_test_child_timeout(deadline)

    def test_child_timeout_depends_only_on_monotonic_time(self) -> None:
        with mock.patch.object(
            time, "monotonic", return_value=579.0
        ), mock.patch.object(
            time, "time", side_effect=(1.0, 10_000_000.0)
        ) as wall_clock:
            self.assertEqual(
                _remaining_trusted_test_child_timeout(700.0), 1.0
            )

        wall_clock.assert_not_called()

    def test_insufficient_child_budget_fails_before_popen_and_still_cleans(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ), mock.patch.object(
                sys.modules[__name__],
                "_run_trusted_test_child",
                side_effect=AssertionError(
                    "trusted Required CI supervisor has insufficient budget "
                    "before child launch"
                ),
            ) as run_child, mock.patch.object(
                sys.modules[__name__], "_close_and_verify_trusted_isolation"
            ) as cleanup:
                with self.assertRaisesRegex(
                    AssertionError, "insufficient budget before child launch"
                ):
                    supervise_trusted_required_ci_tests(
                        trusted_root,
                        candidate_root,
                        supervisor_deadline=(
                            time.monotonic()
                            + TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS
                        ),
                    )

        run_child.assert_called_once()
        cleanup.assert_called_once()

    def test_popen_startup_time_is_deducted_before_communicate(self) -> None:
        with mock.patch.object(
            sys.modules[__name__],
            "_remaining_trusted_test_child_timeout",
            side_effect=AssertionError(
                "trusted Required CI supervisor has insufficient budget "
                "before child launch"
            ),
        ), mock.patch.object(subprocess, "Popen") as unstarted:
            with self.assertRaisesRegex(
                AssertionError, "insufficient budget before child launch"
            ):
                _run_trusted_test_child(
                    ["trusted-child"],
                    cwd=Path("/tmp"),
                    environment={},
                    pass_fds=(),
                    supervisor_deadline=700.0,
                )
        unstarted.assert_not_called()

        class FixtureProcess:
            pid = 424242
            returncode = 0

            def __init__(self) -> None:
                self.communicate_timeouts: list[float] = []

            def communicate(self, *, timeout: float):
                self.communicate_timeouts.append(timeout)
                return "stdout", "stderr"

        allowed_process = FixtureProcess()
        with mock.patch.object(
            time, "monotonic", side_effect=(100.0, 579.0)
        ), mock.patch.object(
            subprocess, "Popen", return_value=allowed_process
        ) as popen:
            completed = _run_trusted_test_child(
                ["trusted-child"],
                cwd=Path("/tmp"),
                environment={},
                pass_fds=(),
                supervisor_deadline=700.0,
            )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(allowed_process.communicate_timeouts, [1.0])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

        rejected_process = FixtureProcess()
        with mock.patch.object(
            time, "monotonic", side_effect=(100.0, 580.0)
        ), mock.patch.object(
            subprocess, "Popen", return_value=rejected_process
        ), mock.patch.object(
            sys.modules[__name__], "_terminate_trusted_test_child"
        ) as terminate:
            with self.assertRaisesRegex(
                AssertionError, "insufficient budget before child launch"
            ):
                _run_trusted_test_child(
                    ["trusted-child"],
                    cwd=Path("/tmp"),
                    environment={},
                    pass_fds=(),
                    supervisor_deadline=700.0,
                )

        terminate.assert_called_once_with(rejected_process)
        self.assertEqual(rejected_process.communicate_timeouts, [])

    def test_trusted_child_abort_kills_its_exact_session_and_reaps(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        child_pid = process.pid
        try:
            _terminate_trusted_test_child(process)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            with self.assertRaises(ProcessLookupError):
                os.killpg(child_pid, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=TRUSTED_TEST_CHILD_REAP_TIMEOUT_SECONDS)

    def test_popen_startup_budget_failure_still_cleans_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            process = mock.Mock(spec=subprocess.Popen)
            process.pid = 424242
            actual_run = _run_trusted_test_child
            popen_started: list[bool] = []

            def run_with_delayed_popen(*args: object, **kwargs: object):
                with mock.patch.object(
                    subprocess, "Popen", return_value=process
                ):
                    popen_started.append(True)
                    return actual_run(*args, **kwargs)

            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ), mock.patch.object(
                sys.modules[__name__],
                "_remaining_trusted_test_child_timeout",
                side_effect=(321.5, AssertionError(
                    "trusted Required CI supervisor has insufficient budget "
                    "before child launch"
                )),
            ), mock.patch.object(
                sys.modules[__name__],
                "_run_trusted_test_child",
                side_effect=run_with_delayed_popen,
            ), mock.patch.object(
                sys.modules[__name__], "_terminate_trusted_test_child"
            ) as terminate, mock.patch.object(
                sys.modules[__name__], "_close_and_verify_trusted_isolation"
            ) as cleanup:
                with self.assertRaisesRegex(
                    AssertionError, "insufficient budget before child launch"
                ):
                    supervise_trusted_required_ci_tests(
                        trusted_root,
                        candidate_root,
                        supervisor_deadline=(
                            time.monotonic()
                            + TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS
                        ),
                    )

        self.assertEqual(popen_started, [True])
        terminate.assert_called_once_with(process)
        process.communicate.assert_not_called()
        cleanup.assert_called_once()

    def test_child_timeout_failure_still_cleans_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            timeout = 321.5
            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ), mock.patch.object(
                sys.modules[__name__],
                "_run_trusted_test_child",
                side_effect=subprocess.TimeoutExpired("trusted child", timeout),
            ) as run_child, mock.patch.object(
                sys.modules[__name__], "_close_and_verify_trusted_isolation"
            ) as cleanup:
                with self.assertRaisesRegex(
                    AssertionError, "did not complete before the fixed timeout"
                ):
                    supervise_trusted_required_ci_tests(
                        trusted_root,
                        candidate_root,
                        supervisor_deadline=(
                            time.monotonic()
                            + TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS
                        ),
                    )

        run_child.assert_called_once()
        cleanup.assert_called_once()

    def test_structure_step_does_not_request_strict_mode_without_a_registry(
        self,
    ) -> None:
        workflow = (REPO_ROOT / ".github/workflows/required-ci.yml").read_text(
            encoding="utf-8"
        )
        structure_step = workflow.split(
            "      - name: Validate Required CI structure\n", 1
        )[1].split("      - name: Run trusted Required CI tests\n", 1)[0]
        supervisor_source = inspect.getsource(_trusted_test_supervisor_main)
        child_source = inspect.getsource(_trusted_test_child_main)

        self.assertNotIn(REQUIRED_CI_ISOLATION_MODE_ENV, structure_step)
        self.assertIn("_require_strict_workflow_mode", supervisor_source)
        self.assertIn("_require_strict_workflow_mode", child_source)

    def test_structure_step_uses_a_dedicated_static_validator_entry(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/required-ci.yml").read_text(
            encoding="utf-8"
        )
        structure_step = workflow.split(
            "      - name: Validate Required CI structure\n", 1
        )[1].split("      - name: Run trusted Required CI tests\n", 1)[0]

        self.assertIn("--validate-required-ci-structure", structure_step)
        self.assertNotIn(TRUSTED_TEST_SUPERVISOR_FLAG, structure_step)
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "expected_candidate_sha",
            return_value=("a" * 40, True),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "candidate_checkout_binding",
            return_value={"binding": "exact"},
        ) as binding, mock.patch.object(
            sys.modules[__name__],
            "validate_required_ci_repository",
            return_value=[],
        ) as validate_repository, mock.patch.object(unittest, "main") as unittest_main:
            self.assertEqual(_trusted_structure_validator_main(), 0)

        self.assertEqual(binding.call_count, 2)
        validate_repository.assert_called_once_with(
            REPO_ROOT, candidate_sha="a" * 40
        )
        unittest_main.assert_not_called()

    def test_structure_validator_cli_does_not_enter_unittest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root, candidate_sha = (
                self.prepare_structure_cli_split(temporary_directory)
            )
            trusted_test_path = (
                distribution_tests_root(trusted_root)
                / "test_required_ci_workflow.py"
            )
            environment = os.environ.copy()
            environment["GITHUB_WORKSPACE"] = str(trusted_root.parent)
            environment["GITHUB_SHA"] = candidate_sha
            environment[REQUIRED_CI_CANDIDATE_ROOT_ENV] = str(candidate_root)
            environment[REQUIRED_CI_CANDIDATE_SHA_ENV] = candidate_sha
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(trusted_test_path),
                    "--validate-required-ci-structure",
                ],
                cwd=trusted_root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")

    def test_structure_cli_rejects_renamed_trusted_checkout_without_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory).resolve(strict=True) / "workspace"
            moved_trusted_root = workspace / ".trusted"
            moved_tests_root = distribution_tests_root(moved_trusted_root)
            moved_tests_root.mkdir(parents=True)
            moved_test_path = moved_tests_root / "test_required_ci_workflow.py"
            shutil.copyfile(Path(__file__).resolve(strict=True), moved_test_path)
            shutil.copyfile(
                TRUSTED_CANDIDATE_SUPPORT_PATH,
                moved_tests_root / "required_ci_candidate.py",
            )
            environment = os.environ.copy()
            environment["GITHUB_WORKSPACE"] = str(workspace)
            environment.pop(REQUIRED_CI_CANDIDATE_ROOT_ENV, None)
            environment.pop(REQUIRED_CI_CANDIDATE_SHA_ENV, None)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(moved_test_path),
                    TRUSTED_STRUCTURE_VALIDATOR_FLAG,
                ],
                cwd=moved_trusted_root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("requires candidate root and SHA together", completed.stderr)

    def test_structure_validation_binds_workflow_and_support_to_frozen_commit(
        self,
    ) -> None:
        for target in ("workflow", "support"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary_directory:
                _, candidate_root, _ = self.prepare_structure_cli_split(
                    temporary_directory
                )
                workflow_path = (
                    candidate_root / ".github/workflows/required-ci.yml"
                )
                support_path = (
                    distribution_tests_root(candidate_root)
                    / "required_ci_candidate.py"
                )
                selected_path = (
                    workflow_path if target == "workflow" else support_path
                )
                trusted_source = selected_path.read_bytes()
                selected_path.write_bytes(
                    b"name: attacker-controlled\n"
                    if target == "workflow"
                    else b"raise SystemExit('attacker-controlled')\n"
                )
                for command in (
                    [
                        _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                        "-C",
                        str(candidate_root),
                        "add",
                        "--all",
                    ],
                    [
                        _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                        "-C",
                        str(candidate_root),
                        "-c",
                        "user.name=Required CI Test",
                        "-c",
                        "user.email=required-ci@example.invalid",
                        "-c",
                        "commit.gpgsign=false",
                        "commit",
                        "-m",
                        f"malicious {target}",
                    ],
                ):
                    completed = subprocess.run(
                        command,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                candidate_sha = _CANDIDATE_SUPPORT._run_candidate_git(
                    candidate_root, "rev-parse", "--verify", "HEAD^{commit}"
                ).decode("ascii")
                candidate_sha = (
                    candidate_sha[:-1]
                    if candidate_sha.endswith("\n")
                    else candidate_sha
                )
                selected_path.write_bytes(trusted_source)

                with self.assertRaisesRegex(
                    AssertionError, "does not match the frozen commit"
                ):
                    validate_required_ci_repository(
                        candidate_root, candidate_sha=candidate_sha
                    )

    def test_structure_validation_scans_callers_from_frozen_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root, _ = self.prepare_structure_cli_split(
                temporary_directory
            )
            caller_path = candidate_root / ".github/workflows/caller.yml"
            caller_path.write_text(
                "jobs:\n"
                "  required:\n"
                "    uses: ./.github/workflows/required-ci.yml\n",
                encoding="utf-8",
            )
            for command in (
                [
                    _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                    "-C",
                    str(candidate_root),
                    "add",
                    "--all",
                ],
                [
                    _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                    "-C",
                    str(candidate_root),
                    "-c",
                    "user.name=Required CI Test",
                    "-c",
                    "user.email=required-ci@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-m",
                    "hidden caller",
                ],
            ):
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            candidate_sha = _CANDIDATE_SUPPORT._run_candidate_git(
                candidate_root, "rev-parse", "--verify", "HEAD^{commit}"
            ).decode("ascii")
            candidate_sha = (
                candidate_sha[:-1]
                if candidate_sha.endswith("\n")
                else candidate_sha
            )
            caller_path.unlink()

            with self.assertRaisesRegex(
                AssertionError, "another Required CI caller"
            ):
                validate_required_ci_repository(
                    candidate_root, candidate_sha=candidate_sha
                )

    def test_production_supervisor_still_requires_exact_strict_mode(self) -> None:
        captured_stderr = io.StringIO()
        with _local_nonstrict_supervisor_environment(), mock.patch.object(
            sys.modules[__name__], "supervise_trusted_required_ci_tests"
        ) as supervise, contextlib.redirect_stderr(captured_stderr):
            self.assertEqual(_trusted_test_supervisor_main(), 1)

        supervise.assert_not_called()
        self.assertIn("requires exact strict isolation", captured_stderr.getvalue())

    def test_registry_acquisition_rejects_noop_watchdog_before_backend_validation(
        self,
    ) -> None:
        previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
        previous_validated = _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED
        _CANDIDATE_SUPPORT._STRICT_SESSION = None
        _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = False
        with tempfile.TemporaryDirectory() as temporary_directory:
            acquired_root = (
                Path(temporary_directory).resolve(strict=True) / "registry"
            )
            acquired_root.mkdir(mode=0o700)
            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_isolation_requested",
                    return_value=True,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "strict_isolation_platform_preflight"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_session_from_environment",
                    return_value=None,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_realm",
                    return_value={"uid": 60000, "gid": 60000},
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT.tempfile,
                    "mkdtemp",
                    return_value=str(acquired_root),
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_ensure_strict_backend",
                    side_effect=AssertionError("injected backend failure"),
                ) as ensure_backend, mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_start_registry_watchdog",
                ) as start_watchdog:
                    with self.assertRaisesRegex(
                        AssertionError, "abandoned without path mutation"
                    ):
                        _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()

                    start_watchdog.assert_called_once()
                    ensure_backend.assert_not_called()
                    self.assertTrue(acquired_root.is_dir())
                    self.assertIsNone(_CANDIDATE_SUPPORT._STRICT_SESSION)
                    self.assertEqual(
                        _CANDIDATE_SUPPORT._ABANDONED_REGISTRY_ACQUISITIONS[-1][
                            "path"
                        ],
                        str(acquired_root),
                    )
            finally:
                self.close_retained_acquisition_descriptors()
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session
                _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = previous_validated

    def test_partial_registry_attempt_is_never_reused_or_overwritten(
        self,
    ) -> None:
        previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
        previous_validated = _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED
        _CANDIDATE_SUPPORT._STRICT_SESSION = None
        _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = False
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            first_root = root / "registry-first"
            second_root = root / "registry-second"
            first_root.mkdir(mode=0o700)
            second_root.mkdir(mode=0o700)
            original_write = (
                _CANDIDATE_SUPPORT._write_registry_acquisition_file_at
            )
            injected = False

            def fail_after_first_lock_write(
                directory_fd: int, name: str, source: bytes, mode: int
            ) -> None:
                nonlocal injected
                original_write(directory_fd, name, source, mode)
                if name == ".session.lock" and not injected:
                    injected = True
                    raise AssertionError("injected setup failure")

            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_isolation_requested",
                    return_value=True,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "strict_isolation_platform_preflight"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_session_from_environment",
                    return_value=None,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_realm",
                    return_value={"uid": 60000, "gid": 60000},
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT.tempfile,
                    "mkdtemp",
                    side_effect=[str(first_root), str(second_root)],
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_write_registry_acquisition_file_at",
                    side_effect=fail_after_first_lock_write,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_start_registry_watchdog",
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_active_strict_session",
                    side_effect=lambda: _CANDIDATE_SUPPORT._STRICT_SESSION,
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "abandoned without path mutation"
                    ):
                        _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()

                    self.assertIsNone(_CANDIDATE_SUPPORT._STRICT_SESSION)
                    first_lock = first_root / ".session.lock"
                    first_lock.write_bytes(b"abandoned-sentinel")
                    resumed = (
                        _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()
                    )

                self.assertEqual(first_lock.read_bytes(), b"abandoned-sentinel")
                self.assertEqual(resumed["root"], second_root)
                self.assertTrue((second_root / ".session.lock").is_file())
            finally:
                self.close_retained_acquisition_descriptors()
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session
                _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = previous_validated

    def test_registry_acquisition_binds_root_before_fd_relative_setup(self) -> None:
        previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
        previous_validated = _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED
        _CANDIDATE_SUPPORT._STRICT_SESSION = None
        _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = False
        with tempfile.TemporaryDirectory() as temporary_directory:
            registry_root = Path(temporary_directory) / "registry"
            registry_root.mkdir(mode=0o700)
            actual = registry_root.lstat()
            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_isolation_requested",
                    return_value=True,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "strict_isolation_platform_preflight",
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_session_from_environment",
                    return_value=None,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_realm",
                    return_value={"uid": 60000, "gid": 60000},
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT.tempfile,
                    "mkdtemp",
                    return_value=str(registry_root),
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_configure_registry_acquisition_at",
                    side_effect=AssertionError("injected fd setup failure"),
                ) as configure:
                    with self.assertRaisesRegex(
                        AssertionError, "abandoned without path mutation"
                    ):
                        _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()

                configure.assert_called_once()
                self.assertTrue(registry_root.is_dir())
                self.assertEqual(
                    (registry_root.stat().st_dev, registry_root.stat().st_ino),
                    (actual.st_dev, actual.st_ino),
                )
                self.assertIsNone(_CANDIDATE_SUPPORT._STRICT_SESSION)
            finally:
                self.close_retained_acquisition_descriptors()
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session
                _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = previous_validated

    def test_registry_acquisition_replacement_retains_both_objects_without_delete(
        self,
    ) -> None:
        previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
        previous_validated = _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED
        _CANDIDATE_SUPPORT._STRICT_SESSION = None
        _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = False
        with tempfile.TemporaryDirectory() as temporary_directory:
            registry_root = Path(temporary_directory) / "registry"
            detached_root = Path(temporary_directory) / "detached-registry"
            registry_root.mkdir(mode=0o700)
            bound_identity = registry_root.stat().st_dev, registry_root.stat().st_ino
            original_configure = (
                _CANDIDATE_SUPPORT._configure_registry_acquisition_at
            )

            def replace_after_fd_setup(
                root_fd: int, *, watchdog_token: str
            ) -> None:
                original_configure(root_fd, watchdog_token=watchdog_token)
                registry_root.rename(detached_root)
                registry_root.mkdir(mode=0o700)
                (registry_root / "replacement-marker").write_bytes(b"replacement")

            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_isolation_requested",
                    return_value=True,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "strict_isolation_platform_preflight",
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_session_from_environment",
                    return_value=None,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_realm",
                    return_value={"uid": 60000, "gid": 60000},
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT.tempfile,
                    "mkdtemp",
                    return_value=str(registry_root),
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_configure_registry_acquisition_at",
                    side_effect=replace_after_fd_setup,
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "abandoned without path mutation"
                    ):
                        _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()

                self.assertIsNone(_CANDIDATE_SUPPORT._STRICT_SESSION)
                self.assertTrue(registry_root.is_dir())
                self.assertTrue(detached_root.is_dir())
                self.assertNotEqual(registry_root.stat().st_ino, bound_identity[1])
                self.assertEqual(
                    (detached_root.stat().st_dev, detached_root.stat().st_ino),
                    bound_identity,
                )
                self.assertEqual(
                    (registry_root / "replacement-marker").read_bytes(),
                    b"replacement",
                )
                self.assertFalse((registry_root / "entries").exists())
                self.assertTrue((detached_root / "entries").is_dir())
            finally:
                self.close_retained_acquisition_descriptors()
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session
                _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = previous_validated

    def test_registry_bind_failure_abandons_old_root_and_retries_fresh(self) -> None:
        previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
        previous_validated = _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED
        _CANDIDATE_SUPPORT._STRICT_SESSION = None
        _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = False
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            first_root = root / "registry-first"
            second_root = root / "registry-second"
            first_root.mkdir(mode=0o700)
            second_root.mkdir(mode=0o700)
            original_bind = (
                _CANDIDATE_SUPPORT._bind_empty_registry_acquisition_root
            )
            bind_attempt = 0

            def fail_first_bind(path: Path):
                nonlocal bind_attempt
                bind_attempt += 1
                if bind_attempt == 1:
                    raise OSError("injected descriptor exhaustion")
                return original_bind(path)

            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_isolation_requested",
                    return_value=True,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "strict_isolation_platform_preflight",
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_session_from_environment",
                    return_value=None,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_realm",
                    return_value={"uid": 60000, "gid": 60000},
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT.tempfile,
                    "mkdtemp",
                    side_effect=[str(first_root), str(second_root)],
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_bind_empty_registry_acquisition_root",
                    side_effect=fail_first_bind,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_start_registry_watchdog",
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_active_strict_session",
                    side_effect=lambda: _CANDIDATE_SUPPORT._STRICT_SESSION,
                ):
                    with self.assertRaisesRegex(
                        AssertionError,
                        "abandoned without path mutation",
                    ):
                        _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()

                    self.assertIsNone(_CANDIDATE_SUPPORT._STRICT_SESSION)
                    resumed = (
                        _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()
                    )

                self.assertEqual(bind_attempt, 2)
                self.assertEqual(resumed["root"], second_root)
                self.assertEqual(list(first_root.iterdir()), [])
                self.assertTrue((second_root / ".session.lock").is_file())
            finally:
                self.close_retained_acquisition_descriptors()
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session
                _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = previous_validated

    def test_registry_acquisition_recovery_never_mutates_abandoned_namespace(
        self,
    ) -> None:
        acquire_source = inspect.getsource(
            _CANDIDATE_SUPPORT.trusted_isolation_chain_registry
        )
        initialize_source = inspect.getsource(
            _CANDIDATE_SUPPORT._initialize_bound_registry_acquisition
        )
        consumer_source = inspect.getsource(
            _CANDIDATE_SUPPORT._consume_retained_registry_acquisition
        )

        self.assertLess(
            initialize_source.index("_start_registry_watchdog"),
            initialize_source.index("_active_strict_session"),
        )
        self.assertIn("_configure_registry_acquisition_at", initialize_source)
        self.assertNotIn("_resume_registry_acquisition", acquire_source)
        for forbidden_call in (
            "_bind_empty_registry_acquisition_root",
            "os.stat",
            ".resolve",
            ".mkdir",
            "_write_single_link_file",
            "os.unlink",
            "os.rmdir",
            "os.rename",
            "shutil.rmtree",
        ):
            self.assertNotIn(forbidden_call, consumer_source)

    def test_unresolved_watchdog_blocks_fresh_registry_acquisition(self) -> None:
        previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
        previous_validated = _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED
        retained = {
            "root": Path("/tmp/abandoned-registry"),
            "closed": False,
            "inherited": False,
            "watchdog_authorized": False,
            "acquisition_retained": {
                "phase": "watchdog-unresolved",
                "device": 1,
                "inode": 2,
            },
        }
        _CANDIDATE_SUPPORT._STRICT_SESSION = retained
        _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = False
        try:
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_isolation_requested",
                return_value=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "strict_isolation_platform_preflight",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_retire_registry_watchdog_handles",
                return_value=["injected unreaped watchdog"],
            ), mock.patch.object(
                _CANDIDATE_SUPPORT.tempfile,
                "mkdtemp",
            ) as mkdtemp:
                with self.assertRaisesRegex(
                    AssertionError, "watchdog is still unresolved"
                ):
                    _CANDIDATE_SUPPORT.trusted_isolation_chain_registry()

            mkdtemp.assert_not_called()
            self.assertIs(_CANDIDATE_SUPPORT._STRICT_SESSION, retained)
        finally:
            _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session
            _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = previous_validated

    def test_live_heartbeat_retirement_retains_every_watchdog_handle(self) -> None:
        class TerminalProcess(subprocess.Popen[bytes]):
            def __init__(self) -> None:
                self.pid = 62006
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.returncode = 0

            def poll(self) -> int:
                return 0

        class StickyHeartbeat(threading.Thread):
            def __init__(self) -> None:
                self.join_count = 0
                self.alive = True

            def is_alive(self) -> bool:
                return self.alive

            def join(self, timeout: float | None = None) -> None:
                self.join_count += 1
                if self.join_count >= 2:
                    self.alive = False

        process = TerminalProcess()
        heartbeat = StickyHeartbeat()
        stop_event = threading.Event()
        stderr = io.BytesIO()
        session: dict[str, object] = {
            "watchdog_process": process,
            "watchdog_stderr": stderr,
            "watchdog_stop": stop_event,
            "watchdog_write_lock": threading.Lock(),
            "watchdog_heartbeat": heartbeat,
            "watchdog_closing": True,
            "watchdog_token": "a" * 32,
        }

        first_failures = (
            _CANDIDATE_SUPPORT._retire_registry_watchdog_handles(
                session, terminate=True
            )
        )

        self.assertEqual(first_failures, ["watchdog heartbeat did not stop"])
        self.assertTrue(stop_event.is_set())
        self.assertIs(session["watchdog_process"], process)
        self.assertIs(session["watchdog_heartbeat"], heartbeat)
        self.assertIs(session["watchdog_stderr"], stderr)
        self.assertFalse(process.stdin.closed)
        self.assertFalse(process.stdout.closed)
        self.assertFalse(stderr.closed)

        second_failures = (
            _CANDIDATE_SUPPORT._retire_registry_watchdog_handles(
                session, terminate=True
            )
        )

        self.assertEqual(second_failures, [])
        self.assertFalse(heartbeat.is_alive())
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(stderr.closed)
        self.assertNotIn("watchdog_process", session)
        self.assertNotIn("watchdog_heartbeat", session)

    def test_watchdog_retirement_never_reuses_a_closed_pidfd_number(
        self,
    ) -> None:
        class FailOnceStream:
            def __init__(self) -> None:
                self.close_count = 0

            def close(self) -> None:
                self.close_count += 1
                if self.close_count == 1:
                    raise OSError("injected stream close failure")

        class TerminalProcess(subprocess.Popen[bytes]):
            def __init__(self, failing_stream: FailOnceStream) -> None:
                self.pid = 62007
                self.stdin = failing_stream
                self.stdout = io.BytesIO()
                self.returncode = 0

            def poll(self) -> int:
                return 0

        pidfd, pidfd_peer = os.pipe()
        replacement_read: int | None = None
        replacement_write: int | None = None
        failing_stream = FailOnceStream()
        process = TerminalProcess(failing_stream)
        launch: dict[str, object] = {
            "process": process,
            "pidfd": pidfd,
            "stderr": io.BytesIO(),
        }
        session: dict[str, object] = {
            "watchdog_launch": launch,
            "watchdog_process": process,
            "watchdog_pidfd": pidfd,
            "watchdog_stderr": launch["stderr"],
            "watchdog_closing": True,
            "watchdog_token": "a" * 32,
        }
        try:
            first_failures = (
                _CANDIDATE_SUPPORT._retire_registry_watchdog_handles(
                    session, terminate=True
                )
            )
            self.assertEqual(
                first_failures,
                ["watchdog stdin close: injected stream close failure"],
            )

            replacement_read, replacement_write = os.pipe()
            self.assertEqual(replacement_read, pidfd)

            second_failures = (
                _CANDIDATE_SUPPORT._retire_registry_watchdog_handles(
                    session, terminate=True
                )
            )

            self.assertEqual(second_failures, [])
            os.fstat(replacement_read)
            self.assertEqual(failing_stream.close_count, 2)
        finally:
            for descriptor in (
                pidfd_peer,
                replacement_read,
                replacement_write,
            ):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise

    def test_watchdog_pidfd_authority_is_retired_before_close_interrupt(
        self,
    ) -> None:
        class TerminalProcess(subprocess.Popen[bytes]):
            def __init__(self) -> None:
                self.pid = 62009
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.returncode = 0

            def poll(self) -> int:
                return 0

        pidfd, pidfd_peer = os.pipe()
        replacement_read: int | None = None
        replacement_write: int | None = None
        process = TerminalProcess()
        launch: dict[str, object] = {
            "process": process,
            "pidfd": pidfd,
            "stderr": io.BytesIO(),
        }
        session: dict[str, object] = {
            "watchdog_launch": launch,
            "watchdog_process": process,
            "watchdog_pidfd": pidfd,
            "watchdog_stderr": launch["stderr"],
            "watchdog_closing": True,
            "watchdog_token": "a" * 32,
        }
        real_close = os.close
        interrupted = False

        def close_then_interrupt(descriptor: int) -> None:
            nonlocal interrupted
            real_close(descriptor)
            if descriptor == pidfd and not interrupted:
                interrupted = True
                raise KeyboardInterrupt("injected post-close interrupt")

        try:
            with mock.patch.object(
                _CANDIDATE_SUPPORT.os,
                "close",
                side_effect=close_then_interrupt,
            ):
                with self.assertRaisesRegex(
                    KeyboardInterrupt, "post-close interrupt"
                ):
                    _CANDIDATE_SUPPORT._retire_registry_watchdog_handles(
                        session, terminate=True
                    )

            replacement_read, replacement_write = os.pipe()
            self.assertEqual(replacement_read, pidfd)

            self.assertEqual(
                _CANDIDATE_SUPPORT._retire_registry_watchdog_handles(
                    session, terminate=True
                ),
                [],
            )
            os.fstat(replacement_read)
        finally:
            for descriptor in (
                pidfd_peer,
                replacement_read,
                replacement_write,
            ):
                if descriptor is not None:
                    try:
                        real_close(descriptor)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise

    def test_supervisor_enters_cleanup_scope_immediately_after_registry_acquire(
        self,
    ) -> None:
        source = inspect.getsource(supervise_trusted_required_ci_tests)
        post_acquire = source.split(
            "trusted_isolation_chain_registry()", 1
        )[1]

        self.assertLess(
            post_acquire.index("try:"),
            post_acquire.index('registry_environment ='),
        )

    def test_execution_snapshot_registers_cleanup_before_first_mutation(
        self,
    ) -> None:
        source = inspect.getsource(_CANDIDATE_SUPPORT._execution_snapshot)

        self.assertIn("_register_trusted_root_chain", source)
        self.assertLess(
            source.index("_register_trusted_root_chain"),
            source.index("_write_single_link_file"),
        )
        self.assertLess(
            source.index("try:"),
            source.index("_write_single_link_file"),
        )
        self.assertIn("_recover_registered_entry", source)

    def test_strict_execution_root_allows_only_runner_and_realm_traversal(
        self,
    ) -> None:
        snapshot_source = inspect.getsource(
            _CANDIDATE_SUPPORT._execution_snapshot
        )
        broker_source = inspect.getsource(_CANDIDATE_SUPPORT._root_tree_main)

        self.assertIn('"own-root"', snapshot_source)
        self.assertIn('"execution-root"', snapshot_source)
        self.assertIn("os.getuid()", snapshot_source)
        self.assertIn('operation == "own-root"', broker_source)
        self.assertIn("os.fchown(descriptor, owner_uid, owner_gid)", broker_source)
        self.assertIn("os.fchmod(descriptor, 0o710)", broker_source)
        self.assertIn("_prepare_isolation_resource_ancestors", snapshot_source)
        self.assertLess(
            snapshot_source.index("_prepare_isolation_resource_ancestors"),
            snapshot_source.index("tempfile.mkdtemp"),
        )

    def test_durable_deletion_receipt_is_fd_bound_and_runner_readable(self) -> None:
        reader_source = inspect.getsource(
            _CANDIDATE_SUPPORT._read_durable_deletion_receipt_file
        )
        broker_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_seal_execution_root_main
        )
        self.assertIn("os.O_NOFOLLOW", reader_source)
        self.assertGreaterEqual(reader_source.count("os.fstat"), 2)
        self.assertIn("os.read", reader_source)
        self.assertNotIn("read_bytes", reader_source)
        self.assertIn("metadata.st_gid", reader_source)
        self.assertIn("0o640", reader_source)
        self.assertIn("expected_file_group", broker_source)
        self.assertIn("expected_file_mode=0o640", broker_source)

    def test_incomplete_root_receipt_staging_is_retired_for_tombstone_replay(
        self,
    ) -> None:
        envelopes = (
            (0, 0o600, b""),
            (os.getgid(), 0o600, b'{"schema_version"'),
            (os.getgid(), 0o640, b"not-json"),
        )
        for selected_gid, selected_mode, content in envelopes:
            with self.subTest(
                gid=selected_gid, mode=oct(selected_mode)
            ), tempfile.TemporaryDirectory() as temporary_directory:
                entries = Path(temporary_directory).resolve(strict=True)
                staged_path = entries / (
                    f"..chain-{'a' * 32}.delete-{'b' * 32}.json."
                    f"tmp-{'c' * 32}"
                )
                staged_path.write_bytes(content)
                original_lstat = Path.lstat
                actual = staged_path.lstat()
                root_owned_metadata = mock.Mock(
                    st_mode=stat.S_IFREG | selected_mode,
                    st_uid=0,
                    st_gid=selected_gid,
                    st_nlink=1,
                    st_size=len(content),
                    st_dev=actual.st_dev,
                    st_ino=actual.st_ino,
                )

                def selected_lstat(path: Path):
                    if path == staged_path:
                        return root_owned_metadata
                    return original_lstat(path)

                with mock.patch.object(
                    Path, "lstat", selected_lstat
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_read_durable_deletion_receipt_file",
                    side_effect=AssertionError("injected partial receipt"),
                ):
                    _CANDIDATE_SUPPORT._recover_deletion_receipt_staging(
                        entries
                    )

                self.assertFalse(staged_path.exists())

        with tempfile.TemporaryDirectory() as temporary_directory:
            entries = Path(temporary_directory).resolve(strict=True)
            staged_path = entries / (
                f"..chain-{'d' * 32}.delete-{'e' * 32}.json."
                f"tmp-{'f' * 32}"
            )
            staged_path.write_bytes(b"runner-owned")
            original_lstat = Path.lstat
            actual = staged_path.lstat()
            unsafe_metadata = mock.Mock(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=12345,
                st_gid=os.getgid(),
                st_nlink=1,
                st_size=12,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino,
            )

            def unsafe_lstat(path: Path):
                if path == staged_path:
                    return unsafe_metadata
                return original_lstat(path)

            with mock.patch.object(
                Path, "lstat", unsafe_lstat
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_read_durable_deletion_receipt_file",
                side_effect=AssertionError("injected forged receipt"),
            ):
                with self.assertRaisesRegex(
                    AssertionError, "staging is unsafe"
                ):
                    _CANDIDATE_SUPPORT._recover_deletion_receipt_staging(
                        entries
                    )

            self.assertTrue(staged_path.is_file())

    def test_complete_receipt_staging_is_never_promoted_as_durable_proof(
        self,
    ) -> None:
        session_id = "a" * 32
        delete_nonce = "b" * 32
        with tempfile.TemporaryDirectory() as temporary_directory:
            entries = Path(temporary_directory).resolve(strict=True)
            final_path = entries / (
                f".chain-{session_id}.delete-{delete_nonce}.json"
            )
            staged_path = entries / (
                f".{final_path.name}.tmp-{'c' * 32}"
            )
            staged_path.write_bytes(b'{"complete":true}')
            original_lstat = Path.lstat
            actual = staged_path.lstat()
            root_owned_metadata = mock.Mock(
                st_mode=stat.S_IFREG | 0o640,
                st_uid=0,
                st_gid=os.getgid(),
                st_nlink=1,
                st_size=actual.st_size,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino,
            )

            def selected_lstat(path: Path):
                if path == staged_path:
                    return root_owned_metadata
                return original_lstat(path)

            with mock.patch.object(
                Path, "lstat", selected_lstat
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_read_durable_deletion_receipt_file",
                return_value={
                    "session_id": session_id,
                    "delete_nonce": delete_nonce,
                },
            ) as read_receipt:
                _CANDIDATE_SUPPORT._recover_deletion_receipt_staging(entries)

            read_receipt.assert_not_called()
            self.assertFalse(staged_path.exists())
            self.assertFalse(final_path.exists())

    def test_all_privileged_launches_use_the_registered_outer_gate(self) -> None:
        support_source = TRUSTED_CANDIDATE_SUPPORT_PATH.read_text(
            encoding="utf-8"
        )
        command_source = inspect.getsource(
            _CANDIDATE_SUPPORT._registered_sudo_command
        )
        launcher_source = inspect.getsource(
            _CANDIDATE_SUPPORT._run_registered_sudo
        )
        gated_launcher_source = inspect.getsource(
            _CANDIDATE_SUPPORT._run_registered_sudo_under_gate
        )

        self.assertEqual(support_source.count('_STRICT_PRIMITIVES["sudo"]'), 1)
        self.assertIn('_STRICT_PRIMITIVES["sudo"]', command_source)
        self.assertNotIn("def _run_sudo", support_source)
        self.assertIn("_registry_session_gate", launcher_source)
        self.assertIn("_REGISTERED_SUDO_WRAPPER_SOURCE", gated_launcher_source)
        self.assertIn("start_new_session=True", gated_launcher_source)

    def test_privileged_tree_changes_are_fd_anchored_and_never_recursive_by_path(
        self,
    ) -> None:
        support_source = TRUSTED_CANDIDATE_SUPPORT_PATH.read_text(encoding="utf-8")

        self.assertNotIn('"-hR"', support_source)
        self.assertTrue(
            hasattr(_CANDIDATE_SUPPORT, "_root_fd_tree_operation")
        )
        walker_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_fd_tree_operation
        )
        self.assertIn("os.O_NOFOLLOW", walker_source)
        self.assertIn("st_nlink != 1", walker_source)
        self.assertIn("os.fchown", walker_source)
        self.assertNotIn("os.chown", walker_source)

    def test_fd_tree_walker_never_changes_a_hardlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            root = parent / "root"
            root.mkdir()
            outside = parent / "outside"
            outside.write_text("outside", encoding="utf-8")
            alias = root / "alias"
            os.link(outside, alias)
            original = outside.stat()
            descriptor = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                with mock.patch.object(os, "fchown"), mock.patch.object(
                    os, "fchmod"
                ):
                    with self.assertRaisesRegex(AssertionError, "hardlink"):
                        _CANDIDATE_SUPPORT._root_fd_tree_operation(
                            descriptor, os.getuid(), os.getgid(), "fixture-shared"
                        )
                    _CANDIDATE_SUPPORT._root_fd_tree_operation(
                        descriptor, os.getuid(), os.getgid(), "fixture-restore"
                    )
            finally:
                os.close(descriptor)

            self.assertFalse(alias.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
            final = outside.stat()
            self.assertEqual(
                (final.st_dev, final.st_ino, final.st_mode),
                (original.st_dev, original.st_ino, original.st_mode),
            )

    def test_fixture_prepare_preflights_all_roots_and_rolls_back_partial_ownership(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory).resolve(strict=True)
            roots = (parent / "first", parent / "second")
            for root in roots:
                root.mkdir()
            previous_roots = dict(_CANDIDATE_SUPPORT._REGISTERED_FIXTURE_ROOTS)
            _CANDIDATE_SUPPORT._REGISTERED_FIXTURE_ROOTS.clear()
            for root in roots:
                metadata = root.lstat()
                _CANDIDATE_SUPPORT._REGISTERED_FIXTURE_ROOTS[root] = (
                    metadata.st_dev,
                    metadata.st_ino,
                )
            trace: list[str] = []

            def preflight(root: Path) -> list[Path]:
                trace.append(f"preflight:{root.name}")
                return [root]

            def mutate(
                _controller: Path,
                operation: str,
                root: Path,
                _owner_uid: int,
                _owner_gid: int,
                profile: str,
            ) -> dict[str, object]:
                self.assertEqual(operation, "own")
                trace.append(f"{profile}:{root.name}")
                if profile == "fixture-shared" and root == roots[1]:
                    raise AssertionError("injected second-root failure")
                return {"status": "complete"}

            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_realm",
                    return_value={"uid": 60000, "gid": 60000},
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_fixture_tree_paths",
                    side_effect=preflight,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_root_tree_operation",
                    side_effect=mutate,
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "injected second-root failure"
                    ):
                        _CANDIDATE_SUPPORT._prepare_strict_fixture_roots(
                            parent / "controller.py", roots, None
                        )
            finally:
                _CANDIDATE_SUPPORT._REGISTERED_FIXTURE_ROOTS.clear()
                _CANDIDATE_SUPPORT._REGISTERED_FIXTURE_ROOTS.update(previous_roots)

        self.assertEqual(
            trace,
            [
                "preflight:first",
                "preflight:second",
                "fixture-shared:first",
                "fixture-shared:second",
                "fixture-restore:second",
                "fixture-restore:first",
            ],
        )

    def test_uid_realm_lock_name_is_persistent_after_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            lock_path = Path(temporary_directory) / "uid-60000.lock"
            lock_file = lock_path.open("a+b")
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

            _CANDIDATE_SUPPORT._release_realm_lock(lock_file, lock_path)

            self.assertTrue(lock_path.is_file())
            replacement = lock_path.open("a+b")
            try:
                fcntl.flock(
                    replacement.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                )
            finally:
                replacement.close()

    def test_uid_realm_lock_rejects_a_symlink_without_touching_its_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target"
            target.write_text("unchanged", encoding="utf-8")
            lock_path = root / "uid-60000.lock"
            lock_path.symlink_to(target.name)

            with self.assertRaisesRegex(AssertionError, "lock is unsafe"):
                _CANDIDATE_SUPPORT._open_realm_lock(lock_path)

            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

    def test_candidate_git_stdout_limit_is_enforced_while_running(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            marker = root / "finished"
            fixture = root / "stdout.py"
            fixture.write_text(
                "import os\n"
                "import pathlib\n"
                "import sys\n"
                "import time\n"
                "marker = pathlib.Path(sys.argv[1])\n"
                "for _ in range(64):\n"
                "    os.write(1, b'x' * 1024)\n"
                "    time.sleep(0.01)\n"
                "marker.write_text('finished', encoding='utf-8')\n",
                encoding="utf-8",
            )
            command = [sys.executable, "-I", "-B", str(fixture), str(marker)]

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "candidate_git_argv",
                return_value=command,
            ):
                with self.assertRaisesRegex(
                    AssertionError, "exceeded its stdout limit"
                ):
                    _CANDIDATE_SUPPORT._run_candidate_git(
                        root, "status", output_limit=4096
                    )

            self.assertFalse(marker.exists())

    def test_candidate_git_stderr_limit_is_enforced_while_running(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            marker = root / "finished"
            fixture = root / "stderr.py"
            fixture.write_text(
                "import os\n"
                "import pathlib\n"
                "import sys\n"
                "import time\n"
                "marker = pathlib.Path(sys.argv[1])\n"
                "for _ in range(64):\n"
                "    os.write(2, b'x' * 1024)\n"
                "    time.sleep(0.01)\n"
                "marker.write_text('finished', encoding='utf-8')\n",
                encoding="utf-8",
            )
            command = [sys.executable, "-I", "-B", str(fixture), str(marker)]

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "candidate_git_argv",
                return_value=command,
            ):
                with self.assertRaisesRegex(
                    AssertionError, "exceeded its stderr limit"
                ):
                    _CANDIDATE_SUPPORT._run_candidate_git(
                        root, "status", output_limit=4096
                    )

            self.assertFalse(marker.exists())

    def test_candidate_git_combined_output_limit_has_an_exact_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            fixture = root / "combined.py"
            fixture.write_text(
                "import os\n"
                "import sys\n"
                "os.write(1, b'o' * int(sys.argv[1]))\n"
                "os.write(2, b'e' * int(sys.argv[2]))\n",
                encoding="utf-8",
            )

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "candidate_git_argv",
                return_value=[
                    sys.executable,
                    "-I",
                    "-B",
                    str(fixture),
                    "2048",
                    "2048",
                ],
            ):
                with self.assertRaisesRegex(AssertionError, "wrote stderr"):
                    _CANDIDATE_SUPPORT._run_candidate_git(
                        root, "status", output_limit=4096
                    )

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "candidate_git_argv",
                return_value=[
                    sys.executable,
                    "-I",
                    "-B",
                    str(fixture),
                    "2048",
                    "2049",
                ],
            ):
                with self.assertRaisesRegex(
                    AssertionError, "exceeded its combined output limit"
                ):
                    _CANDIDATE_SUPPORT._run_candidate_git(
                        root, "status", output_limit=4096
                    )

    def test_candidate_git_cleanup_revalidates_darwin_eperm_after_a_live_race(
        self,
    ) -> None:
        process_group = 43210
        for live_after_eperm, expected_error in (
            (False, None),
            (True, "live-member cleanup"),
        ):
            with self.subTest(live_after_eperm=live_after_eperm):
                process = mock.Mock(pid=process_group)
                with mock.patch.object(
                    _CANDIDATE_SUPPORT.sys, "platform", "darwin"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_wait_candidate_git_exit_without_reaping",
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_candidate_git_process_group_has_live_members",
                    side_effect=(True, live_after_eperm),
                ) as live_members, mock.patch.object(
                    _CANDIDATE_SUPPORT.os,
                    "killpg",
                    side_effect=(
                        None,
                        PermissionError(errno.EPERM, "injected Darwin race"),
                    ),
                ) as kill_group:
                    if expected_error is None:
                        _CANDIDATE_SUPPORT._terminate_candidate_git_process_tree(
                            process, process_group
                        )
                    else:
                        with self.assertRaisesRegex(
                            AssertionError, expected_error
                        ):
                            _CANDIDATE_SUPPORT._terminate_candidate_git_process_tree(
                                process, process_group
                            )

                self.assertEqual(live_members.call_count, 2)
                self.assertEqual(
                    kill_group.call_args_list,
                    [
                        mock.call(process_group, signal.SIGKILL),
                        mock.call(process_group, signal.SIGKILL),
                    ],
                )
                process.wait.assert_called_once()

    def test_candidate_git_cleanup_reports_darwin_eperm_revalidation_failure(
        self,
    ) -> None:
        process_group = 43211
        process = mock.Mock(pid=process_group)
        with mock.patch.object(
            _CANDIDATE_SUPPORT.sys, "platform", "darwin"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_wait_candidate_git_exit_without_reaping",
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_candidate_git_process_group_has_live_members",
            side_effect=(True, RuntimeError("injected inventory failure")),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os,
            "killpg",
            side_effect=(
                None,
                PermissionError(errno.EPERM, "injected Darwin race"),
            ),
        ):
            with self.assertRaisesRegex(
                AssertionError,
                "live-member revalidation: injected inventory failure",
            ):
                _CANDIDATE_SUPPORT._terminate_candidate_git_process_tree(
                    process, process_group
                )

        process.wait.assert_called_once()

    def test_candidate_git_initial_darwin_eperm_is_not_a_terminal_signal(
        self,
    ) -> None:
        process_group = 43212
        process = mock.Mock(pid=process_group)
        events: list[str] = []
        signal_attempts = 0
        live_results = iter((True, False))

        def signal_group(selected_group: int, selected_signal: int) -> None:
            nonlocal signal_attempts
            self.assertEqual(selected_group, process_group)
            self.assertEqual(selected_signal, signal.SIGKILL)
            signal_attempts += 1
            events.append(f"signal-{signal_attempts}")
            if signal_attempts == 1:
                raise PermissionError(errno.EPERM, "injected initial denial")

        def wait_for_leader(
            selected_process: object, selected_deadline: float
        ) -> None:
            self.assertIs(selected_process, process)
            self.assertGreater(selected_deadline, time.monotonic())
            events.append("leader-exit")

        def inventory(selected_group: int) -> bool:
            self.assertEqual(selected_group, process_group)
            result = next(live_results)
            events.append(f"live-{str(result).lower()}")
            return result

        process.wait.side_effect = lambda **_kwargs: events.append("reap") or 0
        with mock.patch.object(
            _CANDIDATE_SUPPORT.sys, "platform", "darwin"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_wait_candidate_git_exit_without_reaping",
            side_effect=wait_for_leader,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_candidate_git_process_group_has_live_members",
            side_effect=inventory,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os, "killpg", side_effect=signal_group
        ):
            _CANDIDATE_SUPPORT._terminate_candidate_git_process_tree(
                process, process_group
            )

        self.assertEqual(
            events,
            [
                "signal-1",
                "leader-exit",
                "live-true",
                "signal-2",
                "live-false",
                "reap",
            ],
        )

    def test_candidate_git_eperm_fallback_is_darwin_only(self) -> None:
        process_group = 43213
        denial = PermissionError(errno.EPERM, "injected non-Darwin denial")
        with mock.patch.object(
            _CANDIDATE_SUPPORT.sys, "platform", "freebsd13"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os, "killpg", side_effect=denial
        ):
            with self.assertRaisesRegex(
                AssertionError, "process inventory is unreadable"
            ):
                _CANDIDATE_SUPPORT._candidate_git_process_group_has_live_members(
                    process_group
                )

        process = mock.Mock(pid=process_group)
        with mock.patch.object(
            _CANDIDATE_SUPPORT.sys, "platform", "freebsd13"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_wait_candidate_git_exit_without_reaping",
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_candidate_git_process_group_has_live_members",
        ) as live_members, mock.patch.object(
            _CANDIDATE_SUPPORT.os, "killpg", side_effect=denial
        ):
            with self.assertRaisesRegex(AssertionError, "signal:.*denial"):
                _CANDIDATE_SUPPORT._terminate_candidate_git_process_tree(
                    process, process_group
                )

        live_members.assert_not_called()
        process.wait.assert_called_once()

    def test_candidate_git_timeout_reaps_its_complete_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            fixture = root / "process-tree.py"
            lock_path = root / "child.lock"
            pid_path = root / "child.pid"
            ready_path = root / "child.ready"
            fixture.write_text(
                "import fcntl\n"
                "import os\n"
                "import pathlib\n"
                "import subprocess\n"
                "import sys\n"
                "import time\n"
                "lock_path, pid_path, ready_path = map(pathlib.Path, sys.argv[2:5])\n"
                "if sys.argv[1] == 'child':\n"
                "    lock = lock_path.open('a+b')\n"
                "    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)\n"
                "    pid_path.write_text(str(os.getpid()), encoding='ascii')\n"
                "    ready_path.write_text('ready', encoding='ascii')\n"
                "    time.sleep(30)\n"
                "else:\n"
                "    subprocess.Popen(\n"
                "        [sys.executable, '-I', '-B', __file__, 'child',\n"
                "         str(lock_path), str(pid_path), str(ready_path)],\n"
                "        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,\n"
                "        stderr=subprocess.DEVNULL, close_fds=True)\n"
                "    deadline = time.monotonic() + 5\n"
                "    while not ready_path.exists():\n"
                "        if time.monotonic() >= deadline:\n"
                "            raise SystemExit(92)\n"
                "        time.sleep(0.01)\n"
                "    time.sleep(30)\n",
                encoding="utf-8",
            )
            command = [
                sys.executable,
                "-I",
                "-B",
                str(fixture),
                "parent",
                str(lock_path),
                str(pid_path),
                str(ready_path),
            ]
            child_pid: int | None = None
            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "candidate_git_argv",
                    return_value=command,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "CANDIDATE_GIT_TIMEOUT_SECONDS",
                    0.4,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "CANDIDATE_GIT_REAP_TIMEOUT_SECONDS",
                    2,
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "exceeded its fixed timeout"
                    ):
                        _CANDIDATE_SUPPORT._run_candidate_git(root, "status")

                child_pid = int(pid_path.read_text(encoding="ascii"))
                lock = lock_path.open("a+b")
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    lock.close()
            finally:
                if child_pid is None and pid_path.exists():
                    child_pid = int(pid_path.read_text(encoding="ascii"))
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_candidate_git_success_reaps_a_lingering_group_before_returning(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            fixture = root / "lingering.py"
            lock_path = root / "child.lock"
            pid_path = root / "child.pid"
            ready_path = root / "child.ready"
            fixture.write_text(
                "import fcntl\n"
                "import os\n"
                "import pathlib\n"
                "import subprocess\n"
                "import sys\n"
                "import time\n"
                "lock_path, pid_path, ready_path = map(pathlib.Path, sys.argv[2:5])\n"
                "if sys.argv[1] == 'child':\n"
                "    lock = lock_path.open('a+b')\n"
                "    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)\n"
                "    pid_path.write_text(str(os.getpid()), encoding='ascii')\n"
                "    ready_path.write_text('ready', encoding='ascii')\n"
                "    time.sleep(30)\n"
                "else:\n"
                "    subprocess.Popen(\n"
                "        [sys.executable, '-I', '-B', __file__, 'child',\n"
                "         str(lock_path), str(pid_path), str(ready_path)],\n"
                "        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,\n"
                "        stderr=subprocess.DEVNULL, close_fds=True)\n"
                "    deadline = time.monotonic() + 5\n"
                "    while not ready_path.exists():\n"
                "        if time.monotonic() >= deadline:\n"
                "            raise SystemExit(92)\n"
                "        time.sleep(0.01)\n",
                encoding="utf-8",
            )
            command = [
                sys.executable,
                "-I",
                "-B",
                str(fixture),
                "parent",
                str(lock_path),
                str(pid_path),
                str(ready_path),
            ]
            child_pid: int | None = None
            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "candidate_git_argv",
                    return_value=command,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "CANDIDATE_GIT_REAP_TIMEOUT_SECONDS",
                    2,
                ):
                    output = _CANDIDATE_SUPPORT._run_candidate_git(root, "status")

                child_pid = int(pid_path.read_text(encoding="ascii"))
                self.assertEqual(output, b"")
                lock = lock_path.open("a+b")
                try:
                    deadline = time.monotonic() + 1
                    while True:
                        try:
                            fcntl.flock(
                                lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                            )
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.01)
                finally:
                    lock.close()
            finally:
                if child_pid is None and pid_path.exists():
                    child_pid = int(pid_path.read_text(encoding="ascii"))
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_candidate_git_safe_directory_ignores_global_pollution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory).resolve(strict=True)
            allowed = home / "allowed"
            allowed.mkdir()
            (home / ".gitconfig").write_text(
                "[safe]\n\tdirectory = *\n\tdirectory = /unexpected\n",
                encoding="utf-8",
            )
            environment = _CANDIDATE_SUPPORT._closed_candidate_environment(
                {},
                home=home,
                temporary_root=home,
                safe_git_directories=(allowed,),
            )
            completed = subprocess.run(
                [
                    _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                    "config",
                    "--show-origin",
                    "--get-all",
                    "safe.directory",
                ],
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 0)
        values = [
            line.split("\t", 1)[1] for line in completed.stdout.splitlines()
        ]
        self.assertEqual(values, ["", str(allowed)])
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_ATTR_NOSYSTEM"], "1")

    def test_candidate_git_ignores_global_and_xdg_attributes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            repository = root / "repository"
            repository.mkdir()
            xdg = root / "xdg"
            attributes = xdg / "git/attributes"
            attributes.parent.mkdir(parents=True)
            attributes.write_text(
                "*.py required-ci-poison=set\n", encoding="utf-8"
            )
            environment = _CANDIDATE_SUPPORT._candidate_git_environment()
            environment.update({"HOME": str(root), "XDG_CONFIG_HOME": str(xdg)})
            initialized = subprocess.run(
                _CANDIDATE_SUPPORT.candidate_git_argv(repository, "init"),
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            checked = subprocess.run(
                _CANDIDATE_SUPPORT.candidate_git_argv(
                    repository,
                    "check-attr",
                    "required-ci-poison",
                    "--",
                    "candidate.py",
                ),
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            closed = _CANDIDATE_SUPPORT._closed_candidate_environment(
                {}, home=root, temporary_root=root
            )

        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(
            checked.stdout.strip(), "candidate.py: required-ci-poison: unspecified"
        )
        self.assertIn("core.attributesFile=/dev/null", _CANDIDATE_SUPPORT._GIT_SAFE_ARGUMENTS)
        count = int(closed["GIT_CONFIG_COUNT"])
        config_pairs = [
            (
                closed[f"GIT_CONFIG_KEY_{index}"],
                closed[f"GIT_CONFIG_VALUE_{index}"],
            )
            for index in range(count)
        ]
        self.assertEqual(config_pairs.count(("core.attributesFile", "/dev/null")), 1)

    def test_root_wrapper_is_bound_before_unshare_can_exec(self) -> None:
        self.assertTrue(hasattr(_CANDIDATE_SUPPORT, "_ROOT_WRAPPER_SOURCE"))
        wrapper_source = _CANDIDATE_SUPPORT._ROOT_WRAPPER_SOURCE
        outer_wrapper_source = (
            _CANDIDATE_SUPPORT._REGISTERED_SUDO_WRAPPER_SOURCE
        )
        controller_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_controller_main
        )
        registered_sudo_source = inspect.getsource(
            _CANDIDATE_SUPPORT._run_registered_sudo_under_gate
        )

        self.assertIn("PR_SET_PDEATHSIG", wrapper_source)
        self.assertIn("controller_start_time", wrapper_source)
        self.assertIn("barrier", wrapper_source)
        self.assertIn("PR_SET_PDEATHSIG", outer_wrapper_source)
        self.assertIn("parent_start_time", outer_wrapper_source)
        self.assertIn("barrier", outer_wrapper_source)
        self.assertIn("wrapper_pidfd", controller_source)
        self.assertIn("_write_root_controller_handshake", controller_source)
        self.assertLess(
            controller_source.rindex("_write_root_controller_handshake"),
            controller_source.index("release_wrapper_barrier"),
        )
        self.assertLess(
            registered_sudo_source.index('"outer-bound"'),
            registered_sudo_source.index('"root-authorized"'),
        )
        self.assertLess(
            registered_sudo_source.index('"root-authorized"'),
            registered_sudo_source.index("_release_wrapper_barrier"),
        )

    def test_prebound_outer_marker_is_recoverable_before_outer_binding(self) -> None:
        registered_source = inspect.getsource(
            _CANDIDATE_SUPPORT._run_registered_sudo_under_gate
        )
        recovery_source = inspect.getsource(
            _CANDIDATE_SUPPORT._recover_registered_entry
        )
        discovery_source = inspect.getsource(
            _CANDIDATE_SUPPORT._discover_prepared_outer
        )
        wrapper_source = _CANDIDATE_SUPPORT._REGISTERED_SUDO_WRAPPER_SOURCE

        self.assertLess(
            registered_source.index("outer_marker=outer_marker"),
            registered_source.index("process = subprocess.Popen("),
        )
        self.assertIn("outer_marker = sys.argv[7]", wrapper_source)
        self.assertLess(
            recovery_source.index("_discover_prepared_outer"),
            recovery_source.index('"closing"'),
        )
        self.assertIn('process_path / "cmdline"', discovery_source)
        self.assertIn("identity[0] != identity[4]", discovery_source)
        self.assertIn("identity[5] != (os.getuid(),) * 4", discovery_source)

    def test_registered_sudo_pipe_failure_replays_published_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entry_path = root / f"chain-{'a' * 32}.json"
            controller_path = root / "controller.py"
            session = {
                "root": root,
                "entries": root,
                "controller_path": controller_path,
                "token": "b" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            trace: list[str] = []
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session

            def register(*_args: object, **_kwargs: object) -> Path:
                trace.append("register")
                return entry_path

            def update(*_args: object, **_kwargs: object) -> dict[str, object]:
                trace.append("bind-marker")
                return {}

            def fail_pipe(_flags: int) -> tuple[int, int]:
                trace.append("pipe")
                raise OSError("injected pipe acquisition failure")

            def recover(*_args: object, **_kwargs: object) -> None:
                trace.append("recover")

            identity = (123, 456, 123, 123, 123, (os.getuid(),) * 4)
            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_process_identity",
                    return_value=identity,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_register_trusted_root_chain",
                    side_effect=register,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_update_trusted_root_chain",
                    side_effect=update,
                ), mock.patch.object(
                    os, "pipe2", side_effect=fail_pipe, create=True
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_recover_registered_entry",
                    side_effect=recover,
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "registered sudo launch failed"
                    ):
                        _CANDIDATE_SUPPORT._run_registered_sudo_under_gate(
                            ["/usr/bin/true"], session_id="a" * 32
                        )
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

        self.assertEqual(trace, ["register", "bind-marker", "pipe", "recover"])

    def test_registered_sudo_post_publish_failure_replays_only_owned_entry(
        self,
    ) -> None:
        for publication_state in ("final-owned", "final-unmarked", "staging"):
            with self.subTest(publication_state=publication_state), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory).resolve(strict=True)
                session_id = "a" * 32
                entry_path = root / f"chain-{session_id}.json"
                staging_path = root / f".{entry_path.name}.tmp-{'c' * 32}"
                controller_path = root / "controller.py"
                session = {
                    "root": root,
                    "entries": root,
                    "controller_path": controller_path,
                    "token": "b" * 32,
                    "target_uid": 60000,
                    "closed": False,
                    "inherited": True,
                    "watchdog_authorized": True,
                }
                trace: list[str] = []
                previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
                _CANDIDATE_SUPPORT._STRICT_SESSION = session

                def register(*_args: object, **kwargs: object) -> Path:
                    trace.append("register")
                    selected = (
                        entry_path
                        if publication_state.startswith("final-")
                        else staging_path
                    )
                    selected.write_text("published", encoding="ascii")
                    if publication_state == "final-owned":
                        callback = kwargs.get("published_callback")
                        self.assertTrue(callable(callback))
                        callback()
                    raise AssertionError("injected post-publish failure")

                def matches(*_args: object, **_kwargs: object) -> bool:
                    trace.append("attempt")
                    return publication_state == "final-unmarked"

                def recover(*_args: object, **_kwargs: object) -> None:
                    trace.append("recover")

                identity = (123, 456, 123, 123, 123, (os.getuid(),) * 4)
                try:
                    with mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_process_identity",
                        return_value=identity,
                    ), mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_register_trusted_root_chain",
                        side_effect=register,
                    ), mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_recover_registered_entry",
                        side_effect=recover,
                    ), mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_registered_entry_matches_publication_attempt",
                        side_effect=matches,
                        create=True,
                    ):
                        with self.assertRaises(AssertionError):
                            _CANDIDATE_SUPPORT._run_registered_sudo_under_gate(
                                ["/usr/bin/true"], session_id=session_id
                            )
                finally:
                    _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

                self.assertEqual(
                    trace,
                    ["register", "recover"]
                    if publication_state == "final-owned"
                    else ["register", "attempt", "recover"]
                    if publication_state == "final-unmarked"
                    else ["register", "attempt"],
                )

    def test_registered_sudo_collision_never_replays_unowned_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            session_id = "a" * 32
            controller_path = root / "controller.py"
            session = {
                "root": root,
                "entries": root,
                "controller_path": controller_path,
                "token": "b" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            identity = (123, 456, 123, 123, 123, (os.getuid(),) * 4)
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=root,
                    session_id=session_id,
                )
                original_bytes = entry_path.read_bytes()
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_process_identity",
                    return_value=identity,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_recover_registered_entry",
                ) as recover:
                    with self.assertRaises(AssertionError):
                        _CANDIDATE_SUPPORT._run_registered_sudo_under_gate(
                            ["/usr/bin/true"], session_id=session_id
                        )
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

            self.assertEqual(entry_path.read_bytes(), original_bytes)
            recover.assert_not_called()

    def test_publication_attempt_nonce_binds_the_exact_final_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            execution_root = root / "execution"
            execution_root.mkdir()
            controller_path = root / "controller.py"
            session = {
                "root": root,
                "entries": entries,
                "controller_path": controller_path,
                "token": "b" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            publication_nonce = "c" * 32
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                    session_id="a" * 32,
                    publication_nonce=publication_nonce,
                )
                binding = _CANDIDATE_SUPPORT._execution_root_binding(
                    execution_root
                )
                self.assertTrue(
                    _CANDIDATE_SUPPORT._registered_entry_matches_publication_attempt(
                        entry_path,
                        session=session,
                        publication_nonce=publication_nonce,
                        execution_root_binding=binding,
                        cleanup_execution_root=False,
                    )
                )
                with self.assertRaisesRegex(
                    AssertionError, "collided with an unowned entry"
                ):
                    _CANDIDATE_SUPPORT._registered_entry_matches_publication_attempt(
                        entry_path,
                        session=session,
                        publication_nonce="d" * 32,
                        execution_root_binding=binding,
                        cleanup_execution_root=False,
                    )
                document = json.loads(entry_path.read_text(encoding="ascii"))
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

        self.assertEqual(document["publication_nonce"], publication_nonce)

    def test_missing_session_leader_never_signals_numeric_sid_members(self) -> None:
        outer = (60001, 1234, 60001, 60001)
        member = (60002, 1235, 60001, 60001, 60001, (0, 0, 0, 0))
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_assert_registered_session_not_reused",
            return_value=False,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_host_session_inventory",
            return_value={member[0]: member},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_root_signal_host_identity"
        ) as signal_identity:
            with self.assertRaisesRegex(
                AssertionError, "lost its generation anchor"
            ):
                _CANDIDATE_SUPPORT._root_close_registered_host_session(outer)

        signal_identity.assert_not_called()

    def test_reappearing_numeric_sid_after_zero_never_signals(self) -> None:
        outer = (60001, 1234, 60001, 60001)
        member = (60002, 1235, 60001, 60001, 60001, (0, 0, 0, 0))
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_assert_registered_session_not_reused",
            return_value=True,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_host_session_inventory",
            side_effect=({}, {member[0]: member}),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_root_signal_host_identity"
        ) as signal_identity, mock.patch.object(time, "sleep"):
            with self.assertRaisesRegex(
                AssertionError, "reappeared after zero inventory"
            ):
                _CANDIDATE_SUPPORT._root_close_registered_host_session(outer)

        signal_identity.assert_not_called()

    def test_registered_session_anchor_is_never_killed_after_members(self) -> None:
        outer = (60001, 1234, 60001, 60001)
        leader = (60001, 1234, 1, 60001, 60001, (0, 0, 0, 0))
        member = (60002, 1235, 60001, 60001, 60001, (0, 0, 0, 0))
        inventories = (
            {leader[0]: leader, member[0]: member},
            {leader[0]: leader},
            {},
            {},
            {},
        )
        signaled: list[tuple[int, int]] = []
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_assert_registered_session_not_reused",
            return_value=True,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_host_session_inventory",
            side_effect=inventories,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_process_identity",
            return_value=leader,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_root_signal_host_identity",
            side_effect=lambda identity, selected_signal: signaled.append(
                (identity[0], selected_signal)
            ),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_registered_anchor_is_terminal",
            return_value=True,
        ), mock.patch.object(time, "sleep"):
            closed = _CANDIDATE_SUPPORT._root_close_registered_host_session(
                outer
            )

        self.assertIn((member[0], signal.SIGKILL), signaled)
        self.assertNotIn((leader[0], signal.SIGKILL), signaled)
        self.assertEqual(closed, 1)

    def test_registered_outer_is_a_persistent_subreaper_anchor(self) -> None:
        source = _CANDIDATE_SUPPORT._REGISTERED_SUDO_WRAPPER_SOURCE

        self.assertIn("PR_SET_CHILD_SUBREAPER", source)
        self.assertIn("os.fork()", source)
        self.assertIn("os.waitpid(-1, 0)", source)
        self.assertIn("PR_SET_PDEATHSIG, 0", source)
        self.assertLess(source.index("os.fork()"), source.index("os.execve"))

    def test_root_cleanup_drains_target_uid_before_waiting_for_anchor(self) -> None:
        source = inspect.getsource(_CANDIDATE_SUPPORT._root_cleanup_main)

        self.assertLess(
            source.index("_root_close_candidate_realm"),
            source.index("_root_close_registered_host_session"),
        )

    def test_live_backend_exercises_every_outer_launch_fault_boundary(self) -> None:
        source = inspect.getsource(_CANDIDATE_SUPPORT._ensure_strict_backend)
        probe_source = inspect.getsource(
            _CANDIDATE_SUPPORT._probe_independent_outer_owner_fault
        )
        for boundary in (
            "after-outer-popen",
            "after-outer-bound",
            "after-root-authorized",
            "after-root-authorized-barrier",
        ):
            with self.subTest(boundary=boundary):
                self.assertIn(f'"{boundary}"', source)
        self.assertIn("signal.SIGKILL", source)
        self.assertIn("signal.SIGSTOP", source)
        self.assertIn("_probe_independent_outer_owner_fault", source)
        self.assertNotIn("_invoke_strict_controller", probe_source)

    def test_outer_fault_probe_uses_an_independent_owner_and_pidfd_only(
        self,
    ) -> None:
        owner_source = inspect.getsource(
            _CANDIDATE_SUPPORT._outer_owner_fault_probe_main
        )
        parent_source = inspect.getsource(
            _CANDIDATE_SUPPORT._probe_independent_outer_owner_fault
        )
        pause_source = inspect.getsource(
            _CANDIDATE_SUPPORT._pause_at_outer_owner_fault_boundary
        )

        self.assertIn("trusted_isolation_chain_registry()", owner_source)
        self.assertLess(
            owner_source.index('bootstrap != b"G"'),
            owner_source.index("trusted_isolation_chain_registry()"),
        )
        self.assertIn("--outer-owner-fault-probe", parent_source)
        self.assertIn("start_new_session=True", parent_source)
        self.assertIn("os.pidfd_open", parent_source)
        self.assertLess(
            parent_source.index("owner_pidfd = os.pidfd_open"),
            parent_source.index('os.write(bootstrap_write_fd, b"G")'),
        )
        self.assertIn("_signal_process_pidfd", parent_source)
        self.assertIn("process.returncode != -signal.SIGKILL", parent_source)
        self.assertIn("os.read(pause_descriptor, 1)", pause_source)
        self.assertNotIn("signal.pause", pause_source)
        self.assertNotIn("_recover_registered_entry", parent_source)
        self.assertNotIn("close_trusted_isolation_chains", parent_source)
        self.assertNotIn("os.kill(", parent_source)

    def test_after_target_active_outer_child_preserves_candidate_root_channel(
        self,
    ) -> None:
        class LaunchCaptured(Exception):
            pass

        class ControllerReached(Exception):
            pass

        captured: dict[str, object] = {}

        def pipe2_cloexec(_flags: int) -> tuple[int, int]:
            read_descriptor, write_descriptor = os.pipe()
            os.set_inheritable(read_descriptor, False)
            os.set_inheritable(write_descriptor, False)
            return read_descriptor, write_descriptor

        def capture_launch(
            command: object, **options: object
        ) -> object:
            captured["command"] = list(command)  # type: ignore[arg-type]
            captured["environment"] = dict(options["env"])  # type: ignore[arg-type]
            captured["cwd"] = options["cwd"]
            raise LaunchCaptured

        fixture_stack = contextlib.ExitStack()
        self.addCleanup(fixture_stack.close)
        candidate_directory = fixture_stack.enter_context(
            tempfile.TemporaryDirectory()
        )
        candidate_root = Path(candidate_directory) / "checkout"
        candidate_root.mkdir(mode=0o700)
        fixture_stack.enter_context(
            mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_TRUSTED_CHECKOUT_ROOT",
                candidate_root,
            )
        )
        self.assertNotEqual(candidate_root.name, ".candidate")
        self.assertNotEqual(candidate_root.name, ".required-ci")
        candidate_sha = "a" * 40
        original_root_selector = os.environ.pop(
            REQUIRED_CI_CANDIDATE_ROOT_ENV, None
        )
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                registry_root = Path(temporary_directory) / "registry"
                registry_root.mkdir(mode=0o700)
                with tempfile.TemporaryFile() as lock_file:
                    with contextlib.ExitStack() as patch_stack:
                        patch_stack.enter_context(
                            mock.patch.dict(
                                os.environ,
                                {
                                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                                },
                                clear=False,
                            )
                        )
                        patch_stack.enter_context(
                            mock.patch.object(
                                _CANDIDATE_SUPPORT,
                                "_active_strict_session",
                                return_value={"root": registry_root},
                            )
                        )
                        patch_stack.enter_context(
                            mock.patch.object(
                                _CANDIDATE_SUPPORT,
                                "_strict_realm",
                                return_value={
                                    "lock": lock_file,
                                    "uid": 60000,
                                    "gid": 60000,
                                },
                            )
                        )
                        patch_stack.enter_context(
                            mock.patch.object(
                                _CANDIDATE_SUPPORT.subprocess,
                                "Popen",
                                side_effect=capture_launch,
                            )
                        )
                        patch_stack.enter_context(
                            mock.patch.object(
                                _CANDIDATE_SUPPORT.os,
                                "pipe2",
                                side_effect=pipe2_cloexec,
                                create=True,
                            )
                        )
                        with self.assertRaises(LaunchCaptured):
                            _CANDIDATE_SUPPORT._probe_independent_outer_owner_fault(
                                "after-target-active",
                                signal.SIGKILL,
                                candidate_root=candidate_root,
                                candidate_sha=candidate_sha,
                            )
        finally:
            if original_root_selector is not None:
                os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = (
                    original_root_selector
                )

        command = captured["command"]
        self.assertIsInstance(command, list)
        command = list(command)  # type: ignore[arg-type]
        self.assertEqual(
            command[:5],
            [
                str(_CANDIDATE_SUPPORT._STRICT_PRIMITIVES["python"]),
                "-I",
                "-B",
                "-S",
                str(_CANDIDATE_SUPPORT._TRUSTED_SUPPORT_PATH),
            ],
        )
        selector_index = command.index("--outer-owner-fault-probe")
        self.assertEqual(selector_index, 5)
        self.assertEqual(captured["cwd"], str(candidate_root))
        captured_environment = captured["environment"]
        self.assertIsInstance(captured_environment, dict)
        captured_environment = dict(captured_environment)  # type: ignore[arg-type]
        self.assertEqual(
            captured_environment[REQUIRED_CI_CANDIDATE_SHA_ENV], candidate_sha
        )

        original_arguments = command[selector_index + 1 :]
        self.assertEqual(len(original_arguments), 7)
        nonce = str(original_arguments[0])
        boundary = str(original_arguments[1])
        session_id = str(original_arguments[3])
        self.assertEqual(boundary, "after-target-active")
        snapshot_calls: list[tuple[Path, str, bytes]] = []
        controller_calls: list[dict[str, object]] = []

        with tempfile.TemporaryDirectory() as temporary_directory:
            control_root = Path(temporary_directory).resolve(strict=True)
            ack_path = control_root / "fault-ack.json"
            sentinel_path = control_root / "sentinel"
            runtime_root = control_root / "runtime"
            runtime_root.mkdir(mode=0o700)
            probe_path = runtime_root / "probe.py"
            _CANDIDATE_SUPPORT._write_single_link_file(
                sentinel_path,
                f"armed:{nonce}".encode("ascii"),
                0o600,
            )
            bootstrap_read, bootstrap_write = os.pipe()
            pause_read, pause_write = os.pipe()
            os.write(bootstrap_write, b"G")
            os.close(bootstrap_write)

            @contextlib.contextmanager
            def observe_snapshot(
                root: Path,
                sha: str,
                *,
                probe_source: bytes,
            ) -> Iterator[dict[str, object]]:
                snapshot_calls.append((root, sha, probe_source))
                yield {
                    "candidate_paths": {Path("probe.py"): probe_path},
                    "runtime_root": runtime_root,
                }

            def reach_controller(
                _snapshot: dict[str, object],
                _command: list[str],
                _environment: dict[str, str],
                _runtime_root: Path,
                _stdin: bytes,
                **options: object,
            ) -> None:
                controller_calls.append(options)
                raise ControllerReached("target-active boundary reached")

            child_arguments = [
                nonce,
                boundary,
                str(ack_path),
                session_id,
                str(bootstrap_read),
                str(pause_read),
                str(sentinel_path),
            ]
            stderr = io.StringIO()
            try:
                with contextlib.ExitStack() as patch_stack:
                    patch_stack.enter_context(
                        mock.patch.dict(
                            os.environ, captured_environment, clear=True
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "strict_isolation_platform_preflight",
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "trusted_isolation_chain_registry",
                            return_value={"inherited": False},
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "close_trusted_isolation_chains",
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "_execution_snapshot",
                            side_effect=observe_snapshot,
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "_closed_candidate_environment",
                            return_value={},
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "_invoke_strict_controller",
                            side_effect=reach_controller,
                        )
                    )
                    patch_stack.enter_context(contextlib.redirect_stderr(stderr))
                    self.assertEqual(
                        _CANDIDATE_SUPPORT._outer_owner_fault_probe_main(
                            child_arguments
                        ),
                        1,
                    )
            finally:
                os.close(pause_write)

        self.assertEqual(
            snapshot_calls,
            [
                (
                    candidate_root,
                    candidate_sha,
                    _CANDIDATE_SUPPORT._TARGET_ACTIVE_PROBE_SOURCE,
                )
            ],
        )
        self.assertEqual(len(controller_calls), 1)
        trusted_fault_probe = controller_calls[0]["trusted_outer_fault_probe"]
        self.assertEqual(trusted_fault_probe[1:3], (nonce, boundary))
        self.assertNotIn(
            REQUIRED_CI_CANDIDATE_ROOT_ENV, captured_environment
        )
        self.assertIn("ControllerReached: target-active boundary reached", stderr.getvalue())
        self.assertNotIn(
            "REQUIRED_CI_CANDIDATE_ROOT must be an absolute .candidate path",
            stderr.getvalue(),
        )

    def test_outer_fault_candidate_root_channel_preserves_split_selector(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory).resolve(strict=True)
            trusted_root = workspace / ".required-ci"
            candidate_root = workspace / ".candidate"
            trusted_root.mkdir(mode=0o700)
            candidate_root.mkdir(mode=0o700)
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_TRUSTED_CHECKOUT_ROOT",
                trusted_root,
            ):
                with mock.patch.dict(
                    os.environ,
                    {REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root)},
                    clear=False,
                ):
                    self.assertEqual(
                        _CANDIDATE_SUPPORT._outer_owner_candidate_root_selector(
                            candidate_root
                        ),
                        str(candidate_root),
                    )

                with mock.patch.dict(
                    os.environ,
                    {REQUIRED_CI_CANDIDATE_ROOT_ENV: str(trusted_root)},
                    clear=False,
                ), self.assertRaisesRegex(
                    AssertionError, "must be an absolute .candidate path"
                ):
                    _CANDIDATE_SUPPORT._outer_owner_candidate_root_selector(
                        trusted_root
                    )

                original_selector = os.environ.pop(
                    REQUIRED_CI_CANDIDATE_ROOT_ENV, None
                )
                try:
                    with self.assertRaisesRegex(
                        AssertionError, "is required in the trusted checkout"
                    ):
                        _CANDIDATE_SUPPORT._outer_owner_candidate_root_selector(
                            trusted_root
                        )
                finally:
                    if original_selector is not None:
                        os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = (
                            original_selector
                        )

    def test_outer_fault_candidate_root_selector_is_captured_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory).resolve(strict=True)
            trusted_root = workspace / "checkout"
            first_candidate_root = workspace / "first" / ".candidate"
            second_candidate_root = workspace / "second" / ".candidate"
            trusted_root.mkdir(mode=0o700)
            first_candidate_root.mkdir(parents=True, mode=0o700)
            second_candidate_root.mkdir(parents=True, mode=0o700)
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_TRUSTED_CHECKOUT_ROOT",
                trusted_root,
            ):
                absent_aba = mock.Mock(
                    side_effect=(
                        None,
                        str(first_candidate_root),
                        None,
                    )
                )
                with mock.patch.object(
                    _CANDIDATE_SUPPORT.os.environ,
                    "get",
                    absent_aba,
                ), self.assertRaisesRegex(
                    AssertionError,
                    "candidate root binding changed",
                ):
                    _CANDIDATE_SUPPORT._outer_owner_candidate_root_selector(
                        first_candidate_root
                    )
                absent_aba.assert_called_once_with(
                    REQUIRED_CI_CANDIDATE_ROOT_ENV
                )

                explicit_aba = mock.Mock(
                    side_effect=(
                        str(first_candidate_root),
                        str(second_candidate_root),
                        str(first_candidate_root),
                    )
                )
                with mock.patch.object(
                    _CANDIDATE_SUPPORT.os.environ,
                    "get",
                    explicit_aba,
                ), self.assertRaisesRegex(
                    AssertionError,
                    "candidate root binding changed",
                ):
                    _CANDIDATE_SUPPORT._outer_owner_candidate_root_selector(
                        second_candidate_root
                    )
                explicit_aba.assert_called_once_with(
                    REQUIRED_CI_CANDIDATE_ROOT_ENV
                )

    def test_outer_fault_ack_early_exit_reports_bounded_sanitized_output(
        self,
    ) -> None:
        stdout_payload = (
            b"probe-start\n  ::warning title=forged::probe-output\n"
            + (b"stdout-middle" * 400)
        )
        stderr_payload = (
            b"\x1b[31m\r\n::stop-commands::forged\n"
            + (b"stderr-middle" * 400)
            + b"\xff\nAssertionError: terminal-cause\n"
        )

        class EarlyExitProcess:
            pid = 73123
            returncode = 73
            inherited_descriptors: list[int] = []

            def poll(self) -> int:
                while self.inherited_descriptors:
                    os.close(self.inherited_descriptors.pop())
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                return self.returncode

        process = EarlyExitProcess()

        def pipe2_cloexec(_flags: int) -> tuple[int, int]:
            read_descriptor, write_descriptor = os.pipe()
            os.set_inheritable(read_descriptor, False)
            os.set_inheritable(write_descriptor, False)
            return read_descriptor, write_descriptor

        def launch_early_exit(*_arguments: object, **options: object) -> object:
            stdout = options["stdout"]
            stderr = options["stderr"]
            self.assertTrue(hasattr(stdout, "write"))
            self.assertTrue(hasattr(stderr, "write"))
            stdout.write(stdout_payload)  # type: ignore[union-attr]
            stderr.write(stderr_payload)  # type: ignore[union-attr]
            stdout.flush()  # type: ignore[union-attr]
            stderr.flush()  # type: ignore[union-attr]
            process.inherited_descriptors = [
                os.dup(descriptor)
                for descriptor in options["pass_fds"]  # type: ignore[union-attr]
            ]
            return process

        owner_identity = (
            process.pid,
            17,
            process.pid,
            process.pid,
            process.pid,
            (os.getuid(),) * 4,
        )
        original_pread = os.pread
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent_registry_root = Path(temporary_directory) / "registry"
            parent_registry_root.mkdir()
            candidate_root = _CANDIDATE_SUPPORT.candidate_repository_root()
            with tempfile.TemporaryFile() as lock_file, tempfile.TemporaryFile() as pidfd:
                with contextlib.ExitStack() as patch_stack:
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "_active_strict_session",
                            return_value={"root": parent_registry_root},
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "_strict_realm",
                            return_value={
                                "lock": lock_file,
                                "uid": 60000,
                                "gid": 60000,
                            },
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "_minimal_supervisor_environment",
                            return_value={},
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT.subprocess,
                            "Popen",
                            side_effect=launch_early_exit,
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT.os,
                            "pipe2",
                            side_effect=pipe2_cloexec,
                            create=True,
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT.os,
                            "pidfd_open",
                            return_value=os.dup(pidfd.fileno()),
                            create=True,
                        )
                    )
                    patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "_process_identity",
                            return_value=owner_identity,
                        )
                    )
                    signal_process = patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "_signal_process_pidfd",
                        )
                    )
                    validate_ack = patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT,
                            "_validate_outer_owner_fault_ack",
                        )
                    )
                    pread = patch_stack.enter_context(
                        mock.patch.object(
                            _CANDIDATE_SUPPORT.os,
                            "pread",
                            side_effect=original_pread,
                        )
                    )
                    with self.assertRaises(AssertionError) as raised:
                        _CANDIDATE_SUPPORT._probe_independent_outer_owner_fault(
                            "after-outer-bound",
                            signal.SIGSTOP,
                            candidate_root=candidate_root,
                            candidate_sha="a" * 40,
                        )

        message = str(raised.exception)
        self.assertTrue(
            message.startswith(
                "strict outer owner exited before publishing its fault ACK"
            )
        )
        self.assertIn('"boundary":"after-outer-bound"', message)
        self.assertIn('"returncode":73', message)
        self.assertIn('"selected_signal":"SIGSTOP"', message)
        self.assertIn("stdout: probe-start", message)
        self.assertIn("\\::warning title=forged::probe-output", message)
        self.assertIn("stderr:", message)
        self.assertIn("\\::stop-commands::forged", message)
        self.assertIn("\\xff", message)
        self.assertIn("AssertionError: terminal-cause", message)
        self.assertNotIn("\x1b", message)
        self.assertNotIn("\r", message)
        for line in message.splitlines():
            self.assertFalse(line.lstrip().startswith("::"), line)
        self.assertLessEqual(len(message), 2200)
        bytes_requested_by_descriptor: dict[int, int] = {}
        for call in pread.call_args_list:
            descriptor, length, _offset = call.args
            bytes_requested_by_descriptor[descriptor] = (
                bytes_requested_by_descriptor.get(descriptor, 0) + length
            )
        self.assertEqual(len(bytes_requested_by_descriptor), 2)
        self.assertTrue(
            all(
                requested <= 4096
                for requested in bytes_requested_by_descriptor.values()
            )
        )
        signal_process.assert_not_called()
        validate_ack.assert_not_called()

    def test_outer_fault_ack_reads_output_only_after_terminal_exit(self) -> None:
        class LiveProcess:
            def poll(self) -> None:
                return None

        class UnexpectedPollProcess:
            def poll(self) -> int:
                raise AssertionError("valid ACK unexpectedly polled the owner")

        class BooleanReturnProcess:
            def poll(self) -> bool:
                return False

        def malformed_ack(*_arguments: object, **_options: object) -> object:
            try:
                raise json.JSONDecodeError("injected", "{", 1)
            except json.JSONDecodeError as error:
                raise AssertionError("strict outer owner fault ACK is malformed") from error

        with tempfile.TemporaryDirectory() as temporary_directory:
            ack_path = Path(temporary_directory) / "fault-ack.json"
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_read_outer_owner_terminal_diagnostic",
                ) as read_diagnostic:
                    with self.assertRaisesRegex(AssertionError, "timed out"):
                        _CANDIDATE_SUPPORT._wait_outer_owner_fault_ack(
                            ack_path,
                            LiveProcess(),  # type: ignore[arg-type]
                            boundary="after-outer-popen",
                            selected_signal=signal.SIGKILL,
                            stdout_file=stdout,
                            stderr_file=stderr,
                            timeout_seconds=0.01,
                        )
                    read_diagnostic.assert_not_called()

                    expected = {"schema_version": 1}
                    with mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_read_outer_owner_json",
                        return_value=expected,
                    ):
                        self.assertIs(
                            _CANDIDATE_SUPPORT._wait_outer_owner_fault_ack(
                                ack_path,
                                UnexpectedPollProcess(),  # type: ignore[arg-type]
                                boundary="after-target-active",
                                selected_signal=signal.SIGSTOP,
                                stdout_file=stdout,
                                stderr_file=stderr,
                            ),
                            expected,
                        )
                    read_diagnostic.assert_not_called()

                    with mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_read_outer_owner_json",
                        side_effect=malformed_ack,
                    ), self.assertRaisesRegex(AssertionError, "ACK is malformed"):
                        _CANDIDATE_SUPPORT._wait_outer_owner_fault_ack(
                            ack_path,
                            UnexpectedPollProcess(),  # type: ignore[arg-type]
                            boundary="after-root-authorized",
                            selected_signal=signal.SIGKILL,
                            stdout_file=stdout,
                            stderr_file=stderr,
                        )
                    read_diagnostic.assert_not_called()

                    with self.assertRaisesRegex(
                        AssertionError, "terminal return code is malformed"
                    ):
                        _CANDIDATE_SUPPORT._wait_outer_owner_fault_ack(
                            ack_path,
                            BooleanReturnProcess(),  # type: ignore[arg-type]
                            boundary="after-root-authorized-barrier",
                            selected_signal=signal.SIGSTOP,
                            stdout_file=stdout,
                            stderr_file=stderr,
                        )
                    read_diagnostic.assert_not_called()

    def test_outer_fault_ack_binds_every_recovery_identity(self) -> None:
        publish_source = inspect.getsource(
            _CANDIDATE_SUPPORT._publish_outer_owner_fault_ack
        )
        validate_source = inspect.getsource(
            _CANDIDATE_SUPPORT._validate_outer_owner_fault_ack
        )
        for field in (
            '"nonce"',
            '"boundary"',
            '"owner"',
            '"registry_root"',
            '"entry"',
            '"outer"',
            '"watchdog"',
        ):
            with self.subTest(field=field):
                self.assertIn(field, publish_source)
                self.assertIn(field, validate_source)
        self.assertIn("_load_chain_registry_entry", publish_source)
        self.assertIn("root_metadata.st_dev", publish_source)
        self.assertIn("root_metadata.st_ino", publish_source)
        self.assertIn("watchdog_identity", publish_source)
        self.assertIn("_chain_registry_lock(entry_path)", publish_source)
        parent_source = inspect.getsource(
            _CANDIDATE_SUPPORT._probe_independent_outer_owner_fault
        )
        absence_source = inspect.getsource(
            _CANDIDATE_SUPPORT._wait_exact_registry_root_absent
        )
        self.assertIn("os.O_DIRECTORY | os.O_NOFOLLOW", parent_source)
        self.assertIn("bound_metadata.st_nlink != 0", absence_source)

    def test_registered_wrapper_waits_for_post_gate_continuation_before_sudo(
        self,
    ) -> None:
        source = _CANDIDATE_SUPPORT._REGISTERED_SUDO_WRAPPER_SOURCE
        compile(source, "<registered-sudo-wrapper>", "exec")

        self.assertIn("continuation_fd", source)
        self.assertIn("ready_fd", source)
        self.assertIn("os.isatty", source)
        self.assertIn('os.open("/dev/tty"', source)
        self.assertIn("os.write(ready_fd, b\"R\")", source)
        self.assertIn("continuation = os.read(continuation_fd, 1)", source)
        self.assertIn("if continuation != b\"C\"", source)
        self.assertLess(
            source.index("os.write(ready_fd, b\"R\")"),
            source.index("continuation = os.read(continuation_fd, 1)"),
        )
        self.assertLess(
            source.index("continuation = os.read(continuation_fd, 1)"),
            source.index("os.fork()"),
        )

    def test_outer_fault_registry_disappearance_rejects_path_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            registry_root = Path(temporary_directory) / "registry"
            registry_root.mkdir(mode=0o700)
            metadata = registry_root.lstat()
            original_identity = (metadata.st_dev, metadata.st_ino)
            replacement_root = Path(temporary_directory) / "replacement"
            replacement_root.mkdir(mode=0o700)
            replacement_metadata = replacement_root.lstat()
            self.assertNotEqual(
                (replacement_metadata.st_dev, replacement_metadata.st_ino),
                original_identity,
            )
            registry_descriptor = os.open(
                registry_root,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
            )
            try:
                registry_root.rmdir()
                replacement_root.rename(registry_root)

                with self.assertRaisesRegex(AssertionError, "identity.*changed"):
                    _CANDIDATE_SUPPORT._wait_exact_registry_root_absent(
                        registry_root,
                        original_identity,
                        timeout_seconds=0.05,
                        bound_descriptor=registry_descriptor,
                    )
            finally:
                os.close(registry_descriptor)

    def test_outer_fault_registry_disappearance_rejects_original_root_present(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            registry_root = Path(temporary_directory) / "registry"
            registry_root.mkdir(mode=0o700)
            metadata = registry_root.lstat()
            original_identity = (metadata.st_dev, metadata.st_ino)
            registry_descriptor = os.open(
                registry_root,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
            )
            try:
                with self.assertRaisesRegex(
                    AssertionError, "registry root was not removed"
                ):
                    _CANDIDATE_SUPPORT._wait_exact_registry_root_absent(
                        registry_root,
                        original_identity,
                        timeout_seconds=0.05,
                        bound_descriptor=registry_descriptor,
                    )
            finally:
                os.close(registry_descriptor)

    def test_outer_fault_probe_reaches_real_target_active_boundary(self) -> None:
        ensure_source = inspect.getsource(
            _CANDIDATE_SUPPORT._ensure_strict_backend
        )
        registered_source = inspect.getsource(
            _CANDIDATE_SUPPORT._run_registered_sudo_under_gate
        )
        controller_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_controller_main
        )
        owner_source = inspect.getsource(
            _CANDIDATE_SUPPORT._outer_owner_fault_probe_main
        )
        parent_source = inspect.getsource(
            _CANDIDATE_SUPPORT._probe_independent_outer_owner_fault
        )

        self.assertIn('"after-target-active"', ensure_source)
        self.assertLess(
            registered_source.index(
                "_release_registered_wrapper_continuation"
            ),
            registered_source.index("_wait_registered_root_active"),
        )
        self.assertLess(
            registered_source.index("_wait_registered_root_active"),
            registered_source.index(
                '"after-target-active"',
                registered_source.index("_wait_registered_root_active"),
            ),
        )
        self.assertIn("_write_root_controller_handshake", controller_source)
        self.assertIn("_wait_root_target_active", controller_source)
        self.assertIn("_publish_root_target_active", controller_source)
        self.assertIn("active_owner_pidfd", controller_source)
        self.assertIn("_mark_root_active_completed", controller_source)
        self.assertIn("_TARGET_ACTIVE_PROBE_SOURCE", owner_source)
        self.assertIn("_execution_snapshot", owner_source)
        self.assertIn("_invoke_strict_controller", owner_source)
        self.assertIn("root_active_pidfds", parent_source)
        self.assertIn('description="root-active', parent_source)
        self.assertIn("_assert_outer_owner_sentinel", parent_source)
        self.assertEqual(
            parent_source.count("_signal_process_pidfd(owner_pidfd"), 2
        )

    def test_root_active_ack_requires_exact_full_ancestry(self) -> None:
        outer = (61000, 100, 61000, 61000)
        target_uid = 60000
        nonce = "a" * 32
        identities = {
            61001: (61001, 101, 61000, 61001, 61000, (501, 0, 0, 0)),
            61002: (61002, 102, 61001, 61002, 61000, (0, 0, 0, 0)),
            61003: (61003, 103, 61002, 61003, 61000, (0, 0, 0, 0)),
            61004: (
                61004,
                104,
                61003,
                61004,
                61004,
                (target_uid,) * 4,
            ),
        }
        root_handshake = {
            "schema_version": 2,
            "phase": "wrapper-bound",
            "nonce": nonce,
            "session_id": "b" * 32,
            "target_uid": target_uid,
            "controller": [61002, 102, 61002, 61000],
            "sudo_parent": [61001, 101, 61001, 61000],
            "wrapper": [61003, 103, 61003, 61000],
        }
        document = {
            "schema_version": 1,
            "nonce": nonce,
            "root_handshake": root_handshake,
            "target_marker": {
                "schema_version": 1,
                "nonce": nonce,
                "uid": target_uid,
                "gid": target_uid,
            },
            "sudo_parent": _CANDIDATE_SUPPORT._process_identity_document(
                identities[61001]
            ),
            "controller": _CANDIDATE_SUPPORT._process_identity_document(
                identities[61002]
            ),
            "wrapper": _CANDIDATE_SUPPORT._process_identity_document(
                identities[61003]
            ),
            "target": _CANDIDATE_SUPPORT._process_identity_document(
                identities[61004]
            ),
        }
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_process_identity",
            side_effect=lambda path: identities.get(int(path.name)),
        ):
            accepted = _CANDIDATE_SUPPORT._validate_registered_root_active(
                document,
                nonce=nonce,
                outer=outer,
                target_uid=target_uid,
                expected_session_id="b" * 32,
            )
            forged = dict(document)
            forged_target = dict(document["target"])
            forged_target["parent_pid"] = 99999
            forged["target"] = forged_target
            with self.assertRaisesRegex(AssertionError, "ancestry"):
                _CANDIDATE_SUPPORT._validate_registered_root_active(
                    forged,
                    nonce=nonce,
                    outer=outer,
                    target_uid=target_uid,
                    expected_session_id="b" * 32,
                )
            forged_session = dict(document)
            forged_handshake = dict(root_handshake)
            forged_handshake["session_id"] = "c" * 32
            forged_session["root_handshake"] = forged_handshake
            with self.assertRaisesRegex(AssertionError, "handshake"):
                _CANDIDATE_SUPPORT._validate_registered_root_active(
                    forged_session,
                    nonce=nonce,
                    outer=outer,
                    target_uid=target_uid,
                    expected_session_id="b" * 32,
                )

        self.assertEqual(
            tuple(identity[0] for identity in accepted),
            (61001, 61002, 61003, 61004),
        )

    def test_namespace_process_cleanup_never_uses_a_bare_pid_kill(self) -> None:
        controller_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_controller_main
        )
        test_cleanup_source = inspect.getsource(
            type(self)._terminate_marked_process
        )
        pidfd_signal_source = inspect.getsource(
            _CANDIDATE_SUPPORT._signal_process_pidfd
        )

        self.assertNotIn("os.kill(process.pid", controller_source)
        self.assertNotIn("os.kill(", test_cleanup_source)
        self.assertIn("_signal_process_pidfd", controller_source)
        self.assertIn("pidfd_send_signal", pidfd_signal_source)

    def test_trusted_parent_closes_registered_root_chains_before_receipt(self) -> None:
        supervisor_source = inspect.getsource(
            supervise_trusted_required_ci_tests
        )
        close_source = inspect.getsource(
            _close_and_verify_trusted_isolation
        )

        self.assertIn("trusted_isolation_chain_registry", supervisor_source)
        self.assertIn("_close_and_verify_trusted_isolation", supervisor_source)
        self.assertIn("finally:", supervisor_source)
        self.assertIn("close_trusted_isolation_chains", close_source)
        self.assertIn("assert_candidate_isolation_quiescent", close_source)
        self.assertLess(
            supervisor_source.index("_close_and_verify_trusted_isolation"),
            supervisor_source.index("_validated_trusted_child_receipt"),
        )

    def test_parent_uid_proof_runs_even_when_registry_cleanup_fails(self) -> None:
        calls: list[str] = []

        def fail_registry(_registry: Mapping[str, object]) -> None:
            calls.append("registry")
            raise AssertionError("injected registry cleanup failure")

        def fail_uid_proof() -> None:
            calls.append("uid")
            raise AssertionError("injected UID proof failure")

        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "close_trusted_isolation_chains",
            side_effect=fail_registry,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "assert_candidate_isolation_quiescent",
            side_effect=fail_uid_proof,
        ):
            with self.assertRaisesRegex(
                AssertionError,
                "registry cleanup.*candidate UID proof",
            ):
                _close_and_verify_trusted_isolation({})

        self.assertEqual(calls, ["registry", "uid"])

    def test_chain_registry_entry_remains_registered_until_cleanup_completes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            token = "a" * 32
            controller_path = root / "controller.py"
            handshake_path = root / "handshake.json"
            execution_root = root / "execution"
            execution_root.mkdir()
            session = {
                "root": root,
                "entries": entries,
                "controller_path": controller_path,
                "token": token,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    handshake_path,
                    60000,
                    execution_root=execution_root,
                )
                prepared = json.loads(entry_path.read_text(encoding="ascii"))
                self.assertEqual(prepared["schema_version"], 2)
                self.assertEqual(prepared["state"], "prepared")
                self.assertEqual(prepared["target_uid"], 60000)
                self.assertEqual(prepared["handshake_path"], str(handshake_path))
                outer = [60001, 1, 60001, 60001]
                _CANDIDATE_SUPPORT._transition_trusted_root_chain(
                    entry_path, ("prepared",), "outer-bound", outer=outer
                )
                _CANDIDATE_SUPPORT._transition_trusted_root_chain(
                    entry_path, ("outer-bound",), "root-authorized"
                )
                _CANDIDATE_SUPPORT._transition_trusted_root_chain(
                    entry_path, ("root-authorized",), "closing"
                )
                with mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_host_session_zero"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_uid_zero"
                ):
                    _CANDIDATE_SUPPORT._mark_trusted_root_chain_closed(
                        entry_path
                    )
                closed = json.loads(entry_path.read_text(encoding="ascii"))
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

            self.assertEqual(closed["state"], "closed")
            self.assertEqual(
                (entry_path.stat().st_nlink, stat.S_IMODE(entry_path.stat().st_mode)),
                (1, 0o600),
            )

    def test_atomic_registry_update_failure_preserves_the_prior_document(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entry_path = root / "chain.json"
            original = {"schema_version": 2, "state": "prepared"}
            replacement = {"schema_version": 2, "state": "outer-bound"}
            _CANDIDATE_SUPPORT._write_chain_registry_entry(
                entry_path, original, create=True
            )
            original_bytes = entry_path.read_bytes()

            with mock.patch.object(
                os,
                "replace",
                side_effect=OSError("injected pre-rename failure"),
            ):
                with self.assertRaisesRegex(
                    AssertionError, "durable document cannot be written"
                ):
                    _CANDIDATE_SUPPORT._write_chain_registry_entry(
                        entry_path, replacement, create=False
                    )

            self.assertEqual(entry_path.read_bytes(), original_bytes)
            self.assertEqual(
                sorted(path.name for path in root.iterdir()), ["chain.json"]
            )
            handshake_source = inspect.getsource(
                _CANDIDATE_SUPPORT._write_root_controller_handshake
            )
            self.assertIn("_atomic_json_document", handshake_source)
            self.assertNotIn("O_TRUNC", handshake_source)

    def test_atomic_create_reports_ownership_only_after_noreplace_publish(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            path = root / "document.json"
            trace: list[str] = []

            def publish(
                source: Path,
                destination: Path,
                *,
                published_callback: object = None,
            ) -> None:
                trace.append("publish")
                os.link(source, destination, follow_symlinks=False)
                self.assertTrue(callable(published_callback))
                published_callback()
                source.unlink()

            def mark_owned() -> None:
                self.assertTrue(path.is_file())
                trace.append("owned")

            def fail_directory_fsync(_directory: Path) -> None:
                trace.append("fsync")
                raise OSError("injected post-publish fsync failure")

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_rename_noreplace",
                side_effect=publish,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_fsync_directory",
                side_effect=fail_directory_fsync,
            ):
                with self.assertRaisesRegex(
                    AssertionError, "durable document cannot be written"
                ):
                    _CANDIDATE_SUPPORT._atomic_json_document(
                        path,
                        {"value": "published"},
                        expected_owner=os.getuid(),
                        create=True,
                        published_callback=mark_owned,
                    )

            self.assertEqual(trace, ["publish", "owned", "fsync"])
            self.assertTrue(path.is_file())

            callback = mock.Mock()
            second = root / "pre-publish.json"
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_rename_noreplace",
                side_effect=OSError("injected pre-publish failure"),
            ):
                with self.assertRaisesRegex(
                    AssertionError, "durable document cannot be written"
                ):
                    _CANDIDATE_SUPPORT._atomic_json_document(
                        second,
                        {"value": "staged"},
                        expected_owner=os.getuid(),
                        create=True,
                        published_callback=callback,
                    )
            callback.assert_not_called()
            self.assertFalse(second.exists())

            fallback_source = root / "fallback-source.json"
            fallback_destination = root / "fallback-destination.json"
            fallback_source.write_text("fallback", encoding="ascii")
            fallback_owned = mock.Mock()
            original_unlink = Path.unlink

            def fail_source_unlink(path: Path, *args: object, **kwargs: object) -> None:
                if path == fallback_source:
                    raise OSError("injected linked-staging unlink failure")
                original_unlink(path, *args, **kwargs)

            with mock.patch.object(
                _CANDIDATE_SUPPORT.sys, "platform", "darwin"
            ), mock.patch.object(Path, "unlink", fail_source_unlink):
                with self.assertRaisesRegex(
                    OSError, "linked-staging unlink failure"
                ):
                    _CANDIDATE_SUPPORT._rename_noreplace(
                        fallback_source,
                        fallback_destination,
                        published_callback=fallback_owned,
                    )

            fallback_owned.assert_called_once_with()
            self.assertEqual(
                (fallback_source.stat().st_dev, fallback_source.stat().st_ino),
                (
                    fallback_destination.stat().st_dev,
                    fallback_destination.stat().st_ino,
                ),
            )

    def test_execution_snapshot_registration_failure_recovers_only_owned_root(
        self,
    ) -> None:
        for publication_state in ("unpublished", "callback", "final-unmarked"):
            with self.subTest(publication_state=publication_state), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory).resolve(strict=True)
                resources = root / "resources"
                resources.mkdir()
                session = {
                    "root": root,
                    "entries": root,
                    "resources": resources,
                    "controller_path": root / "controller.py",
                    "token": "b" * 32,
                    "target_uid": 60000,
                    "closed": False,
                }
                trace: list[str] = []

                def register(*_args: object, **kwargs: object) -> Path:
                    trace.append("register")
                    if publication_state == "callback":
                        callback = kwargs.get("published_callback")
                        self.assertTrue(callable(callback))
                        callback()
                    raise AssertionError("injected resource publication failure")

                def matches(*_args: object, **_kwargs: object) -> bool:
                    trace.append("attempt")
                    return publication_state == "final-unmarked"

                def recover(*_args: object, **_kwargs: object) -> None:
                    trace.append("recover")

                original_rmtree = shutil.rmtree

                def remove(path: Path) -> None:
                    trace.append("rmtree")
                    original_rmtree(path)

                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_strict_isolation_requested",
                    return_value=True,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_registry_session_gate",
                    return_value=contextlib.nullcontext(),
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_active_strict_session",
                    return_value=session,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_prepare_isolation_resource_ancestors",
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_register_trusted_root_chain",
                    side_effect=register,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_recover_registered_entry",
                    side_effect=recover,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_registered_entry_matches_publication_attempt",
                    side_effect=matches,
                    create=True,
                ), mock.patch.object(
                    shutil,
                    "rmtree",
                    side_effect=remove,
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "resource publication failure"
                    ):
                        with _CANDIDATE_SUPPORT._execution_snapshot(
                            root, "a" * 40, probe_source=b"pass\n"
                        ):
                            self.fail("snapshot unexpectedly yielded")

                self.assertEqual(
                    trace,
                    ["register", "recover"]
                    if publication_state == "callback"
                    else ["register", "attempt", "recover"]
                    if publication_state == "final-unmarked"
                    else ["register", "attempt", "rmtree"],
                )

    def test_execution_snapshot_recovers_exact_staged_resource_intent_before_delete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            resources = root / "resources"
            resources.mkdir(mode=0o700)
            controller_path = root / "controller.py"
            session = {
                "root": root,
                "entries": entries,
                "resources": resources,
                "controller_path": controller_path,
                "token": "b" * 32,
                "target_uid": 60000,
                "closed": False,
            }
            original_rename = _CANDIDATE_SUPPORT._rename_noreplace
            original_unlink = Path.unlink
            rename_calls = 0
            staging_unlink_failures = 0

            def fail_first_publish(
                source: Path,
                destination: Path,
                *,
                published_callback: object = None,
            ) -> None:
                nonlocal rename_calls
                rename_calls += 1
                if rename_calls == 1:
                    raise OSError("injected pre-publish failure")
                original_rename(
                    source,
                    destination,
                    published_callback=published_callback,
                )

            def fail_first_staging_unlink(
                path: Path, *args: object, **kwargs: object
            ) -> None:
                nonlocal staging_unlink_failures
                if (
                    staging_unlink_failures == 0
                    and _CANDIDATE_SUPPORT._CHAIN_STAGING_NAME_PATTERN.fullmatch(
                        path.name
                    )
                ):
                    staging_unlink_failures += 1
                    raise OSError("injected staged-intent retirement failure")
                original_unlink(path, *args, **kwargs)

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_isolation_requested",
                return_value=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_registry_session_gate",
                return_value=contextlib.nullcontext(),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_active_strict_session",
                return_value=session,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_prepare_isolation_resource_ancestors",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_rename_noreplace",
                side_effect=fail_first_publish,
            ), mock.patch.object(
                Path,
                "unlink",
                fail_first_staging_unlink,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_recover_registered_entry",
            ) as recover:
                with self.assertRaisesRegex(
                    AssertionError, "durable document cannot be written"
                ):
                    with _CANDIDATE_SUPPORT._execution_snapshot(
                        root, "a" * 40, probe_source=b"pass\n"
                    ):
                        self.fail("snapshot unexpectedly yielded")

            final_entries = sorted(entries.glob("chain-*.json"))
            staged_entries = sorted(entries.glob(".chain-*.json.tmp-*"))
            resource_roots = list(resources.iterdir())
            self.assertEqual(rename_calls, 2)
            self.assertEqual(staging_unlink_failures, 1)
            self.assertEqual(len(final_entries), 1)
            self.assertEqual(staged_entries, [])
            self.assertEqual(len(resource_roots), 1)
            recover.assert_called_once_with(
                final_entries[0], allow_recovery_broker=True
            )

    def test_execution_snapshot_never_claims_an_unowned_staged_resource_intent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            resources = root / "resources"
            resources.mkdir(mode=0o700)
            controller_path = root / "controller.py"
            session = {
                "root": root,
                "entries": entries,
                "resources": resources,
                "controller_path": controller_path,
                "token": "b" * 32,
                "target_uid": 60000,
                "closed": False,
            }
            original_register = (
                _CANDIDATE_SUPPORT._register_trusted_root_chain
            )

            def stage_another_attempt(
                *args: object, **kwargs: object
            ) -> Path:
                selected_kwargs = dict(kwargs)
                selected_kwargs["publication_nonce"] = "c" * 32
                selected_kwargs.pop("published_callback", None)
                final_path = original_register(*args, **selected_kwargs)
                staged_path = (
                    entries / f".{final_path.name}.tmp-{'d' * 32}"
                )
                final_path.rename(staged_path)
                raise AssertionError("injected unowned staged intent")

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_isolation_requested",
                return_value=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_registry_session_gate",
                return_value=contextlib.nullcontext(),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_active_strict_session",
                return_value=session,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_prepare_isolation_resource_ancestors",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_register_trusted_root_chain",
                side_effect=stage_another_attempt,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_recover_registered_entry",
            ) as recover, mock.patch.object(
                shutil,
                "rmtree",
            ) as remove:
                with self.assertRaisesRegex(
                    AssertionError, "belongs to another attempt"
                ):
                    with _CANDIDATE_SUPPORT._execution_snapshot(
                        root, "a" * 40, probe_source=b"pass\n"
                    ):
                        self.fail("snapshot unexpectedly yielded")

            self.assertEqual(list(entries.glob("chain-*.json")), [])
            self.assertEqual(
                len(list(entries.glob(".chain-*.json.tmp-*"))), 1
            )
            self.assertEqual(len(list(resources.iterdir())), 1)
            recover.assert_not_called()
            remove.assert_not_called()

    def test_parent_registry_replays_cleanup_and_uid_zero_proof(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            resources = root / "resources"
            resources.mkdir(mode=0o700)
            tombstones = root / ".tombstones"
            tombstones.mkdir(mode=0o710)
            session_lock = root / ".session.lock"
            session_lock.write_bytes(b"")
            session_lock.chmod(0o600)
            controller_path = root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            execution_root = root / "execution"
            execution_root.mkdir()
            token = "b" * 32
            registry = {
                "root": root,
                "entries": entries,
                "resources": resources,
                "tombstones": tombstones,
                "controller_path": controller_path,
                "token": token,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            calls: list[str] = []
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = registry
            try:
                _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                )

                def cleanup_uid(
                    _selected_controller: Path, _target_uid: int
                ) -> None:
                    calls.append("uid")

                def stable_uid(_target_uid: int) -> None:
                    calls.append("stable")

                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_root_uid_cleanup",
                    side_effect=cleanup_uid,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_stable_uid_zero",
                    side_effect=stable_uid,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
                ):
                    _CANDIDATE_SUPPORT.close_trusted_isolation_chains(
                        registry
                    )
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

            self.assertEqual(calls, ["stable", "uid", "stable"])
            self.assertFalse(root.exists())

    def test_owner_replay_orders_process_uid_and_resource_to_a_fixpoint(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True) / "registry"
            root.mkdir()
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            resources = root / "resources"
            resources.mkdir(mode=0o700)
            tombstones = root / ".tombstones"
            tombstones.mkdir(mode=0o710)
            controller_path = root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            resource_path = entries / f"chain-{'0' * 32}.json"
            process_path = entries / f"chain-{'f' * 32}.json"
            spawned_path = entries / f"chain-{'e' * 32}.json"
            documents: dict[Path, dict[str, object]] = {
                resource_path: {
                    "state": "closing",
                    "cleanup_execution_root": True,
                    "outer": None,
                    "execution_root_delete_nonce": None,
                    "execution_root_deleted": None,
                },
                process_path: {
                    "state": "prepared",
                    "cleanup_execution_root": False,
                    "outer": None,
                    "execution_root_delete_nonce": None,
                    "execution_root_deleted": None,
                },
            }
            session = {
                "root": root,
                "entries": entries,
                "resources": resources,
                "tombstones": tombstones,
                "controller_path": controller_path,
                "token": "a" * 32,
                "target_uid": 60000,
                "closed": False,
            }
            trace: list[str] = []
            spawned = False

            def inventory(
                _entries: Path, *, recover_staging: bool = False
            ) -> list[Path]:
                self.assertTrue(recover_staging)
                return sorted(documents)

            def load(entry_path: Path) -> dict[str, object]:
                return documents[entry_path]

            def recover(
                entry_path: Path, *, allow_recovery_broker: bool
            ) -> None:
                nonlocal spawned
                self.assertTrue(allow_recovery_broker)
                document = documents[entry_path]
                if document["state"] == "closed":
                    return
                label = (
                    "resource"
                    if entry_path == resource_path
                    else "spawned"
                    if entry_path == spawned_path
                    else "process"
                )
                trace.append(label)
                document["state"] = "closed"
                if entry_path == resource_path and not spawned:
                    spawned = True
                    documents[spawned_path] = {
                        "state": "prepared",
                        "cleanup_execution_root": False,
                        "outer": None,
                        "execution_root_delete_nonce": None,
                        "execution_root_deleted": None,
                    }

            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_chain_registry_entries",
                    side_effect=inventory,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_load_chain_registry_entry",
                    side_effect=load,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_recover_registered_entry",
                    side_effect=recover,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_root_uid_cleanup",
                    side_effect=lambda *_args: trace.append("uid"),
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_stable_uid_zero",
                    side_effect=lambda *_args: trace.append("stable"),
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_cleanup_orphan_resource_roots"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
                ):
                    _CANDIDATE_SUPPORT._close_trusted_isolation_chains_under_gate(
                        session
                    )
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

        self.assertEqual(
            trace,
            [
                "process",
                "uid",
                "stable",
                "resource",
                "spawned",
                "uid",
                "stable",
            ],
        )

    def test_resource_recovery_failure_restarts_at_process_and_uid_phases(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True) / "registry"
            root.mkdir()
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            resources = root / "resources"
            resources.mkdir(mode=0o700)
            tombstones = root / ".tombstones"
            tombstones.mkdir(mode=0o710)
            controller_path = root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            first_resource = entries / f"chain-{'0' * 32}.json"
            second_resource = entries / f"chain-{'1' * 32}.json"
            spawned_process = entries / f"chain-{'f' * 32}.json"
            documents: dict[Path, dict[str, object]] = {
                first_resource: {
                    "state": "closing",
                    "cleanup_execution_root": True,
                    "outer": None,
                    "execution_root_delete_nonce": None,
                    "execution_root_deleted": None,
                },
                second_resource: {
                    "state": "closing",
                    "cleanup_execution_root": True,
                    "outer": None,
                    "execution_root_delete_nonce": None,
                    "execution_root_deleted": None,
                },
            }
            session = {
                "root": root,
                "entries": entries,
                "resources": resources,
                "tombstones": tombstones,
                "controller_path": controller_path,
                "token": "a" * 32,
                "target_uid": 60000,
                "closed": False,
            }
            trace: list[str] = []
            injected_failure = False

            def inventory(
                _entries: Path, *, recover_staging: bool = False
            ) -> list[Path]:
                self.assertTrue(recover_staging)
                return sorted(documents)

            def load(entry_path: Path) -> dict[str, object]:
                return documents[entry_path]

            def recover(
                entry_path: Path, *, allow_recovery_broker: bool
            ) -> None:
                nonlocal injected_failure
                self.assertTrue(allow_recovery_broker)
                document = documents[entry_path]
                if document["state"] == "closed":
                    return
                if entry_path == first_resource and not injected_failure:
                    injected_failure = True
                    trace.append("first-resource-failed")
                    documents[spawned_process] = {
                        "state": "prepared",
                        "cleanup_execution_root": False,
                        "outer": None,
                        "execution_root_delete_nonce": None,
                        "execution_root_deleted": None,
                    }
                    raise AssertionError(
                        "injected nested broker recovery failure"
                    )
                label = (
                    "first-resource"
                    if entry_path == first_resource
                    else "second-resource"
                    if entry_path == second_resource
                    else "spawned-process"
                )
                trace.append(label)
                document["state"] = "closed"

            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_chain_registry_entries",
                    side_effect=inventory,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_load_chain_registry_entry",
                    side_effect=load,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_recover_registered_entry",
                    side_effect=recover,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_root_uid_cleanup",
                    side_effect=lambda *_args: trace.append("uid"),
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_stable_uid_zero",
                    side_effect=lambda *_args: trace.append("stable"),
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_cleanup_orphan_resource_roots"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
                ):
                    _CANDIDATE_SUPPORT._close_trusted_isolation_chains_under_gate(
                        session
                    )
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

        self.assertEqual(
            trace,
            [
                "uid",
                "stable",
                "first-resource-failed",
                "spawned-process",
                "uid",
                "stable",
                "first-resource",
                "second-resource",
            ],
        )

    def test_parent_registry_retains_recovery_state_on_cleanup_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            session_lock = root / ".session.lock"
            session_lock.write_bytes(b"")
            session_lock.chmod(0o600)
            controller_path = root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            execution_root = root / "execution"
            execution_root.mkdir()
            registry = {
                "root": root,
                "entries": entries,
                "controller_path": controller_path,
                "token": "c" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = registry
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                )
                calls: list[str] = []

                def fail_recovery(
                    _entry_path: Path, *, allow_recovery_broker: bool
                ) -> None:
                    self.assertTrue(allow_recovery_broker)
                    calls.append("entry")
                    raise AssertionError("injected entry recovery failure")

                def cleanup_uid(
                    _selected_controller: Path, _target_uid: int
                ) -> None:
                    calls.append("uid")

                def stable_uid(_target_uid: int) -> None:
                    calls.append("stable")

                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_recover_registered_entry",
                    side_effect=fail_recovery,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_root_uid_cleanup",
                    side_effect=cleanup_uid,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_stable_uid_zero",
                    side_effect=stable_uid,
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "recovery state retained"
                    ):
                        _CANDIDATE_SUPPORT.close_trusted_isolation_chains(
                            registry
                        )
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

            self.assertGreaterEqual(calls.count("entry"), 2)
            self.assertEqual(calls.count("entry"), calls.count("uid"))
            self.assertEqual(calls.count("uid"), calls.count("stable"))
            self.assertEqual(
                calls,
                ["entry", "uid", "stable"] * calls.count("entry"),
            )
            self.assertTrue(root.is_dir())
            retained = json.loads(entry_path.read_text(encoding="ascii"))
            self.assertEqual(retained["state"], "prepared")

    def test_execution_root_delete_failure_retains_closing_state_for_replay(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory).resolve(strict=True)
            registry_root = fixture_root / "registry"
            entries = registry_root / "entries"
            entries.mkdir(parents=True, mode=0o700)
            resources = registry_root / "resources"
            resources.mkdir()
            tombstones = registry_root / ".tombstones"
            tombstones.mkdir()
            execution_root = resources / "execution"
            execution_root.mkdir()
            controller_path = registry_root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            registry = {
                "root": registry_root,
                "entries": entries,
                "resources": resources,
                "tombstones": tombstones,
                "controller_path": controller_path,
                "token": "d" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = registry
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                    cleanup_execution_root=True,
                )
                with mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_uid_zero"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_registered_resource_seal",
                    side_effect=AssertionError("injected delete failure"),
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "injected delete failure"
                    ):
                        _CANDIDATE_SUPPORT._recover_registered_entry(
                            entry_path, allow_recovery_broker=True
                        )

                retained = json.loads(entry_path.read_text(encoding="ascii"))
                self.assertEqual(retained["state"], "deleting")
                self.assertRegex(
                    retained["execution_root_delete_nonce"], r"^[0-9a-f]{32}$"
                )
                self.assertTrue(execution_root.is_dir())

                durable_receipts: list[dict[str, object]] = []

                def seal_execution_root(
                    _controller: Path,
                    _entry_path: Path,
                    document: Mapping[str, object],
                ) -> None:
                    metadata = execution_root.lstat()
                    execution_root.rmdir()
                    vault_metadata = tombstones.lstat()
                    session_id = str(document["session_id"])
                    delete_nonce = str(document["execution_root_delete_nonce"])
                    durable_receipts.append(
                        {
                            "schema_version": 2,
                            "kind": "sealed-empty-tombstone",
                            "token": document["token"],
                            "session_id": session_id,
                            "delete_nonce": delete_nonce,
                            "path": str(execution_root),
                            "device": metadata.st_dev,
                            "inode": metadata.st_ino,
                            "vault_device": vault_metadata.st_dev,
                            "vault_inode": vault_metadata.st_ino,
                            "tombstone_name": (
                                f"sealed-{session_id}-{delete_nonce}"
                            ),
                            "origin_absent": True,
                            "tombstone_empty": True,
                            "tombstone_owner_uid": 0,
                            "tombstone_owner_gid": os.getgid(),
                            "tombstone_mode": 0o710,
                        }
                    )

                def read_durable_receipt(_path: Path) -> dict[str, object]:
                    if not durable_receipts:
                        raise AssertionError("durable receipt is absent")
                    return durable_receipts[-1]

                with mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_uid_zero"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_registered_resource_seal",
                    side_effect=seal_execution_root,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_read_durable_deletion_receipt_file",
                    side_effect=read_durable_receipt,
                ):
                    _CANDIDATE_SUPPORT._recover_registered_entry(
                        entry_path, allow_recovery_broker=True
                    )
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

            replayed = json.loads(entry_path.read_text(encoding="ascii"))
            self.assertEqual(replayed["state"], "closed")
            self.assertFalse(execution_root.exists())

    def test_crash_after_tombstone_rename_replays_exact_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            registry_root = Path(temporary_directory).resolve(strict=True)
            entries = registry_root / "entries"
            resources = registry_root / "resources"
            tombstones = registry_root / ".tombstones"
            entries.mkdir(mode=0o700)
            resources.mkdir()
            tombstones.mkdir()
            execution_root = resources / "execution"
            execution_root.mkdir()
            original = execution_root.lstat()
            controller_path = registry_root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            session_id = "a" * 32
            delete_nonce = "b" * 32
            session = {
                "root": registry_root,
                "entries": entries,
                "resources": resources,
                "tombstones": tombstones,
                "controller_path": controller_path,
                "token": "c" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                    cleanup_execution_root=True,
                    session_id=session_id,
                )
                _CANDIDATE_SUPPORT._transition_trusted_root_chain(
                    entry_path, ("prepared",), "closing"
                )
                document = _CANDIDATE_SUPPORT._transition_trusted_root_chain(
                    entry_path,
                    ("closing",),
                    "deleting",
                    execution_root_delete_nonce=delete_nonce,
                )
                tombstone = tombstones / f"sealed-{session_id}-{delete_nonce}"
                execution_root.rename(tombstone)
                vault_metadata = tombstones.lstat()
                durable_receipt = {
                    "schema_version": 2,
                    "kind": "sealed-empty-tombstone",
                    "token": document["token"],
                    "session_id": session_id,
                    "delete_nonce": delete_nonce,
                    "path": str(execution_root),
                    "device": original.st_dev,
                    "inode": original.st_ino,
                    "vault_device": vault_metadata.st_dev,
                    "vault_inode": vault_metadata.st_ino,
                    "tombstone_name": tombstone.name,
                    "origin_absent": True,
                    "tombstone_empty": True,
                    "tombstone_owner_uid": 0,
                    "tombstone_owner_gid": os.getgid(),
                    "tombstone_mode": 0o710,
                }

                def replay_seal(
                    _controller: Path,
                    selected_entry: Path,
                    _document: Mapping[str, object],
                ) -> None:
                    self.assertEqual(selected_entry, entry_path)
                    self.assertFalse(execution_root.exists())
                    selected = tombstone.lstat()
                    self.assertEqual(
                        (selected.st_dev, selected.st_ino),
                        (original.st_dev, original.st_ino),
                    )
                    tombstone.rmdir()

                with mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_uid_zero"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_registered_resource_seal",
                    side_effect=replay_seal,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_exact_durable_deletion_receipt",
                    return_value=durable_receipt,
                ):
                    _CANDIDATE_SUPPORT._recover_registered_entry(
                        entry_path, allow_recovery_broker=True
                    )
                replayed = json.loads(entry_path.read_text(encoding="ascii"))
                self.assertEqual(replayed["state"], "closed")
                self.assertFalse(tombstone.exists())
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

    def test_stale_authorizer_cannot_resurrect_a_recovered_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            execution_root = root / "execution"
            execution_root.mkdir()
            controller_path = root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            session = {
                "root": root,
                "entries": entries,
                "controller_path": controller_path,
                "token": "e" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                )
                original_load = _CANDIDATE_SUPPORT._load_chain_registry_entry
                authorizer_loaded = threading.Event()
                release_authorizer = threading.Event()
                recovery_finished = threading.Event()
                authorizer_errors: list[BaseException] = []
                recovery_errors: list[BaseException] = []
                paused = False

                def pausing_load(path: Path):
                    nonlocal paused
                    document = original_load(path)
                    if (
                        threading.current_thread().name == "stale-authorizer"
                        and document.get("state") == "prepared"
                        and not paused
                    ):
                        paused = True
                        authorizer_loaded.set()
                        if not release_authorizer.wait(2):
                            raise AssertionError("authorizer fixture timed out")
                    return document

                def authorize() -> None:
                    try:
                        _CANDIDATE_SUPPORT._transition_trusted_root_chain(
                            entry_path,
                            ("prepared",),
                            "outer-bound",
                            outer=[60001, 1, 60001, 60001],
                        )
                    except BaseException as error:
                        authorizer_errors.append(error)

                def recover() -> None:
                    try:
                        _CANDIDATE_SUPPORT._recover_registered_entry(
                            entry_path, allow_recovery_broker=True
                        )
                    except BaseException as error:
                        recovery_errors.append(error)
                    finally:
                        recovery_finished.set()

                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_load_chain_registry_entry",
                    side_effect=pausing_load,
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_host_session_inventory",
                    return_value={},
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_host_session_zero"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_uid_zero"
                ):
                    authorizer = threading.Thread(
                        target=authorize, name="stale-authorizer"
                    )
                    recovery = threading.Thread(
                        target=recover, name="chain-recovery"
                    )
                    authorizer.start()
                    self.assertTrue(authorizer_loaded.wait(1))
                    recovery.start()
                    recovery_finished.wait(0.25)
                    release_authorizer.set()
                    authorizer.join(2)
                    recovery.join(2)

                self.assertFalse(authorizer.is_alive())
                self.assertFalse(recovery.is_alive())
                self.assertEqual(authorizer_errors, [])
                self.assertEqual(recovery_errors, [])
                recovered = original_load(entry_path)
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

            self.assertEqual(recovered["state"], "closed")

    def test_durable_document_create_never_replaces_a_racing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entry_path = root / "chain.json"
            sentinel = b"concurrent-entry"
            original_exists = Path.exists
            selected_calls = 0

            def racing_exists(path: Path) -> bool:
                nonlocal selected_calls
                if path == entry_path:
                    selected_calls += 1
                    if selected_calls == 2:
                        entry_path.write_bytes(sentinel)
                        return False
                return original_exists(path)

            with mock.patch.object(Path, "exists", racing_exists):
                with self.assertRaisesRegex(
                    AssertionError, "appeared|already exists"
                ):
                    _CANDIDATE_SUPPORT._atomic_json_document(
                        entry_path,
                        {"schema_version": 2, "state": "prepared"},
                        expected_owner=os.getuid(),
                        create=True,
                    )

            self.assertEqual(entry_path.read_bytes(), sentinel)

    def test_inherited_child_cannot_close_the_parent_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            controller_path = root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            registry = {
                "root": root,
                "entries": entries,
                "controller_path": controller_path,
                "token": "f" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = registry
            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT, "_invoke_root_uid_cleanup"
                ) as cleanup_uid, mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_uid_zero"
                ) as stable_uid:
                    with self.assertRaisesRegex(
                        AssertionError, "inherited.*cannot close"
                    ):
                        _CANDIDATE_SUPPORT.close_trusted_isolation_chains(
                            registry
                        )
                cleanup_uid.assert_not_called()
                stable_uid.assert_not_called()
                self.assertTrue(root.is_dir())
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

    def test_registry_entry_must_match_the_active_session_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            execution_root = root / "execution"
            execution_root.mkdir()
            controller_path = root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            session = {
                "root": root,
                "entries": entries,
                "controller_path": controller_path,
                "token": "1" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                )
                document = json.loads(entry_path.read_text(encoding="ascii"))
                document["token"] = "2" * 32
                _CANDIDATE_SUPPORT._write_chain_registry_entry(
                    entry_path, document, create=False
                )
                with self.assertRaisesRegex(
                    AssertionError, "active session binding"
                ):
                    _CANDIDATE_SUPPORT._load_chain_registry_entry(entry_path)
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

    def test_missing_execution_root_is_not_a_deletion_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory).resolve(strict=True)
            registry_root = fixture_root / "registry"
            entries = registry_root / "entries"
            entries.mkdir(parents=True, mode=0o700)
            resources = registry_root / "resources"
            resources.mkdir()
            tombstones = registry_root / ".tombstones"
            tombstones.mkdir()
            execution_root = resources / "execution"
            execution_root.mkdir()
            controller_path = registry_root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            session = {
                "root": registry_root,
                "entries": entries,
                "resources": resources,
                "tombstones": tombstones,
                "controller_path": controller_path,
                "token": "3" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                    cleanup_execution_root=True,
                )
                execution_root.rmdir()
                with mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_uid_zero"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_registered_resource_seal",
                    side_effect=AssertionError(
                        "sealed tombstone recovery state is ambiguous"
                    ),
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "recovery state is ambiguous"
                    ):
                        _CANDIDATE_SUPPORT._recover_registered_entry(
                            entry_path, allow_recovery_broker=True
                        )
                retained = json.loads(entry_path.read_text(encoding="ascii"))
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

            self.assertEqual(retained["state"], "deleting")

    def test_renamed_execution_root_is_not_a_deletion_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory).resolve(strict=True)
            registry_root = fixture_root / "registry"
            entries = registry_root / "entries"
            entries.mkdir(parents=True, mode=0o700)
            resources = registry_root / "resources"
            resources.mkdir()
            tombstones = registry_root / ".tombstones"
            tombstones.mkdir()
            execution_root = resources / "execution"
            execution_root.mkdir()
            original = execution_root.lstat()
            moved_root = fixture_root / "moved-execution"
            controller_path = registry_root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            session = {
                "root": registry_root,
                "entries": entries,
                "resources": resources,
                "tombstones": tombstones,
                "controller_path": controller_path,
                "token": "4" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                    cleanup_execution_root=True,
                )
                execution_root.rename(moved_root)
                with mock.patch.object(
                    _CANDIDATE_SUPPORT, "_stable_uid_zero"
                ), mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_invoke_registered_resource_seal",
                    side_effect=AssertionError(
                        "sealed tombstone recovery state is ambiguous"
                    ),
                ):
                    with self.assertRaisesRegex(
                        AssertionError, "recovery state is ambiguous"
                    ):
                        _CANDIDATE_SUPPORT._recover_registered_entry(
                            entry_path, allow_recovery_broker=True
                        )
                retained = json.loads(entry_path.read_text(encoding="ascii"))
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

            moved = moved_root.lstat()
            self.assertEqual(
                (moved.st_dev, moved.st_ino),
                (original.st_dev, original.st_ino),
            )
            self.assertGreater(moved.st_nlink, 0)
            self.assertEqual(retained["state"], "deleting")
            self.assertIsNone(retained["execution_root_deleted"])

    def test_interrupted_entry_create_is_reconciled_before_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            execution_root = root / "execution"
            execution_root.mkdir()
            controller_path = root / "controller.py"
            controller_path.write_text("pass\n", encoding="utf-8")
            session_id = "5" * 32
            session = {
                "root": root,
                "entries": entries,
                "controller_path": controller_path,
                "token": "6" * 32,
                "target_uid": 60000,
                "closed": False,
                "inherited": True,
                "watchdog_authorized": True,
            }
            previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
            _CANDIDATE_SUPPORT._STRICT_SESSION = session
            try:
                entry_path = _CANDIDATE_SUPPORT._register_trusted_root_chain(
                    controller_path,
                    None,
                    60000,
                    execution_root=execution_root,
                    session_id=session_id,
                )
                staged_path = entries / f".{entry_path.name}.tmp-{'7' * 32}"
                entry_path.rename(staged_path)
                self.assertFalse(entry_path.exists())
                self.assertTrue(staged_path.is_file())
                recovered = _CANDIDATE_SUPPORT._chain_registry_entries(
                    entries, recover_staging=True
                )
                document = _CANDIDATE_SUPPORT._load_chain_registry_entry(
                    recovered[0]
                )
            finally:
                _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session

        self.assertEqual(recovered, [entries / f"chain-{session_id}.json"])
        self.assertEqual(document["state"], "prepared")
        self.assertEqual(document["session_id"], session_id)

    def test_root_deletion_receipt_separates_directory_and_file_ownership(
        self,
    ) -> None:
        atomic_source = inspect.getsource(_CANDIDATE_SUPPORT._atomic_json_document)
        broker_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_seal_execution_root_main
        )
        reader_source = inspect.getsource(
            _CANDIDATE_SUPPORT._read_durable_deletion_receipt_file
        )

        self.assertIn("expected_file_owner", atomic_source)
        self.assertIn("expected_owner=runner_uid", broker_source)
        self.assertIn("expected_file_owner=0", broker_source)
        self.assertIn("expected_file_group=runner_gid", broker_source)
        self.assertIn("expected_file_mode=0o640", broker_source)
        self.assertIn("metadata.st_uid != 0", reader_source)

    def test_root_seal_holds_bound_fd_through_receipt_and_optional_gc(self) -> None:
        delete_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_fd_delete_contents
        )
        broker_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_seal_execution_root_main
        )
        gc_source = inspect.getsource(
            _CANDIDATE_SUPPORT._gc_bound_sealed_tombstone
        )

        self.assertLess(
            delete_source.index("os.rmdir"),
            delete_source.index("os.close(child_fd)"),
        )
        self.assertLess(
            broker_source.index("_atomic_json_document"),
            broker_source.index("_gc_bound_sealed_tombstone"),
        )
        self.assertLess(
            gc_source.index("_fsync_directory(receipt_path.parent)"),
            gc_source.index("os.rmdir(tombstone_name"),
        )
        self.assertIn("os.fstat(tombstone_fd)", gc_source)
        self.assertIn("st_nlink", gc_source)

    def test_receipt_directory_fsync_failure_keeps_exact_tombstone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            entries = root / "entries"
            vault = root / "vault"
            entries.mkdir()
            vault.mkdir()
            receipt_path = entries / "receipt.json"
            tombstone = vault / "sealed-entry"
            tombstone.mkdir()
            tombstone_metadata = tombstone.lstat()
            vault_fd = os.open(vault, os.O_RDONLY | os.O_DIRECTORY)
            tombstone_fd = os.open(
                tombstone,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            try:
                with mock.patch.object(
                    _CANDIDATE_SUPPORT,
                    "_fsync_directory",
                    side_effect=OSError("injected receipt directory fsync failure"),
                ):
                    with self.assertRaisesRegex(
                        OSError, "receipt directory fsync failure"
                    ):
                        _CANDIDATE_SUPPORT._gc_bound_sealed_tombstone(
                            receipt_path,
                            vault_fd,
                            tombstone.name,
                            tombstone_fd,
                            expected_identity=(
                                tombstone_metadata.st_dev,
                                tombstone_metadata.st_ino,
                            ),
                            expected_uid=os.getuid(),
                            expected_gid=os.getgid(),
                            expected_mode=stat.S_IMODE(
                                tombstone_metadata.st_mode
                            ),
                        )

                rebound = tombstone.lstat()
                self.assertEqual(
                    (rebound.st_dev, rebound.st_ino),
                    (tombstone_metadata.st_dev, tombstone_metadata.st_ino),
                )
                self.assertEqual(os.listdir(tombstone_fd), [])
            finally:
                os.close(tombstone_fd)
                os.close(vault_fd)

        helper_source = inspect.getsource(
            _CANDIDATE_SUPPORT._gc_bound_sealed_tombstone
        )
        self.assertLess(
            helper_source.index("_fsync_directory(receipt_path.parent)"),
            helper_source.index("os.rmdir(tombstone_name"),
        )

    def test_tombstone_identity_mismatch_is_not_treated_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            resources = root / "resources"
            vault = root / "vault"
            resources.mkdir()
            vault.mkdir()
            origin = resources / "origin"
            origin.mkdir()
            wrong_tombstone = vault / "sealed-entry"
            wrong_tombstone.mkdir()
            origin_metadata = origin.lstat()
            wrong_metadata = wrong_tombstone.lstat()
            resources_fd = os.open(resources, os.O_RDONLY | os.O_DIRECTORY)
            vault_fd = os.open(vault, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertIsNone(
                    _CANDIDATE_SUPPORT._open_optional_bound_directory_entry(
                        vault_fd,
                        "missing",
                        origin_metadata.st_dev,
                        origin_metadata.st_ino,
                    )
                )
                with self.assertRaisesRegex(
                    AssertionError, "identity changed"
                ):
                    _CANDIDATE_SUPPORT._open_optional_bound_directory_entry(
                        vault_fd,
                        wrong_tombstone.name,
                        origin_metadata.st_dev,
                        origin_metadata.st_ino,
                    )
            finally:
                os.close(resources_fd)
                os.close(vault_fd)

            self.assertEqual(
                (origin.lstat().st_dev, origin.lstat().st_ino),
                (origin_metadata.st_dev, origin_metadata.st_ino),
            )
            self.assertEqual(
                (
                    wrong_tombstone.lstat().st_dev,
                    wrong_tombstone.lstat().st_ino,
                ),
                (wrong_metadata.st_dev, wrong_metadata.st_ino),
            )
            broker_source = inspect.getsource(
                _CANDIDATE_SUPPORT._root_seal_execution_root_main
            )
            self.assertIn("_open_optional_bound_directory_entry", broker_source)
            self.assertIn("_rename_directory_entry_noreplace", broker_source)
            self.assertNotIn("os.rename(", broker_source)

    def test_root_python_entrypoints_are_isolated_without_site_loading(self) -> None:
        self.assertEqual(
            _CANDIDATE_SUPPORT._ROOT_PYTHON_ARGUMENTS,
            ("-I", "-B", "-S"),
        )
        configured = {
            "target_uid": 60000,
            "target_gid": 60000,
            "selector": "/opt/hostedtoolcache/Python/3.x/bin/python",
            "resolved": "/opt/hostedtoolcache/Python/3.x/bin/python3.14",
        }
        candidate_argv = [configured["resolved"], "-I", "/candidate.py"]
        with self.root_command_mount_contract(), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_revalidate_configured_candidate_interpreter",
            return_value=configured,
        ):
            command = _CANDIDATE_SUPPORT._root_controller_candidate_command(
                self.root_command_config(
                    candidate_argv=candidate_argv,
                    candidate_interpreter=configured,
                ),
                1234,
                9,
            )
        bootstrap_index = command.index("-c")
        self.assertEqual(
            command[bootstrap_index - 4 : bootstrap_index],
            ["/usr/bin/python3", "-I", "-B", "-S"],
        )
        configured_bootstrap_index = command.index(
            _CANDIDATE_SUPPORT._CONFIGURED_RUNTIME_BOOTSTRAP_SOURCE
        )
        self.assertEqual(
            command[configured_bootstrap_index + 1 :], candidate_argv
        )
        self.assertIn(
            'runtime_binding["resolved"]',
            _CANDIDATE_SUPPORT._CANDIDATE_BOOTSTRAP_SOURCE,
        )
        self.assertIn(
            "os.execve(candidate_argv[0]",
            _CANDIDATE_SUPPORT._CONFIGURED_RUNTIME_BOOTSTRAP_SOURCE,
        )
        compile(
            _CANDIDATE_SUPPORT._CANDIDATE_BOOTSTRAP_SOURCE,
            "<system-isolation-bootstrap>",
            "exec",
        )
        with self.root_command_mount_contract(), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_revalidate_configured_candidate_interpreter",
            return_value=configured,
        ), self.assertRaisesRegex(
            AssertionError, "configured interpreter identity changed"
        ):
            _CANDIDATE_SUPPORT._root_controller_candidate_command(
                self.root_command_config(
                    candidate_argv=["/other/python", "-I"],
                    candidate_interpreter=configured,
                ),
                1234,
                9,
            )
        compile(
            _CANDIDATE_SUPPORT._CONFIGURED_RUNTIME_BOOTSTRAP_SOURCE,
            "<configured-runtime-bootstrap>",
            "exec",
        )
        system_config = self.root_command_config()
        with self.root_command_mount_contract():
            system_command = (
                _CANDIDATE_SUPPORT._root_controller_candidate_command(
                    system_config, 1234, 9
                )
            )
        self.assertIn("/usr/bin/python3", system_command)
        with self.root_command_mount_contract(), self.assertRaisesRegex(
            AssertionError, "system interpreter identity changed"
        ):
            _CANDIDATE_SUPPORT._root_controller_candidate_command(
                {**system_config, "candidate_argv": ["/tmp/python", "-I"]},
                1234,
                9,
            )

    def test_strict_root_command_isolates_ipc_before_candidate_launch(self) -> None:
        with self.root_command_mount_contract():
            command = _CANDIDATE_SUPPORT._root_controller_candidate_command(
                self.root_command_config(), 1234, 9
            )

        self.assertIn("--ipc", command)
        self.assertLess(command.index("--ipc"), command.index("/usr/bin/setpriv"))
        self.assertNotIn("/usr/bin/prlimit", command)

    def test_strict_bootstrap_nofile_capacity_matches_live_descriptor_peak(
        self,
    ) -> None:
        def bindings(
            writable_count: int,
            read_count: int,
            component_depth: int,
        ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
            writable = [
                {
                    "path": f"/writable-{index}",
                    "device": 1,
                    "inode": index + 1,
                    "host_mount_id": index + 100,
                }
                for index in range(writable_count)
            ]
            components = [
                {
                    "path": "/" if index == 0 else f"/component-{index}",
                    "kind": "directory",
                    "device": 2,
                    "inode": index + 1,
                    "uid": 0,
                    "gid": 0,
                    "permissions": 0o755,
                }
                for index in range(component_depth)
            ]
            readable = [
                {
                    "schema_version": 1,
                    "purpose": "system-arch-library",
                    "kind": "directory",
                    "path": f"/read-{index}",
                    "target_uid": 60000,
                    "target_gid": 60000,
                    "components": components,
                    "host_mount_id": index + 200,
                }
                for index in range(read_count)
            ]
            return writable, readable

        cases = (
            (64, 32, 24, 191),
            (16, 1, 24, 64),
            (16, 2, 24, 65),
            (16, 1, 25, 65),
        )
        for writable_count, read_count, depth, expected in cases:
            with self.subTest(
                writable=writable_count, readable=read_count, depth=depth
            ):
                writable, readable = bindings(
                    writable_count, read_count, depth
                )
                self.assertEqual(
                    _CANDIDATE_SUPPORT._strict_bootstrap_nofile_requirement(
                        writable, readable
                    ),
                    expected,
                )

        writable, readable = bindings(64, 32, 88)
        self.assertEqual(
            _CANDIDATE_SUPPORT._strict_bootstrap_nofile_requirement(
                writable, readable
            ),
            _CANDIDATE_SUPPORT._STRICT_BOOTSTRAP_NOFILE_LIMIT - 1,
        )
        writable, readable = bindings(64, 32, 89)
        self.assertEqual(
            _CANDIDATE_SUPPORT._strict_bootstrap_nofile_requirement(
                writable, readable
            ),
            _CANDIDATE_SUPPORT._STRICT_BOOTSTRAP_NOFILE_LIMIT,
        )
        writable, readable = bindings(64, 32, 90)
        with self.assertRaisesRegex(
            AssertionError, "descriptor capacity exceeds its fixed limit"
        ):
            _CANDIDATE_SUPPORT._strict_bootstrap_nofile_requirement(
                writable, readable
            )

        with mock.patch.object(
            _CANDIDATE_SUPPORT.resource,
            "getrlimit",
            return_value=(64, 190),
        ), self.assertRaisesRegex(
            AssertionError, "inherited hard limit is insufficient"
        ):
            _CANDIDATE_SUPPORT._assert_strict_bootstrap_nofile_capacity(191)
        for hard_limit in (191, 192, _CANDIDATE_SUPPORT.resource.RLIM_INFINITY):
            with self.subTest(hard_limit=hard_limit), mock.patch.object(
                _CANDIDATE_SUPPORT.resource,
                "getrlimit",
                return_value=(32, hard_limit),
            ):
                _CANDIDATE_SUPPORT._assert_strict_bootstrap_nofile_capacity(
                    191
                )

    def test_strict_bootstrap_nofile_capacity_is_bound_before_launch(self) -> None:
        bootstrap_source = _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE
        bootstrap_nodes = ast.parse(bootstrap_source).body
        requirement_node = next(
            node
            for node in bootstrap_nodes
            if isinstance(node, ast.FunctionDef)
            and node.name == "bootstrap_nofile_requirement"
        )
        limit_node = next(
            node
            for node in bootstrap_nodes
            if isinstance(node, ast.FunctionDef)
            and node.name == "set_bootstrap_nofile_limit"
        )
        requirement_module = ast.Module(
            body=[requirement_node, limit_node], type_ignores=[]
        )
        ast.fix_missing_locations(requirement_module)
        namespace: dict[str, object] = {}
        exec(
            compile(
                requirement_module,
                "<strict-bootstrap-nofile-requirement>",
                "exec",
            ),
            namespace,
        )
        embedded_requirement = namespace["bootstrap_nofile_requirement"]
        writable = [{} for _ in range(64)]
        readable = [
            {"components": [{} for _ in range(24)]} for _ in range(32)
        ]
        self.assertEqual(embedded_requirement(writable, readable), 191)
        cap_readable = [
            {"components": [{} for _ in range(89)]} for _ in range(32)
        ]
        self.assertEqual(
            embedded_requirement(writable, cap_readable),
            _CANDIDATE_SUPPORT._STRICT_BOOTSTRAP_NOFILE_LIMIT,
        )
        over_cap_readable = [
            {"components": [{} for _ in range(90)]} for _ in range(32)
        ]
        with self.assertRaises(SystemExit) as over_cap:
            embedded_requirement(writable, over_cap_readable)
        self.assertEqual(over_cap.exception.code, 150)

        class FakeResource:
            RLIMIT_NOFILE = 7
            RLIM_INFINITY = -1

            def __init__(self, hard_limit: int) -> None:
                self.limit = (32, hard_limit)
                self.calls: list[tuple[int, tuple[int, int]]] = []

            def getrlimit(self, selected: int) -> tuple[int, int]:
                self.assert_selected(selected)
                return self.limit

            def setrlimit(
                self, selected: int, value: tuple[int, int]
            ) -> None:
                self.assert_selected(selected)
                self.calls.append((selected, value))
                self.limit = value

            def assert_selected(self, selected: int) -> None:
                if selected != self.RLIMIT_NOFILE:
                    raise AssertionError("unexpected resource selector")

        set_embedded_limit = namespace["set_bootstrap_nofile_limit"]
        for hard_limit, accepted in ((190, False), (191, True), (192, True)):
            with self.subTest(embedded_hard_limit=hard_limit):
                fake_resource = FakeResource(hard_limit)
                namespace["resource"] = fake_resource
                if accepted:
                    set_embedded_limit(191)
                    self.assertEqual(fake_resource.limit, (191, 191))
                    self.assertEqual(
                        fake_resource.calls, [(fake_resource.RLIMIT_NOFILE, (191, 191))]
                    )
                else:
                    with self.assertRaises(SystemExit) as rejected:
                        set_embedded_limit(191)
                    self.assertEqual(rejected.exception.code, 150)
                    self.assertEqual(fake_resource.calls, [])

        default_config = self.root_command_config()
        with self.root_command_mount_contract(), mock.patch.object(
            _CANDIDATE_SUPPORT.resource,
            "getrlimit",
            return_value=(32, 64),
        ):
            low_command = _CANDIDATE_SUPPORT._root_controller_candidate_command(
                default_config, 1234, 9
            )
            high_command = _CANDIDATE_SUPPORT._root_controller_candidate_command(
                default_config, 1234, 300
            )
        for command, readiness in ((low_command, "9"), (high_command, "300")):
            bootstrap_index = command.index(bootstrap_source)
            self.assertEqual(command[bootstrap_index + 1], readiness)
            self.assertEqual(command[bootstrap_index + 2], "64")

        maximal_writable = [
            {
                "path": f"/writable-{index}",
                "device": 1,
                "inode": index + 1,
                "host_mount_id": index + 100,
            }
            for index in range(64)
        ]
        maximal_readable = [
            {
                **self.root_command_config()["read_roots"][0],
                "path": f"/read-{index}",
                "components": [{} for _ in range(24)],
                "host_mount_id": index + 200,
            }
            for index in range(32)
        ]
        maximal_config = self.root_command_config(
            writable_roots=maximal_writable,
            read_roots=maximal_readable,
        )
        with self.root_command_mount_contract(), mock.patch.object(
            _CANDIDATE_SUPPORT.resource,
            "getrlimit",
            return_value=(64, 191),
        ):
            maximal_command = (
                _CANDIDATE_SUPPORT._root_controller_candidate_command(
                    maximal_config, 1234, 9
                )
            )
        maximal_bootstrap_index = maximal_command.index(bootstrap_source)
        self.assertEqual(maximal_command[maximal_bootstrap_index + 2], "191")

        temp_limit = "set_bootstrap_nofile_limit(required_nofile)"
        final_limit = "resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))"
        self.assertIn(temp_limit, bootstrap_source)
        self.assertIn(final_limit, bootstrap_source)
        self.assertLess(
            bootstrap_source.index(temp_limit),
            bootstrap_source.index("os.open("),
        )
        self.assertLess(
            bootstrap_source.index(temp_limit),
            bootstrap_source.index(
                "os.dup2(readiness_fd, NETWORK_INTERFACE_FD"
            ),
        )
        self.assertLess(
            bootstrap_source.index(
                "activate_candidate_landlock(landlock_ruleset_fd)"
            ),
            bootstrap_source.index(final_limit),
        )
        self.assertLess(
            bootstrap_source.index(final_limit),
            bootstrap_source.index("open_descriptors = set()"),
        )
        invoke_source = inspect.getsource(
            _CANDIDATE_SUPPORT._invoke_strict_controller
        )
        self.assertLess(
            invoke_source.index("_assert_strict_bootstrap_nofile_capacity"),
            invoke_source.index("_run_registered_sudo("),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            snapshot_root = Path(temporary_directory).resolve(strict=True)
            snapshot = {
                "config_path": snapshot_root / "config.json",
                "controller_path": snapshot_root / "controller.py",
                "handshake_path": snapshot_root / "handshake.json",
                "execution_root": snapshot_root,
            }
            writable_bindings = self.root_command_config()["writable_roots"]
            read_bindings = self.root_command_config()["read_roots"]
            with contextlib.ExitStack() as patch_stack:
                patch_stack.enter_context(
                    mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_strict_realm",
                        return_value={"uid": 60000, "gid": 60000},
                    )
                )
                patch_stack.enter_context(
                    mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_strict_writable_root_bindings",
                        return_value=writable_bindings,
                    )
                )
                patch_stack.enter_context(
                    mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_strict_host_read_root_bindings",
                        return_value=read_bindings,
                    )
                )
                patch_stack.enter_context(
                    mock.patch.object(
                        _CANDIDATE_SUPPORT.resource,
                        "getrlimit",
                        return_value=(32, 63),
                    )
                )
                root_tree = patch_stack.enter_context(
                    mock.patch.object(
                        _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
                    )
                )
                registered_sudo = patch_stack.enter_context(
                    mock.patch.object(
                        _CANDIDATE_SUPPORT, "_run_registered_sudo"
                    )
                )
                popen = patch_stack.enter_context(
                    mock.patch.object(_CANDIDATE_SUPPORT.subprocess, "Popen")
                )
                patch_stack.enter_context(
                    self.assertRaisesRegex(
                        AssertionError, "inherited hard limit is insufficient"
                    )
                )
                _CANDIDATE_SUPPORT._invoke_strict_controller(
                    snapshot,
                    ["/usr/bin/python3", "-I", "/probe.py"],
                    {},
                    snapshot_root,
                    b"",
                    timeout_seconds=1,
                )
        root_tree.assert_not_called()
        registered_sudo.assert_not_called()
        popen.assert_not_called()

    def test_strict_bootstrap_nofile_allocator_honors_limit_boundary(
        self,
    ) -> None:
        probe = textwrap.dedent(
            """\
            import errno
            import json
            import os
            import resource
            import sys

            limit = int(sys.argv[1])
            readiness = int(sys.argv[2])
            source = os.open("/dev/null", os.O_WRONLY)
            try:
                os.dup2(source, readiness, inheritable=False)
                os.dup2(source, 63, inheritable=False)
            finally:
                os.close(source)
            resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))
            if resource.getrlimit(resource.RLIMIT_NOFILE) != (limit, limit):
                raise SystemExit(90)
            os.fstat(readiness)
            os.fstat(63)
            opened = []
            failure_errno = None
            while True:
                try:
                    opened.append(
                        os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                    )
                except OSError as error:
                    failure_errno = error.errno
                    break
            report = {
                "failure_errno": failure_errno,
                "maximum": max(opened),
                "opened": len(opened),
                "readiness_live": os.fstat(readiness).st_mode > 0,
            }
            for descriptor in opened:
                os.close(descriptor)
            os.close(readiness)
            os.close(63)
            sys.stdout.write(json.dumps(report, sort_keys=True) + "\\n")
            """
        )
        for limit in (64, 65):
            for readiness in (9, 80):
                with self.subTest(limit=limit, readiness=readiness):
                    completed = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-B",
                            "-S",
                            "-c",
                            probe,
                            str(limit),
                            str(readiness),
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(
                        completed.returncode, 0, completed.stderr
                    )
                    report = json.loads(completed.stdout)
                    occupied = {0, 1, 2, 63, readiness}
                    occupied_below_limit = {
                        descriptor
                        for descriptor in occupied
                        if descriptor < limit
                    }
                    available = set(range(limit)) - occupied_below_limit
                    self.assertEqual(
                        report,
                        {
                            "failure_errno": errno.EMFILE,
                            "maximum": max(available),
                            "opened": len(available),
                            "readiness_live": True,
                        },
                    )

    def test_strict_root_command_binds_network_namespace_and_uses_proc_inventory(
        self,
    ) -> None:
        with self.root_command_mount_contract():
            command = _CANDIDATE_SUPPORT._root_controller_candidate_command(
                self.root_command_config(), 1234, 9
            )

        bootstrap_source = _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE
        candidate_source = _CANDIDATE_SUPPORT._CANDIDATE_BOOTSTRAP_SOURCE
        invoke_source = inspect.getsource(
            _CANDIDATE_SUPPORT._invoke_strict_controller
        )
        bootstrap_index = command.index(bootstrap_source)
        candidate_index = command.index(candidate_source)
        self.assertIn("--net", command)
        self.assertLess(command.index("--net"), command.index("/usr/bin/setpriv"))
        self.assertEqual(command[bootstrap_index + 5], "net:[103]")
        self.assertEqual(command[candidate_index + 5], "1234")
        self.assertEqual(command[candidate_index + 6], "net:[103]")
        self.assertEqual(command[candidate_index + 7], "63")
        self.assertEqual(command[candidate_index + 8], "null")
        self.assertEqual(
            command[candidate_index + 9],
            _CANDIDATE_SUPPORT._CONFIGURED_RUNTIME_BOOTSTRAP_SOURCE,
        )
        self.assertEqual(command[candidate_index + 10], "/usr/bin/python3")
        self.assertEqual(command.count("net:[103]"), 2)
        self.assertIn(
            'host_network_namespace = _strict_host_namespace_identity("net")',
            invoke_source,
        )
        self.assertIn(
            '"host_network_namespace": host_network_namespace', invoke_source
        )
        self.assertIn("host_network_namespace", bootstrap_source)
        self.assertIn(
            'os.readlink("/proc/self/ns/net") == host_network_namespace',
            bootstrap_source,
        )
        self.assertIn("host_network_namespace", candidate_source)
        self.assertIn(
            'current_network_namespace = os.readlink("/proc/self/ns/net")',
            candidate_source,
        )
        self.assertIn(
            "current_network_namespace == host_network_namespace",
            candidate_source,
        )
        self.assertNotIn(
            '("/proc/self/net/dev", "file")', bootstrap_source
        )
        self.assertIn(
            "read_network_interfaces(network_interface_fd)", candidate_source
        )
        self.assertNotIn('os.open(\n            path,', candidate_source)
        self.assertNotIn('os.listdir("/sys/class/net")', candidate_source)
        self.assertIn(
            "strict candidate network interface inventory rejected",
            candidate_source,
        )
        self.assertIn("fallback tunnel devices is unsupported", candidate_source)
        with self.root_command_mount_contract(), self.assertRaisesRegex(
            AssertionError, "trusted boundary is malformed"
        ):
            _CANDIDATE_SUPPORT._root_controller_candidate_command(
                self.root_command_config(host_network_namespace=None),
                1234,
                9,
            )
        with self.root_command_mount_contract(), self.assertRaisesRegex(
            AssertionError, "host namespace identity changed"
        ):
            _CANDIDATE_SUPPORT._root_controller_candidate_command(
                self.root_command_config(host_network_namespace="net:[999]"),
                1234,
                9,
            )

        parsed_candidate = ast.parse(candidate_source)
        candidate_nodes = parsed_candidate.body
        network_identity_index = next(
            index
            for index, node in enumerate(candidate_nodes)
            if isinstance(node, ast.Try)
            and any(
                isinstance(statement, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and target.id == "current_network_namespace"
                    for target in statement.targets
                )
                for statement in node.body
            )
        )
        network_identity_nodes = candidate_nodes[
            network_identity_index : network_identity_index + 4
        ]
        self.assertEqual(len(network_identity_nodes), 4)
        self.assertTrue(
            all(isinstance(node, ast.If) for node in network_identity_nodes[1:])
        )
        reject_network_probe = next(
            node
            for node in candidate_nodes
            if isinstance(node, ast.FunctionDef)
            and node.name == "reject_network_probe"
        )
        network_identity_module = ast.Module(
            body=[reject_network_probe, *network_identity_nodes],
            type_ignores=[],
        )
        ast.fix_missing_locations(network_identity_module)
        network_identity_code = compile(
            network_identity_module,
            "<network-namespace-identity>",
            "exec",
        )
        valid_namespace_os = mock.Mock()
        valid_namespace_os.readlink.return_value = "net:[104]"
        exec(
            network_identity_code,
            {
                "host_network_namespace": "net:[103]",
                "os": valid_namespace_os,
                "re": re,
                "sys": sys,
            },
        )
        unreadable_namespace_os = mock.Mock()
        unreadable_namespace_os.readlink.side_effect = PermissionError(
            errno.EACCES, "network namespace cannot be read"
        )
        diagnostic = io.StringIO()
        with contextlib.redirect_stderr(diagnostic), self.assertRaises(
            SystemExit
        ) as rejected:
            exec(
                network_identity_code,
                {
                    "host_network_namespace": "net:[103]",
                    "os": unreadable_namespace_os,
                    "re": re,
                    "sys": sys,
                },
            )
        self.assertEqual(rejected.exception.code, 127)
        self.assertIn("stage=namespace-read:errno=13", diagnostic.getvalue())
        for name, host_identity, current_identity in (
            ("missing", "", "net:[104]"),
            ("reordered argument", "null", "net:[104]"),
            ("malformed host", "net:[]", "net:[104]"),
            ("host namespace reused", "net:[103]", "net:[103]"),
            ("malformed current", "net:[103]", "mnt:[104]"),
        ):
            rejected_namespace_os = mock.Mock()
            rejected_namespace_os.readlink.return_value = current_identity
            diagnostic = io.StringIO()
            with self.subTest(name=name):
                with contextlib.redirect_stderr(diagnostic), self.assertRaises(
                    SystemExit
                ) as rejected:
                    exec(
                        network_identity_code,
                        {
                            "host_network_namespace": host_identity,
                            "os": rejected_namespace_os,
                            "re": re,
                            "sys": sys,
                        },
                    )
                self.assertEqual(rejected.exception.code, 127)
                self.assertIn("stage=", diagnostic.getvalue())

        enforcement_assignment = next(
            node
            for node in candidate_nodes
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "network_interfaces"
                for target in node.targets
            )
        )
        enforcement_if = next(
            node
            for node in candidate_nodes
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "network_interfaces"
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.NotEq)
            and len(node.test.comparators) == 1
            and isinstance(node.test.comparators[0], ast.Set)
            and ast.literal_eval(node.test.comparators[0]) == {"lo"}
        )
        enforcement_assignment_index = candidate_nodes.index(
            enforcement_assignment
        )
        enforcement_if_index = candidate_nodes.index(enforcement_if)
        self.assertEqual(
            enforcement_if_index, enforcement_assignment_index + 1
        )
        enforcement_module = ast.Module(
            body=candidate_nodes[
                enforcement_assignment_index : enforcement_if_index + 1
            ],
            type_ignores=[],
        )
        ast.fix_missing_locations(enforcement_module)
        enforcement_code = compile(
            enforcement_module,
            "<network-interface-enforcement>",
            "exec",
        )
        exec(
            enforcement_code,
            {
                "json": json,
                "network_interface_fd": 63,
                "read_network_interfaces": lambda descriptor: {"lo"},
                "sys": sys,
            },
        )
        for rejected_interfaces in (set(), {"lo", "eth0"}):
            diagnostic = io.StringIO()
            with self.subTest(rejected_interfaces=rejected_interfaces):
                with contextlib.redirect_stderr(diagnostic), self.assertRaises(
                    SystemExit
                ) as rejected:
                    exec(
                        enforcement_code,
                        {
                            "json": json,
                            "network_interface_fd": 63,
                            "read_network_interfaces": (
                                lambda descriptor, result=rejected_interfaces: result
                            ),
                            "sys": sys,
                        },
                    )
                self.assertEqual(rejected.exception.code, 127)
                self.assertIn(
                    "strict candidate network interface inventory rejected",
                    diagnostic.getvalue(),
                )

    def test_strict_network_inventory_uses_a_sealed_preopened_descriptor(
        self,
    ) -> None:
        with self.root_command_mount_contract():
            command = _CANDIDATE_SUPPORT._root_controller_candidate_command(
                self.root_command_config(), 1234, 9
            )

        bootstrap_source = _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE
        candidate_source = _CANDIDATE_SUPPORT._CANDIDATE_BOOTSTRAP_SOURCE
        candidate_index = command.index(candidate_source)

        self.assertNotIn(
            '("/proc/self/net/dev", "file")', bootstrap_source
        )
        self.assertIn("NETWORK_INTERFACE_FD = 63", bootstrap_source)
        self.assertIn(
            'os.open(\n            "/proc/self/net/dev",', bootstrap_source
        )
        self.assertIn(
            "os.dup2(source_descriptor, NETWORK_INTERFACE_FD",
            bootstrap_source,
        )
        self.assertIn(
            "os.set_inheritable(NETWORK_INTERFACE_FD, True)",
            bootstrap_source,
        )
        self.assertIn(
            "{readiness_fd, NETWORK_INTERFACE_FD}", bootstrap_source
        )
        self.assertEqual(command[candidate_index + 7], "63")
        self.assertIn("network_interface_fd_value = sys.argv[7]", candidate_source)
        self.assertIn(
            "network_interface_fd = int(network_interface_fd_value)",
            candidate_source,
        )
        self.assertIn(
            "network_interfaces = read_network_interfaces(network_interface_fd)",
            candidate_source,
        )
        self.assertNotIn("/proc/self/net/dev", candidate_source)
        self.assertEqual(
            _CANDIDATE_SUPPORT._STRICT_NETWORK_INTERFACE_FD, 63
        )
        self.assertEqual(bootstrap_source.count('"/proc/self/net/dev"'), 1)
        self.assertLess(
            bootstrap_source.index(
                "resource.setrlimit(limit_name, (value, value))"
            ),
            bootstrap_source.index(
                "os.dup2(readiness_fd, NETWORK_INTERFACE_FD"
            ),
        )
        self.assertLess(
            bootstrap_source.index(
                "os.dup2(readiness_fd, NETWORK_INTERFACE_FD"
            ),
            bootstrap_source.index("core_pattern_descriptor = os.open("),
        )
        self.assertLess(
            bootstrap_source.index('"/proc/self/net/dev"'),
            bootstrap_source.index(
                "landlock_ruleset_fd = prepare_candidate_landlock("
            ),
        )
        self.assertLess(
            bootstrap_source.index(
                "landlock_ruleset_fd = prepare_candidate_landlock("
            ),
            bootstrap_source.index(
                "activate_candidate_landlock(landlock_ruleset_fd)"
            ),
        )

        candidate_nodes = ast.parse(candidate_source).body
        helper_names = {
            "reject_network_probe",
            "candidate_open_descriptors",
            "read_network_interfaces",
        }
        helper_nodes = [
            node
            for node in candidate_nodes
            if isinstance(node, ast.FunctionDef) and node.name in helper_names
        ]
        self.assertEqual({node.name for node in helper_nodes}, helper_names)
        helper_module = ast.Module(body=helper_nodes, type_ignores=[])
        ast.fix_missing_locations(helper_module)
        helper_namespace = {
            "errno": errno,
            "fcntl": fcntl,
            "NETWORK_INTERFACE_FD": 63,
            "os": os,
            "stat": stat,
            "sys": sys,
        }
        exec(
            compile(helper_module, "<sealed-network-interface-fd>", "exec"),
            helper_namespace,
        )
        read_interfaces = helper_namespace["read_network_interfaces"]
        header = (
            "Inter-|   Receive |  Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|"
            "bytes packets errs drop fifo colls carrier compressed\n"
        )
        lo_row = "    lo: " + " ".join("0" for _ in range(16)) + "\n"
        eth_row = "  eth0: " + " ".join("1" for _ in range(16)) + "\n"

        saved_descriptor = None
        saved_inheritable = None
        descriptor_was_open = False
        try:
            saved_inheritable = os.get_inheritable(63)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            saved_descriptor = os.dup(63)
            descriptor_was_open = True

        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                fixture = Path(temporary_directory) / "dev"

                def install_fixture(
                    data: bytes, flags: int = os.O_RDONLY
                ) -> None:
                    fixture.write_bytes(data)
                    source_descriptor = os.open(fixture, flags)
                    if source_descriptor == 63:
                        os.set_inheritable(source_descriptor, True)
                    else:
                        try:
                            os.dup2(source_descriptor, 63, inheritable=True)
                        finally:
                            os.close(source_descriptor)

                install_fixture((header + lo_row).encode("ascii"))
                inventory = (["0", "1", "2", "63"], ["0", "1", "2"])
                with mock.patch.object(
                    os,
                    "open",
                    side_effect=PermissionError(
                        errno.EACCES, "pathname reopen must not occur"
                    ),
                ) as forbidden_open, mock.patch.object(
                    os, "listdir", side_effect=inventory
                ):
                    self.assertEqual(read_interfaces(63), {"lo"})
                forbidden_open.assert_not_called()
                with self.assertRaises(OSError) as closed:
                    os.fstat(63)
                self.assertEqual(closed.exception.errno, errno.EBADF)

                install_fixture((header + lo_row + eth_row).encode("ascii"))
                with mock.patch.object(
                    os,
                    "listdir",
                    side_effect=(["0", "1", "2", "63"], ["0", "1", "2"]),
                ):
                    self.assertEqual(read_interfaces(63), {"lo", "eth0"})

                for malformed, expected_stage in (
                    ((header + "missing-colon\n").encode("ascii"), "proc-row"),
                    ((header + lo_row + lo_row).encode("ascii"), "proc-row"),
                    (
                        (
                            header
                            + "   bad: "
                            + " ".join(["0"] * 15 + ["x"])
                            + "\n"
                        ).encode("ascii"),
                        "proc-row",
                    ),
                    (b"X" * 65537, "proc-size"),
                    ((header + lo_row).encode("ascii") + b"\xff", "proc-decode"),
                ):
                    install_fixture(malformed)
                    diagnostic = io.StringIO()
                    listdir_values = (
                        [["0", "1", "2", "63"]]
                        if expected_stage == "proc-size"
                        else [["0", "1", "2", "63"], ["0", "1", "2"]]
                    )
                    with self.subTest(stage=expected_stage), mock.patch.object(
                        os, "listdir", side_effect=listdir_values
                    ), contextlib.redirect_stderr(diagnostic), self.assertRaises(
                        SystemExit
                    ) as rejected:
                        read_interfaces(63)
                    self.assertEqual(rejected.exception.code, 127)
                    self.assertIn(f"stage={expected_stage}", diagnostic.getvalue())

                try:
                    os.close(63)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
                diagnostic = io.StringIO()
                with contextlib.redirect_stderr(diagnostic), self.assertRaises(
                    SystemExit
                ) as rejected:
                    read_interfaces(63)
                self.assertEqual(rejected.exception.code, 127)
                self.assertIn("stage=fd-stat:errno=9", diagnostic.getvalue())

                diagnostic = io.StringIO()
                with contextlib.redirect_stderr(diagnostic), self.assertRaises(
                    SystemExit
                ) as rejected:
                    read_interfaces(62)
                self.assertEqual(rejected.exception.code, 127)
                self.assertIn("stage=fd-number", diagnostic.getvalue())

                install_fixture((header + lo_row).encode("ascii"), os.O_RDWR)
                diagnostic = io.StringIO()
                with contextlib.redirect_stderr(diagnostic), self.assertRaises(
                    SystemExit
                ) as rejected:
                    read_interfaces(63)
                self.assertEqual(rejected.exception.code, 127)
                self.assertIn("stage=fd-access", diagnostic.getvalue())

                read_descriptor, write_descriptor = os.pipe()
                try:
                    if read_descriptor == 63:
                        os.set_inheritable(read_descriptor, True)
                    else:
                        os.dup2(read_descriptor, 63, inheritable=True)
                finally:
                    if read_descriptor != 63:
                        os.close(read_descriptor)
                    os.close(write_descriptor)
                diagnostic = io.StringIO()
                with contextlib.redirect_stderr(diagnostic), self.assertRaises(
                    SystemExit
                ) as rejected:
                    read_interfaces(63)
                self.assertEqual(rejected.exception.code, 127)
                self.assertIn("stage=fd-type", diagnostic.getvalue())

                install_fixture((header + lo_row).encode("ascii"))
                duplicate_descriptor = os.dup(63)
                try:
                    diagnostic = io.StringIO()
                    with mock.patch.object(
                        os,
                        "listdir",
                        return_value=["0", "1", "2", "63", str(duplicate_descriptor)],
                    ), contextlib.redirect_stderr(
                        diagnostic
                    ), self.assertRaises(SystemExit) as rejected:
                        read_interfaces(63)
                    self.assertEqual(rejected.exception.code, 127)
                    self.assertIn(
                        "stage=fd-inventory-before", diagnostic.getvalue()
                    )
                finally:
                    os.close(duplicate_descriptor)

                install_fixture((header + lo_row).encode("ascii"))
                diagnostic = io.StringIO()
                with mock.patch.object(
                    os,
                    "listdir",
                    side_effect=(
                        ["0", "1", "2", "63"],
                        ["0", "1", "2", "63"],
                    ),
                ), mock.patch.object(
                    os, "close", return_value=None
                ) as suppressed_close, contextlib.redirect_stderr(
                    diagnostic
                ), self.assertRaises(SystemExit) as rejected:
                    read_interfaces(63)
                self.assertEqual(rejected.exception.code, 127)
                self.assertIn("stage=fd-inventory-after", diagnostic.getvalue())
                suppressed_close.assert_called_once_with(63)
                os.fstat(63)
        finally:
            try:
                os.close(63)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
            if descriptor_was_open:
                self.assertIsNotNone(saved_descriptor)
                try:
                    os.dup2(
                        int(saved_descriptor),
                        63,
                        inheritable=bool(saved_inheritable),
                    )
                finally:
                    os.close(saved_descriptor)

    def test_strict_root_command_seals_host_mounts_before_setpriv(self) -> None:
        with self.root_command_mount_contract():
            command = _CANDIDATE_SUPPORT._root_controller_candidate_command(
                self.root_command_config(), 1234, 9
            )
        unshare_index = command.index("/usr/bin/unshare")
        setpriv_index = command.index("/usr/bin/setpriv")
        root_python_index = command.index(
            "/usr/bin/python3", unshare_index + 1
        )
        bootstrap_source = _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE

        self.assertLess(root_python_index, setpriv_index)
        self.assertNotIn("/usr/bin/prlimit", command)
        self.assertEqual(
            command[root_python_index + 1 : root_python_index + 5],
            ["-I", "-B", "-S", "-c"],
        )
        self.assertIn(
            "mount_setattr",
            _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE,
        )
        self.assertIn("MOUNT_ATTR_NODEV = 4", bootstrap_source)
        self.assertIn("resource.RLIMIT_CORE: 1", bootstrap_source)
        self.assertIn(
            "resource.setrlimit(limit_name, (value, value))",
            bootstrap_source,
        )
        self.assertIn('"/proc/sys/kernel/core_pattern"', bootstrap_source)
        self.assertIn('core_pattern.startswith("|")', bootstrap_source)
        self.assertLess(
            bootstrap_source.index(
                "resource.setrlimit(limit_name, (value, value))"
            ),
            bootstrap_source.rindex("install_candidate_seccomp_filter()"),
        )
        self.assertIn(
            'set_mount_attributes("/", recursive=True, readonly=True, nodev=True)',
            bootstrap_source,
        )
        self.assertIn(
            'set_mount_attributes(\n        "",\n        recursive=False,\n        descriptor=safe_device_descriptor,\n        nodev=False,\n    )',
            bootstrap_source,
        )
        self.assertIn(
            "install_candidate_seccomp_filter",
            _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE,
        )
        self.assertIn(
            "activate_candidate_landlock",
            _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE,
        )
        self.assertLess(
            bootstrap_source.index(
                "landlock_ruleset_fd = prepare_candidate_landlock("
            ),
            bootstrap_source.index(
                "for descriptor in (*bound_descriptors, *source_descriptors)"
            ),
        )
        self.assertLess(
            bootstrap_source.index(
                "for descriptor in (*bound_descriptors, *source_descriptors)"
            ),
            bootstrap_source.index(
                "activate_candidate_landlock(landlock_ruleset_fd)"
            ),
        )
        self.assertLess(
            bootstrap_source.index(
                "activate_candidate_landlock(landlock_ruleset_fd)"
            ),
            bootstrap_source.rindex("install_candidate_seccomp_filter()"),
        )
        self.assertLess(
            bootstrap_source.rindex("install_candidate_seccomp_filter()"),
            bootstrap_source.index('os.write(readiness_fd, b"G")'),
        )
        self.assertNotIn("host_mount_id", bootstrap_source)
        self.assertIn(
            "source_mount_record = initial_inventory.get(source_mount_id)",
            bootstrap_source,
        )
        self.assertIn(
            'source_mount_record["mountpoint"] == path', bootstrap_source
        )
        bootstrap_index = command.index(bootstrap_source)
        namespace_bindings = json.loads(command[bootstrap_index + 6])
        self.assertEqual(
            namespace_bindings,
            [{"device": 1, "inode": 2, "path": "/execution"}],
        )
        namespace_read_bindings = json.loads(command[bootstrap_index + 7])
        expected_read_binding = dict(self.root_command_config()["read_roots"][0])
        expected_read_binding.pop("host_mount_id")
        self.assertEqual(namespace_read_bindings, [expected_read_binding])
        parsed_bootstrap = ast.parse(bootstrap_source)
        validate_binding = next(
            node
            for node in parsed_bootstrap.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "validate_binding"
        )
        validate_module = ast.Module(
            body=[validate_binding], type_ignores=[]
        )
        ast.fix_missing_locations(validate_module)
        validate_namespace = {"os": os, "stat": stat}
        exec(
            compile(
                validate_module,
                "<mount-namespace-binding-validator>",
                "exec",
            ),
            validate_namespace,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            selected_root = Path(temporary_directory).resolve(strict=True)
            metadata = selected_root.lstat()
            namespace_binding = {
                "path": str(selected_root),
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
            }
            self.assertEqual(
                validate_namespace["validate_binding"](namespace_binding),
                str(selected_root),
            )
            with self.assertRaises(SystemExit) as rejected:
                validate_namespace["validate_binding"](
                    {**namespace_binding, "host_mount_id": 17}
                )
            self.assertEqual(rejected.exception.code, 156)
        compile(
            _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE,
            "<mount-namespace-bootstrap>",
            "exec",
        )

    def test_strict_mount_policy_blocks_persistent_host_channels(self) -> None:
        bootstrap_source = _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE
        candidate_source = _CANDIDATE_SUPPORT._CANDIDATE_BOOTSTRAP_SOURCE
        host_read_source = inspect.getsource(
            _CANDIDATE_SUPPORT._strict_host_read_root_bindings
        )

        self.assertIn("LANDLOCK_MINIMUM_ABI = 4", bootstrap_source)
        self.assertIn("LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2", bootstrap_source)
        self.assertIn("LANDLOCK_ACCESS_FS_WRITE_FILE", bootstrap_source)
        self.assertIn("LANDLOCK_ACCESS_FS_MAKE_FIFO", bootstrap_source)
        self.assertIn("LANDLOCK_ACCESS_FS_TRUNCATE", bootstrap_source)
        self.assertNotIn("LANDLOCK_ACCESS_FS_IOCTL_DEV", bootstrap_source)
        self.assertNotIn("LANDLOCK_ACCESS_FS_READ_DIR", bootstrap_source)
        self.assertNotIn("os.listdir(trusted_root)", candidate_source)
        self.assertIn(
            '"trusted-test-file": "file"', bootstrap_source
        )
        self.assertIn(
            '"system-arch-library": "directory"', bootstrap_source
        )
        self.assertIn(
            'READ_ROOT_PURPOSES.get(document.get("purpose"))',
            bootstrap_source,
        )
        self.assertIn(
            "handled_access_fs=LANDLOCK_WRITE_ACCESS | LANDLOCK_ACCESS_FS_READ_FILE",
            bootstrap_source,
        )
        self.assertIn(
            "(descriptor, LANDLOCK_ACCESS_FS_READ_FILE)", bootstrap_source
        )
        self.assertIn("for descriptor in read_descriptors", bootstrap_source)
        self.assertIn(
            '("/proc/sys/kernel/cap_last_cap", "file")', bootstrap_source
        )
        self.assertNotIn(
            '("/proc/self/fdinfo", "directory")', bootstrap_source
        )
        self.assertNotIn('("/proc", "directory")', bootstrap_source)
        self.assertIn('Path("/usr/lib") / multiarch', host_read_source)
        self.assertNotIn(
            'Path("/lib64"), Path("/usr/lib"), Path("/usr/lib64")',
            host_read_source,
        )
        self.assertIn('Path("/etc/ld.so.preload").lstat()', host_read_source)
        self.assertIn(
            'system_stdlib / "lib-dynload"', host_read_source
        )
        self.assertIn(
            'trusted_git.parent != Path("/usr/bin")', host_read_source
        )
        self.assertIn('"/dev/null"', bootstrap_source)
        self.assertIn("os.major(null_metadata.st_rdev) != 1", bootstrap_source)
        self.assertIn("os.minor(null_metadata.st_rdev) != 3", bootstrap_source)
        self.assertIn("ctypes.sizeof(LandlockPathBeneathAttr) != 12", bootstrap_source)
        self.assertIn("0x7E020080", bootstrap_source)
        self.assertIn("errno.ENOSYS", bootstrap_source)
        self.assertIn("16, 41, 42", bootstrap_source)
        self.assertIn("29, 37, 97", bootstrap_source)
        self.assertIn("321,", bootstrap_source)
        self.assertIn("280,", bootstrap_source)
        self.assertIn("160,", bootstrap_source)
        self.assertIn("164,", bootstrap_source)
        self.assertIn("302,", bootstrap_source)
        self.assertIn("261,", bootstrap_source)
        self.assertIn("prlimit_syscall,", bootstrap_source)
        self.assertIn(
            "SockFilter(BPF_JMP_JEQ_K, 0, 5, prlimit_syscall)",
            bootstrap_source,
        )
        self.assertIn(
            "SockFilter(BPF_LD_W_ABS, 0, 0, 32)", bootstrap_source
        )
        self.assertIn(
            "SockFilter(BPF_LD_W_ABS, 0, 0, 36)", bootstrap_source
        )
        install_function = next(
            node
            for node in ast.parse(bootstrap_source).body
            if isinstance(node, ast.FunctionDef)
            and node.name == "install_candidate_seccomp_filter"
        )
        architecture_assignment = next(
            node
            for node in install_function.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "architecture"
                for target in node.targets
            )
        )
        architecture_call = architecture_assignment.value
        self.assertIsInstance(architecture_call, ast.Call)
        architecture_get = architecture_call.func
        self.assertIsInstance(architecture_get, ast.Attribute)
        architecture_mapping = architecture_get.value
        self.assertIsInstance(architecture_mapping, ast.Dict)
        architectures = {
            ast.literal_eval(key): ast.literal_eval(value)
            for key, value in zip(
                architecture_mapping.keys,
                architecture_mapping.values,
                strict=True,
            )
        }
        self.assertEqual(architectures["x86_64"][3], 302)
        self.assertNotIn(302, architectures["x86_64"][4])
        self.assertEqual(architectures["aarch64"][3], 261)
        self.assertNotIn(261, architectures["aarch64"][4])
        self.assertNotIn("FS_IOC_", bootstrap_source)
        self.assertIn("72,", bootstrap_source)
        self.assertIn("25,", bootstrap_source)
        self.assertIn("SockFilter(BPF_LD_W_ABS, 0, 0, 24)", bootstrap_source)
        self.assertIn("SockFilter(BPF_JMP_JEQ_K, 0, 1, 1036)", bootstrap_source)
        for syscall_number in (
            41,
            53,
            86,
            248,
            265,
            272,
            307,
            308,
            425,
        ):
            self.assertIn(str(syscall_number), bootstrap_source)
        self.assertNotIn('os.listdir("/sys/class/net")', candidate_source)
        self.assertIn(
            "read_network_interfaces(network_interface_fd)", candidate_source
        )
        self.assertNotIn("socket.if_nameindex", candidate_source)
        self.assertIn('status.get("Seccomp") != "2"', candidate_source)
        self.assertIn("Seccomp_filters", candidate_source)
        self.assertIn('"/proc/self/limits"', candidate_source)
        self.assertNotIn("resource.getrlimit", candidate_source)
        live_source = inspect.getsource(
            type(self).test_strict_target_access_policy_blocks_snapshot_write_and_control_read
        )
        self.assertIn("fifo_path, os.O_RDWR | os.O_NONBLOCK", live_source)
        self.assertIn('fifo_prefill = b"host-fifo-byte"', live_source)
        self.assertIn("fifo_read_errno = operation_errno", live_source)
        self.assertIn("readable_roots=(rw_hint_path,)", live_source)
        self.assertNotIn('f"/proc/self/fdinfo/', live_source)
        self.assertIn(
            'record["mountpoint"] == "/dev/shm"', live_source
        )
        self.assertIn("len(dev_shm_mounts) != 1", live_source)
        self.assertIn(
            'record["mountpoint"] == "/dev/null"', live_source
        )
        self.assertIn("len(devnull_mounts) != 1", live_source)
        self.assertIn(
            '"/tmp/required-ci-alias-probe-target"', live_source
        )
        self.assertIn(
            'self.assertEqual(listener_fifo_remaining, b"host-fifo-byte")',
            live_source,
        )

    def test_strict_host_ipc_helper_acquisition_failure_reaps_direct_child(
        self,
    ) -> None:
        live_source = inspect.cleandoc(
            inspect.getsource(
                type(self).test_strict_target_access_policy_blocks_snapshot_write_and_control_read
            )
        )
        parsed = ast.parse(live_source)
        start_helper = next(
            node
            for node in ast.walk(parsed)
            if isinstance(node, ast.FunctionDef)
            and node.name == "start_host_ipc_helper"
        )
        start_helper.returns = None
        for argument in (
            *start_helper.args.posonlyargs,
            *start_helper.args.args,
            *start_helper.args.kwonlyargs,
        ):
            argument.annotation = None
        helper_module = ast.Module(body=[start_helper], type_ignores=[])
        ast.fix_missing_locations(helper_module)
        helper_namespace = {
            "Path": Path,
            "_CANDIDATE_SUPPORT": _CANDIDATE_SUPPORT,
            "helper_source": "import time\ntime.sleep(30)\n",
            "subprocess": subprocess,
            "sys": sys,
        }
        exec(
            compile(helper_module, "<strict-host-ipc-helper-start>", "exec"),
            helper_namespace,
        )
        start = helper_namespace["start_host_ipc_helper"]
        real_popen = subprocess.Popen
        launched: list[subprocess.Popen[bytes]] = []

        def launch(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            launched.append(process)
            return process

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            socket_path = root / "host.sock"
            fifo_path = root / "host.fifo"
            go_path = root / "go"
            ready_path = root / "ready"
            with mock.patch.object(
                subprocess, "Popen", side_effect=launch
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_process_identity",
                side_effect=RuntimeError("identity probe failed"),
            ), self.assertRaisesRegex(RuntimeError, "identity probe failed"):
                start(
                    socket_path,
                    fifo_path,
                    go_path,
                    ready_path,
                    mode="normal",
                )

            self.assertEqual(len(launched), 1)
            self.assertIsNotNone(launched[0].poll())
            self.assertFalse(socket_path.exists())
            self.assertFalse(fifo_path.exists())
            self.assertFalse(ready_path.exists())

    def test_writable_root_mount_boundaries_fail_before_privilege(self) -> None:
        root = Path("/tmp/execution")
        device = os.makedev(8, 1)
        metadata = mock.Mock(st_dev=device, st_ino=2)

        def mount_inventory(*mountpoints: Path) -> dict[int, dict[str, object]]:
            inventory: dict[int, dict[str, object]] = {
                7: {
                    "parent_id": 1,
                    "major_minor": (8, 1),
                    "root": "/",
                    "mountpoint": Path("/"),
                }
            }
            for mount_id, mountpoint in enumerate(mountpoints, start=8):
                inventory[mount_id] = {
                    "parent_id": 7,
                    "major_minor": (0, mount_id),
                    "root": "/",
                    "mountpoint": mountpoint,
                }
            return inventory

        common_patches = (
            mock.patch.object(os, "O_PATH", 0x200000, create=True),
            mock.patch.object(os, "open", return_value=11),
            mock.patch.object(os, "fstat", return_value=metadata),
            mock.patch.object(os, "close"),
            mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_descriptor_mount_id",
                return_value=7,
            ),
            mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_execution_root_binding",
                return_value={
                    "path": str(root),
                    "device": device,
                    "inode": 2,
                },
            ),
        )
        with contextlib.ExitStack() as stack:
            for patcher in common_patches:
                stack.enter_context(patcher)
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_mount_inventory",
                return_value=mount_inventory(root),
            ), self.assertRaisesRegex(
                AssertionError, "contains a host mount boundary"
            ):
                _CANDIDATE_SUPPORT._strict_writable_root_mount_binding(root)
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_mount_inventory",
                return_value=mount_inventory(root / "nested"),
            ), self.assertRaisesRegex(
                AssertionError, "contains a host mount boundary"
            ):
                _CANDIDATE_SUPPORT._strict_writable_root_mount_binding(root)
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_mount_inventory",
                return_value=mount_inventory(),
            ):
                self.assertEqual(
                    _CANDIDATE_SUPPORT._strict_writable_root_mount_binding(root),
                    7,
                )

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_mount_inventory",
                return_value=mount_inventory(root / "nested"),
            ), self.assertRaisesRegex(
                AssertionError, "host read root contains a mount boundary"
            ):
                _CANDIDATE_SUPPORT._strict_host_read_root_mount_binding(root)

        host_binding = {
            "path": str(root),
            "device": 1,
            "inode": 2,
            "host_mount_id": 7,
        }
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_execution_root_binding",
            return_value={"path": str(root), "device": 1, "inode": 2},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_writable_root_mount_binding",
            return_value=8,
        ), self.assertRaisesRegex(AssertionError, "binding changed"):
            _CANDIDATE_SUPPORT._revalidate_strict_writable_root_bindings(
                [host_binding]
            )

    def test_strict_directory_mount_aliases_fail_closed_at_both_layers(
        self,
    ) -> None:
        selected_root = Path("/allowed")
        device = os.makedev(8, 1)
        topology = {
            7: {
                "parent_id": 1,
                "major_minor": (8, 1),
                "root": "/",
                "mountpoint": Path("/"),
            },
            8: {
                "parent_id": 7,
                "major_minor": (8, 1),
                # Filesystems may override mountinfo show_path; this opaque
                # value must not be treated as a source-coordinate proof.
                "root": "/opaque",
                "mountpoint": Path("/alias"),
            },
            9: {
                "parent_id": 8,
                "major_minor": (0, 42),
                "root": "/",
                "mountpoint": Path("/alias/sub"),
            },
        }
        with mock.patch.object(
            os, "O_PATH", 0x200000, create=True
        ), mock.patch.object(
            os, "open", return_value=11
        ), mock.patch.object(
            os, "fstat", return_value=mock.Mock(st_dev=device, st_ino=2)
        ), mock.patch.object(
            os, "close"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_descriptor_mount_id",
            return_value=7,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_mount_inventory",
            return_value=topology,
        ), self.assertRaisesRegex(
            AssertionError, "host read root has a mount alias"
        ):
            _CANDIDATE_SUPPORT._strict_host_read_root_mount_binding(
                selected_root
            )

        bootstrap_source = _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE
        parsed_bootstrap = ast.parse(bootstrap_source)
        topology_functions = {
            node.name: node
            for node in parsed_bootstrap.body
            if isinstance(node, ast.FunctionDef)
            and node.name
            in {
                "path_at_or_below",
                "validate_directory_mount_topology",
            }
        }
        self.assertEqual(
            set(topology_functions),
            {
                "path_at_or_below",
                "validate_directory_mount_topology",
            },
        )
        topology_module = ast.Module(
            body=[
                topology_functions[name]
                for name in (
                    "path_at_or_below",
                    "validate_directory_mount_topology",
                )
            ],
            type_ignores=[],
        )
        ast.fix_missing_locations(topology_module)
        topology_namespace = {"os": os}
        exec(
            compile(
                topology_module,
                "<mount-alias-validator>",
                "exec",
            ),
            topology_namespace,
        )
        namespace_topology = {
            mount_id: {
                **record,
                "root": record["root"],
                "mountpoint": str(record["mountpoint"]),
                "options": frozenset({"ro"}),
                "optional": (),
                "filesystem": "ext4",
                "source": "/dev/root",
                "super_options": frozenset({"ro"}),
            }
            for mount_id, record in topology.items()
        }
        with self.assertRaises(SystemExit) as rejected:
            topology_namespace["validate_directory_mount_topology"](
                str(selected_root), 7, device, namespace_topology, 172
            )
        self.assertEqual(rejected.exception.code, 172)

        initial_singleton_topology = {
            7: {
                **namespace_topology[7],
                "parent_id": 7,
            }
        }
        for same_rootfs_path in ("/usr/lib/python3.12", "/tmp/execution"):
            topology_namespace["validate_directory_mount_topology"](
                same_rootfs_path,
                7,
                device,
                initial_singleton_topology,
                172,
            )

        read_validation = bootstrap_source.index(
            "read_descriptors.append(validate_read_root(document, initial_inventory))"
        )
        overlap_guard = bootstrap_source.index(
            "for writable_path in binding_paths\n        ) or any("
        )
        first_private_mount = bootstrap_source.index(
            'mount_call(\n            "required-ci-private"'
        )
        first_writable_bind = bootstrap_source.index(
            'mount_call(\n            f"/proc/self/fd/{source_descriptor}"'
        )
        self.assertLess(overlap_guard, read_validation)
        self.assertLess(read_validation, first_private_mount)
        self.assertLess(read_validation, first_writable_bind)
        self.assertIn(
            "os.path.commonpath((path, writable_path)) == path",
            bootstrap_source,
        )
        self.assertIn(
            "os.path.commonpath((path, writable_path)) == writable_path",
            bootstrap_source,
        )
        self.assertNotIn(
            "validate_read_root(document, final_inventory)", bootstrap_source
        )
        final_revalidation = bootstrap_source.index(
            "revalidate_held_read_root(document, descriptor)"
        )
        landlock_prepare = bootstrap_source.index(
            "landlock_ruleset_fd = prepare_candidate_landlock("
        )
        self.assertLess(first_writable_bind, final_revalidation)
        self.assertLess(final_revalidation, landlock_prepare)
        self.assertIn(
            "current_descriptor = validate_read_root(document, None)",
            bootstrap_source,
        )
        self.assertIn(
            "set(final_inventory) != expected_mount_ids", bootstrap_source
        )
        self.assertIn("| {safe_device_mount_id}", bootstrap_source)
        self.assertIn("def prove_directory_alias_rejection", bootstrap_source)
        self.assertIn("libc.umount2(os.fsencode(target), 0)", bootstrap_source)
        self.assertLess(
            bootstrap_source.index(
                "current_inventory = prove_directory_alias_rejection("
            ),
            bootstrap_source.index('os.write(readiness_fd, b"G")'),
        )
        for protected_surface in (
            '"/tmp"',
            '"/var/tmp"',
            '"/run"',
            '"/dev/shm"',
            '"/dev"',
            '"/dev/mqueue"',
            '"/dev/null"',
        ):
            self.assertIn(protected_surface, bootstrap_source)

    def test_strict_mount_topology_binds_device_graph_and_raw_paths(self) -> None:
        self.assertEqual(
            _CANDIDATE_SUPPORT._decode_strict_mountinfo_path("/"), Path("/")
        )
        self.assertEqual(
            _CANDIDATE_SUPPORT._decode_strict_mountinfo_path(
                r"/alias\134040"
            ),
            Path(r"/alias\040"),
        )
        for value in (
            "relative",
            "/alias//child",
            "/alias/./child",
            "/alias/../child",
            r"/alias\000child",
        ):
            with self.subTest(value=value), self.assertRaisesRegex(
                AssertionError, "mount topology is malformed"
            ):
                _CANDIDATE_SUPPORT._decode_strict_mountinfo_path(value)

        valid_mountinfo = (
            b"7 7 8:1 opaque-show-path / ro - ext4 /dev/root ro\n"
        )
        with mock.patch.object(
            _CANDIDATE_SUPPORT.os, "open", return_value=11
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os,
            "read",
            side_effect=(valid_mountinfo, b""),
        ), mock.patch.object(_CANDIDATE_SUPPORT.os, "close"):
            inventory = _CANDIDATE_SUPPORT._strict_mount_inventory()
        self.assertEqual(
            inventory,
            {
                7: {
                    "parent_id": 7,
                    "major_minor": (8, 1),
                    "root": "opaque-show-path",
                    "mountpoint": Path("/"),
                }
            },
        )
        malformed_graph = (
            b"7 1 8:1 / / ro - ext4 /dev/root ro\n"
            b"8 2 8:1 /other /other ro - ext4 /dev/root ro\n"
        )
        with mock.patch.object(
            _CANDIDATE_SUPPORT.os, "open", return_value=11
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os,
            "read",
            side_effect=(malformed_graph, b""),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT.os, "close"
        ), self.assertRaisesRegex(
            AssertionError, "mount topology is malformed"
        ):
            _CANDIDATE_SUPPORT._strict_mount_inventory()

        selected_root = Path("/allowed")
        device = os.makedev(8, 1)
        _CANDIDATE_SUPPORT._strict_validate_directory_mount_topology(
            selected_root,
            7,
            device,
            inventory,
            "host read root",
        )
        with self.assertRaisesRegex(
            AssertionError, "mount identity changed"
        ):
            _CANDIDATE_SUPPORT._strict_validate_directory_mount_topology(
                selected_root,
                7,
                os.makedev(8, 2),
                inventory,
                "host read root",
            )

        self_parent_topology = {
            7: {
                "parent_id": 7,
                "major_minor": (8, 1),
                "root": "/",
                "mountpoint": Path("/"),
            },
            8: {
                "parent_id": 7,
                "major_minor": (9, 1),
                "root": "/",
                "mountpoint": Path("/selected"),
            },
            9: {
                "parent_id": 7,
                "major_minor": (10, 1),
                "root": "/",
                "mountpoint": Path("/unrelated"),
            },
        }
        _CANDIDATE_SUPPORT._strict_validate_directory_mount_topology(
            Path("/selected/child"),
            8,
            os.makedev(9, 1),
            self_parent_topology,
            "host read root",
        )

        parsed_bootstrap = ast.parse(
            _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE
        )
        self.assertIn(
            '"root": fields[3]',
            _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE,
        )
        self.assertNotIn(
            '"root": decode_mount_path(fields[3])',
            _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE,
        )
        decoder_functions = {
            node.name: node
            for node in parsed_bootstrap.body
            if isinstance(node, ast.FunctionDef)
            and node.name in {"decode_mount_field", "decode_mount_path"}
        }
        decoder_module = ast.Module(
            body=[
                decoder_functions["decode_mount_field"],
                decoder_functions["decode_mount_path"],
            ],
            type_ignores=[],
        )
        ast.fix_missing_locations(decoder_module)
        decoder_namespace = {"os": os}
        exec(
            compile(decoder_module, "<mount-path-decoder>", "exec"),
            decoder_namespace,
        )
        self.assertEqual(
            decoder_namespace["decode_mount_path"](r"/alias\134040"),
            r"/alias\040",
        )
        with self.assertRaises(SystemExit) as rejected_path:
            decoder_namespace["decode_mount_path"]("/alias/../child")
        self.assertEqual(rejected_path.exception.code, 155)

    def test_strict_host_read_binding_requires_runner_writable_roots_hardened(
        self,
    ) -> None:
        real_policy = _CANDIDATE_SUPPORT._assert_strict_target_runtime_policy
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory).resolve(strict=True)
            localtime_root = fixture_root / "usr/share/zoneinfo"
            localtime_root.mkdir(parents=True)
            localtime_path = localtime_root / "UTC"
            localtime_path.write_bytes(b"UTC")
            runtime_root = fixture_root / "opt/hostedtoolcache/Python/3.14.7/x64"
            interpreter_path = runtime_root / "bin/python3.14"
            stdlib_root = runtime_root / "lib/python3.14"
            interpreter_path.parent.mkdir(parents=True)
            stdlib_root.mkdir(parents=True)
            interpreter_path.write_bytes(b"python")
            unbound_path = fixture_root / "usr/share/unbound"
            unbound_path.write_bytes(b"unbound")

            fixture_paths = [
                fixture_root,
                *(path for path in fixture_root.rglob("*") if path.is_dir()),
                localtime_path,
                interpreter_path,
                unbound_path,
            ]
            fixture_identities = {
                (path.lstat().st_dev, path.lstat().st_ino)
                for path in fixture_paths
            }

            def enforce_fixture_policy(
                metadata: os.stat_result, **kwargs: object
            ) -> None:
                if (metadata.st_dev, metadata.st_ino) in fixture_identities:
                    real_policy(metadata, **kwargs)

            acl_entries: dict[Path, set[str]] = {}

            def enforce_fixture_acl(path: Path, description: str) -> None:
                if acl_entries.get(path):
                    raise AssertionError(
                        f"{description} has an unexpected POSIX ACL"
                    )

            def normalize_acl(root: Path, *, recursive: bool) -> None:
                for path, entries in acl_entries.items():
                    if path == root or (recursive and path.is_relative_to(root)):
                        entries.clear()

            for path in fixture_paths:
                path.chmod(0o555)
            try:
                common_patches = (
                    mock.patch.object(os, "O_PATH", 0, create=True),
                    mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_assert_strict_target_runtime_policy",
                        side_effect=enforce_fixture_policy,
                    ),
                    mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_strict_runtime_acl_is_absent",
                        side_effect=enforce_fixture_acl,
                    ),
                    mock.patch.object(
                        _CANDIDATE_SUPPORT,
                        "_strict_host_read_root_mount_binding",
                        return_value=17,
                    ),
                )
                with contextlib.ExitStack() as stack:
                    for patcher in common_patches:
                        stack.enter_context(patcher)

                    (fixture_root / "usr/share").chmod(0o777)
                    with self.assertRaisesRegex(
                        AssertionError, "access policy is unsafe"
                    ):
                        _CANDIDATE_SUPPORT._capture_strict_host_read_root_binding(
                            localtime_path,
                            purpose="localtime",
                            kind="file",
                            target_uid=60000,
                            target_gid=60000,
                        )
                    (fixture_root / "usr/share").chmod(0o555)
                    localtime_path.chmod(0o777)
                    with self.assertRaisesRegex(
                        AssertionError, "access policy is unsafe"
                    ):
                        _CANDIDATE_SUPPORT._capture_strict_host_read_root_binding(
                            localtime_path,
                            purpose="localtime",
                            kind="file",
                            target_uid=60000,
                            target_gid=60000,
                        )
                    localtime_path.chmod(0o555)

                    (fixture_root / "opt").chmod(0o777)
                    with self.assertRaisesRegex(
                        AssertionError, "access policy is unsafe"
                    ):
                        _CANDIDATE_SUPPORT._capture_strict_host_read_root_binding(
                            interpreter_path,
                            purpose="configured-executable",
                            kind="file",
                            target_uid=60000,
                            target_gid=60000,
                        )
                    (fixture_root / "opt").chmod(0o555)
                    interpreter_path.chmod(0o777)
                    with self.assertRaisesRegex(
                        AssertionError, "access policy is unsafe"
                    ):
                        _CANDIDATE_SUPPORT._capture_strict_host_read_root_binding(
                            interpreter_path,
                            purpose="configured-executable",
                            kind="file",
                            target_uid=60000,
                            target_gid=60000,
                        )
                    interpreter_path.chmod(0o555)

                    acl_entries.update(
                        {
                            fixture_root / "usr/share": {"access", "default"},
                            localtime_root: {"access", "default"},
                            localtime_path: {"access"},
                            fixture_root / "opt": {"access", "default"},
                            runtime_root: {"access", "default"},
                            interpreter_path: {"access"},
                            stdlib_root: {"access", "default"},
                            unbound_path: {"access"},
                        }
                    )
                    for path, purpose, kind in (
                        (localtime_path, "localtime", "file"),
                        (interpreter_path, "configured-executable", "file"),
                        (stdlib_root, "configured-stdlib", "directory"),
                    ):
                        with self.subTest(path=path, acl_state="present"):
                            with self.assertRaisesRegex(
                                AssertionError, "unexpected POSIX ACL"
                            ):
                                _CANDIDATE_SUPPORT._capture_strict_host_read_root_binding(
                                    path,
                                    purpose=purpose,
                                    kind=kind,
                                    target_uid=60000,
                                    target_gid=60000,
                                )

                    normalize_acl(localtime_root, recursive=True)
                    normalize_acl(runtime_root, recursive=True)
                    for ancestor in (
                        fixture_root / "usr/share",
                        fixture_root / "opt",
                        fixture_root / "opt/hostedtoolcache",
                        fixture_root / "opt/hostedtoolcache/Python",
                        fixture_root / "opt/hostedtoolcache/Python/3.14.7",
                    ):
                        normalize_acl(ancestor, recursive=False)
                    self.assertEqual(acl_entries[unbound_path], {"access"})
                    self.assertFalse(
                        any(
                            entries
                            for path, entries in acl_entries.items()
                            if path != unbound_path
                        )
                    )

                    for path, purpose, kind in (
                        (localtime_path, "localtime", "file"),
                        (interpreter_path, "configured-executable", "file"),
                        (stdlib_root, "configured-stdlib", "directory"),
                    ):
                        with self.subTest(path=path):
                            binding = (
                                _CANDIDATE_SUPPORT._capture_strict_host_read_root_binding(
                                    path,
                                    purpose=purpose,
                                    kind=kind,
                                    target_uid=60000,
                                    target_gid=60000,
                                )
                            )
                            self.assertEqual(binding["path"], str(path))
            finally:
                for path in sorted(
                    fixture_paths, key=lambda value: len(value.parts), reverse=True
                ):
                    path.chmod(0o755 if path.is_dir() else 0o644)

    def test_strict_host_read_roots_reject_wide_runtime_prefixes(self) -> None:
        for prefix in (Path("/opt"), Path("/usr")):
            with self.subTest(prefix=prefix), mock.patch.object(
                _CANDIDATE_SUPPORT.os,
                "uname",
                return_value=mock.Mock(machine="x86_64"),
            ), mock.patch.object(
                Path,
                "resolve",
                new=lambda self, strict=False: self,
            ), mock.patch.object(
                Path,
                "stat",
                return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o755),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_canonical_existing_directory",
                side_effect=lambda path, _description: path,
            ), mock.patch.dict(
                _CANDIDATE_SUPPORT._STRICT_PRIMITIVES,
                {"python": Path("/usr/bin/python3.12")},
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_revalidate_configured_candidate_interpreter",
                return_value={
                    "target_uid": 60000,
                    "target_gid": 60000,
                    "resolved": str(prefix / "bin/python3.14"),
                    "stdlib_resolved": str(prefix / "lib/python3.14/os.py"),
                },
            ), self.assertRaisesRegex(
                AssertionError, "runtime prefix is not narrowly bound"
            ):
                _CANDIDATE_SUPPORT._strict_host_read_root_bindings(
                    {"binding": "synthetic"}, 60000, 60000
                )

    def test_strict_host_read_root_capture_reports_purpose_and_preserves_cause(
        self,
    ) -> None:
        terminal_cause = AssertionError("terminal-cause")
        with mock.patch.object(
            _CANDIDATE_SUPPORT.os,
            "uname",
            return_value=mock.Mock(machine="x86_64"),
        ), mock.patch.object(
            Path,
            "resolve",
            new=lambda self, strict=False: self,
        ), mock.patch.object(
            Path,
            "stat",
            return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o555),
        ), mock.patch.object(
            Path,
            "lstat",
            side_effect=FileNotFoundError,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_canonical_existing_directory",
            side_effect=lambda path, _description: path,
        ), mock.patch.dict(
            _CANDIDATE_SUPPORT._STRICT_PRIMITIVES,
            {
                "python": Path("/usr/bin/python3.12"),
                "setpriv": Path("/usr/bin/setpriv"),
                "env": Path("/usr/bin/env"),
            },
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_revalidate_trusted_git_binding",
            return_value=Path("/usr/bin/git"),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_capture_strict_host_read_root_binding",
            side_effect=terminal_cause,
        ), self.assertRaisesRegex(
            AssertionError,
            "strict host read root system-arch-library directory rejected: "
            "terminal-cause",
        ) as raised:
            _CANDIDATE_SUPPORT._strict_host_read_root_bindings(
                None, 60000, 60000
            )

        self.assertIs(raised.exception.__cause__, terminal_cause)

    def test_strict_host_read_roots_reject_ld_preload(self) -> None:
        with mock.patch.object(
            _CANDIDATE_SUPPORT.os,
            "uname",
            return_value=mock.Mock(machine="x86_64"),
        ), mock.patch.object(
            Path,
            "resolve",
            new=lambda self, strict=False: self,
        ), mock.patch.object(
            Path,
            "stat",
            return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o755),
        ), mock.patch.object(
            Path,
            "lstat",
            return_value=mock.Mock(st_mode=stat.S_IFREG | 0o644),
        ), self.assertRaisesRegex(
            AssertionError, "ld.so.preload is unsupported"
        ):
            _CANDIDATE_SUPPORT._strict_host_read_root_bindings(
                None, 60000, 60000
            )

    def test_strict_host_read_file_binding_tracks_only_identity_and_access_policy(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            selected = root / "trusted-read.txt"
            selected.write_text("trusted\n", encoding="utf-8")
            selected.chmod(0o444)
            original_open = os.open

            with mock.patch.object(os, "O_PATH", 0, create=True), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_assert_strict_target_runtime_policy",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_runtime_acl_is_absent",
            ):
                binding = (
                    _CANDIDATE_SUPPORT._capture_strict_host_read_root_binding(
                        selected,
                        purpose="trusted-test-file",
                        kind="file",
                        target_uid=60000,
                        target_gid=60000,
                    )
                )
                with self.assertRaisesRegex(AssertionError, "is malformed"):
                    _CANDIDATE_SUPPORT._revalidate_strict_host_read_root_bindings(
                        [{**binding, "purpose": "system-arch-library"}]
                    )
                os.utime(selected, None)
                self.assertEqual(
                    _CANDIDATE_SUPPORT._revalidate_strict_host_read_root_bindings(
                        [binding]
                    ),
                    [binding],
                )

                selected.chmod(0o440)
                with self.assertRaisesRegex(AssertionError, "binding changed"):
                    _CANDIDATE_SUPPORT._revalidate_strict_host_read_root_bindings(
                        [binding]
                    )
                selected.chmod(0o444)

                detached = root / "detached.txt"
                selected.rename(detached)
                selected.write_text("trusted\n", encoding="utf-8")
                selected.chmod(0o444)
                with self.assertRaisesRegex(AssertionError, "binding changed"):
                    _CANDIDATE_SUPPORT._revalidate_strict_host_read_root_bindings(
                        [binding]
                    )

                def deny_leaf_open(
                    value: object,
                    flags: int,
                    *args: object,
                    **kwargs: object,
                ) -> int:
                    if value == selected.name and "dir_fd" in kwargs:
                        raise PermissionError(errno.EACCES, "denied", str(value))
                    return original_open(value, flags, *args, **kwargs)

                with mock.patch.object(
                    os, "open", side_effect=deny_leaf_open
                ), self.assertRaisesRegex(AssertionError, "is unreadable"):
                    _CANDIDATE_SUPPORT._capture_strict_host_read_root_binding(
                        selected,
                        purpose="trusted-test-file",
                        kind="file",
                        target_uid=60000,
                        target_gid=60000,
                    )
        controller_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_controller_main
        )
        self.assertLess(
            controller_source.index("_root_wrapper_command("),
            controller_source.index("subprocess.Popen("),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            snapshot_root = Path(temporary_directory).resolve(strict=True)
            snapshot = {
                "config_path": snapshot_root / "config.json",
                "controller_path": snapshot_root / "controller.py",
                "handshake_path": snapshot_root / "handshake.json",
                "execution_root": snapshot_root,
            }
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_realm",
                return_value={"uid": 60000, "gid": 60000},
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_writable_root_bindings",
                side_effect=AssertionError(
                    "strict writable root contains a host mount boundary"
                ),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
            ) as root_tree, mock.patch.object(
                _CANDIDATE_SUPPORT, "_run_registered_sudo"
            ) as registered_sudo, mock.patch.object(
                _CANDIDATE_SUPPORT.subprocess, "Popen"
            ) as popen, self.assertRaisesRegex(
                AssertionError, "contains a host mount boundary"
            ):
                _CANDIDATE_SUPPORT._invoke_strict_controller(
                    snapshot,
                    ["/usr/bin/python3", "-I", "/probe.py"],
                    {},
                    snapshot_root,
                    b"",
                    timeout_seconds=1,
                )
        root_tree.assert_not_called()
        registered_sudo.assert_not_called()
        popen.assert_not_called()

    def test_mount_namespace_readiness_gate_is_exact(self) -> None:
        readiness_read, readiness_write = os.pipe()
        terminal_read, terminal_write = os.pipe()
        try:
            os.write(readiness_write, b"G")
            _CANDIDATE_SUPPORT._wait_mount_namespace_ready(
                readiness_read, terminal_read, timeout_seconds=0.1
            )
        finally:
            for descriptor in (
                readiness_read,
                readiness_write,
                terminal_read,
                terminal_write,
            ):
                os.close(descriptor)

        controller_source = inspect.getsource(
            _CANDIDATE_SUPPORT._root_controller_main
        )
        self.assertIn(
            "pass_fds=(barrier_read_fd, mount_readiness_write_fd)",
            controller_source,
        )
        self.assertLess(
            controller_source.index("_release_wrapper_barrier"),
            controller_source.index("_wait_mount_namespace_ready"),
        )
        self.assertLess(
            controller_source.index("_wait_mount_namespace_ready"),
            controller_source.index("process.communicate"),
        )
        bootstrap_source = _CANDIDATE_SUPPORT._MOUNT_NAMESPACE_BOOTSTRAP_SOURCE
        self.assertLess(
            bootstrap_source.index("mount_setattr = libc.mount_setattr"),
            bootstrap_source.index("os.write(readiness_fd, b\"G\")"),
        )
        self.assertLess(
            bootstrap_source.index("install_candidate_seccomp_filter()"),
            bootstrap_source.index("os.write(readiness_fd, b\"G\")"),
        )

        readiness_read, readiness_write = os.pipe()
        terminal_read, terminal_write = os.pipe()
        try:
            os.close(readiness_write)
            readiness_write = -1
            with self.assertRaisesRegex(
                AssertionError, "did not become ready"
            ):
                _CANDIDATE_SUPPORT._wait_mount_namespace_ready(
                    readiness_read, terminal_read, timeout_seconds=0.1
                )
        finally:
            for descriptor in (
                readiness_read,
                terminal_read,
                terminal_write,
            ):
                os.close(descriptor)

        readiness_read, readiness_write = os.pipe()
        terminal_read, terminal_write = os.pipe()
        try:
            os.close(terminal_write)
            terminal_write = -1
            with self.assertRaisesRegex(
                AssertionError, "exited before readiness"
            ):
                _CANDIDATE_SUPPORT._wait_mount_namespace_ready(
                    readiness_read, terminal_read, timeout_seconds=0.1
                )
        finally:
            for descriptor in (
                readiness_read,
                readiness_write,
                terminal_read,
            ):
                os.close(descriptor)

    def test_private_surface_ancestors_cannot_be_writable_roots(self) -> None:
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_execution_root_binding",
            side_effect=lambda path: {
                "path": str(path),
                "device": 1,
                "inode": hash(str(path)),
            },
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_writable_root_mount_binding",
            return_value=17,
        ):
            for exposed in (Path("/tmp"), Path("/var")):
                with self.subTest(exposed=exposed), self.assertRaisesRegex(
                    AssertionError, "private host surface"
                ):
                    _CANDIDATE_SUPPORT._strict_writable_root_bindings(
                        Path("/execution"), (exposed,)
                    )
            bindings = _CANDIDATE_SUPPORT._strict_writable_root_bindings(
                Path("/tmp/execution"), (Path("/var/tmp/fixture"),)
            )
        self.assertEqual(
            [document["path"] for document in bindings],
            ["/tmp/execution", "/var/tmp/fixture"],
        )

    def test_strict_controller_rejects_unbound_runtime_before_privilege(
        self,
    ) -> None:
        with mock.patch.object(
            _CANDIDATE_SUPPORT, "_strict_realm"
        ) as strict_realm, mock.patch.object(
            _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
        ) as root_tree, mock.patch.object(
            _CANDIDATE_SUPPORT, "_run_registered_sudo"
        ) as registered_sudo, self.assertRaisesRegex(
            AssertionError, "identity changed before privilege"
        ):
            _CANDIDATE_SUPPORT._invoke_strict_controller(
                {},
                ["/tmp/python", "-I", "/probe.py"],
                {},
                Path("/tmp"),
                b"",
                timeout_seconds=1,
            )
        strict_realm.assert_not_called()
        root_tree.assert_not_called()
        registered_sudo.assert_not_called()
        with mock.patch.object(
            _CANDIDATE_SUPPORT, "_strict_realm"
        ) as strict_realm, mock.patch.object(
            _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
        ) as root_tree, mock.patch.object(
            _CANDIDATE_SUPPORT, "_run_registered_sudo"
        ) as registered_sudo, self.assertRaisesRegex(
            AssertionError, "identity changed before privilege"
        ):
            _CANDIDATE_SUPPORT._invoke_strict_controller(
                {},
                ["/other/python", "-I", "/probe.py"],
                {},
                Path("/tmp"),
                b"",
                timeout_seconds=1,
                candidate_interpreter_binding={
                    "resolved": "/configured/python"
                },
            )
        strict_realm.assert_not_called()
        root_tree.assert_not_called()
        registered_sudo.assert_not_called()

    def test_strict_controller_revalidates_runtime_before_privilege(
        self,
    ) -> None:
        binding = {
            "resolved": "/configured/python",
            "target_uid": 60000,
            "target_gid": 60000,
        }
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_realm",
            return_value={"uid": 60000, "gid": 60000},
        ) as strict_realm, mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_revalidate_configured_candidate_interpreter",
            side_effect=AssertionError(
                "configured candidate interpreter binding changed"
            ),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
        ) as root_tree, mock.patch.object(
            _CANDIDATE_SUPPORT, "_run_registered_sudo"
        ) as registered_sudo, mock.patch.object(
            _CANDIDATE_SUPPORT.subprocess, "Popen"
        ) as popen, self.assertRaisesRegex(
            AssertionError, "binding changed"
        ):
            _CANDIDATE_SUPPORT._invoke_strict_controller(
                {},
                ["/configured/python", "-I", "/probe.py"],
                {},
                Path("/tmp"),
                b"",
                timeout_seconds=1,
                candidate_interpreter_binding=binding,
            )
        strict_realm.assert_not_called()
        root_tree.assert_not_called()
        registered_sudo.assert_not_called()
        popen.assert_not_called()

        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_revalidate_configured_candidate_interpreter",
            return_value=binding,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_realm",
            return_value={"uid": 60001, "gid": 60001},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
        ) as root_tree, mock.patch.object(
            _CANDIDATE_SUPPORT, "_run_registered_sudo"
        ) as registered_sudo, mock.patch.object(
            _CANDIDATE_SUPPORT.subprocess, "Popen"
        ) as popen, self.assertRaisesRegex(
            AssertionError, "target identity changed"
        ):
            _CANDIDATE_SUPPORT._invoke_strict_controller(
                {},
                ["/configured/python", "-I", "/probe.py"],
                {},
                Path("/tmp"),
                b"",
                timeout_seconds=1,
                candidate_interpreter_binding=binding,
            )
        root_tree.assert_not_called()
        registered_sudo.assert_not_called()
        popen.assert_not_called()

    def test_strict_controller_binds_host_read_roots_before_privilege(
        self,
    ) -> None:
        snapshot = {
            "config_path": Path("/tmp/config.json"),
            "controller_path": Path("/tmp/controller.py"),
            "handshake_path": Path("/tmp/handshake.json"),
            "execution_root": Path("/tmp/execution"),
        }
        readable = Path("/tmp/read-sentinel")
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_realm",
            return_value={"uid": 60000, "gid": 60000},
        ) as strict_realm, mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_writable_root_bindings",
            return_value=[
                {
                    "path": "/tmp/execution",
                    "device": 1,
                    "inode": 2,
                    "host_mount_id": 3,
                }
            ],
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_host_read_root_bindings",
            side_effect=AssertionError("strict read prefix is unsafe"),
        ) as bind_reads, mock.patch.object(
            _CANDIDATE_SUPPORT, "_invoke_root_tree_operation"
        ) as root_tree, mock.patch.object(
            _CANDIDATE_SUPPORT, "_run_registered_sudo"
        ) as registered_sudo, mock.patch.object(
            _CANDIDATE_SUPPORT.subprocess, "Popen"
        ) as popen, self.assertRaisesRegex(
            AssertionError, "read prefix is unsafe"
        ):
            _CANDIDATE_SUPPORT._invoke_strict_controller(
                snapshot,
                [
                    str(_CANDIDATE_SUPPORT._STRICT_PRIMITIVES["python"]),
                    "-I",
                    "-S",
                    "/probe.py",
                ],
                {},
                Path("/tmp/execution"),
                b"",
                timeout_seconds=1,
                readable_roots=(readable,),
            )
        strict_realm.assert_called_once_with()
        bind_reads.assert_called_once_with(
            None,
            60000,
            60000,
            readable_roots=(readable,),
        )
        root_tree.assert_not_called()
        registered_sudo.assert_not_called()
        popen.assert_not_called()

    def test_configured_interpreter_binding_accepts_setup_python_symlinks_and_rejects_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            runtime_root = root / "toolcache"
            bin_root = runtime_root / "bin"
            lib_root = runtime_root / "lib"
            bin_root.mkdir(parents=True)
            lib_root.mkdir()
            real_interpreter = bin_root / "python3.14"
            intermediate_interpreter = bin_root / "python3"
            selector = bin_root / "python"
            stdlib_real = lib_root / "os-real.py"
            stdlib_selector = lib_root / "os.py"
            real_interpreter.write_bytes(b"configured-python\n")
            real_interpreter.chmod(0o755)
            intermediate_interpreter.symlink_to(real_interpreter.name)
            selector.symlink_to(intermediate_interpreter.name)
            stdlib_real.write_bytes(b"stdlib\n")
            stdlib_real.chmod(0o644)
            stdlib_selector.symlink_to(stdlib_real.name)

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_capture_strict_runtime_lexical_path",
                wraps=_CANDIDATE_SUPPORT._capture_strict_runtime_lexical_path,
            ) as lexical_capture, mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_assert_strict_target_runtime_policy",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_runtime_acl_is_absent",
            ):
                binding = (
                    _CANDIDATE_SUPPORT._capture_strict_candidate_interpreter_binding(
                        str(selector),
                        str(stdlib_selector),
                        target_uid=60000,
                        target_gid=60000,
                        version=(3, 14, 7),
                        implementation="cpython",
                    )
                )

                self.assertEqual(binding["selector"], str(selector))
                self.assertEqual(binding["resolved"], str(real_interpreter))
                self.assertEqual(
                    [
                        selected.kwargs["executable"]
                        for selected in lexical_capture.call_args_list
                    ],
                    [True, False, True, False],
                )
                selector_components = binding["selector_components"]
                self.assertIsInstance(selector_components, list)
                assert isinstance(selector_components, list)
                self.assertEqual(
                    [
                        item["link_target"]
                        for item in selector_components
                        if item["kind"] == "symlink"
                    ],
                    [intermediate_interpreter.name],
                )

                interpreter_identity = (
                    real_interpreter.stat().st_dev,
                    real_interpreter.stat().st_ino,
                )
                stdlib_identity = (
                    stdlib_real.stat().st_dev,
                    stdlib_real.stat().st_ino,
                )
                detached_runtime = root / "detached-toolcache"
                runtime_root.rename(detached_runtime)
                runtime_root.mkdir()
                (detached_runtime / "bin").rename(runtime_root / "bin")
                (detached_runtime / "lib").rename(runtime_root / "lib")
                self.assertEqual(
                    (
                        real_interpreter.stat().st_dev,
                        real_interpreter.stat().st_ino,
                    ),
                    interpreter_identity,
                )
                self.assertEqual(
                    (stdlib_real.stat().st_dev, stdlib_real.stat().st_ino),
                    stdlib_identity,
                )
                with self.assertRaisesRegex(
                    AssertionError, "binding changed"
                ):
                    _CANDIDATE_SUPPORT._revalidate_configured_candidate_interpreter(
                        binding
                    )

    def test_configured_interpreter_binding_classifies_unreadable_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            runtime_root = root / "toolcache"
            runtime_root.mkdir()
            interpreter = runtime_root / "python"
            stdlib = runtime_root / "os.py"
            interpreter.write_bytes(b"configured-python\n")
            interpreter.chmod(0o755)
            stdlib.write_bytes(b"stdlib\n")
            original_open = os.open

            def deny_interpreter_open(
                selected: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if selected == interpreter.name and "dir_fd" in kwargs:
                    raise PermissionError(errno.EACCES, "denied", str(selected))
                return original_open(selected, flags, *args, **kwargs)

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_assert_strict_target_runtime_policy",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_runtime_acl_is_absent",
            ), mock.patch.object(
                os, "open", side_effect=deny_interpreter_open
            ), self.assertRaisesRegex(AssertionError, "interpreter is unreadable"):
                _CANDIDATE_SUPPORT._capture_strict_candidate_interpreter_binding(
                    str(interpreter),
                    str(stdlib),
                    target_uid=60000,
                    target_gid=60000,
                    version=(3, 14, 7),
                    implementation="cpython",
                )

    def test_configured_interpreter_binding_accepts_execute_only_leaf(
        self,
    ) -> None:
        if not hasattr(os, "O_PATH"):
            self.skipTest("Linux O_PATH is required for this regression")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            interpreter = root / "python"
            interpreter.write_bytes(b"configured-python\n")
            interpreter.chmod(0o111)
            original_open = os.open
            leaf_flags: list[int] = []

            def record_open(
                selected: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if selected == interpreter.name and "dir_fd" in kwargs:
                    leaf_flags.append(flags)
                return original_open(selected, flags, *args, **kwargs)

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_assert_strict_target_runtime_policy",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_runtime_acl_is_absent",
            ), mock.patch.object(os, "open", side_effect=record_open):
                documents = (
                    _CANDIDATE_SUPPORT._capture_strict_runtime_canonical_path(
                        interpreter,
                        target_uid=60000,
                        target_gid=60000,
                        description="configured candidate interpreter",
                        executable=True,
                    )
                )

            self.assertEqual(documents[-1]["kind"], "file")
            self.assertTrue(leaf_flags)
            self.assertTrue(all(flags & os.O_PATH for flags in leaf_flags))

    def test_configured_interpreter_target_access_policy_is_exact(self) -> None:
        def metadata(mode: int) -> os.stat_result:
            return os.stat_result(
                (mode, 11, 12, 1, 1000, 1000, 4096, 0, 0, 0)
            )

        _CANDIDATE_SUPPORT._assert_strict_target_runtime_policy(
            metadata(stat.S_IFDIR | 0o755),
            target_uid=60000,
            target_gid=60000,
            description="configured candidate interpreter",
            directory=True,
            executable=False,
        )
        _CANDIDATE_SUPPORT._assert_strict_target_runtime_policy(
            metadata(stat.S_IFREG | 0o755),
            target_uid=60000,
            target_gid=60000,
            description="configured candidate interpreter",
            directory=False,
            executable=True,
        )
        _CANDIDATE_SUPPORT._assert_strict_target_runtime_policy(
            metadata(stat.S_IFREG | 0o111),
            target_uid=60000,
            target_gid=60000,
            description="configured candidate interpreter",
            directory=False,
            executable=True,
        )
        _CANDIDATE_SUPPORT._assert_strict_target_runtime_policy(
            metadata(stat.S_IFREG | 0o644),
            target_uid=60000,
            target_gid=60000,
            description="configured candidate standard library",
            directory=False,
            executable=False,
        )
        hardlinked = list(metadata(stat.S_IFREG | 0o755))
        hardlinked[3] = 2
        _CANDIDATE_SUPPORT._assert_strict_target_runtime_policy(
            os.stat_result(hardlinked),
            target_uid=60000,
            target_gid=60000,
            description="configured candidate interpreter",
            directory=False,
            executable=True,
        )
        for mode, directory, executable in (
            (stat.S_IFDIR | 0o757, True, False),
            (stat.S_IFREG | 0o744, False, True),
            (stat.S_IFREG | 0o646, False, False),
        ):
            with self.subTest(mode=oct(mode)), self.assertRaisesRegex(
                AssertionError, "access policy is unsafe"
            ):
                _CANDIDATE_SUPPORT._assert_strict_target_runtime_policy(
                    metadata(mode),
                    target_uid=60000,
                    target_gid=60000,
                    description="configured candidate runtime",
                    directory=directory,
                    executable=executable,
                )
        for mode, directory, executable in (
            (stat.S_IFDIR | 0o555, True, False),
            (stat.S_IFREG | 0o555, False, True),
            (stat.S_IFREG | 0o444, False, False),
        ):
            target_owned = list(metadata(mode))
            target_owned[4] = 60000
            with self.subTest(
                target_owned=oct(mode)
            ), self.assertRaisesRegex(
                AssertionError, "access policy is unsafe"
            ):
                _CANDIDATE_SUPPORT._assert_strict_target_runtime_policy(
                    os.stat_result(target_owned),
                    target_uid=60000,
                    target_gid=60000,
                    description="configured candidate runtime",
                    directory=directory,
                    executable=executable,
                )

    def test_configured_interpreter_policy_is_bound_after_active_session_before_privilege(
        self,
    ) -> None:
        events: list[str] = []

        def active_session() -> dict[str, object]:
            events.append("active-session")
            return {}

        def realm() -> dict[str, object]:
            events.append("realm")
            return {"uid": 60000, "gid": 60000}

        def reject_binding(_uid: int, _gid: int) -> dict[str, object]:
            events.append("interpreter-binding")
            raise AssertionError(
                "configured candidate interpreter access policy is unsafe"
            )

        with mock.patch.object(
            _CANDIDATE_SUPPORT, "strict_isolation_platform_preflight"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_isolation_requested",
            return_value=True,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_active_strict_session",
            side_effect=active_session,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_strict_realm", side_effect=realm
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_bind_configured_candidate_interpreter",
            side_effect=reject_binding,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "candidate_repository_root"
        ) as candidate_root, mock.patch.object(
            _CANDIDATE_SUPPORT, "_ensure_strict_backend"
        ) as ensure_backend, mock.patch.object(
            _CANDIDATE_SUPPORT, "_run_registered_sudo"
        ) as registered_sudo, mock.patch.object(
            subprocess, "Popen"
        ) as popen, mock.patch.dict(
            os.environ,
            {REQUIRED_CI_CANDIDATE_SHA_ENV: "a" * 40},
            clear=False,
        ):
            with self.assertRaisesRegex(AssertionError, "access policy is unsafe"):
                _CANDIDATE_SUPPORT._run_candidate_process(
                    Path("/candidate.py"),
                    [sys.executable, "-I", "/candidate.py"],
                )

        self.assertEqual(
            events, ["active-session", "realm", "interpreter-binding"]
        )
        candidate_root.assert_not_called()
        ensure_backend.assert_not_called()
        registered_sudo.assert_not_called()
        popen.assert_not_called()

    def test_configured_runtime_bootstrap_rejects_version_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            candidate = root / "candidate.py"
            candidate.write_text(
                "import os\n"
                "import sys\n"
                "if os.environ.get('REQUIRED_CI_CLOSED') != '1':\n"
                "    raise SystemExit(90)\n"
                "if 'REQUIRED_CI_LAUNCHER_CANARY' in os.environ:\n"
                "    raise SystemExit(91)\n"
                "print('.'.join(map(str, sys.version_info[:3])))\n",
                encoding="utf-8",
            )
            binding = {
                "schema_version": 1,
                "selector": sys.executable,
                "resolved": str(Path(sys.executable).resolve(strict=True)),
                "stdlib_resolved": str(Path(os.__file__).resolve(strict=True)),
                "version": list(sys.version_info[:3]),
                "implementation": sys.implementation.name,
            }
            arguments = [
                sys.executable,
                "-I",
                "-B",
                "-S",
                "-c",
                _CANDIDATE_SUPPORT._CONFIGURED_RUNTIME_BOOTSTRAP_SOURCE,
                binding["resolved"],
                binding["stdlib_resolved"],
                binding["implementation"],
                *[str(value) for value in binding["version"]],
                "1",
                "REQUIRED_CI_CLOSED=1",
                binding["resolved"],
                "-I",
                str(candidate),
            ]
            completed = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env={**os.environ, "REQUIRED_CI_LAUNCHER_CANARY": "1"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                completed.stdout,
                ".".join(map(str, sys.version_info[:3])) + "\n",
            )

            arguments[9:12] = ["0", "0", "0"]
            rejected = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env={**os.environ, "REQUIRED_CI_LAUNCHER_CANARY": "1"},
            )
            self.assertEqual(rejected.returncode, 118)

            arguments[9:12] = [str(value) for value in binding["version"]]
            arguments[7] = "/missing/os.py"
            rejected = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env={**os.environ, "REQUIRED_CI_LAUNCHER_CANARY": "1"},
            )
            self.assertEqual(rejected.returncode, 118)

    def test_strict_candidate_uses_the_configured_interpreter_runtime(self) -> None:
        real_interpreter = sys.executable
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            candidate_root = root / ".candidate"
            candidate_root.mkdir()
            script = candidate_root / "candidate.py"
            snapshot_script = root / "snapshot-candidate.py"
            configured_interpreter = root / "configured-python3"
            configured_selector = root / "configured-python"
            workspace_root = root / "candidate-workspace"
            runtime_root = root / "runtime"
            workspace_root.mkdir()
            runtime_root.mkdir()
            source = (
                "import os\n"
                "if os.environ.get('REQUIRED_CI_CONFIGURED_RUNTIME') != '1':\n"
                "    raise SystemExit(91)\n"
                "print('configured-runtime')\n"
            )
            script.write_text(source, encoding="utf-8")
            snapshot_script.write_text(source, encoding="utf-8")
            configured_interpreter.write_text(
                "#!/bin/sh\n"
                "export REQUIRED_CI_CONFIGURED_RUNTIME=1\n"
                f"exec {real_interpreter!r} \"$@\"\n",
                encoding="utf-8",
            )
            configured_interpreter.chmod(0o755)
            configured_selector.symlink_to(configured_interpreter.name)
            before = {
                "candidate_root": str(candidate_root),
                "candidate_sha": "a" * 40,
                "candidate_script_sha256": {},
            }
            snapshot = {
                "candidate_paths": {
                    script.name: snapshot_script,
                    "required_ci_candidate.py": snapshot_script,
                },
                "workspace_root": workspace_root,
                "runtime_root": runtime_root,
                "controller_path": root / "controller.py",
            }

            @contextlib.contextmanager
            def execution_snapshot(*_args: object, **_kwargs: object):
                yield snapshot

            @contextlib.contextmanager
            def prepared_fixtures(*_args: object, **_kwargs: object):
                yield ()

            receipt_overrides: dict[str, object] = {}

            def invoke_controller(
                _snapshot: Mapping[str, object],
                candidate_argv: list[str],
                environment: Mapping[str, str],
                cwd: Path,
                input_bytes: bytes,
                **_kwargs: object,
            ) -> dict[str, object]:
                completed = subprocess.run(
                    candidate_argv,
                    cwd=cwd,
                    env=dict(environment),
                    input=input_bytes,
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
                receipt: dict[str, object] = {
                    "status": "completed",
                    "cleanup_status": "complete",
                    "timed_out": False,
                    "process_leak_observed": False,
                    "returncode": completed.returncode,
                    "stdout_base64": __import__("base64").b64encode(
                        completed.stdout
                    ).decode("ascii"),
                    "stderr_base64": __import__("base64").b64encode(
                        completed.stderr
                    ).decode("ascii"),
                }
                receipt.update(receipt_overrides)
                return receipt

            with mock.patch.object(
                _CANDIDATE_SUPPORT.sys,
                "executable",
                str(configured_selector),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "strict_isolation_platform_preflight",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_isolation_requested",
                return_value=True,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_active_strict_session",
                return_value={},
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_bind_configured_candidate_interpreter",
                return_value={
                    "selector": str(configured_selector),
                    "resolved": str(configured_interpreter),
                },
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "candidate_repository_root",
                return_value=candidate_root,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "expected_candidate_sha",
                return_value=("a" * 40, True),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_candidate_checkout_binding_with_sources",
                return_value=(before, {}, {}),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_validated_candidate_script",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_ensure_strict_backend",
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_execution_snapshot",
                side_effect=execution_snapshot,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_prepared_candidate_fixtures",
                side_effect=prepared_fixtures,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_fixture_git_repositories",
                return_value=(),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_invoke_strict_controller",
                side_effect=invoke_controller,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "candidate_checkout_binding",
                return_value=before,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_candidate_uid_inventory",
                return_value=set(),
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_strict_realm",
                return_value={"uid": 60000, "gid": 60000},
            ), mock.patch.dict(
                os.environ,
                {REQUIRED_CI_CANDIDATE_SHA_ENV: "a" * 40},
                clear=False,
            ):
                completed = _CANDIDATE_SUPPORT.run_candidate_python(script)
                receipt_overrides["timed_out"] = 0
                with self.subTest(field="timed_out"):
                    self.assertRaisesRegex(
                        AssertionError,
                        "timed-out receipt is malformed",
                        _CANDIDATE_SUPPORT.run_candidate_python,
                        script,
                    )
                receipt_overrides.clear()
                receipt_overrides["process_leak_observed"] = 0.0
                with self.subTest(field="process_leak_observed"):
                    self.assertRaisesRegex(
                        AssertionError,
                        "process-leak receipt is malformed",
                        _CANDIDATE_SUPPORT.run_candidate_python,
                        script,
                    )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "configured-runtime\n")
            self.assertEqual(completed.args[0], str(configured_interpreter))

    def supervise(self, trusted_root: Path, candidate_root: Path) -> dict[str, object]:
        candidate_sha = self.initialize_candidate_checkout(candidate_root)
        with _local_nonstrict_supervisor_environment(), mock.patch.dict(
            os.environ,
            {
                REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
            },
            clear=False,
        ):
            return supervise_trusted_required_ci_tests(
                trusted_root,
                candidate_root,
                supervisor_deadline=(
                    time.monotonic() + TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS
                ),
            )

    def test_local_supervisor_harness_clears_inherited_strict_registry(
        self,
    ) -> None:
        inherited_environment = {
            REQUIRED_CI_ISOLATION_MODE_ENV: REQUIRED_CI_ISOLATION_MODE,
            "REQUIRED_CI_INTERNAL_ISOLATION_UID": "60000",
            "REQUIRED_CI_INTERNAL_ISOLATION_GID": "60000",
            "REQUIRED_CI_INTERNAL_ISOLATION_LOCK_FD": "19",
            "REQUIRED_CI_INTERNAL_ISOLATION_REGISTRY": "/parent/entries",
            "REQUIRED_CI_INTERNAL_ISOLATION_REGISTRY_TOKEN": "a" * 32,
        }
        observed_environment: dict[str, str] = {}

        def record_environment(
            _trusted_root: Path,
            _candidate_root: Path,
            *,
            supervisor_deadline: float,
        ) -> dict[str, str]:
            self.assertGreater(supervisor_deadline, time.monotonic())
            observed_environment.update(os.environ)
            return {"status": "completed"}

        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            with mock.patch.dict(
                os.environ, inherited_environment, clear=False
            ), mock.patch.object(
                sys.modules[__name__],
                "supervise_trusted_required_ci_tests",
                side_effect=record_environment,
            ):
                self.supervise(trusted_root, candidate_root)

        for key in inherited_environment:
            self.assertNotIn(key, observed_environment)

    @staticmethod
    def readme_test_commands(repo_root: Path) -> list[str]:
        readme = (repo_root / "README.md").read_text(encoding="utf-8")
        if sum(line == "## Test" for line in readme.splitlines()) != 1:
            raise AssertionError("README must contain exactly one Test heading")
        match = re.search(r"\n## Test\n\n```bash\n(?P<body>[^`]*)\n```\n?\Z", readme)
        if match is None:
            raise AssertionError("README test command block is missing or malformed")
        return match.group("body").splitlines()

    def prepare_hook_adapter_split(
        self, temporary_directory: str
    ) -> tuple[Path, Path]:
        root = Path(temporary_directory).resolve(strict=True)
        trusted_root = root / ".required-ci"
        candidate_root = root / ".candidate"
        source_tests_root = TRUSTED_CONTENT_ROOT / CANDIDATE_TESTS_RELATIVE_PATH
        for repository_root in (trusted_root, candidate_root):
            tests_root = distribution_tests_root(repository_root)
            tests_root.mkdir(parents=True)
            shutil.copyfile(
                source_tests_root / "test_waited_delivery_hook_adapter.py",
                tests_root / "test_waited_delivery_hook_adapter.py",
            )
        shutil.copyfile(
            TRUSTED_CANDIDATE_SUPPORT_PATH,
            distribution_tests_root(trusted_root) / "required_ci_candidate.py",
        )
        candidate_scripts_root = (
            distribution_content_root(candidate_root)
            / "skills/waited-delivery/scripts"
        )
        candidate_scripts_root.mkdir(parents=True)
        for relative_path in _CANDIDATE_SUPPORT.CANDIDATE_SCRIPT_RELATIVE_PATHS:
            shutil.copyfile(
                TRUSTED_CONTENT_ROOT / relative_path,
                distribution_content_root(candidate_root) / relative_path,
            )
        return trusted_root, candidate_root

    def test_supervisor_rejects_dead_prompt_fallback_with_success_stub(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_hook_adapter_split(
                temporary_directory
            )
            adapter_path = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts/waited_delivery_hook_adapter.py"
            )
            source = adapter_path.read_text(encoding="utf-8")
            live_fallback = (
                "            _record_hook_failure(error)\n"
                "            try:\n"
                "                prompt = _build_stop_fallback_prompt("
            )
            dead_fallback = (
                "            _record_hook_failure(error)\n"
                "            return _success_hook_response()\n"
                "            try:\n"
                "                prompt = _build_stop_fallback_prompt("
            )
            self.assertIn(live_fallback, source)
            adapter_path.write_text(
                source.replace(live_fallback, dead_fallback, 1),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                AssertionError, "trusted Required CI tests did not complete"
            ):
                self.supervise(trusted_root, candidate_root)

    def test_supervisor_rejects_deep_fault_paths_replaced_by_success_stubs(
        self,
    ) -> None:
        mutations = {
            "last resort bypass": (
                "                _record_hook_failure(fallback_error)\n"
                "                try:\n",
                "                _record_hook_failure(fallback_error)\n"
                "                return _success_hook_response()\n"
                "                try:\n",
            ),
            "prompt write bypass": (
                "        try:\n"
                "            print(prompt, file=sys.stderr)\n",
                "        try:\n"
                "            return _success_hook_response()\n"
                "            print(prompt, file=sys.stderr)\n",
            ),
        }
        for name, (live_source, dead_source) in mutations.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    trusted_root, candidate_root = self.prepare_hook_adapter_split(
                        temporary_directory
                    )
                    adapter_path = (
                        distribution_content_root(candidate_root)
                        / "skills/waited-delivery/scripts/"
                        "waited_delivery_hook_adapter.py"
                    )
                    source = adapter_path.read_text(encoding="utf-8")
                    self.assertIn(live_source, source)
                    adapter_path.write_text(
                        source.replace(live_source, dead_source, 1),
                        encoding="utf-8",
                    )

                    with self.assertRaisesRegex(
                        AssertionError, "trusted Required CI tests did not complete"
                    ):
                        self.supervise(trusted_root, candidate_root)

    def test_hook_fault_probe_rejects_invalid_targets_and_sequences(self) -> None:
        adapter_path = _CANDIDATE_SUPPORT.candidate_script(
            "waited_delivery_hook_adapter.py"
        )
        runner_path = _CANDIDATE_SUPPORT.candidate_script(
            "waited_delivery_runner.py"
        )
        with self.assertRaisesRegex(AssertionError, "invalid fault sequence"):
            _CANDIDATE_SUPPORT.run_candidate_hook_fault_probe(
                adapter_path,
                ("fallback",),
                input_text="{}",
            )
        with self.assertRaisesRegex(AssertionError, "requires the hook adapter"):
            _CANDIDATE_SUPPORT.run_candidate_hook_fault_probe(
                runner_path,
                ("continuation",),
                input_text="{}",
            )

    def test_hook_fault_probe_executes_an_isolated_trusted_snapshot(self) -> None:
        adapter_path = _CANDIDATE_SUPPORT.candidate_script(
            "waited_delivery_hook_adapter.py"
        )
        completed = _CANDIDATE_SUPPORT.run_candidate_hook_fault_probe(
            adapter_path,
            ("continuation",),
            input_text="{}",
        )
        original_support = Path(
            _CANDIDATE_SUPPORT.run_candidate_hook_fault_probe.__code__.co_filename
        ).resolve(strict=True)

        self.assertNotEqual(Path(completed.args[3]), original_support)
        self.assertNotIn(original_support.parent, Path(completed.args[3]).parents)

    def test_readme_test_commands_are_isolated_and_ordered(self) -> None:
        if DISTRIBUTION_PROFILE == "private":
            self.skipTest(
                "canonical repository documentation is not shipped in private distribution"
            )
        self.assertEqual(
            self.readme_test_commands(REPO_ROOT),
            [README_COMPILE_COMMAND, README_DISCOVERY_COMMAND],
        )

    def test_readme_compile_checks_syntax_without_temp_or_bytecode(self) -> None:
        if DISTRIBUTION_PROFILE == "private":
            self.skipTest(
                "canonical repository documentation is not shipped in private distribution"
            )
        compile_command, _discovery_command = self.readme_test_commands(REPO_ROOT)
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)

        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory).resolve(strict=True)
            candidate_root = fixture_root / "candidate"
            scripts_root = (
                candidate_root / "skills/waited-delivery/scripts"
            )
            controlled_tmp = fixture_root / "controlled tmp"
            fake_bin = fixture_root / "bin"
            scripts_root.mkdir(parents=True)
            controlled_tmp.mkdir()
            fake_bin.mkdir()
            mktemp_marker = fixture_root / "mktemp-called"
            fake_mktemp = fake_bin / "mktemp"
            fake_mktemp.write_text(
                f"#!{sys.executable}\n"
                "from pathlib import Path\n"
                f"Path({str(mktemp_marker)!r}).write_text('called', encoding='utf-8')\n"
                "raise SystemExit(97)\n",
                encoding="utf-8",
            )
            fake_mktemp.chmod(0o700)
            python_argv_marker = fixture_root / "python-argv.json"
            fake_python = fake_bin / "python3"
            fake_python.write_text(
                f"#!{sys.executable}\n"
                "import json\n"
                "from pathlib import Path\n"
                "import sys\n"
                "arguments = sys.argv[1:]\n"
                f"Path({str(python_argv_marker)!r}).write_text(\n"
                "    json.dumps(arguments), encoding='utf-8'\n"
                ")\n"
                "unsafe = (\n"
                "    arguments[:3] != ['-I', '-B', '-c']\n"
                "    or len(arguments) != 4\n"
                "    or 'py_compile' in arguments[3]\n"
                "    or 'pycache_prefix' in arguments[3]\n"
                "    or 'mktemp' in arguments[3]\n"
                ")\n"
                "raise SystemExit(98 if unsafe else 0)\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment.get('PATH', '')}",
                    "TMPDIR": str(controlled_tmp),
                }
            )
            environment.pop("BASH_ENV", None)

            def run_compile() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [str(bash), "-c", compile_command],
                    cwd=candidate_root,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

            def assert_no_compile_artifacts() -> None:
                self.assertFalse(mktemp_marker.exists())
                self.assertEqual(list(controlled_tmp.iterdir()), [])
                self.assertEqual(list(candidate_root.rglob("__pycache__")), [])
                self.assertEqual(list(candidate_root.rglob("*.pyc")), [])

            valid_path = scripts_root / "valid.py"
            valid_path.write_bytes(
                b'# coding: latin-1\nraise RuntimeError("executed")\n'
                b'value = "caf\xe9"\n'
            )
            legacy_command = (
                "python3 -I -X "
                "pycache_prefix=/tmp/codex-waited-delivery-pycache "
                "-m py_compile skills/waited-delivery/scripts/*.py"
            )
            legacy_completed = subprocess.run(
                [str(bash), "-c", legacy_command],
                cwd=candidate_root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(legacy_completed.returncode, 98)
            legacy_arguments = json.loads(
                python_argv_marker.read_text(encoding="utf-8")
            )
            self.assertIn(
                "pycache_prefix=/tmp/codex-waited-delivery-pycache",
                legacy_arguments,
            )
            self.assertIn("py_compile", legacy_arguments)
            assert_no_compile_artifacts()
            python_argv_marker.unlink()

            completed = run_compile()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            python_arguments = json.loads(
                python_argv_marker.read_text(encoding="utf-8")
            )
            self.assertEqual(python_arguments[:3], ["-I", "-B", "-c"])
            self.assertEqual(len(python_arguments), 4)
            self.assertNotIn("py_compile", python_arguments[3])
            self.assertNotIn("pycache_prefix", python_arguments[3])
            self.assertNotIn("mktemp", python_arguments[3])
            assert_no_compile_artifacts()

            fake_python.unlink()
            completed = run_compile()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            assert_no_compile_artifacts()

            invalid_path = scripts_root / "invalid.py"
            invalid_path.write_bytes(b"def invalid(:\n    pass\n")
            completed = run_compile()
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("SyntaxError", completed.stderr)
            assert_no_compile_artifacts()

            valid_path.unlink()
            invalid_path.unlink()
            completed = run_compile()
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("no candidate Python helpers found", completed.stderr)
            assert_no_compile_artifacts()

    def test_readme_compile_preserves_candidate_binding_and_supervisor(self) -> None:
        if DISTRIBUTION_PROFILE == "private":
            self.skipTest(
                "canonical repository documentation is not shipped in private distribution"
            )
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            shutil.copyfile(REPO_ROOT / "README.md", candidate_root / "README.md")
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            commands = self.readme_test_commands(candidate_root)
            self.assertEqual(
                commands,
                [README_COMPILE_COMMAND, README_DISCOVERY_COMMAND],
            )
            bash = shutil.which("bash")
            self.assertIsNotNone(bash)
            completed = subprocess.run(
                [str(bash), "-c", commands[0]],
                cwd=candidate_root,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ):
                before = _CANDIDATE_SUPPORT.candidate_checkout_binding(
                    candidate_root, candidate_sha, require_clean=True
                )
                receipt = supervise_trusted_required_ci_tests(
                    trusted_root,
                    candidate_root,
                    supervisor_deadline=(
                        time.monotonic()
                        + TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS
                    ),
                )
                after = _CANDIDATE_SUPPORT.candidate_checkout_binding(
                    candidate_root, candidate_sha, require_clean=True
                )
            self.assertEqual(before, after)
            self.assertEqual(receipt["status"], "completed")

    def test_supervisor_proves_expected_inventory_and_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root,
                "test_required.py",
                self.required_module()
                + "\nclass AddedTests(unittest.TestCase):\n"
                "    def test_added(self):\n"
                "        pass\n",
            )

            receipt = self.supervise(trusted_root, candidate_root)

        self.assertEqual(
            set(receipt),
            {
                "schema_version",
                "status",
                "candidate_root",
                "candidate_distribution_profile",
                "candidate_sha",
                "candidate_script_sha256",
                "trusted_inventory",
                "trusted_source_sha256",
                "expected_test_count",
                "executed_test_count",
                "failures",
                "errors",
                "skipped",
                "expected_failures",
                "unexpected_successes",
            },
        )
        self.assertEqual(receipt["schema_version"], 3)
        self.assertEqual(receipt["status"], "completed")
        self.assertEqual(receipt["expected_test_count"], 2)
        self.assertEqual(receipt["executed_test_count"], 2)

    def test_supervisor_rejects_empty_candidate_runtime_with_preserved_inventory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            trusted_root = root / ".required-ci"
            candidate_root = root / ".candidate"
            source_tests_root = (
                TRUSTED_CONTENT_ROOT / "skills/waited-delivery/tests"
            )
            functional_test_modules = (
                "test_skill_contract.py",
                "test_waited_delivery_bridge.py",
                "test_waited_delivery_hook_adapter.py",
                "test_waited_delivery_runner.py",
            )
            copied_paths = (
                Path("README.md"),
                Path("docs/DEPENDENCIES.md"),
                Path("skills/waited-delivery/SKILL.md"),
            )
            for repository_root in (trusted_root, candidate_root):
                for relative_path in copied_paths:
                    destination = distribution_content_root(repository_root) / relative_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(TRUSTED_CONTENT_ROOT / relative_path, destination)
                tests_root = distribution_tests_root(repository_root)
                tests_root.mkdir(parents=True, exist_ok=True)
                for module_name in functional_test_modules:
                    shutil.copyfile(
                        source_tests_root / module_name,
                        tests_root / module_name,
                    )
                if repository_root == trusted_root:
                    shutil.copyfile(
                        TRUSTED_CANDIDATE_SUPPORT_PATH,
                        tests_root / "required_ci_candidate.py",
                    )

            trusted_scripts_root = (
                distribution_content_root(trusted_root)
                / "skills/waited-delivery/scripts"
            )
            candidate_scripts_root = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts"
            )
            trusted_scripts_root.mkdir(parents=True)
            candidate_scripts_root.mkdir(parents=True)
            for source_script in sorted(
                (TRUSTED_CONTENT_ROOT / "skills/waited-delivery/scripts").glob("*.py")
            ):
                shutil.copyfile(source_script, trusted_scripts_root / source_script.name)
                (candidate_scripts_root / source_script.name).write_text(
                    "pass\n", encoding="utf-8"
                )

            with self.assertRaisesRegex(
                AssertionError, "trusted Required CI tests did not complete"
            ):
                self.supervise(trusted_root, candidate_root)

    def test_supervisor_child_argv_and_environment_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )
            actual_run = _run_trusted_test_child
            captured_calls: list[tuple[list[str], dict[str, object]]] = []

            def recording_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                captured_calls.append((command, kwargs.copy()))
                return actual_run(command, **kwargs)

            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                    TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV: "999.000000000",
                },
                clear=False,
            ):
                with mock.patch.object(
                    sys.modules[__name__],
                    "_run_trusted_test_child",
                    side_effect=recording_run,
                ):
                    receipt = supervise_trusted_required_ci_tests(
                        trusted_root,
                        candidate_root,
                        supervisor_deadline=(
                            time.monotonic()
                            + TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS
                        ),
                    )

        self.assertEqual(receipt["status"], "completed")
        child_calls = [
            call
            for call in captured_calls
            if call[0][:2] == [sys.executable, "-I"]
        ]
        self.assertEqual(len(child_calls), 1)
        command, options = child_calls[0]
        self.assertEqual(
            command,
            [
                sys.executable,
                "-I",
                "-B",
                "-S",
                str(Path(__file__).resolve(strict=True)),
                TRUSTED_TEST_CHILD_FLAG,
                str(trusted_root),
            ],
        )
        self.assertEqual(options["cwd"], trusted_root)
        self.assertEqual(
            options["pass_fds"], (), "local nonstrict harness must not pass a realm fd"
        )
        self.assertIsInstance(options["supervisor_deadline"], float)
        child_environment = options["environment"]
        self.assertIsInstance(child_environment, dict)
        self.assertEqual(
            child_environment[REQUIRED_CI_CANDIDATE_ROOT_ENV], str(candidate_root)
        )
        self.assertEqual(
            child_environment[REQUIRED_CI_CANDIDATE_SHA_ENV], candidate_sha
        )
        self.assertEqual(child_environment["GITHUB_SHA"], candidate_sha)
        self.assertNotIn("PYTHONHOME", child_environment)
        self.assertNotIn("PYTHONPATH", child_environment)
        self.assertNotIn(
            TRUSTED_TEST_SUPERVISOR_DEADLINE_ENV, child_environment
        )
        for key in LOCAL_SUPERVISOR_ISOLATION_ENV:
            self.assertNotIn(key, child_environment)

    def test_supervisor_rejects_candidate_on_trusted_sys_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            original_sys_path = sys.path.copy()
            try:
                sys.path.insert(0, str(candidate_root))
                with self.assertRaisesRegex(AssertionError, "trusted sys.path"):
                    _assert_candidate_absent_from_sys_path(candidate_root)
            finally:
                sys.path[:] = original_sys_path

    def test_supervisor_rejects_missing_or_replaced_trusted_support(self) -> None:
        for state in ("missing", "replaced", "symlink"):
            with self.subTest(state=state):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    trusted_root, candidate_root = self.prepare_roots(
                        temporary_directory
                    )
                    self.write_test_module(
                        candidate_root, "test_required.py", self.required_module()
                    )
                    support_path = (
                        distribution_tests_root(trusted_root)
                        / "required_ci_candidate.py"
                    )
                    if state == "missing":
                        support_path.unlink()
                    elif state == "replaced":
                        support_path.write_text(
                            "raise SystemExit(0)\n", encoding="utf-8"
                        )
                    else:
                        support_path.unlink()
                        support_path.symlink_to(TRUSTED_CANDIDATE_SUPPORT_PATH)

                    with self.assertRaisesRegex(
                        AssertionError,
                        "trusted test source|trusted candidate support",
                    ):
                        self.supervise(trusted_root, candidate_root)

    def test_supervisor_does_not_load_candidate_root_unittest_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            canary = Path(temporary_directory) / "unittest-shadow.executed"
            (candidate_root / "unittest.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(canary)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )

            receipt = self.supervise(trusted_root, candidate_root)

            self.assertEqual(receipt["status"], "completed")
            self.assertFalse(canary.exists())

    def test_supervisor_never_executes_candidate_runtime_monkeypatches(self) -> None:
        monkeypatches = {
            "unittest": 'unittest.TestLoader.testMethodPrefix = "forged_"\n',
            "json": 'json.dumps = lambda *args, **kwargs: "forged"\n',
            "__main__": (
                "__main__._trusted_test_child_main = "
                "lambda *args, **kwargs: {}\n"
            ),
        }

        for name, monkeypatch in monkeypatches.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    trusted_root, candidate_root = self.prepare_roots(
                        temporary_directory
                    )
                    canary = Path(temporary_directory) / f"{name}.executed"
                    candidate_module = (
                        "import __main__\n"
                        "import json\n"
                        "from pathlib import Path\n"
                        "import unittest\n\n"
                        f"Path({str(canary)!r}).write_text('executed', encoding='utf-8')\n"
                        f"{monkeypatch}\n"
                        "class RequiredTests(unittest.TestCase):\n"
                        "    def test_one(self):\n"
                        "        pass\n"
                        "    def test_two(self):\n"
                        "        pass\n"
                    )
                    self.write_test_module(
                        candidate_root, "test_required.py", candidate_module
                    )

                    receipt = self.supervise(trusted_root, candidate_root)

                    self.assertEqual(receipt["status"], "completed")
                    self.assertFalse(canary.exists())

    def test_supervisor_ignores_a_forged_candidate_completion_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            canary = Path(temporary_directory) / "forged-receipt.executed"
            forged_receipt = {
                "schema_version": TRUSTED_TEST_RECEIPT_SCHEMA_VERSION,
                "status": "completed",
                "trusted_inventory": [],
                "expected_test_count": 2,
                "executed_test_count": 2,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "expected_failures": 0,
                "unexpected_successes": 0,
            }
            forged_stdout = (
                TRUSTED_TEST_RECEIPT_SENTINEL
                + json.dumps(
                    forged_receipt, sort_keys=True, separators=(",", ":")
                )
                + "\n"
            ).encode()
            candidate_module = (
                "import os\n"
                "from pathlib import Path\n"
                "import unittest\n\n"
                f"Path({str(canary)!r}).write_text('executed', encoding='utf-8')\n"
                f"os.write(1, {forged_stdout!r})\n"
                f"os._exit({TRUSTED_TEST_CHILD_SUCCESS_EXIT})\n\n"
                "class RequiredTests(unittest.TestCase):\n"
                "    def test_one(self):\n"
                "        raise AssertionError('must not run')\n"
                "    def test_two(self):\n"
                "        raise AssertionError('must not run')\n"
            )
            self.write_test_module(
                candidate_root, "test_required.py", candidate_module
            )

            receipt = self.supervise(trusted_root, candidate_root)

            self.assertEqual(receipt["status"], "completed")
            self.assertFalse(canary.exists())

    def test_supervisor_does_not_import_candidate_os_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            canary = Path(temporary_directory) / "os-exit.executed"
            candidate_module = (
                "import os\n"
                "from pathlib import Path\n"
                "import unittest\n\n"
                f"Path({str(canary)!r}).write_text('executed', encoding='utf-8')\n"
                "os._exit(0)\n\n"
                "class RequiredTests(unittest.TestCase):\n"
                "    def test_one(self):\n"
                "        pass\n"
                "    def test_two(self):\n"
                "        pass\n"
            )
            self.write_test_module(
                candidate_root, "test_required.py", candidate_module
            )

            receipt = self.supervise(trusted_root, candidate_root)

            self.assertEqual(receipt["status"], "completed")
            self.assertFalse(canary.exists())

    def test_supervisor_rejects_an_existing_empty_test_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            tests_root = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/tests"
            )
            (tests_root / "README.txt").write_text("no tests\n", encoding="utf-8")

            with self.assertRaisesRegex(AssertionError, "expected test inventory"):
                self.supervise(trusted_root, candidate_root)

    def test_supervisor_does_not_import_candidate_system_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            canary = Path(temporary_directory) / "system-exit.executed"
            self.write_test_module(
                candidate_root,
                "test_required.py",
                "from pathlib import Path\n"
                "import unittest\n\n"
                f"Path({str(canary)!r}).write_text('executed', encoding='utf-8')\n"
                "raise SystemExit(0)\n\n"
                "class RequiredTests(unittest.TestCase):\n"
                "    def test_one(self):\n"
                "        pass\n"
                "    def test_two(self):\n"
                "        pass\n",
            )

            receipt = self.supervise(trusted_root, candidate_root)

            self.assertEqual(receipt["status"], "completed")
            self.assertFalse(canary.exists())

    def test_supervisor_rejects_candidate_load_tests_hook(self) -> None:
        partial_module = self.required_module() + (
            "\ndef load_tests(loader, tests, pattern):\n"
            "    return unittest.TestSuite([RequiredTests('test_one')])\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root,
                "test_required.py",
                partial_module,
            )

            with self.assertRaisesRegex(AssertionError, "load_tests"):
                self.supervise(trusted_root, candidate_root)

    def test_supervisor_does_not_execute_candidate_test_early_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            canary = Path(temporary_directory) / "test-body.executed"
            candidate_module = (
                "from pathlib import Path\n"
                "import unittest\n\n"
                "class RequiredTests(unittest.TestCase):\n"
                "    def test_one(self):\n"
                f"        Path({str(canary)!r}).write_text('executed', encoding='utf-8')\n"
                "        raise SystemExit(0)\n"
                "    def test_two(self):\n"
                "        pass\n"
            )
            self.write_test_module(
                candidate_root, "test_required.py", candidate_module
            )

            receipt = self.supervise(trusted_root, candidate_root)

            self.assertEqual(receipt["status"], "completed")
            self.assertFalse(canary.exists())

    def test_supervisor_rejects_deleted_or_renamed_expected_tests(self) -> None:
        fixtures = {
            "deleted module": (
                "test_other.py",
                "import unittest\n\n"
                "class OtherTests(unittest.TestCase):\n"
                "    def test_other(self):\n"
                "        pass\n",
            ),
            "renamed module": ("test_renamed.py", self.required_module()),
            "renamed test": (
                "test_required.py",
                self.required_module().replace("test_one", "test_renamed", 1),
            ),
        }

        for name, (module_name, candidate_module) in fixtures.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    trusted_root, candidate_root = self.prepare_roots(
                        temporary_directory
                    )
                    self.write_test_module(
                        candidate_root,
                        module_name,
                        candidate_module,
                    )

                    with self.assertRaisesRegex(
                        AssertionError, "expected test inventory"
                    ):
                        self.supervise(trusted_root, candidate_root)

    def test_supervisor_rejects_skipped_expected_tests(self) -> None:
        fixtures = {
            "method decorator": self.required_module().replace(
                "    def test_one(self):\n",
                "    @unittest.skip('disabled')\n"
                "    def test_one(self):\n",
                1,
            ),
            "class decorator": self.required_module().replace(
                "class RequiredTests(unittest.TestCase):\n",
                "@unittest.skip('disabled')\n"
                "class RequiredTests(unittest.TestCase):\n",
                1,
            ),
        }
        for name, skipped_module in fixtures.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    trusted_root, candidate_root = self.prepare_roots(
                        temporary_directory
                    )
                    self.write_test_module(
                        candidate_root,
                        "test_required.py",
                        skipped_module,
                    )

                    with self.assertRaisesRegex(AssertionError, "decorators"):
                        self.supervise(trusted_root, candidate_root)

    def test_candidate_cannot_reselect_trusted_git_after_support_load(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            fake_bin = Path(temporary_directory).resolve(strict=True) / "candidate-bin"
            fake_bin.mkdir()
            canary = fake_bin / "executed"
            fake_git = fake_bin / "git"
            fake_git.write_text(
                "#!/bin/sh\n"
                f"printf executed > {str(canary)!r}\n"
                "exit 0\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                    "PATH": str(fake_bin),
                },
                clear=False,
            ):
                binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
                    candidate_root, candidate_sha, require_clean=True
                )

            argv = _CANDIDATE_SUPPORT.candidate_git_argv(
                candidate_root, "rev-parse", "HEAD"
            )
            self.assertEqual(
                argv[0], _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE
            )
            self.assertTrue(Path(argv[0]).is_absolute())
            self.assertNotIn(candidate_root, Path(argv[0]).parents)
            self.assertEqual(binding["candidate_sha"], candidate_sha)
            self.assertFalse(canary.exists())
            self.assertTrue(trusted_root.is_dir())

    def test_candidate_binding_rejects_invalid_sha_and_dirty_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha.upper(),
                },
                clear=False,
            ):
                with self.assertRaisesRegex(AssertionError, "lowercase 40-hex"):
                    _CANDIDATE_SUPPORT.expected_candidate_sha(candidate_root)

            (candidate_root / "untracked.txt").write_text(
                "candidate mutation\n", encoding="utf-8"
            )
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ):
                with self.assertRaisesRegex(AssertionError, "exactly clean"):
                    _CANDIDATE_SUPPORT.candidate_checkout_binding(
                        candidate_root, candidate_sha, require_clean=True
                    )

    def test_local_dirty_helper_executes_a_bound_worktree_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            runner_path = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            readme_path = candidate_root / "README.md"
            readme_path.write_text("frozen nonhelper\n", encoding="utf-8")
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            readme_path.write_text("dirty nonhelper\n", encoding="utf-8")
            runner_relative = (
                TRUSTED_CONTENT_RELATIVE_ROOT
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            ).as_posix()
            dirty_source = (
                "from pathlib import Path\n"
                f"workspace_copy = Path({runner_relative!r}).read_text(encoding='utf-8')\n"
                "helper = ('dirty worktree helper' if 'dirty-worktree-sentinel' "
                "in workspace_copy else 'frozen helper')\n"
                "print(f'{helper}:{Path(\"README.md\").read_text(encoding=\"utf-8\").strip()}')\n"
                "# dirty-worktree-sentinel\n"
            )
            runner_path.write_text(dirty_source, encoding="utf-8")
            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root)},
                clear=False,
            ):
                os.environ.pop(REQUIRED_CI_CANDIDATE_SHA_ENV, None)
                binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
                    candidate_root, candidate_sha, require_clean=False
                )
                completed = _CANDIDATE_SUPPORT.run_candidate_python(
                    runner_path
                )

            script_manifest = binding["candidate_script_sha256"]
            self.assertIsInstance(script_manifest, dict)
            if not isinstance(script_manifest, dict):
                raise AssertionError("candidate script manifest is malformed")
            self.assertEqual(
                script_manifest[runner_relative],
                hashlib.sha256(dirty_source.encode("utf-8")).hexdigest(),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                completed.stdout, "dirty worktree helper:frozen nonhelper\n"
            )
            self.assertNotEqual(Path(completed.args[2]), runner_path)
            self.assertEqual(runner_path.read_text(encoding="utf-8"), dirty_source)
            self.assertEqual(
                readme_path.read_text(encoding="utf-8"), "dirty nonhelper\n"
            )

    def test_local_capture_rejects_same_bytes_through_replaced_ancestor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            content_root = distribution_content_root(candidate_root)
            scripts_root = content_root / "skills/waited-delivery/scripts"
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            detached_scripts = scripts_root.with_name("detached-scripts")
            outside_scripts = candidate_root.parent / "outside-scripts"
            shutil.copytree(scripts_root, outside_scripts)
            runner_path = scripts_root / "waited_delivery_runner.py"
            original_open = os.open
            original_lstat = Path.lstat
            runner_lstat_count = 0
            swapped = False

            def replace_scripts_before_second_leaf_lstat(
                selected_path: Path,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal runner_lstat_count, swapped
                if Path(selected_path) == runner_path:
                    runner_lstat_count += 1
                    if runner_lstat_count == 2 and not swapped:
                        scripts_root.rename(detached_scripts)
                        scripts_root.symlink_to(
                            outside_scripts, target_is_directory=True
                        )
                        swapped = True
                return original_lstat(selected_path, *args, **kwargs)

            def replace_scripts_before_open(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal swapped
                selected = Path(selected_path)
                if not swapped and (
                    selected == runner_path
                    or (selected == Path("scripts") and "dir_fd" in kwargs)
                ):
                    scripts_root.rename(detached_scripts)
                    scripts_root.symlink_to(
                        outside_scripts, target_is_directory=True
                    )
                    swapped = True
                return original_open(selected_path, flags, *args, **kwargs)

            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root)},
                clear=False,
            ), mock.patch.object(
                Path,
                "lstat",
                new=replace_scripts_before_second_leaf_lstat,
            ), mock.patch.object(
                os,
                "open",
                side_effect=replace_scripts_before_open,
            ):
                os.environ.pop(REQUIRED_CI_CANDIDATE_SHA_ENV, None)
                with self.assertRaisesRegex(
                    AssertionError, "path binding|bound safely"
                ):
                    _CANDIDATE_SUPPORT.candidate_checkout_binding(
                        candidate_root,
                        candidate_sha,
                        require_clean=False,
                    )

            self.assertTrue(swapped, "the ancestor replacement fixture must execute")
            self.assertTrue(scripts_root.is_symlink())
            self.assertEqual(
                (detached_scripts / runner_path.name).read_bytes(),
                (outside_scripts / runner_path.name).read_bytes(),
            )

    def test_local_capture_rejects_whole_checkout_root_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            runner_relative = (
                TRUSTED_CONTENT_RELATIVE_ROOT
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            runner_path = candidate_root / runner_relative
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            detached_root = candidate_root.with_name("detached-candidate")
            replacement_root = candidate_root.with_name("replacement-candidate")
            shutil.copytree(candidate_root, replacement_root, symlinks=True)
            original_open = os.open
            swapped = False

            def replace_checkout_before_open(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal swapped
                selected = Path(selected_path)
                if not swapped and (
                    selected == runner_path
                    or (
                        selected == Path(candidate_root.name)
                        and "dir_fd" in kwargs
                    )
                ):
                    candidate_root.rename(detached_root)
                    replacement_root.rename(candidate_root)
                    swapped = True
                return original_open(selected_path, flags, *args, **kwargs)

            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root)},
                clear=False,
            ), mock.patch.object(
                os, "open", side_effect=replace_checkout_before_open
            ):
                os.environ.pop(REQUIRED_CI_CANDIDATE_SHA_ENV, None)
                with self.assertRaisesRegex(
                    AssertionError, "checkout root path binding changed"
                ):
                    _CANDIDATE_SUPPORT.candidate_checkout_binding(
                        candidate_root,
                        candidate_sha,
                        require_clean=False,
                    )

            self.assertTrue(swapped, "the checkout replacement fixture must execute")
            self.assertEqual(
                (detached_root / runner_relative).read_bytes(),
                (candidate_root / runner_relative).read_bytes(),
            )

    def test_local_capture_allows_benign_checkout_child_churn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            benign_child = candidate_root / "benign-child"
            original_read = os.read
            churned = False

            def create_benign_child(
                descriptor: int, length: int
            ) -> bytes:
                nonlocal churned
                if not churned:
                    benign_child.mkdir()
                    churned = True
                return original_read(descriptor, length)

            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root)},
                clear=False,
            ), mock.patch.object(os, "read", side_effect=create_benign_child):
                os.environ.pop(REQUIRED_CI_CANDIDATE_SHA_ENV, None)
                binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
                    candidate_root,
                    candidate_sha,
                    require_clean=False,
                )

            self.assertTrue(churned, "the benign churn fixture must execute")
            self.assertTrue(benign_child.is_dir())
            self.assertEqual(binding["candidate_sha"], candidate_sha)

    def test_local_capture_never_blocks_on_fifo_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            content_root = distribution_content_root(candidate_root)
            runner_path = (
                content_root
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            detached_runner = runner_path.with_name("detached-runner.py")
            original_open = os.open
            guard_descriptor: int | None = None
            leaf_open_flags: int | None = None
            replaced = False
            captured_error: BaseException | None = None

            def replace_runner_with_fifo(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal guard_descriptor, leaf_open_flags, replaced
                selected = Path(selected_path)
                if not replaced and (
                    selected == runner_path
                    or (
                        selected == Path(runner_path.name)
                        and "dir_fd" in kwargs
                    )
                ):
                    runner_path.rename(detached_runner)
                    os.mkfifo(runner_path)
                    guard_descriptor = original_open(
                        runner_path, os.O_RDWR | os.O_NONBLOCK
                    )
                    leaf_open_flags = flags
                    replaced = True
                return original_open(selected_path, flags, *args, **kwargs)

            def capture_candidate_binding() -> None:
                nonlocal captured_error
                try:
                    _CANDIDATE_SUPPORT.candidate_checkout_binding(
                        candidate_root,
                        candidate_sha,
                        require_clean=False,
                    )
                except BaseException as error:
                    captured_error = error

            try:
                with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                    os.environ,
                    {REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root)},
                    clear=False,
                ), mock.patch.object(
                    os, "open", side_effect=replace_runner_with_fifo
                ):
                    os.environ.pop(REQUIRED_CI_CANDIDATE_SHA_ENV, None)
                    worker = threading.Thread(target=capture_candidate_binding)
                    worker.start()
                    worker.join(timeout=0.25)
                    completed_without_writer = not worker.is_alive()
                    if worker.is_alive():
                        guard_descriptor = original_open(
                            runner_path, os.O_RDWR | os.O_NONBLOCK
                        )
                        worker.join(timeout=2)
                    self.assertFalse(
                        worker.is_alive(),
                        "the FIFO fixture worker must be recoverable",
                    )
            finally:
                if guard_descriptor is not None:
                    os.close(guard_descriptor)

            self.assertTrue(replaced, "the FIFO replacement fixture must execute")
            self.assertTrue(
                completed_without_writer,
                "candidate capture must reject a FIFO without waiting for a writer",
            )
            self.assertIsInstance(captured_error, AssertionError)
            self.assertIn("candidate file identity is unsafe", str(captured_error))
            self.assertIsNotNone(leaf_open_flags)
            assert leaf_open_flags is not None
            self.assertTrue(leaf_open_flags & os.O_NONBLOCK)
            self.assertTrue(leaf_open_flags & os.O_NOCTTY)
            self.assertTrue(stat.S_ISFIFO(runner_path.lstat().st_mode))
            self.assertTrue(detached_runner.is_file())

    def test_local_snapshot_reuses_the_binding_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            runner_path = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            self.initialize_candidate_checkout(candidate_root)
            runner_path.write_text("print('captured once')\n", encoding="utf-8")
            original_capture = _CANDIDATE_SUPPORT._candidate_script_sources
            capture_count = 0

            def capture_sources(root: Path) -> dict[Path, bytes]:
                nonlocal capture_count
                capture_count += 1
                return original_capture(root)

            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root)},
                clear=False,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_candidate_script_sources",
                side_effect=capture_sources,
            ):
                os.environ.pop(REQUIRED_CI_CANDIDATE_SHA_ENV, None)
                completed = _CANDIDATE_SUPPORT.run_candidate_python(runner_path)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "captured once\n")
            self.assertEqual(
                capture_count,
                2,
                "binding and final revalidation may capture once each; the "
                "snapshot must consume the initial held-FD capture",
            )

    def test_strict_execution_never_falls_back_to_worktree_sources(self) -> None:
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "strict_isolation_platform_preflight",
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_strict_isolation_requested",
            return_value=True,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_active_strict_session",
            return_value={},
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "candidate_repository_root",
            return_value=Path("/candidate"),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "expected_candidate_sha",
            return_value=("a" * 40, False),
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "candidate_checkout_binding",
        ) as binding, mock.patch.object(subprocess, "Popen") as popen:
            with self.assertRaisesRegex(
                AssertionError, "explicit frozen candidate SHA"
            ):
                _CANDIDATE_SUPPORT.run_candidate_python(Path("/candidate.py"))

        binding.assert_not_called()
        popen.assert_not_called()

    def test_execution_snapshot_reads_the_frozen_candidate_sha_not_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            content_root = distribution_content_root(candidate_root)
            bridge_relative = Path(
                "skills/waited-delivery/scripts/waited_delivery_bridge.py"
            )
            bridge_path = content_root / bridge_relative
            bridge_path.write_text("print('frozen-a')\n", encoding="utf-8")
            readme_path = candidate_root / "README.md"
            readme_path.write_text("frozen-readme\n", encoding="utf-8")
            frozen_sha = self.initialize_candidate_checkout(candidate_root)
            bridge_path.write_text("print('moving-b')\n", encoding="utf-8")
            readme_path.write_text("moving-readme\n", encoding="utf-8")
            for command in (
                [
                    _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                    "-C",
                    str(candidate_root),
                    "add",
                    "--all",
                ],
                [
                    _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE,
                    "-C",
                    str(candidate_root),
                    "-c",
                    "user.name=Required CI Test",
                    "-c",
                    "user.email=required-ci@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-m",
                    "moving head",
                ],
            ):
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

            with _CANDIDATE_SUPPORT._execution_snapshot(
                candidate_root, frozen_sha
            ) as snapshot:
                candidate_paths = snapshot["candidate_paths"]
                self.assertIsInstance(candidate_paths, dict)
                if not isinstance(candidate_paths, dict):
                    raise AssertionError("candidate snapshot fixture is malformed")
                snapshot_bridge = Path(
                    candidate_paths["waited_delivery_bridge.py"]
                )
                snapshot_bytes = snapshot_bridge.read_bytes()
                workspace_root = snapshot["workspace_root"]
                self.assertIsInstance(workspace_root, Path)
                assert isinstance(workspace_root, Path)
                snapshot_readme = (workspace_root / "README.md").read_bytes()

            self.assertEqual(snapshot_bytes, b"print('frozen-a')\n")
            self.assertEqual(snapshot_readme, b"frozen-readme\n")
            self.assertEqual(bridge_path.read_bytes(), b"print('moving-b')\n")
            self.assertEqual(readme_path.read_bytes(), b"moving-readme\n")

    def test_capability_probe_snapshot_never_reads_candidate_git(self) -> None:
        probe_source = b"print('probe')\n"
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_tracked_candidate_script_bytes",
            side_effect=AssertionError("candidate Git must not be read"),
        ):
            with _CANDIDATE_SUPPORT._execution_snapshot(
                Path("/not-used"), "a" * 40, probe_source=probe_source
            ) as snapshot:
                candidate_paths = snapshot["candidate_paths"]
                self.assertIsInstance(candidate_paths, dict)
                if not isinstance(candidate_paths, dict):
                    raise AssertionError("capability probe snapshot is malformed")
                probe_path = Path(candidate_paths["strict-capability-probe.py"])
                self.assertEqual(probe_path.read_bytes(), probe_source)

    def test_snapshot_permission_gate_rejects_nonstrict_root_evidence(
        self,
    ) -> None:
        with _local_nonstrict_supervisor_environment(), mock.patch.object(
            os, "geteuid", return_value=0
        ):
            self.assertFalse(_snapshot_permission_probe_is_meaningful())

        with _local_nonstrict_supervisor_environment(), mock.patch.object(
            os, "geteuid", return_value=501
        ):
            self.assertTrue(_snapshot_permission_probe_is_meaningful())

        with mock.patch.dict(
            os.environ,
            {REQUIRED_CI_ISOLATION_MODE_ENV: REQUIRED_CI_ISOLATION_MODE},
            clear=False,
        ), mock.patch.object(os, "geteuid", return_value=0):
            self.assertTrue(_snapshot_permission_probe_is_meaningful())

    def test_candidate_script_persistent_mutation_fails_closed(self) -> None:
        if not _snapshot_permission_probe_is_meaningful():
            self.skipTest(
                "non-strict UID 0 cannot prove snapshot DAC write denial"
            )
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            runner_path = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            runner_path.write_text(
                "from pathlib import Path\n"
                "target = Path(__file__).with_name('waited_delivery_bridge.py')\n"
                "target.write_text('tampered\\n', encoding='utf-8')\n",
                encoding="utf-8",
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ):
                completed = _CANDIDATE_SUPPORT.run_candidate_python(runner_path)

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Permission denied", completed.stderr)
            self.assertEqual(
                (
                    distribution_content_root(candidate_root)
                    / "skills/waited-delivery/scripts/waited_delivery_bridge.py"
                ).read_text(encoding="utf-8"),
                "pass\n",
            )

    def test_candidate_script_restore_is_isolated_before_next_execution(self) -> None:
        if not _snapshot_permission_probe_is_meaningful():
            self.skipTest(
                "non-strict UID 0 cannot prove snapshot DAC write denial"
            )
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            scripts_root = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts"
            )
            runner_path = scripts_root / "waited_delivery_runner.py"
            bridge_path = scripts_root / "waited_delivery_bridge.py"
            runner_path.write_text(
                "from pathlib import Path\n"
                "target = Path(__file__).with_name('waited_delivery_bridge.py')\n"
                "original = target.read_bytes()\n"
                "target.write_bytes(b'tampered\\n')\n"
                "target.write_bytes(original)\n"
                "print('restored')\n",
                encoding="utf-8",
            )
            bridge_path.write_text("print('original')\n", encoding="utf-8")
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ):
                rejected = _CANDIDATE_SUPPORT.run_candidate_python(runner_path)
                subsequent = _CANDIDATE_SUPPORT.run_candidate_python(bridge_path)

            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("Permission denied", rejected.stderr)
            self.assertEqual(subsequent.returncode, 0, subsequent.stderr)
            self.assertEqual(subsequent.stdout, "original\n")

    def test_candidate_process_uses_an_isolated_candidate_workspace_cwd(self) -> None:
        with _CANDIDATE_SUPPORT.candidate_fixture_directory(
            "required-ci-candidate-cwd-"
        ) as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            candidate_readme = candidate_root / "README.md"
            candidate_readme.write_text("candidate-relative\n", encoding="utf-8")
            runner_path = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            runner_path.write_text(
                "from pathlib import Path\n"
                "import os\n"
                "if Path('.git').exists():\n"
                "    raise SystemExit('candidate workspace exposed .git')\n"
                "if {Path(os.environ[name]).name for name in "
                "('HOME', 'TEMP', 'TMP', 'TMPDIR')} != {'runtime'}:\n"
                "    raise SystemExit('candidate runtime roots were not isolated')\n"
                "target = Path('README.md')\n"
                "before = target.read_text(encoding='utf-8').strip()\n"
                "target.write_text('workspace-mutated\\n', encoding='utf-8')\n"
                "print(f'{Path.cwd().name}:{before}:'\n"
                "      f'{target.read_text(encoding=\"utf-8\").strip()}')\n",
                encoding="utf-8",
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ):
                completed = _CANDIDATE_SUPPORT.run_candidate_python(runner_path)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                completed.stdout,
                ".candidate:candidate-relative:workspace-mutated\n",
            )
            self.assertEqual(
                candidate_readme.read_text(encoding="utf-8"),
                "candidate-relative\n",
            )

    def test_candidate_workspace_rejects_export_archive_transformations(
        self,
    ) -> None:
        fixtures = (
            (
                "export-ignore",
                "omitted.txt export-ignore\n",
                "omitted.txt",
                "must remain present\n",
                "file inventory is incomplete",
            ),
            (
                "export-subst",
                "substituted.txt export-subst\n",
                "substituted.txt",
                "$Format:%H$\n",
                "file policy changed|blob identity changed",
            ),
        )
        for name, attributes, selected_name, selected_source, message in fixtures:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                _, candidate_root = self.prepare_roots(temporary)
                (candidate_root / ".gitattributes").write_text(
                    attributes, encoding="utf-8"
                )
                (candidate_root / selected_name).write_text(
                    selected_source, encoding="utf-8"
                )
                candidate_sha = self.initialize_candidate_checkout(candidate_root)

                with self.assertRaisesRegex(AssertionError, message):
                    _CANDIDATE_SUPPORT._candidate_workspace_sources(
                        candidate_root,
                        candidate_sha,
                        _CANDIDATE_SUPPORT._candidate_script_sources(
                            candidate_root
                        ),
                    )

    def test_candidate_workspace_archive_rejects_policy_and_framing_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            (candidate_root / "README.md").write_text(
                "candidate archive\n", encoding="utf-8"
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            object_format, inventory, archive_output = (
                self.candidate_workspace_archive_fixture(
                    candidate_root, candidate_sha
                )
            )
            with tarfile.open(
                fileobj=io.BytesIO(archive_output), mode="r:"
            ) as archive:
                readme = archive.getmember("README.md")
                skills_directory = archive.getmember("skills")

            valid = _CANDIDATE_SUPPORT._candidate_workspace_archive_sources(
                archive_output,
                candidate_sha=candidate_sha,
                object_format=object_format,
                tree_inventory=inventory,
            )
            self.assertEqual(valid[Path("README.md")], (b"candidate archive\n", False))
            original_candidate_git = _CANDIDATE_SUPPORT._run_candidate_git
            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_run_candidate_git",
                wraps=original_candidate_git,
            ) as candidate_git:
                _CANDIDATE_SUPPORT._candidate_workspace_sources(
                    candidate_root,
                    candidate_sha,
                    _CANDIDATE_SUPPORT._candidate_script_sources(candidate_root),
                )
            archive_calls = [
                call
                for call in candidate_git.call_args_list
                if "archive" in call.args
            ]
            self.assertEqual(len(archive_calls), 1)
            self.assertEqual(
                archive_calls[0].kwargs["output_limit"],
                _CANDIDATE_SUPPORT.CANDIDATE_WORKSPACE_ARCHIVE_LIMIT_BYTES,
            )

            mutated_data = bytearray(archive_output)
            mutated_data[readme.offset_data] ^= 1
            cases = (
                (
                    "blob",
                    bytes(mutated_data),
                    "blob identity changed",
                ),
                (
                    "mode",
                    self.mutate_tar_header(
                        archive_output,
                        readme.offset,
                        100,
                        108,
                        b"0000777\0",
                    ),
                    "file policy changed",
                ),
                (
                    "hardlink",
                    self.mutate_tar_header(
                        archive_output,
                        readme.offset,
                        156,
                        157,
                        b"1",
                    ),
                    "member type is unsupported",
                ),
                (
                    "symlink",
                    self.mutate_tar_header(
                        archive_output,
                        readme.offset,
                        156,
                        157,
                        b"2",
                    ),
                    "member type is unsupported",
                ),
                (
                    "special",
                    self.mutate_tar_header(
                        archive_output,
                        readme.offset,
                        156,
                        157,
                        b"6",
                    ),
                    "member type is unsupported",
                ),
                (
                    "path",
                    self.mutate_tar_header(
                        archive_output,
                        readme.offset,
                        0,
                        100,
                        b"../README.md" + b"\0" * (100 - len("../README.md")),
                    ),
                    "path is unsafe",
                ),
                (
                    "root-directory-alias",
                    self.mutate_tar_header(
                        archive_output,
                        skills_directory.offset,
                        0,
                        100,
                        b"./" + b"\0" * 98,
                    ),
                    "path is unsafe",
                ),
                (
                    "empty-archive",
                    b"\0" * _CANDIDATE_SUPPORT._CANDIDATE_WORKSPACE_TAR_RECORD_BYTES,
                    "framing is malformed",
                ),
                (
                    "concatenated",
                    archive_output + archive_output,
                    "framing is malformed",
                ),
                (
                    "trailing-nonzero",
                    archive_output + b"x" * 512,
                    "framing is malformed",
                ),
                (
                    "trailing-zero-record",
                    archive_output
                    + b"\0" * _CANDIDATE_SUPPORT._CANDIDATE_WORKSPACE_TAR_RECORD_BYTES,
                    "framing is malformed",
                ),
            )
            for name, candidate_archive, message in cases:
                with self.subTest(name=name), self.assertRaisesRegex(
                    AssertionError, message
                ):
                    _CANDIDATE_SUPPORT._candidate_workspace_archive_sources(
                        candidate_archive,
                        candidate_sha=candidate_sha,
                        object_format=object_format,
                        tree_inventory=inventory,
                    )

    def test_candidate_workspace_rejects_caps_aliases_and_git_metadata(
        self,
    ) -> None:
        object_format = "sha1"
        blob_oid = _CANDIDATE_SUPPORT._candidate_workspace_blob_oid(
            b"x", object_format
        )
        too_many = b"".join(
            f"100644 blob {blob_oid} 1\tfile-{index:03d}\0".encode("ascii")
            for index in range(
                _CANDIDATE_SUPPORT.CANDIDATE_WORKSPACE_FILE_LIMIT + 1
            )
        )
        with self.assertRaisesRegex(AssertionError, "file inventory.*limit"):
            _CANDIDATE_SUPPORT._candidate_workspace_tree_inventory(
                too_many, object_format
            )

        oversized = (
            "100644 blob "
            + blob_oid
            + " "
            + str(
                _CANDIDATE_SUPPORT.CANDIDATE_WORKSPACE_TOTAL_SIZE_LIMIT_BYTES
                + 1
            )
            + "\tlarge.bin\0"
        ).encode("ascii")
        with self.assertRaisesRegex(AssertionError, "content exceeds.*total limit"):
            _CANDIDATE_SUPPORT._candidate_workspace_tree_inventory(
                oversized, object_format
            )
        oversized_file = (
            "100644 blob "
            + blob_oid
            + " "
            + str(_CANDIDATE_SUPPORT.CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES + 1)
            + "\ttoo-large.bin\0"
        ).encode("ascii")
        with self.assertRaisesRegex(AssertionError, "file exceeds.*size limit"):
            _CANDIDATE_SUPPORT._candidate_workspace_tree_inventory(
                oversized_file, object_format
            )

        aliases = (
            {Path("README.md"): (b"a", False), Path("readme.md"): (b"b", False)},
            {
                Path("\N{LATIN SMALL LETTER E WITH ACUTE}.txt"): (b"a", False),
                Path("e\N{COMBINING ACUTE ACCENT}.txt"): (b"b", False),
            },
        )
        for sources in aliases:
            with self.subTest(paths=tuple(sources)), self.assertRaisesRegex(
                AssertionError, "filesystem alias"
            ):
                _CANDIDATE_SUPPORT._validated_candidate_workspace_sources(
                    sources
                )
        for path in (b".git/config", b".GIT/config"):
            with self.subTest(path=path), self.assertRaisesRegex(
                AssertionError, "path is unsafe"
            ):
                _CANDIDATE_SUPPORT._candidate_workspace_path(path)
        with mock.patch.object(
            _CANDIDATE_SUPPORT, "_run_candidate_git"
        ) as candidate_git, self.assertRaisesRegex(
            AssertionError, "helper override inventory is not exact"
        ):
            _CANDIDATE_SUPPORT._candidate_workspace_sources(
                Path("/unused"), "a" * 40, {}
            )
        candidate_git.assert_not_called()

    def test_candidate_workspace_directory_budget_precedes_archive_expansion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            deep_file = candidate_root.joinpath(
                "deep",
                *(["d"] * _CANDIDATE_SUPPORT.CANDIDATE_WORKSPACE_DIRECTORY_LIMIT),
                "payload.txt",
            )
            deep_file.parent.mkdir(parents=True)
            deep_file.write_text("payload\n", encoding="utf-8")
            (candidate_root / ".gitattributes").write_text(
                "/deep export-ignore\n", encoding="utf-8"
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            content_root = distribution_content_root(candidate_root)
            candidate_sources = {
                relative_path: (content_root / relative_path).read_bytes()
                for relative_path in _CANDIDATE_SUPPORT.CANDIDATE_SCRIPT_RELATIVE_PATHS
            }
            original_run_git = _CANDIDATE_SUPPORT._run_candidate_git
            observed_arguments: list[tuple[str, ...]] = []

            def record_git(
                root: Path,
                *arguments: str,
                **kwargs: object,
            ) -> bytes:
                observed_arguments.append(arguments)
                return original_run_git(root, *arguments, **kwargs)

            with mock.patch.object(
                _CANDIDATE_SUPPORT,
                "_run_candidate_git",
                side_effect=record_git,
            ), self.assertRaisesRegex(
                AssertionError, "directory inventory.*limit"
            ):
                _CANDIDATE_SUPPORT._candidate_workspace_sources(
                    candidate_root,
                    candidate_sha,
                    candidate_sources,
                )

            self.assertFalse(
                any("archive" in arguments for arguments in observed_arguments),
                observed_arguments,
            )

    def test_candidate_workspace_directory_budget_has_an_exact_boundary(
        self,
    ) -> None:
        object_format = "sha1"
        blob_oid = _CANDIDATE_SUPPORT._candidate_workspace_blob_oid(
            b"x", object_format
        )

        def tree_record(depth: int) -> bytes:
            path = "/".join(["d"] * depth + ["file.txt"])
            return (
                f"100644 blob {blob_oid} 1\t{path}\0".encode("ascii")
            )

        exact_inventory = _CANDIDATE_SUPPORT._candidate_workspace_tree_inventory(
            tree_record(
                _CANDIDATE_SUPPORT.CANDIDATE_WORKSPACE_DIRECTORY_LIMIT
            ),
            object_format,
        )
        directory_trie, directory_count = (
            _CANDIDATE_SUPPORT._candidate_workspace_directory_trie(
                exact_inventory
            )
        )
        self.assertEqual(
            directory_count,
            _CANDIDATE_SUPPORT.CANDIDATE_WORKSPACE_DIRECTORY_LIMIT,
        )
        self.assertTrue(
            _CANDIDATE_SUPPORT._candidate_workspace_directory_is_expected(
                directory_trie,
                Path(*(["d"] * directory_count)),
            )
        )

        with self.assertRaisesRegex(
            AssertionError, "directory inventory.*limit"
        ):
            _CANDIDATE_SUPPORT._candidate_workspace_tree_inventory(
                tree_record(directory_count + 1), object_format
            )

        shallow_inventory = (
            _CANDIDATE_SUPPORT._candidate_workspace_tree_inventory(
                (
                    f"100644 blob {blob_oid} 1\talpha/one.txt\0"
                    f"100644 blob {blob_oid} 1\tbeta/two.txt\0"
                ).encode("ascii"),
                object_format,
            )
        )
        _, shallow_count = _CANDIDATE_SUPPORT._candidate_workspace_directory_trie(
            shallow_inventory
        )
        self.assertEqual(shallow_count, 2)

    def test_candidate_workspace_alias_preflight_precedes_snapshot_writes(
        self,
    ) -> None:
        candidate_sources = {
            relative_path: b"pass\n"
            for relative_path in _CANDIDATE_SUPPORT.CANDIDATE_SCRIPT_RELATIVE_PATHS
        }
        aliased_workspace = {
            Path("README.md"): (b"first", False),
            Path("readme.md"): (b"second", False),
        }
        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_candidate_workspace_sources",
            return_value=aliased_workspace,
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_write_single_link_file"
        ) as write_snapshot_file:
            with self.assertRaisesRegex(AssertionError, "filesystem alias"):
                with _CANDIDATE_SUPPORT._execution_snapshot(
                    Path("/unused"),
                    "a" * 40,
                    candidate_sources=candidate_sources,
                ):
                    self.fail("aliased workspace unexpectedly materialized")

        write_snapshot_file.assert_not_called()

        with mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_run_candidate_git",
            return_value=b"sha256\n",
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_write_single_link_file"
        ) as write_snapshot_file:
            with self.assertRaisesRegex(AssertionError, "SHA-1 authority"):
                with _CANDIDATE_SUPPORT._execution_snapshot(
                    Path("/unused"),
                    "a" * 40,
                    candidate_sources=candidate_sources,
                ):
                    self.fail("SHA-256 workspace unexpectedly materialized")

        write_snapshot_file.assert_not_called()

    def test_candidate_workspace_materialization_never_overwrites_a_host_alias(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            execution_root = Path(temporary_directory).resolve(strict=True)
            sources = {
                Path("first.txt"): (b"first", False),
                Path("second.txt"): (b"second", False),
            }
            original_open = os.open
            alias_rejected = False
            file_flags: int | None = None

            def reject_second_host_name(
                selected_path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal alias_rejected, file_flags
                if selected_path == "second.txt" and "dir_fd" in kwargs:
                    alias_rejected = True
                    file_flags = flags
                    raise FileExistsError("simulated host filesystem alias")
                return original_open(selected_path, flags, *args, **kwargs)

            with mock.patch.object(
                os, "open", side_effect=reject_second_host_name
            ), self.assertRaisesRegex(
                AssertionError, "cannot be created uniquely"
            ):
                _CANDIDATE_SUPPORT._materialize_candidate_workspace(
                    execution_root, sources
                )

            self.assertTrue(alias_rejected, "the host alias fixture must execute")
            self.assertIsNotNone(file_flags)
            assert file_flags is not None
            self.assertTrue(file_flags & os.O_EXCL)
            self.assertTrue(file_flags & os.O_NOFOLLOW)
            self.assertTrue(file_flags & os.O_NONBLOCK)
            self.assertTrue(file_flags & os.O_NOCTTY)
            workspace_root = execution_root / ".candidate"
            self.assertEqual((workspace_root / "first.txt").read_bytes(), b"first")
            self.assertFalse((workspace_root / "second.txt").exists())

    def test_candidate_workspace_materialization_rejects_a_host_git_alias(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            execution_root = Path(temporary_directory).resolve(strict=True)
            original_stat = os.stat
            alias_reported = False

            def report_host_git_alias(
                selected_path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal alias_reported
                if selected_path == ".git" and "dir_fd" in kwargs:
                    alias_reported = True
                    return os.stat_result(
                        (stat.S_IFREG | 0o644, 1, 1, 1, 0, 0, 1, 0, 0, 0)
                    )
                return original_stat(selected_path, *args, **kwargs)

            with mock.patch.object(
                os, "stat", side_effect=report_host_git_alias
            ), self.assertRaisesRegex(
                AssertionError, "exposes a Git metadata alias"
            ):
                _CANDIDATE_SUPPORT._materialize_candidate_workspace(
                    execution_root,
                    {Path("content.txt"): (b"content", False)},
                )

            self.assertTrue(alias_reported, "the Git alias fixture must execute")

    def test_candidate_workspace_is_execution_scoped_and_has_exact_policies(
        self,
    ) -> None:
        self.assertEqual(
            _CANDIDATE_SUPPORT._ROOT_TREE_MODE_PROFILES["candidate-workspace"],
            (0o770, 0o660, 0o770, False),
        )
        self.assertEqual(
            _CANDIDATE_SUPPORT._ROOT_TREE_MODE_PROFILES["candidate-code"],
            (0o550, 0o440, 0o550, False),
        )
        self.assertEqual(
            _CANDIDATE_SUPPORT._ROOT_TREE_MODE_PROFILES["trusted-control"],
            (0o700, 0o400, 0o500, False),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            with _CANDIDATE_SUPPORT._execution_snapshot(
                candidate_root, candidate_sha
            ) as snapshot:
                execution_root = snapshot["execution_root"]
                workspace_root = snapshot["workspace_root"]
                self.assertIsInstance(execution_root, Path)
                self.assertIsInstance(workspace_root, Path)
                assert isinstance(execution_root, Path)
                assert isinstance(workspace_root, Path)
                self.assertEqual(workspace_root.parent, execution_root)
                self.assertFalse((workspace_root / ".git").exists())
                self.assertTrue(workspace_root.is_dir())
            self.assertFalse(execution_root.exists())

    def test_explicit_candidate_cwd_is_not_replaced_by_the_workspace(self) -> None:
        with _CANDIDATE_SUPPORT.candidate_fixture_directory(
            "required-ci-candidate-explicit-"
        ) as temporary_directory, _CANDIDATE_SUPPORT.candidate_fixture_directory(
            "required-ci-explicit-cwd-"
        ) as explicit_directory:
            _, candidate_root = self.prepare_roots(temporary_directory)
            explicit_root = Path(explicit_directory).resolve(strict=True)
            (explicit_root / "marker.txt").write_text(
                "explicit\n", encoding="utf-8"
            )
            overflow_root = candidate_root / "workspace-overflow"
            overflow_root.mkdir()
            for index in range(
                _CANDIDATE_SUPPORT.CANDIDATE_WORKSPACE_FILE_LIMIT + 1
            ):
                (overflow_root / f"file-{index:03d}").write_text(
                    "overflow\n", encoding="utf-8"
                )
            execution_marker = explicit_root / "executed"
            runner_path = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            runner_path.write_text(
                "from pathlib import Path\n"
                "print(\n"
                "    f'{Path.cwd().name}:'\n"
                "    f'{Path(\"marker.txt\").read_text(encoding=\"utf-8\").strip()}'\n"
                ")\n",
                encoding="utf-8",
            )
            with runner_path.open("a", encoding="utf-8") as runner:
                runner.write(
                    "Path(" + repr(str(execution_marker)) + ").write_text("
                    "'ran', encoding='utf-8')\n"
                )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ):
                with self.assertRaisesRegex(
                    AssertionError, "file inventory.*limit"
                ):
                    _CANDIDATE_SUPPORT.run_candidate_python(
                        runner_path,
                        writable_roots=(explicit_root,),
                    )
                self.assertFalse(execution_marker.exists())
                completed = _CANDIDATE_SUPPORT.run_candidate_python(
                    runner_path,
                    cwd=explicit_root,
                    writable_roots=(explicit_root,),
                )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                completed.stdout,
                f"{explicit_root.name}:explicit\n",
            )
            self.assertEqual(execution_marker.read_text(encoding="utf-8"), "ran")

    def test_strict_target_access_policy_blocks_snapshot_write_and_control_read(
        self,
    ) -> None:
        mode = os.environ.get(REQUIRED_CI_ISOLATION_MODE_ENV)
        if mode is None:
            self.skipTest(
                "strict target credential transition is exercised only by the "
                "trusted Required CI supervisor"
            )
        self.assertEqual(mode, REQUIRED_CI_ISOLATION_MODE)
        if sys.platform != "linux":
            self.skipTest("strict live mount and IPC isolation requires Linux")
        _CANDIDATE_SUPPORT._ensure_strict_backend()

        host_mount_namespace = os.readlink("/proc/self/ns/mnt")
        host_ipc_namespace = os.readlink("/proc/self/ns/ipc")
        realm = _CANDIDATE_SUPPORT._strict_realm()
        target_uid = int(realm["uid"])
        target_gid = int(realm["gid"])

        runner_temp_value = os.environ.get("RUNNER_TEMP")
        if runner_temp_value is None or not Path(runner_temp_value).is_absolute():
            raise AssertionError(
                "strict live RUNNER_TEMP must be an absolute trusted directory"
            )
        runner_temp = Path(runner_temp_value).resolve(strict=True)
        private_surfaces = tuple(
            Path(value) for value in ("/tmp", "/var/tmp", "/run", "/dev/shm")
        )
        if any(
            runner_temp == surface or surface in runner_temp.parents
            for surface in private_surfaces
        ):
            raise AssertionError(
                "strict live RUNNER_TEMP must be outside private mount surfaces"
            )
        for ancestor in (runner_temp, *runner_temp.parents):
            metadata = ancestor.stat()
            if not stat.S_ISDIR(metadata.st_mode) or not metadata.st_mode & 0o001:
                raise AssertionError(
                    "strict live RUNNER_TEMP is not traversable by the target UID"
                )
            _CANDIDATE_SUPPORT._acl_is_absent(
                ancestor, "strict live RUNNER_TEMP ancestor"
            )
            if ancestor == Path("/"):
                break

        surface_roots: list[Path] = []
        surface_identities: dict[Path, tuple[int, int]] = {}
        surface_markers: dict[Path, Path] = {}

        def remove_empty_bound_root(
            root: Path, identity: tuple[int, int]
        ) -> None:
            metadata = root.lstat()
            if (metadata.st_dev, metadata.st_ino) != identity:
                raise AssertionError(f"host setup root identity changed: {root}")
            root.rmdir()

        setup_cleanup = contextlib.ExitStack()
        try:
            ipc_root = Path(
                tempfile.mkdtemp(prefix="required-ci-host-ipc-", dir=runner_temp)
            ).resolve(strict=True)
            ipc_root_metadata = ipc_root.lstat()
            ipc_root_identity = (
                ipc_root_metadata.st_dev,
                ipc_root_metadata.st_ino,
            )
            setup_cleanup.callback(
                remove_empty_bound_root, ipc_root, ipc_root_identity
            )
            ipc_root.chmod(0o711)
            _CANDIDATE_SUPPORT._acl_is_absent(
                ipc_root, "strict live host IPC scaffold"
            )
            socket_path = ipc_root / "post-seal.sock"
            fifo_path = ipc_root / "post-seal.fifo"
            if len(os.fsencode(socket_path)) >= 104:
                raise AssertionError(
                    "strict live RUNNER_TEMP produces an unsafe AF_UNIX path length"
                )

            for surface in (
                Path("/tmp"),
                Path("/var/tmp"),
                Path("/dev/shm"),
                Path("/run/lock"),
            ):
                root = Path(
                    tempfile.mkdtemp(prefix="required-ci-private-", dir=surface)
                ).resolve(strict=True)
                metadata = root.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink < 1:
                    raise AssertionError(
                        "strict live host scaffold identity is unsafe"
                    )
                surface_roots.append(root)
                surface_identities[root] = (metadata.st_dev, metadata.st_ino)
                setup_cleanup.callback(
                    remove_empty_bound_root,
                    root,
                    surface_identities[root],
                )
                root.chmod(0o777)
                surface_markers[root] = root / (
                    "posix-shm-private-marker"
                    if surface == Path("/dev/shm")
                    else "candidate-private-marker"
                )

            libc = ctypes.CDLL(None, use_errno=True)
            libc.shmget.argtypes = (ctypes.c_int, ctypes.c_size_t, ctypes.c_int)
            libc.shmget.restype = ctypes.c_int
            libc.shmctl.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
            libc.shmctl.restype = ctypes.c_int
            libc.mq_unlink.argtypes = (ctypes.c_char_p,)
            libc.mq_unlink.restype = ctypes.c_int

            def remove_setup_sysv(shmid: int) -> None:
                ctypes.set_errno(0)
                if libc.shmctl(shmid, 0, None) != 0:
                    raise OSError(ctypes.get_errno(), "shmctl setup cleanup failed")

            sysv_key = 0
            host_shmid = -1
            for _ in range(64):
                sysv_key = (uuid.uuid4().int & 0x3FFFFFFF) or 1
                ctypes.set_errno(0)
                host_shmid = libc.shmget(
                    sysv_key,
                    4096,
                    0o1000 | 0o2000 | 0o666,
                )
                if host_shmid >= 0:
                    setup_cleanup.callback(remove_setup_sysv, host_shmid)
                    break
                if ctypes.get_errno() != errno.EEXIST:
                    raise OSError(ctypes.get_errno(), "shmget sentinel failed")
            if host_shmid < 0:
                raise AssertionError(
                    "strict live SysV sentinel key inventory exhausted"
                )

            mqueue_name = f"/required-ci-{uuid.uuid4().hex}"
            host_mqueue_path = Path("/dev/mqueue") / mqueue_name[1:]
            if host_mqueue_path.exists():
                raise AssertionError(
                    "strict live POSIX mqueue name unexpectedly exists"
                )
        except BaseException:
            setup_cleanup.close()
            raise
        else:
            setup_cleanup.pop_all()

        trusted_control_relative = (
            TRUSTED_CONTENT_RELATIVE_ROOT
            / "skills/waited-delivery/tests/required_ci_candidate.py"
        ).as_posix()
        go_marker: Path | None = None
        ready_marker: Path | None = None
        explicit_marker: Path | None = None
        listener_created: list[bool] = []
        listener_received: list[bytes] = []
        listener_fifo_remaining: bytes | None = None
        listener_errors: list[BaseException] = []
        listener_nodes: dict[Path, tuple[int, int, int]] = {}
        listener_process: subprocess.Popen[bytes] | None = None
        listener_identity: tuple[int, ...] | None = None
        rw_hint_path = ipc_root / "rw-hint-sentinel"
        rw_hint_identity: tuple[int, int] | None = None
        rw_hint_descriptor: int | None = None
        rw_hint_baseline: bytes | None = None
        completed: subprocess.CompletedProcess[str] | None = None
        helper_source = inspect.cleandoc(
            r'''
            import json
            import os
            from pathlib import Path
            import select
            import signal
            import socket
            import sys
            import time

            if len(sys.argv) != 6 or sys.argv[1] not in ("normal", "hang"):
                raise SystemExit(70)
            mode = sys.argv[1]
            socket_path = Path(sys.argv[2])
            fifo_path = Path(sys.argv[3])
            go_marker = Path(sys.argv[4])
            ready_marker = Path(sys.argv[5])
            if mode == "hang":
                signal.signal(signal.SIGTERM, signal.SIG_IGN)

            deadline = time.monotonic() + 15.0
            while not go_marker.exists():
                readable, _, _ = select.select([0], [], [], 0.05)
                if readable:
                    os.read(0, 16)
                    raise SystemExit(71)
                if time.monotonic() >= deadline:
                    raise SystemExit(72)
            if go_marker.read_text(encoding="utf-8") != "go\n":
                raise SystemExit(73)

            received = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                socket_path.chmod(0o666)
                os.mkfifo(fifo_path, 0o666)
                fifo_path.chmod(0o666)
                fifo_descriptor = os.open(
                    fifo_path, os.O_RDWR | os.O_NONBLOCK
                )
                try:
                    fifo_prefill = b"host-fifo-byte"
                    if os.write(fifo_descriptor, fifo_prefill) != len(fifo_prefill):
                        raise SystemExit(74)
                    server.listen(1)
                    server.settimeout(0.05)
                    nodes = {}
                    for path in (socket_path, fifo_path):
                        metadata = path.lstat()
                        nodes[str(path)] = [
                            metadata.st_dev,
                            metadata.st_ino,
                            metadata.st_mode,
                            metadata.st_uid,
                        ]
                    print(
                        json.dumps(
                            {
                                "go_observed": True,
                                "nodes": nodes,
                                "pid": os.getpid(),
                                "status": "ready",
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                    ready_marker.write_text("ready\n", encoding="utf-8")
                    while True:
                        readable, _, _ = select.select([0], [], [], 0.05)
                        if readable:
                            command = os.read(0, 16)
                            if mode == "normal":
                                break
                            time.sleep(0.05)
                        try:
                            connection, _ = server.accept()
                        except TimeoutError:
                            pass
                        else:
                            with connection:
                                connection.settimeout(0.5)
                                received.append(connection.recv(16).hex())
                    try:
                        fifo_remaining = os.read(fifo_descriptor, len(fifo_prefill))
                    except BlockingIOError:
                        fifo_remaining = b""
                finally:
                    os.close(fifo_descriptor)
            print(
                json.dumps(
                    {
                        "fifo_remaining": fifo_remaining.hex(),
                        "received": received,
                        "status": "completed",
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            '''
        ) + "\n"

        def start_host_ipc_helper(
            selected_socket: Path,
            selected_fifo: Path,
            selected_go: Path,
            selected_ready: Path,
            *,
            mode: str,
        ) -> tuple[subprocess.Popen[bytes], tuple[int, ...]]:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    helper_source,
                    mode,
                    str(selected_socket),
                    str(selected_fifo),
                    str(selected_go),
                    str(selected_ready),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                identity = _CANDIDATE_SUPPORT._process_identity(
                    Path("/proc") / str(process.pid)
                )
                if identity is None or identity[0] != process.pid:
                    raise AssertionError("host IPC helper identity is unavailable")
            except BaseException:
                def kill_unreaped_helper() -> None:
                    if process.poll() is None:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass

                kill_unreaped_helper()
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    kill_unreaped_helper()
                    process.communicate(timeout=2)
                if process.poll() is None:
                    raise AssertionError(
                        "host IPC helper could not be reaped after acquisition failure"
                    )
                raise
            return process, identity

        def stop_host_ipc_helper(
            process: subprocess.Popen[bytes],
            identity: tuple[int, ...],
            *,
            expect_graceful: bool,
        ) -> tuple[bytes, bytes]:
            def assert_live_direct_child() -> None:
                observed = _CANDIDATE_SUPPORT._process_identity(
                    Path("/proc") / str(process.pid)
                )
                if process.poll() is not None or observed != identity:
                    raise AssertionError(
                        "host IPC helper is not the live unreaped direct child"
                    )
                children_path = (
                    Path("/proc")
                    / str(process.pid)
                    / "task"
                    / str(process.pid)
                    / "children"
                )
                children = children_path.read_bytes()
                if len(children) > 4096 or children.split():
                    raise AssertionError("host IPC helper has a descendant")

            if process.poll() is None:
                assert_live_direct_child()
                if process.stdin is not None:
                    try:
                        process.stdin.write(b"stop\n")
                        process.stdin.flush()
                    except BrokenPipeError:
                        pass
                    finally:
                        process.stdin.close()
                        process.stdin = None
            try:
                stdout, stderr = process.communicate(timeout=0.5)
            except subprocess.TimeoutExpired:
                assert_live_direct_child()
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=0.5)
                except subprocess.TimeoutExpired:
                    assert_live_direct_child()
                    process.kill()
                    stdout, stderr = process.communicate(timeout=2)
            if (
                process.poll() is None
                or _CANDIDATE_SUPPORT._process_identity(
                    Path("/proc") / str(process.pid)
                )
                == identity
            ):
                raise AssertionError("host IPC helper was not reaped")
            if len(stdout) > 65536 or len(stderr) > 65536:
                raise AssertionError("host IPC helper output exceeded its bound")
            if expect_graceful:
                if process.returncode != 0 or stderr:
                    raise AssertionError(
                        "host IPC helper did not stop cleanly: "
                        + stderr.decode("utf-8", errors="replace")
                    )
            elif process.returncode != -signal.SIGKILL:
                raise AssertionError(
                    "hanging host IPC helper did not require the kill fallback"
                )
            return stdout, stderr

        def parse_host_ipc_helper(
            stdout: bytes,
            expected_paths: tuple[Path, Path],
            expected_pid: int,
            *,
            completed_required: bool,
        ) -> tuple[
            dict[Path, tuple[int, int, int]], list[bytes], bytes | None
        ]:
            try:
                documents = [
                    json.loads(line)
                    for line in stdout.decode("utf-8").splitlines()
                ]
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise AssertionError("host IPC helper output is malformed") from error
            expected_count = 2 if completed_required else 1
            if len(documents) != expected_count:
                raise AssertionError("host IPC helper output count is wrong")
            ready = documents[0]
            if (
                type(ready) is not dict
                or ready.get("status") != "ready"
                or ready.get("pid") != expected_pid
                or ready.get("go_observed") is not True
                or type(ready.get("nodes")) is not dict
            ):
                raise AssertionError("host IPC helper readiness is malformed")
            nodes: dict[Path, tuple[int, int, int]] = {}
            for path in expected_paths:
                value = ready["nodes"].get(str(path))
                if (
                    type(value) is not list
                    or len(value) != 4
                    or any(type(item) is not int for item in value)
                    or value[3] != os.getuid()
                ):
                    raise AssertionError("host IPC helper node binding is malformed")
                nodes[path] = (value[0], value[1], value[2])
            if not completed_required:
                return nodes, [], None
            terminal = documents[1]
            if (
                type(terminal) is not dict
                or terminal.get("status") != "completed"
                or type(terminal.get("received")) is not list
                or type(terminal.get("fifo_remaining")) is not str
                or any(
                    type(value) is not str
                    for value in terminal.get("received", [])
                )
            ):
                raise AssertionError("host IPC helper terminal output is malformed")
            try:
                received = [bytes.fromhex(value) for value in terminal["received"]]
                fifo_remaining = bytes.fromhex(terminal["fifo_remaining"])
            except ValueError as error:
                raise AssertionError(
                    "host IPC helper receipt bytes are malformed"
                ) from error
            return nodes, received, fifo_remaining

        def remove_host_ipc_node(
            path: Path,
            expected: tuple[int, int, int] | None,
            expected_kind,
        ) -> None:
            root_metadata = ipc_root.lstat()
            if (
                root_metadata.st_dev,
                root_metadata.st_ino,
            ) != ipc_root_identity:
                raise AssertionError("host IPC scaffold identity changed")
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                if expected is not None:
                    raise AssertionError(f"host IPC node disappeared: {path}")
                return
            if expected is not None and (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
            ) != expected:
                raise AssertionError(f"host IPC node identity changed: {path}")
            if (
                not expected_kind(metadata.st_mode)
                or metadata.st_uid != os.getuid()
            ):
                raise AssertionError(
                    f"host IPC node ownership/type changed: {path}"
                )
            path.unlink()

        def remove_host_regular(
            path: Path, expected: tuple[int, int] | None
        ) -> None:
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                if expected is not None:
                    raise AssertionError(f"host IPC marker disappeared: {path}")
                return
            if expected is not None and (
                metadata.st_dev,
                metadata.st_ino,
            ) != expected:
                raise AssertionError(f"host IPC marker identity changed: {path}")
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise AssertionError(
                    f"host IPC marker ownership/type changed: {path}"
                )
            path.unlink()

        hang_socket = ipc_root / "hang.sock"
        hang_fifo = ipc_root / "hang.fifo"
        hang_go = ipc_root / "hang-go"
        hang_ready = ipc_root / "hang-ready"
        hang_process: subprocess.Popen[bytes] | None = None
        hang_identity: tuple[int, ...] | None = None
        hang_nodes: dict[Path, tuple[int, int, int]] = {}
        hang_go_identity: tuple[int, int] | None = None
        hang_ready_identity: tuple[int, int] | None = None
        hang_cleanup_errors: list[str] = []
        try:
            hang_process, hang_identity = start_host_ipc_helper(
                hang_socket,
                hang_fifo,
                hang_go,
                hang_ready,
                mode="hang",
            )
            hang_go.write_text("go\n", encoding="utf-8")
            metadata = hang_go.lstat()
            hang_go_identity = (metadata.st_dev, metadata.st_ino)
            deadline = time.monotonic() + 5.0
            while not hang_ready.exists():
                if hang_process.poll() is not None:
                    raise AssertionError(
                        "hanging host IPC helper exited before readiness"
                    )
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        "hanging host IPC helper did not become ready"
                    )
                time.sleep(0.01)
            if hang_ready.read_text(encoding="utf-8") != "ready\n":
                raise AssertionError("hanging host IPC helper readiness changed")
            metadata = hang_ready.lstat()
            hang_ready_identity = (metadata.st_dev, metadata.st_ino)
            stdout, stderr = stop_host_ipc_helper(
                hang_process,
                hang_identity,
                expect_graceful=False,
            )
            if stderr:
                raise AssertionError("hanging host IPC helper wrote stderr")
            hang_nodes, received, fifo_remaining = parse_host_ipc_helper(
                stdout,
                (hang_socket, hang_fifo),
                hang_process.pid,
                completed_required=False,
            )
            if received:
                raise AssertionError(
                    "hanging host IPC helper unexpectedly received candidate data"
                )
            if fifo_remaining is not None:
                raise AssertionError(
                    "hanging host IPC helper emitted a terminal FIFO receipt"
                )
        finally:
            if (
                hang_process is not None
                and hang_identity is not None
                and (
                    hang_process.poll() is None
                    or _CANDIDATE_SUPPORT._process_identity(
                        Path("/proc") / str(hang_process.pid)
                    )
                    == hang_identity
                )
            ):
                try:
                    stop_host_ipc_helper(
                        hang_process,
                        hang_identity,
                        expect_graceful=False,
                    )
                except BaseException as error:
                    hang_cleanup_errors.append(str(error))
            helper_terminal = (
                hang_process is None
                or (
                    hang_process.poll() is not None
                    and (
                        hang_identity is None
                        or _CANDIDATE_SUPPORT._process_identity(
                            Path("/proc") / str(hang_process.pid)
                        )
                        != hang_identity
                    )
                )
            )
            if not helper_terminal:
                hang_cleanup_errors.append(
                    "hanging host IPC helper remained active"
                )
            else:
                for path, kind in (
                    (hang_socket, stat.S_ISSOCK),
                    (hang_fifo, stat.S_ISFIFO),
                ):
                    try:
                        remove_host_ipc_node(path, hang_nodes.get(path), kind)
                    except BaseException as error:
                        hang_cleanup_errors.append(str(error))
                for path, expected in (
                    (hang_ready, hang_ready_identity),
                    (hang_go, hang_go_identity),
                ):
                    try:
                        remove_host_regular(path, expected)
                    except BaseException as error:
                        hang_cleanup_errors.append(str(error))
                try:
                    if tuple(ipc_root.iterdir()):
                        raise AssertionError(
                            "hanging host IPC helper left scaffold residue"
                        )
                except BaseException as error:
                    hang_cleanup_errors.append(str(error))
            if hang_cleanup_errors:
                raise AssertionError("; ".join(hang_cleanup_errors))

        try:
            rw_hint_path.write_bytes(b"required-ci-rw-hint\n")
            rw_hint_path.chmod(0o444)
            metadata = rw_hint_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o444
            ):
                raise AssertionError("host fcntl sentinel identity is unsafe")
            rw_hint_identity = (metadata.st_dev, metadata.st_ino)
            rw_hint_descriptor = os.open(
                rw_hint_path,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                rw_hint_baseline = fcntl.fcntl(
                    rw_hint_descriptor, 1035, bytes(8)
                )
            except OSError as error:
                raise AssertionError(
                    "strict live host filesystem does not support F_GET_RW_HINT"
                ) from error
            if type(rw_hint_baseline) is not bytes or len(rw_hint_baseline) != 8:
                raise AssertionError("strict live F_GET_RW_HINT result is malformed")
            with _CANDIDATE_SUPPORT.candidate_fixture_directory(
                "required-ci-access-policy-"
            ) as temporary_directory, _CANDIDATE_SUPPORT.candidate_fixture_directory(
                "required-ci-access-allowed-"
            ) as explicit_directory:
                _, candidate_root = self.prepare_roots(temporary_directory)
                explicit_root = Path(explicit_directory).resolve(strict=True)
                go_marker = explicit_root / "candidate-go"
                ready_marker = explicit_root / "host-ipc-ready"
                explicit_marker = explicit_root / "allowed-write"
                git_root = explicit_root / "git-fixture"
                git_root.mkdir()
                (git_root / "tracked.txt").write_text(
                    "tracked\n", encoding="utf-8"
                )
                trusted_git = _CANDIDATE_SUPPORT.TRUSTED_GIT_EXECUTABLE
                git_environment = os.environ.copy()
                git_environment.update(
                    {
                        "GIT_CONFIG_GLOBAL": "/dev/null",
                        "GIT_CONFIG_NOSYSTEM": "1",
                        "GIT_OPTIONAL_LOCKS": "0",
                        "GIT_TERMINAL_PROMPT": "0",
                    }
                )
                subprocess.run(
                    [
                        trusted_git,
                        "init",
                        "--quiet",
                        "--object-format=sha1",
                        str(git_root),
                    ],
                    check=True,
                    capture_output=True,
                    env=git_environment,
                    timeout=5,
                )
                subprocess.run(
                    [trusted_git, "-C", str(git_root), "add", "tracked.txt"],
                    check=True,
                    capture_output=True,
                    env=git_environment,
                    timeout=5,
                )
                subprocess.run(
                    [
                        trusted_git,
                        "-c",
                        "user.name=Required CI",
                        "-c",
                        "user.email=required-ci@example.invalid",
                        "-c",
                        "commit.gpgSign=false",
                        "-C",
                        str(git_root),
                        "commit",
                        "--quiet",
                        "-m",
                        "fixture",
                    ],
                    check=True,
                    capture_output=True,
                    env=git_environment,
                    timeout=5,
                )
                runner_path = (
                    distribution_content_root(candidate_root)
                    / "skills/waited-delivery/scripts/waited_delivery_runner.py"
                )
                candidate_source = inspect.cleandoc(
                        r'''
                        import ctypes
                        from compression import zstd
                        import errno
                        import fcntl
                        import json
                        import os
                        from pathlib import Path
                        import resource
                        import signal
                        import socket
                        import stat
                        import struct
                        import subprocess
                        import sys
                        import termios
                        import time

                        if len(sys.argv) != 10:
                            raise SystemExit(90)
                        explicit_root = Path(sys.argv[1])
                        surface_roots = tuple(Path(value) for value in sys.argv[2:6])
                        socket_path = Path(__REQUIRED_CI_SOCKET_PATH__)
                        fifo_path = Path(__REQUIRED_CI_FIFO_PATH__)
                        trusted_git = __REQUIRED_CI_GIT_PATH__
                        rw_hint_path = Path(__REQUIRED_CI_RW_HINT_PATH__)
                        sysv_key = int(sys.argv[6])
                        trusted_relative = Path(sys.argv[7])
                        host_ipc_namespace = sys.argv[8]
                        mqueue_name = sys.argv[9]
                        candidate_path = Path(__file__)
                        candidate_root = next(
                            parent for parent in candidate_path.parents
                            if parent.name == "candidate-code"
                        )
                        trusted_control = (
                            candidate_root.parent / "trusted-control" / trusted_relative
                        )

                        try:
                            candidate_path.write_bytes(b"candidate mutation\n")
                        except PermissionError:
                            write_status = "write-denied"
                        else:
                            write_status = "write-allowed"
                        try:
                            trusted_control.read_bytes()
                        except PermissionError:
                            read_status = "read-denied"
                        else:
                            read_status = "read-allowed"
                        stdlib_path = Path(os.__file__)
                        stdlib_status = (
                            "stdlib-readable"
                            if stdlib_path.read_bytes()
                            else "stdlib-empty"
                        )
                        try:
                            with stdlib_path.open("ab"):
                                pass
                        except PermissionError:
                            stdlib_write_status = "stdlib-write-denied"
                        else:
                            stdlib_write_status = "stdlib-write-allowed"
                        try:
                            with Path(sys.executable).open("ab"):
                                pass
                        except PermissionError:
                            interpreter_write_status = "interpreter-write-denied"
                        else:
                            interpreter_write_status = "interpreter-write-allowed"

                        workspace_marker = Path.cwd() / "workspace-write"
                        runtime_marker = Path(os.environ["TMPDIR"]) / "runtime-write"
                        explicit_marker = explicit_root / "allowed-write"
                        for marker, payload in (
                            (workspace_marker, "workspace\n"),
                            (runtime_marker, "runtime\n"),
                            (explicit_marker, "explicit\n"),
                        ):
                            marker.write_text(payload, encoding="utf-8")
                            if marker.read_text(encoding="utf-8") != payload:
                                raise SystemExit(91)
                        allowed_writes = {
                            "explicit": explicit_marker.read_text(encoding="utf-8"),
                            "runtime": runtime_marker.read_text(encoding="utf-8"),
                            "workspace": workspace_marker.read_text(encoding="utf-8"),
                        }

                        private_markers = {}
                        for index, root in enumerate(surface_roots):
                            root.mkdir(mode=0o700, parents=True, exist_ok=True)
                            name = (
                                "posix-shm-private-marker"
                                if index == 2
                                else "candidate-private-marker"
                            )
                            marker = root / name
                            marker.write_text("private\n", encoding="utf-8")
                            private_markers[str(marker)] = marker.read_text(
                                encoding="utf-8"
                            )

                        go_marker = explicit_root / "candidate-go"
                        ready_marker = explicit_root / "host-ipc-ready"
                        go_marker.write_text("go\n", encoding="utf-8")
                        deadline = time.monotonic() + 15.0
                        while not ready_marker.exists():
                            if time.monotonic() >= deadline:
                                raise SystemExit(92)
                            time.sleep(0.01)
                        if ready_marker.read_text(encoding="utf-8") != "ready\n":
                            raise SystemExit(92)
                        socket_metadata = socket_path.lstat()
                        fifo_metadata = fifo_path.lstat()
                        post_seal_nodes_visible = (
                            stat.S_ISSOCK(socket_metadata.st_mode)
                            and stat.S_IMODE(socket_metadata.st_mode) == 0o666
                            and stat.S_ISFIFO(fifo_metadata.st_mode)
                            and stat.S_IMODE(fifo_metadata.st_mode) == 0o666
                        )
                        if not post_seal_nodes_visible:
                            raise SystemExit(92)

                        def operation_errno(operation):
                            try:
                                operation()
                            except OSError as error:
                                return error.errno
                            return 0

                        limits_descriptor = os.open(
                            "/proc/self/limits",
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        )
                        try:
                            limits_bytes = os.read(limits_descriptor, 65537)
                        finally:
                            os.close(limits_descriptor)
                        if not limits_bytes or len(limits_bytes) > 65536:
                            raise SystemExit(92)
                        limits_lines = limits_bytes.decode("ascii").splitlines()
                        core_limit_rows = [
                            line.split()
                            for line in limits_lines
                            if line.startswith("Max core file size ")
                        ]
                        if len(core_limit_rows) != 1:
                            raise SystemExit(92)
                        core_limit_fields = core_limit_rows[0]
                        if core_limit_fields[-3:] != ["1", "1", "bytes"]:
                            raise SystemExit(92)
                        core_limits = core_limit_fields[-3:]

                        core_pattern_descriptor = os.open(
                            "/proc/sys/kernel/core_pattern",
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        )
                        try:
                            core_pattern_bytes = os.read(
                                core_pattern_descriptor, 4097
                            )
                        finally:
                            os.close(core_pattern_descriptor)
                        if not core_pattern_bytes or len(core_pattern_bytes) > 4096:
                            raise SystemExit(92)
                        core_pattern = core_pattern_bytes.decode("ascii")
                        if core_pattern.endswith("\n"):
                            core_pattern = core_pattern[:-1]
                        if (
                            not core_pattern
                            or "\n" in core_pattern
                            or "\r" in core_pattern
                            or "\x00" in core_pattern
                        ):
                            raise SystemExit(92)
                        if core_pattern.startswith("|"):
                            if not core_pattern[1:].strip():
                                raise SystemExit(92)
                        elif (
                            core_pattern in {".", ".."}
                            or "/" in core_pattern
                            or not all(
                                0x21 <= ord(character) <= 0x7E
                                for character in core_pattern
                            )
                        ):
                            raise SystemExit(92)
                        setrlimit_errno = operation_errno(
                            lambda: resource.setrlimit(
                                resource.RLIMIT_CORE, (0, 0)
                            )
                        )
                        prlimit_errno = operation_errno(
                            lambda: resource.prlimit(
                                0, resource.RLIMIT_CORE, (0, 0)
                            )
                        )

                        crash_root = explicit_root / "core-crash"
                        crash_root.mkdir(mode=0o700)
                        crash = subprocess.run(
                            [
                                sys.executable,
                                "-I",
                                "-B",
                                "-c",
                                "import ctypes; ctypes.string_at(0)",
                            ],
                            check=False,
                            cwd=crash_root,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=5,
                        )
                        core_files = []
                        for core_file in sorted(crash_root.iterdir()):
                            core_metadata = core_file.lstat()
                            if (
                                not stat.S_ISREG(core_metadata.st_mode)
                                or core_metadata.st_nlink != 1
                                or core_metadata.st_size > 1
                            ):
                                raise SystemExit(92)
                            core_files.append(
                                {"name": core_file.name, "size": core_metadata.st_size}
                            )
                        if len(core_files) > 1:
                            raise SystemExit(92)
                        core_returncode = crash.returncode

                        def pathname_socket_operation():
                            candidate_socket = socket.socket(
                                socket.AF_UNIX, socket.SOCK_STREAM
                            )
                            try:
                                candidate_socket.connect(str(socket_path))
                                candidate_socket.sendall(b"socket")
                            finally:
                                candidate_socket.close()

                        def socketpair_operation():
                            first, second = socket.socketpair()
                            try:
                                first.sendall(b"pair")
                            finally:
                                first.close()
                                second.close()

                        def fifo_operation():
                            descriptor = os.open(
                                fifo_path, os.O_WRONLY | os.O_NONBLOCK
                            )
                            try:
                                os.write(descriptor, b"fifo")
                            finally:
                                os.close(descriptor)

                        def fifo_read_operation():
                            descriptor = os.open(
                                fifo_path, os.O_RDONLY | os.O_NONBLOCK
                            )
                            try:
                                os.read(descriptor, 64)
                            finally:
                                os.close(descriptor)

                        socket_errno = operation_errno(pathname_socket_operation)
                        socketpair_errno = operation_errno(socketpair_operation)
                        fifo_errno = operation_errno(fifo_operation)
                        fifo_read_errno = operation_errno(fifo_read_operation)

                        link_source = explicit_root / "link-source"
                        link_target = explicit_root / "link-target"
                        link_source.write_text("source\n", encoding="utf-8")
                        link_errno = operation_errno(
                            lambda: os.link(link_source, link_target)
                        )

                        rw_hint_descriptor = os.open(
                            rw_hint_path,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        )
                        try:
                            rw_hint_before = fcntl.fcntl(
                                rw_hint_descriptor, 1035, bytes(8)
                            )
                            selected_hint = (
                                4 if struct.unpack("=Q", rw_hint_before)[0] == 5 else 5
                            )
                            rw_hint_set_errno = operation_errno(
                                lambda: fcntl.fcntl(
                                    rw_hint_descriptor,
                                    1036,
                                    struct.pack("=Q", selected_hint),
                                )
                            )
                        finally:
                            os.close(rw_hint_descriptor)

                        ioctl_read, ioctl_write = os.pipe()
                        try:
                            tcgets_errno = operation_errno(
                                lambda: fcntl.ioctl(
                                    ioctl_read,
                                    termios.TCGETS,
                                    bytearray(64),
                                    True,
                                )
                            )
                            arbitrary_ioctl_errno = operation_errno(
                                lambda: fcntl.ioctl(
                                    ioctl_read,
                                    0x12345678,
                                    bytearray(64),
                                    True,
                                )
                            )
                        finally:
                            os.close(ioctl_read)
                            os.close(ioctl_write)

                        libc = ctypes.CDLL(None, use_errno=True)
                        libc.syscall.restype = ctypes.c_long
                        libc.shmget.argtypes = (
                            ctypes.c_int,
                            ctypes.c_size_t,
                            ctypes.c_int,
                        )
                        libc.shmget.restype = ctypes.c_int

                        machine = os.uname().machine
                        syscall_numbers = {
                            "x86_64": (272, 435, 250, 425, 321),
                            "aarch64": (97, 435, 219, 425, 280),
                        }.get(machine)
                        if syscall_numbers is None:
                            raise SystemExit(93)

                        def syscall_errno(number, *arguments):
                            ctypes.set_errno(0)
                            result = libc.syscall(number, *arguments)
                            return 0 if result >= 0 else ctypes.get_errno()

                        (
                            unshare_number,
                            clone3_number,
                            keyctl_number,
                            io_uring_number,
                            bpf_number,
                        ) = syscall_numbers
                        unshare_errno = syscall_errno(unshare_number, 0x08000000)
                        clone3_errno = syscall_errno(clone3_number, 0, 0)
                        keyctl_errno = syscall_errno(keyctl_number, 0, 0, 0, 0, 0)
                        io_uring_errno = syscall_errno(io_uring_number, 1, 0)
                        bpf_errno = syscall_errno(bpf_number, 0x7FFFFFFF, 0, 0)

                        ctypes.set_errno(0)
                        observed_shmid = libc.shmget(sysv_key, 0, 0)
                        sysv_lookup_errno = (
                            0 if observed_shmid >= 0 else ctypes.get_errno()
                        )
                        private_shmid = -1
                        if sysv_lookup_errno == errno.ENOENT:
                            ctypes.set_errno(0)
                            private_shmid = libc.shmget(
                                sysv_key,
                                4096,
                                0o1000 | 0o2000 | 0o600,
                            )
                            if private_shmid < 0:
                                raise OSError(
                                    ctypes.get_errno(), "private shmget failed"
                                )

                        candidate_ipc_namespace = os.readlink("/proc/self/ns/ipc")
                        mqueue_created = False
                        if candidate_ipc_namespace != host_ipc_namespace:
                            libc.mq_open.argtypes = (
                                ctypes.c_char_p,
                                ctypes.c_int,
                                ctypes.c_uint,
                                ctypes.c_void_p,
                            )
                            libc.mq_open.restype = ctypes.c_int
                            libc.mq_close.argtypes = (ctypes.c_int,)
                            libc.mq_close.restype = ctypes.c_int
                            ctypes.set_errno(0)
                            queue = libc.mq_open(
                                mqueue_name.encode("ascii"),
                                os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC,
                                0o600,
                                None,
                            )
                            if queue < 0:
                                raise OSError(
                                    ctypes.get_errno(), "private mq_open failed"
                                )
                            if libc.mq_close(queue) != 0:
                                raise OSError(
                                    ctypes.get_errno(), "private mq_close failed"
                                )
                            mqueue_created = True

                        subprocess_result = subprocess.run(
                            [
                                sys.executable,
                                "-I",
                                "-B",
                                "-c",
                                "print('subprocess-ok')",
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                        if subprocess_result.stdout != "subprocess-ok\n":
                            raise SystemExit(96)
                        subprocess.run(
                            [
                                sys.executable,
                                "-I",
                                "-B",
                                "-c",
                                "raise SystemExit(0)",
                            ],
                            check=True,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        with open("/dev/null", "rb", buffering=0) as null_read:
                            if null_read.read(1) != b"":
                                raise SystemExit(96)
                        with open("/dev/null", "wb", buffering=0) as null_write:
                            if null_write.write(b"x") != 1:
                                raise SystemExit(96)

                        def devzero_operation():
                            descriptor = os.open(
                                "/dev/zero", os.O_RDONLY | os.O_CLOEXEC
                            )
                            os.close(descriptor)

                        devzero_errno = operation_errno(devzero_operation)

                        entrypoint_usage = {}
                        for name in (
                            "waited_delivery_bridge.py",
                            "waited_delivery_hook_adapter.py",
                        ):
                            entrypoint = candidate_path.with_name(name)
                            completed = subprocess.run(
                                [
                                    sys.executable,
                                    "-I",
                                    "-B",
                                    str(entrypoint),
                                    "--help",
                                ],
                                check=True,
                                capture_output=True,
                                text=True,
                                timeout=5,
                            )
                            first_line = completed.stdout.splitlines()[:1]
                            expected_prefix = f"usage: {name} "
                            if (
                                completed.stderr
                                or len(completed.stdout.encode("utf-8")) > 65536
                                or len(first_line) != 1
                                or not first_line[0].startswith(expected_prefix)
                            ):
                                raise SystemExit(96)
                            entrypoint_usage[name] = first_line[0]

                        zstd_payload = b"required-ci-zstd-round-trip\n" * 32
                        zstd_encoded = zstd.compress(zstd_payload)
                        if (
                            not zstd_encoded
                            or zstd.decompress(zstd_encoded) != zstd_payload
                        ):
                            raise SystemExit(96)

                        git_root = explicit_root / "git-fixture"
                        os.environ["GIT_OPTIONAL_LOCKS"] = "0"
                        git_prefix = [
                            trusted_git,
                            "--no-pager",
                            "-c",
                            "core.hooksPath=/dev/null",
                            "-c",
                            "core.attributesFile=/dev/null",
                            "-c",
                            "core.fsmonitor=false",
                            "-C",
                            str(git_root),
                        ]

                        def run_git(arguments):
                            completed = subprocess.run(
                                [*git_prefix, *arguments],
                                check=True,
                                capture_output=True,
                                timeout=5,
                            )
                            if (
                                len(completed.stdout) > 65536
                                or len(completed.stderr) > 65536
                                or completed.stderr
                            ):
                                raise SystemExit(96)
                            return completed.stdout

                        git_head = run_git(
                            ["rev-parse", "--verify", "HEAD^{commit}"]
                        ).decode("ascii").strip()
                        git_status = run_git(
                            ["status", "--porcelain=v1", "--untracked-files=no"]
                        ).decode("utf-8")
                        git_tree = run_git(
                            ["ls-tree", "--name-only", "HEAD"]
                        ).decode("utf-8")
                        git_archive = run_git(["archive", "--format=tar", "HEAD"])
                        git_blob = run_git(
                            ["cat-file", "blob", "HEAD:tracked.txt"]
                        ).decode("utf-8")

                        status = {}
                        with open("/proc/self/status", encoding="ascii") as status_file:
                            for line in status_file:
                                if ":" in line:
                                    key, value = line.split(":", 1)
                                    status[key] = value.strip()

                        mount_records = []
                        with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
                            for line in mountinfo:
                                fields = line.split()
                                separator = fields.index("-")
                                mount_records.append({
                                    "id": int(fields[0]),
                                    "mountpoint": fields[4],
                                    "options": fields[5].split(","),
                                    "filesystem": fields[separator + 1],
                                    "source": fields[separator + 2],
                                })
                        if any(
                            record["mountpoint"]
                            in {
                                "/tmp/required-ci-alias-probe-source",
                                "/tmp/required-ci-alias-probe-target",
                            }
                            for record in mount_records
                        ):
                            raise SystemExit(94)
                        dev_shm_mounts = [
                            record
                            for record in mount_records
                            if record["mountpoint"] == "/dev/shm"
                            and record["filesystem"] == "tmpfs"
                            and record["source"] == "required-ci-private"
                            and "rw" in record["options"]
                            and "nodev" in record["options"]
                        ]
                        if len(dev_shm_mounts) != 1:
                            raise SystemExit(94)
                        dev_shm_mount = dev_shm_mounts[0]

                        null_descriptor = os.open(
                            "/dev/null",
                            getattr(os, "O_PATH")
                            | os.O_NOFOLLOW
                            | os.O_CLOEXEC,
                        )
                        try:
                            null_metadata = os.fstat(null_descriptor)
                        finally:
                            os.close(null_descriptor)
                        devnull_mounts = [
                            record
                            for record in mount_records
                            if record["mountpoint"] == "/dev/null"
                            and "ro" in record["options"]
                            and "nodev" not in record["options"]
                        ]
                        if (
                            len(devnull_mounts) != 1
                            or not stat.S_ISCHR(null_metadata.st_mode)
                        ):
                            raise SystemExit(94)
                        devnull_mount = devnull_mounts[0]
                        devnull_device = {
                            "gid": null_metadata.st_gid,
                            "major": os.major(null_metadata.st_rdev),
                            "minor": os.minor(null_metadata.st_rdev),
                            "mode": stat.S_IMODE(null_metadata.st_mode),
                            "uid": null_metadata.st_uid,
                        }

                        sysctls = {}
                        for path in (
                            "/proc/sys/kernel/shmmax",
                            "/proc/sys/kernel/shmall",
                            "/proc/sys/kernel/shmmni",
                            "/proc/sys/kernel/msgmax",
                            "/proc/sys/kernel/msgmnb",
                            "/proc/sys/kernel/msgmni",
                            "/proc/sys/kernel/sem",
                            "/proc/sys/fs/mqueue/queues_max",
                            "/proc/sys/fs/mqueue/msg_max",
                            "/proc/sys/fs/mqueue/msgsize_max",
                            "/proc/sys/fs/mqueue/msg_default",
                            "/proc/sys/fs/mqueue/msgsize_default",
                        ):
                            sysctls[path] = " ".join(
                                Path(path).read_text(encoding="ascii").split()
                            )

                        result = {
                            "allowed_writes": allowed_writes,
                            "arbitrary_ioctl_errno": arbitrary_ioctl_errno,
                            "bpf_errno": bpf_errno,
                            "dev_shm_mount": dev_shm_mount,
                            "devnull_device": devnull_device,
                            "devnull_mount": devnull_mount,
                            "devnull_subprocess": True,
                            "devzero_errno": devzero_errno,
                            "entrypoint_usage": entrypoint_usage,
                            "fifo_errno": fifo_errno,
                            "fifo_read_errno": fifo_read_errno,
                            "ids": [
                                os.getuid(),
                                os.geteuid(),
                                os.getgid(),
                                os.getegid(),
                            ],
                            "interpreter_write_status": interpreter_write_status,
                            "ipc_namespace": candidate_ipc_namespace,
                            "io_uring_errno": io_uring_errno,
                            "git": {
                                "archive_size": len(git_archive),
                                "blob": git_blob,
                                "head": git_head,
                                "status": git_status,
                                "tree": git_tree,
                            },
                            "keyctl_errno": keyctl_errno,
                            "link_errno": link_errno,
                            "clone3_errno": clone3_errno,
                            "core_files": core_files,
                            "core_limits": core_limits,
                            "core_pattern": core_pattern,
                            "core_returncode": core_returncode,
                            "mqueue_created": mqueue_created,
                            "mqueue_visible": Path(
                                "/dev/mqueue", mqueue_name[1:]
                            ).exists(),
                            "mount_namespace": os.readlink("/proc/self/ns/mnt"),
                            "no_new_privs": status.get("NoNewPrivs"),
                            "post_seal_nodes_visible": post_seal_nodes_visible,
                            "prlimit_errno": prlimit_errno,
                            "private_markers": private_markers,
                            "read_status": read_status,
                            "rw_hint_before": rw_hint_before.hex(),
                            "rw_hint_set_errno": rw_hint_set_errno,
                            "runtime": sys.executable,
                            "seccomp": status.get("Seccomp"),
                            "seccomp_filters": status.get("Seccomp_filters"),
                            "setrlimit_errno": setrlimit_errno,
                            "socket_errno": socket_errno,
                            "socketpair_errno": socketpair_errno,
                            "stdlib_status": stdlib_status,
                            "stdlib_write_status": stdlib_write_status,
                            "subprocess": subprocess_result.stdout,
                            "sysctls": sysctls,
                            "sysv_private_created": private_shmid >= 0,
                            "sysv_lookup_errno": sysv_lookup_errno,
                            "tcgets_errno": tcgets_errno,
                            "unshare_errno": unshare_errno,
                            "version": ".".join(map(str, sys.version_info[:3])),
                            "write_status": write_status,
                            "zstd": {
                                "compressed_size": len(zstd_encoded),
                                "payload_size": len(zstd_payload),
                            },
                        }
                        print(json.dumps(result, sort_keys=True))
                        if (
                            result["ids"]
                            != [os.getuid(), os.getuid(), os.getgid(), os.getgid()]
                            or write_status != "write-denied"
                            or read_status != "read-denied"
                            or stdlib_status != "stdlib-readable"
                            or stdlib_write_status != "stdlib-write-denied"
                            or interpreter_write_status
                            != "interpreter-write-denied"
                            or set(private_markers.values()) != {"private\n"}
                            or socket_errno != errno.EACCES
                            or socketpair_errno != errno.EACCES
                            or fifo_errno != errno.EACCES
                            or fifo_read_errno != errno.EACCES
                            or link_errno != errno.EACCES
                            or unshare_errno != errno.EACCES
                            or clone3_errno != errno.ENOSYS
                            or core_limits != ["1", "1", "bytes"]
                            or core_returncode != -signal.SIGSEGV
                            or len(core_files) > 1
                            or setrlimit_errno != errno.EACCES
                            or prlimit_errno != errno.EACCES
                            or keyctl_errno != errno.EACCES
                            or io_uring_errno != errno.EACCES
                            or tcgets_errno != errno.EACCES
                            or arbitrary_ioctl_errno != errno.EACCES
                            or bpf_errno != errno.EACCES
                            or devzero_errno != errno.EACCES
                            or devnull_mount["mountpoint"] != "/dev/null"
                            or "ro" not in devnull_mount["options"]
                            or "nodev" in devnull_mount["options"]
                            or devnull_device
                            != {
                                "gid": 0,
                                "major": 1,
                                "minor": 3,
                                "mode": 0o666,
                                "uid": 0,
                            }
                            or rw_hint_set_errno != errno.EACCES
                            or sysv_lookup_errno != errno.ENOENT
                            or private_shmid < 0
                            or not mqueue_created
                            or not result["mqueue_visible"]
                            or subprocess_result.stdout != "subprocess-ok\n"
                            or git_status
                            or git_tree != "tracked.txt\n"
                            or git_blob != "tracked\n"
                            or len(git_head) != 40
                            or not git_archive
                        ):
                            raise SystemExit(95)
                        '''
                    )
                candidate_source = candidate_source.replace(
                    "__REQUIRED_CI_SOCKET_PATH__", repr(str(socket_path))
                ).replace(
                    "__REQUIRED_CI_FIFO_PATH__", repr(str(fifo_path))
                ).replace(
                    "__REQUIRED_CI_GIT_PATH__", repr(trusted_git)
                ).replace(
                    "__REQUIRED_CI_RW_HINT_PATH__", repr(str(rw_hint_path))
                )
                self.assertNotIn("/proc/self/fdinfo/", candidate_source)
                runner_path.write_text(
                    candidate_source + "\n",
                    encoding="utf-8",
                )
                candidate_sha = self.initialize_candidate_checkout(candidate_root)
                listener_process, listener_identity = start_host_ipc_helper(
                    socket_path,
                    fifo_path,
                    go_marker,
                    ready_marker,
                    mode="normal",
                )
                try:
                    with mock.patch.dict(
                        os.environ,
                        {
                            REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                            REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                        },
                        clear=False,
                    ):
                        completed = _CANDIDATE_SUPPORT.run_candidate_python(
                            runner_path,
                            arguments=(
                                str(explicit_root),
                                *(str(root) for root in surface_roots),
                                str(sysv_key),
                                trusted_control_relative,
                                host_ipc_namespace,
                                mqueue_name,
                            ),
                            writable_roots=(explicit_root,),
                            readable_roots=(rw_hint_path,),
                        )
                finally:
                    try:
                        helper_stdout, helper_stderr = stop_host_ipc_helper(
                            listener_process,
                            listener_identity,
                            expect_graceful=True,
                        )
                        (
                            listener_nodes,
                            listener_received,
                            listener_fifo_remaining,
                        ) = parse_host_ipc_helper(
                            helper_stdout,
                            (socket_path, fifo_path),
                            listener_process.pid,
                            completed_required=True,
                        )
                        if helper_stderr:
                            raise AssertionError(
                                "host IPC helper wrote unexpected stderr"
                            )
                        listener_created.append(True)
                    except BaseException as error:
                        listener_errors.append(error)

                self.assertIsNotNone(listener_process.returncode)
                self.assertNotEqual(
                    _CANDIDATE_SUPPORT._process_identity(
                        Path("/proc") / str(listener_process.pid)
                    ),
                    listener_identity,
                )
                self.assertFalse(listener_errors, listener_errors)
                self.assertEqual(listener_created, [True])
                self.assertEqual(listener_received, [])
                self.assertEqual(listener_fifo_remaining, b"host-fifo-byte")
                self.assertEqual(set(listener_nodes), {socket_path, fifo_path})
                assert completed is not None
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = json.loads(completed.stdout)
                self.assertEqual(
                    result["ids"],
                    [target_uid, target_uid, target_gid, target_gid],
                )
                self.assertEqual(result["write_status"], "write-denied")
                self.assertEqual(result["read_status"], "read-denied")
                self.assertEqual(result["stdlib_status"], "stdlib-readable")
                self.assertEqual(
                    result["stdlib_write_status"], "stdlib-write-denied"
                )
                self.assertEqual(
                    result["interpreter_write_status"],
                    "interpreter-write-denied",
                )
                self.assertEqual(
                    result["runtime"], str(Path(sys.executable).resolve(strict=True))
                )
                self.assertEqual(
                    result["version"], ".".join(map(str, sys.version_info[:3]))
                )
                self.assertEqual(result["mount_namespace"] == host_mount_namespace, False)
                self.assertEqual(result["ipc_namespace"] == host_ipc_namespace, False)
                self.assertEqual(result["no_new_privs"], "1")
                self.assertIs(result["post_seal_nodes_visible"], True)
                self.assertEqual(result["seccomp"], "2")
                self.assertGreaterEqual(int(result["seccomp_filters"]), 1)
                self.assertEqual(result["socket_errno"], errno.EACCES)
                self.assertEqual(result["socketpair_errno"], errno.EACCES)
                self.assertEqual(result["fifo_errno"], errno.EACCES)
                self.assertEqual(result["fifo_read_errno"], errno.EACCES)
                self.assertEqual(result["link_errno"], errno.EACCES)
                self.assertEqual(result["unshare_errno"], errno.EACCES)
                self.assertEqual(result["clone3_errno"], errno.ENOSYS)
                self.assertEqual(result["io_uring_errno"], errno.EACCES)
                self.assertEqual(result["keyctl_errno"], errno.EACCES)
                self.assertEqual(result["tcgets_errno"], errno.EACCES)
                self.assertEqual(
                    result["arbitrary_ioctl_errno"], errno.EACCES
                )
                self.assertEqual(result["bpf_errno"], errno.EACCES)
                self.assertEqual(result["core_limits"], ["1", "1", "bytes"])
                self.assertEqual(result["core_returncode"], -signal.SIGSEGV)
                self.assertLessEqual(len(result["core_files"]), 1)
                for core_file in result["core_files"]:
                    self.assertEqual(set(core_file), {"name", "size"})
                    self.assertIsInstance(core_file["name"], str)
                    self.assertLessEqual(core_file["size"], 1)
                core_pattern = result["core_pattern"]
                self.assertIsInstance(core_pattern, str)
                if core_pattern.startswith("|"):
                    self.assertTrue(core_pattern[1:].strip())
                else:
                    self.assertNotIn(core_pattern, {".", ".."})
                    self.assertNotIn("/", core_pattern)
                    self.assertTrue(
                        all(
                            0x21 <= ord(character) <= 0x7E
                            for character in core_pattern
                        )
                    )
                self.assertEqual(result["setrlimit_errno"], errno.EACCES)
                self.assertEqual(result["prlimit_errno"], errno.EACCES)
                actual_core_files = []
                for core_file in sorted((explicit_root / "core-crash").iterdir()):
                    core_metadata = core_file.lstat()
                    self.assertTrue(stat.S_ISREG(core_metadata.st_mode))
                    self.assertEqual(core_metadata.st_nlink, 1)
                    self.assertLessEqual(core_metadata.st_size, 1)
                    actual_core_files.append(
                        {"name": core_file.name, "size": core_metadata.st_size}
                    )
                self.assertEqual(actual_core_files, result["core_files"])
                self.assertEqual(result["devzero_errno"], errno.EACCES)
                self.assertEqual(result["rw_hint_set_errno"], errno.EACCES)
                assert rw_hint_baseline is not None
                self.assertEqual(result["rw_hint_before"], rw_hint_baseline.hex())
                self.assertEqual(result["sysv_lookup_errno"], errno.ENOENT)
                self.assertIs(result["sysv_private_created"], True)
                self.assertIs(result["mqueue_created"], True)
                self.assertIs(result["mqueue_visible"], True)
                self.assertEqual(result["subprocess"], "subprocess-ok\n")
                self.assertIs(result["devnull_subprocess"], True)
                self.assertEqual(result["devnull_mount"]["mountpoint"], "/dev/null")
                self.assertIn("ro", result["devnull_mount"]["options"])
                self.assertNotIn("nodev", result["devnull_mount"]["options"])
                self.assertEqual(
                    result["devnull_device"],
                    {
                        "gid": 0,
                        "major": 1,
                        "minor": 3,
                        "mode": 0o666,
                        "uid": 0,
                    },
                )
                self.assertEqual(
                    set(result["entrypoint_usage"]),
                    {
                        "waited_delivery_bridge.py",
                        "waited_delivery_hook_adapter.py",
                    },
                )
                for name, usage in result["entrypoint_usage"].items():
                    self.assertTrue(usage.startswith(f"usage: {name} "))
                self.assertGreater(result["zstd"]["compressed_size"], 0)
                self.assertEqual(result["zstd"]["payload_size"], 896)
                self.assertEqual(
                    result["allowed_writes"],
                    {
                        "explicit": "explicit\n",
                        "runtime": "runtime\n",
                        "workspace": "workspace\n",
                    },
                )
                self.assertEqual(result["git"]["status"], "")
                self.assertEqual(result["git"]["tree"], "tracked.txt\n")
                self.assertEqual(result["git"]["blob"], "tracked\n")
                self.assertRegex(result["git"]["head"], r"\A[0-9a-f]{40}\Z")
                self.assertGreater(result["git"]["archive_size"], 0)
                self.assertEqual(
                    result["dev_shm_mount"]["mountpoint"], "/dev/shm"
                )
                self.assertEqual(result["dev_shm_mount"]["filesystem"], "tmpfs")
                self.assertEqual(
                    result["dev_shm_mount"]["source"], "required-ci-private"
                )
                self.assertIn("rw", result["dev_shm_mount"]["options"])
                expected_sysctls = {
                    "/proc/sys/kernel/shmmax": "8388608",
                    "/proc/sys/kernel/shmall": str(
                        8388608 // os.sysconf("SC_PAGE_SIZE")
                    ),
                    "/proc/sys/kernel/shmmni": "64",
                    "/proc/sys/kernel/msgmax": "8192",
                    "/proc/sys/kernel/msgmnb": "65536",
                    "/proc/sys/kernel/msgmni": "64",
                    "/proc/sys/kernel/sem": "64 256 32 64",
                    "/proc/sys/fs/mqueue/queues_max": "64",
                    "/proc/sys/fs/mqueue/msg_max": "64",
                    "/proc/sys/fs/mqueue/msgsize_max": "8192",
                    "/proc/sys/fs/mqueue/msg_default": "16",
                    "/proc/sys/fs/mqueue/msgsize_default": "8192",
                }
                self.assertEqual(result["sysctls"], expected_sysctls)
                self.assertEqual(
                    result["private_markers"],
                    {
                        str(marker): "private\n"
                        for marker in surface_markers.values()
                    },
                )
                assert explicit_marker is not None
                self.assertEqual(
                    explicit_marker.read_text(encoding="utf-8"), "explicit\n"
                )
                for marker in surface_markers.values():
                    self.assertFalse(marker.exists())
                self.assertFalse(host_mqueue_path.exists())
                ctypes.set_errno(0)
                self.assertEqual(libc.shmget(sysv_key, 0, 0), host_shmid)
                assert rw_hint_descriptor is not None
                self.assertEqual(
                    fcntl.fcntl(rw_hint_descriptor, 1035, bytes(8)),
                    rw_hint_baseline,
                )
        finally:
            cleanup_errors: list[str] = []
            if (
                listener_process is not None
                and listener_identity is not None
                and (
                    listener_process.poll() is None
                    or _CANDIDATE_SUPPORT._process_identity(
                        Path("/proc") / str(listener_process.pid)
                    )
                    == listener_identity
                )
            ):
                try:
                    stop_host_ipc_helper(
                        listener_process,
                        listener_identity,
                        expect_graceful=True,
                    )
                except BaseException as error:
                    cleanup_errors.append(str(error))
            listener_terminal = (
                listener_process is None
                or (
                    listener_process.poll() is not None
                    and (
                        listener_identity is None
                        or _CANDIDATE_SUPPORT._process_identity(
                            Path("/proc") / str(listener_process.pid)
                        )
                        != listener_identity
                    )
                )
            )
            if not listener_terminal:
                cleanup_errors.append(
                    "host IPC listener remained active during exact cleanup"
                )
            else:
                for path, expected_kind in (
                    (socket_path, stat.S_ISSOCK),
                    (fifo_path, stat.S_ISFIFO),
                ):
                    try:
                        remove_host_ipc_node(
                            path,
                            listener_nodes.get(path),
                            expected_kind,
                        )
                    except BaseException as error:
                        cleanup_errors.append(str(error))
            if rw_hint_descriptor is not None:
                try:
                    os.close(rw_hint_descriptor)
                except OSError as error:
                    cleanup_errors.append(str(error))
                rw_hint_descriptor = None
            try:
                metadata = rw_hint_path.lstat()
                if rw_hint_identity is not None and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) != rw_hint_identity:
                    raise AssertionError("host fcntl sentinel identity changed")
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o444
                ):
                    raise AssertionError(
                        "host fcntl sentinel ownership/type changed"
                    )
                rw_hint_path.unlink()
            except FileNotFoundError:
                if rw_hint_identity is not None:
                    cleanup_errors.append("host fcntl sentinel disappeared")
            except BaseException as error:
                cleanup_errors.append(str(error))
            for root in surface_roots:
                try:
                    metadata = root.lstat()
                    if (metadata.st_dev, metadata.st_ino) != surface_identities[root]:
                        raise AssertionError(
                            f"host private-surface scaffold identity changed: {root}"
                        )
                    marker = surface_markers[root]
                    try:
                        marker_metadata = marker.lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        if (
                            not stat.S_ISREG(marker_metadata.st_mode)
                            or marker_metadata.st_nlink != 1
                        ):
                            raise AssertionError(
                                f"unsafe host private-surface residue: {marker}"
                            )
                        marker.unlink()
                    root.rmdir()
                except BaseException as error:
                    cleanup_errors.append(str(error))
            if listener_terminal:
                try:
                    metadata = ipc_root.lstat()
                    if (metadata.st_dev, metadata.st_ino) != ipc_root_identity:
                        raise AssertionError("host IPC scaffold identity changed")
                    ipc_root.rmdir()
                except BaseException as error:
                    cleanup_errors.append(str(error))
            ctypes.set_errno(0)
            mqueue_cleanup = libc.mq_unlink(mqueue_name.encode("ascii"))
            if mqueue_cleanup != 0 and ctypes.get_errno() != errno.ENOENT:
                cleanup_errors.append(
                    f"POSIX mqueue cleanup failed: errno {ctypes.get_errno()}"
                )
            if host_shmid >= 0:
                ctypes.set_errno(0)
                if libc.shmctl(host_shmid, 0, None) != 0:
                    cleanup_errors.append(
                        f"SysV sentinel cleanup failed: errno {ctypes.get_errno()}"
                    )
                else:
                    ctypes.set_errno(0)
                    if (
                        libc.shmget(sysv_key, 0, 0) != -1
                        or ctypes.get_errno() != errno.ENOENT
                    ):
                        cleanup_errors.append(
                            "SysV sentinel remained after exact cleanup"
                        )
            if cleanup_errors:
                raise AssertionError("; ".join(cleanup_errors))

    def test_candidate_cannot_use_runner_environment_for_trusted_source_aba(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            trusted_root = root / ".required-ci"
            trusted_root.mkdir()
            trusted_control = trusted_root / "control.py"
            trusted_control.write_text("VALUE = 'trusted'\n", encoding="utf-8")
            _, candidate_root = self.prepare_roots(temporary_directory)
            canary = root / "trusted-aba.executed"
            runner_path = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            runner_path.write_text(
                "import os\n"
                "from pathlib import Path\n"
                "import runpy\n\n"
                "trusted = Path(os.environ['GITHUB_WORKSPACE']) / "
                "'.required-ci/control.py'\n"
                "original = trusted.read_bytes()\n"
                "try:\n"
                f"    trusted.write_text(\"from pathlib import Path\\nPath({str(canary)!r}).write_text('executed', encoding='utf-8')\\n\", encoding='utf-8')\n"
                "    runpy.run_path(str(trusted), run_name='_required_ci_aba')\n"
                "finally:\n"
                "    trusted.write_bytes(original)\n",
                encoding="utf-8",
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            candidate_environment = os.environ.copy()
            candidate_environment["GITHUB_WORKSPACE"] = str(root)
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ):
                completed = _CANDIDATE_SUPPORT.run_candidate_python(
                    runner_path,
                    env=candidate_environment,
                )

            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(canary.exists())
            self.assertEqual(
                trusted_control.read_text(encoding="utf-8"), "VALUE = 'trusted'\n"
            )

    @staticmethod
    def _terminate_marked_process(marker: Path, lock_path: Path) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.02)
        if not marker.exists():
            return
        if sys.platform == "linux":
            realm = _CANDIDATE_SUPPORT._strict_realm()
            _CANDIDATE_SUPPORT._invoke_root_uid_cleanup(
                TRUSTED_CANDIDATE_SUPPORT_PATH,
                int(realm["uid"]),
            )
        with lock_path.open("a+b") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_candidate_setsid_descendant_cannot_outlive_success_receipt(self) -> None:
        with _CANDIDATE_SUPPORT.candidate_fixture_directory(
            "required-ci-setsid-"
        ) as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            _, candidate_root = self.prepare_roots(temporary_directory)
            marker = root / "setsid-descendant.pid"
            lock_path = root / "setsid-descendant.lock"
            token = f"required-ci-setsid-{root.name}"
            daemon = root / "setsid_daemon.py"
            daemon.write_text(
                "from pathlib import Path\n"
                "import fcntl\n"
                "import os\n"
                "import sys\n"
                "import time\n"
                "lock_file = Path(sys.argv[2]).open('a+b')\n"
                "fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)\n"
                "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='utf-8')\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            runner_path = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            runner_path.write_text(
                "import subprocess\n"
                "import sys\n"
                "import time\n"
                "subprocess.Popen(\n"
                f"    [sys.executable, '-I', {str(daemon)!r}, {str(marker)!r}, {str(lock_path)!r}, {token!r}],\n"
                "    stdin=subprocess.DEVNULL,\n"
                "    stdout=subprocess.DEVNULL,\n"
                "    stderr=subprocess.DEVNULL,\n"
                "    start_new_session=True,\n"
                ")\n"
                "time.sleep(0.2)\n",
                encoding="utf-8",
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            try:
                with mock.patch.dict(
                    os.environ,
                    {
                        REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                        REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                        REQUIRED_CI_ISOLATION_MODE_ENV: REQUIRED_CI_ISOLATION_MODE,
                    },
                    clear=False,
                ):
                    if sys.platform != "linux":
                        with self.assertRaisesRegex(
                            AssertionError,
                            "requires Linux procfs before any subprocess",
                        ):
                            _CANDIDATE_SUPPORT.run_candidate_python(
                                runner_path, writable_roots=(root,)
                            )
                        self.assertFalse(marker.exists())
                        return
                    registry_environment = (
                        os.environ.get(
                            _CANDIDATE_SUPPORT._ISOLATION_REGISTRY_ENV
                        ),
                        os.environ.get(
                            _CANDIDATE_SUPPORT._ISOLATION_REGISTRY_TOKEN_ENV
                        ),
                    )
                    if (
                        registry_environment == (None, None)
                        and _CANDIDATE_SUPPORT._STRICT_SESSION is None
                    ):
                        with self.assertRaisesRegex(
                            AssertionError,
                            "strict isolation session must be active",
                        ):
                            _CANDIDATE_SUPPORT.run_candidate_python(
                                runner_path, writable_roots=(root,)
                            )
                        self.assertFalse(marker.exists())
                        return
                    if registry_environment != (None, None):
                        self.assertNotIn(
                            None,
                            registry_environment,
                            "strict inherited registry environment must be complete",
                        )
                    completed = _CANDIDATE_SUPPORT.run_candidate_python(
                        runner_path, writable_roots=(root,)
                    )
                    self.assertEqual(completed.returncode, 0)
                    _CANDIDATE_SUPPORT.assert_candidate_isolation_quiescent()
                    with lock_path.open("a+b") as lock_file:
                        fcntl.flock(
                            lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                        )
            finally:
                self._terminate_marked_process(marker, lock_path)

    def test_strict_candidate_probe_requires_an_active_registry_session(self) -> None:
        previous_session = _CANDIDATE_SUPPORT._STRICT_SESSION
        previous_validated = _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED
        _CANDIDATE_SUPPORT._STRICT_SESSION = None
        _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = False
        try:
            with _local_nonstrict_supervisor_environment(), mock.patch.dict(
                os.environ,
                {REQUIRED_CI_ISOLATION_MODE_ENV: REQUIRED_CI_ISOLATION_MODE},
                clear=False,
            ), mock.patch.object(
                _CANDIDATE_SUPPORT, "strict_isolation_platform_preflight"
            ):
                with self.assertRaisesRegex(
                    AssertionError,
                    "strict isolation session must be active",
                ):
                    _CANDIDATE_SUPPORT._ensure_strict_backend()
        finally:
            _CANDIDATE_SUPPORT._STRICT_SESSION = previous_session
            _CANDIDATE_SUPPORT._STRICT_BACKEND_VALIDATED = previous_validated

    def test_setsid_fixture_fails_closed_without_inherited_registry(
        self,
    ) -> None:
        with _local_nonstrict_supervisor_environment(), mock.patch.object(
            sys, "platform", "linux"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "strict_isolation_platform_preflight"
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_SESSION", None
        ), mock.patch.object(
            _CANDIDATE_SUPPORT, "_STRICT_BACKEND_VALIDATED", False
        ):
            self.test_candidate_setsid_descendant_cannot_outlive_success_receipt()

    def test_candidate_stdout_cannot_form_the_trusted_parent_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )
            runner_path = (
                distribution_content_root(candidate_root)
                / "skills/waited-delivery/scripts/waited_delivery_runner.py"
            )
            runner_path.write_text(
                f"print({TRUSTED_TEST_RECEIPT_SENTINEL!r} + '{{}}')\n",
                encoding="utf-8",
            )
            candidate_sha = self.initialize_candidate_checkout(candidate_root)
            with mock.patch.dict(
                os.environ,
                {
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                },
                clear=False,
            ):
                candidate_output = _CANDIDATE_SUPPORT.run_candidate_python(
                    runner_path
                )
                candidate_binding = _CANDIDATE_SUPPORT.candidate_checkout_binding(
                    candidate_root, candidate_sha, require_clean=True
                )

            self.assertEqual(candidate_output.returncode, 0)
            self.assertEqual(
                candidate_output.stdout,
                f"{TRUSTED_TEST_RECEIPT_SENTINEL}{{}}\n",
            )
            trusted_inventory = _direct_test_inventory(trusted_root, "trusted")
            trusted_manifest = _trusted_test_source_manifest(trusted_root)
            with self.assertRaisesRegex(
                AssertionError, "did not complete under the isolated child"
            ):
                _validated_trusted_child_receipt(
                    candidate_output,
                    trusted_inventory,
                    trusted_manifest,
                    candidate_binding,
                )

    def test_candidate_subprocess_timeout_and_lingering_group_fail_closed(self) -> None:
        fixtures = {
            "timeout": (
                "import time\n"
                "time.sleep(30)\n",
                "fixed timeout",
            ),
            "lingering process group": (
                "import subprocess\n"
                "import sys\n"
                "subprocess.Popen(\n"
                "    [sys.executable, '-c', 'import time; time.sleep(30)'],\n"
                "    stdin=subprocess.DEVNULL,\n"
                "    stdout=subprocess.DEVNULL,\n"
                "    stderr=subprocess.DEVNULL,\n"
                ")\n",
                "active descendant",
            ),
        }
        for name, (source, message) in fixtures.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    _, candidate_root = self.prepare_roots(temporary_directory)
                    runner_path = (
                        distribution_content_root(candidate_root)
                        / "skills/waited-delivery/scripts/waited_delivery_runner.py"
                    )
                    runner_path.write_text(source, encoding="utf-8")
                    candidate_sha = self.initialize_candidate_checkout(candidate_root)
                    with mock.patch.dict(
                        os.environ,
                        {
                            REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                            REQUIRED_CI_CANDIDATE_SHA_ENV: candidate_sha,
                        },
                        clear=False,
                    ):
                        timeout = (
                            mock.patch.object(
                                _CANDIDATE_SUPPORT,
                                "CANDIDATE_PROCESS_TIMEOUT_SECONDS",
                                0.1,
                            )
                            if name == "timeout"
                            else contextlib.nullcontext()
                        )
                        with timeout:
                            strict = (
                                os.environ.get(REQUIRED_CI_ISOLATION_MODE_ENV)
                                == REQUIRED_CI_ISOLATION_MODE
                            )
                            if name == "lingering process group" and strict:
                                completed = (
                                    _CANDIDATE_SUPPORT.run_candidate_python(
                                        runner_path
                                    )
                                )
                                self.assertEqual(
                                    completed.returncode, 0, completed.stderr
                                )
                                _CANDIDATE_SUPPORT.assert_candidate_isolation_quiescent()
                            else:
                                with self.assertRaisesRegex(
                                    AssertionError, message
                                ):
                                    _CANDIDATE_SUPPORT.run_candidate_python(
                                        runner_path
                                    )


class RequiredCiCallerRegressionTests(unittest.TestCase):
    @staticmethod
    def write_workflow(repo_root: Path, relative_path: str, workflow: str) -> None:
        path = repo_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(workflow, encoding="utf-8")

    def test_workflow_inventory_rejects_local_and_same_repository_callers(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repo_root = Path(temporary_directory)
            fixtures = {
                ".github/workflows/required-ci.yml": (
                    "jobs:\n"
                    "  ignored-canonical-self-reference:\n"
                    "    uses: ./.github/workflows/required-ci.yml\n"
                ),
                ".github/workflows/local-caller.yml": (
                    "jobs:\n"
                    "  required:\n"
                    "    uses: ./.github/workflows/required-ci.yml\n"
                ),
                ".github/workflows/dollar-caller.yml": (
                    "jobs:\n"
                    "  required:\n"
                    "    uses: $/.github/workflows/required-ci.yml\n"
                ),
                ".github/workflows/remote-caller.yaml": (
                    "jobs:\n"
                    "  required:\n"
                    "    uses: 'Joey-Tools/codex-waited-delivery/.github/workflows/required-ci.yml@master'\n"
                ),
                ".github/workflows/near-misses.yaml": (
                    "# uses: ./.github/workflows/required-ci.yml\n"
                    "jobs:\n"
                    "  yaml-leaf:\n"
                    "    uses: ./.github/workflows/required-ci.yaml\n"
                    "  other-repository:\n"
                    "    uses: Joey-Tools/example/.github/workflows/required-ci.yml@master\n"
                    "  suffixed-path:\n"
                    "    uses: ./.github/workflows/required-ci.yml.disabled\n"
                    "  case-variant-path:\n"
                    "    uses: Joey-Tools/codex-waited-delivery/.github/workflows/Required-CI.yml@master\n"
                    "  dollar-call-with-ref:\n"
                    "    uses: $/.github/workflows/required-ci.yml@master\n"
                    "  ordinary-string:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          echo 'uses: ./.github/workflows/required-ci.yml'\n"
                    "  action-input-named-uses:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - uses: example/action@v1\n"
                    "        with:\n"
                    "          uses: ./.github/workflows/required-ci.yml\n"
                ),
            }
            for relative_path, workflow in fixtures.items():
                self.write_workflow(repo_root, relative_path, workflow)

            callers = required_ci_callers_in_repository(repo_root)

        self.assertEqual(
            [
                (path.as_posix(), line_number, uses)
                for path, line_number, uses in callers
            ],
            [
                (
                    ".github/workflows/dollar-caller.yml",
                    3,
                    "$/.github/workflows/required-ci.yml",
                ),
                (
                    ".github/workflows/local-caller.yml",
                    3,
                    "./.github/workflows/required-ci.yml",
                ),
                (
                    ".github/workflows/remote-caller.yaml",
                    3,
                    "Joey-Tools/codex-waited-delivery/.github/workflows/required-ci.yml@master",
                ),
            ],
        )

    def test_workflow_inventory_rejects_explicit_yaml_tags_on_job_uses(
        self,
    ) -> None:
        tagged_values = {
            "standard local tag": "!!str ./.github/workflows/required-ci.yml",
            "custom remote tag": (
                "!required-ci "
                "'Joey-Tools/codex-waited-delivery/.github/workflows/"
                "required-ci.yml@master'"
            ),
            "verbatim local tag": (
                "!<tag:yaml.org,2002:str> "
                '"./.github/workflows/required-ci.yml"'
            ),
            "tag and anchor combination": (
                "!!str &required ./.github/workflows/required-ci.yml"
            ),
        }

        for name, tagged_value in tagged_values.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    repo_root = Path(temporary_directory)
                    self.write_workflow(
                        repo_root,
                        ".github/workflows/tagged-caller.yml",
                        "jobs:\n"
                        "  required:\n"
                        f"    uses: {tagged_value}\n",
                    )

                    with self.assertRaisesRegex(
                        AssertionError, "explicit YAML tags"
                    ):
                        required_ci_callers_in_repository(repo_root)

    def test_yaml_tag_text_in_non_structural_content_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repo_root = Path(temporary_directory)
            self.write_workflow(
                repo_root,
                ".github/workflows/tag-text-near-misses.yml",
                "# uses: !!str ./.github/workflows/required-ci.yml\n"
                "jobs:\n"
                "  quoted-tag-text:\n"
                "    uses: '!!str ./.github/workflows/required-ci.yml'\n"
                "  ordinary-action:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: |\n"
                "          echo 'uses: !!str "
                "./.github/workflows/required-ci.yml'\n"
                "      - uses: example/action@v1\n"
                "        with:\n"
                "          uses: !!str ./.github/workflows/required-ci.yml\n",
            )

            callers = required_ci_callers_in_repository(repo_root)

        self.assertEqual(callers, [])

    def test_repository_has_no_duplicate_required_ci_caller(self) -> None:
        if DISTRIBUTION_PROFILE == "private":
            self.skipTest(
                "repository workflows are not packaged in the private skill-only "
                "distribution"
            )

        self.assertEqual(required_ci_callers_in_repository(REPO_ROOT), [])


class RequiredCiWorkflowTests(unittest.TestCase):
    def test_trusted_step_launcher_captures_deadline_before_its_only_exec(
        self,
    ) -> None:
        compile(
            TRUSTED_TEST_SUPERVISOR_LAUNCHER_SOURCE,
            "<trusted-test-supervisor-launcher>",
            "exec",
        )
        self.assertNotIn("\n", TRUSTED_TEST_SUPERVISOR_COMMAND)
        self.assertEqual(
            TRUSTED_TEST_SUPERVISOR_STEP.count(
                f"          {TRUSTED_TEST_SUPERVISOR_COMMAND}\n"
            ),
            1,
        )
        self.assertEqual(
            TRUSTED_TEST_SUPERVISOR_LAUNCHER_SOURCE.count("time.monotonic()"),
            1,
        )
        self.assertEqual(
            TRUSTED_TEST_SUPERVISOR_LAUNCHER_SOURCE.count("os.execve"), 1
        )
        self.assertLess(
            TRUSTED_TEST_SUPERVISOR_LAUNCHER_SOURCE.index("time.monotonic()"),
            TRUSTED_TEST_SUPERVISOR_LAUNCHER_SOURCE.index("os.execve"),
        )
        self.assertNotIn("time.time()", TRUSTED_TEST_SUPERVISOR_LAUNCHER_SOURCE)

    def test_workflow_and_supervisor_budgets_form_exact_nested_envelopes(
        self,
    ) -> None:
        job_timeout_seconds = int(EXPECTED_TEST_TIMEOUT_MINUTES) * 60

        self.assertEqual(TRUSTED_PRE_SUPERVISOR_TIMEOUT_MINUTES, 17)
        self.assertEqual(TRUSTED_TEST_STEP_TIMEOUT_MINUTES, 15)
        self.assertEqual(TRUSTED_JOB_RUNNER_MARGIN_MINUTES, 5)
        self.assertEqual(
            TRUSTED_PRE_SUPERVISOR_TIMEOUT_MINUTES
            + TRUSTED_TEST_STEP_TIMEOUT_MINUTES
            + TRUSTED_JOB_RUNNER_MARGIN_MINUTES,
            int(EXPECTED_TEST_TIMEOUT_MINUTES),
        )
        self.assertEqual(TRUSTED_TEST_SUITE_TIMEOUT_SECONDS, 10 * 60)
        self.assertEqual(TRUSTED_TEST_CLEANUP_RESERVE_SECONDS, 2 * 60)
        self.assertEqual(TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS, 12 * 60)
        self.assertEqual(TRUSTED_TEST_STEP_RUNNER_MARGIN_SECONDS, 3 * 60)
        self.assertEqual(TRUSTED_TEST_MINIMUM_CHILD_TIMEOUT_SECONDS, 1)
        self.assertEqual(
            TRUSTED_TEST_SUITE_TIMEOUT_SECONDS
            + TRUSTED_TEST_CLEANUP_RESERVE_SECONDS,
            TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS,
        )
        self.assertEqual(
            TRUSTED_TEST_SUPERVISOR_BUDGET_SECONDS
            + TRUSTED_TEST_STEP_RUNNER_MARGIN_SECONDS,
            TRUSTED_TEST_STEP_TIMEOUT_MINUTES * 60,
        )
        self.assertEqual(
            TRUSTED_PRE_SUPERVISOR_TIMEOUT_MINUTES * 60
            + TRUSTED_TEST_STEP_TIMEOUT_MINUTES * 60
            + TRUSTED_JOB_RUNNER_MARGIN_MINUTES * 60,
            job_timeout_seconds,
        )

    def test_module_postpones_runtime_annotation_evaluation(self) -> None:
        source = Path(__file__).resolve(strict=True).read_text(encoding="utf-8")

        self.assertTrue(
            source.startswith("from __future__ import annotations\n"),
            "workflow tests must import on Python 3.9 before builtin generic "
            "annotations are evaluated",
        )

    def test_documented_python_entrypoints_avoid_python_39_affix_apis(
        self,
    ) -> None:
        candidate_source = TRUSTED_CANDIDATE_SUPPORT_PATH.read_text(
            encoding="utf-8"
        )
        workflow_source = Path(__file__).resolve(strict=True).read_text(
            encoding="utf-8"
        )
        for description, source in (
            ("candidate support", candidate_source),
            ("workflow tests", workflow_source),
        ):
            forbidden = sorted(
                {
                    node.attr
                    for node in ast.walk(ast.parse(source))
                    if isinstance(node, ast.Attribute)
                    and node.attr in {"removeprefix", "removesuffix"}
                }
            )
            self.assertEqual(
                forbidden,
                [],
                f"{description} must avoid Python 3.9-only string-affix APIs",
            )

        if DISTRIBUTION_PROFILE == "canonical":
            documented_commands = (
                TrustedCandidateTestSupervisorRegressionTests.readme_test_commands(
                    REPO_ROOT
                )
            )
            self.assertEqual(
                documented_commands,
                [README_COMPILE_COMMAND, README_DISCOVERY_COMMAND],
            )
        candidate_sha = "a" * 40
        with mock.patch.dict(
            os.environ, {REQUIRED_CI_CANDIDATE_SHA_ENV: ""}, clear=False
        ), mock.patch.object(
            _CANDIDATE_SUPPORT,
            "_run_candidate_git",
            return_value=f"{candidate_sha}\n".encode("ascii"),
        ):
            os.environ.pop(REQUIRED_CI_CANDIDATE_SHA_ENV, None)
            observed_sha, require_clean = (
                _CANDIDATE_SUPPORT.expected_candidate_sha(REPO_ROOT)
            )
        self.assertEqual(observed_sha, candidate_sha)
        self.assertFalse(require_clean)

        candidate_binding = {"candidate_sha": candidate_sha}
        trusted_inventory = [
            {"module": "test_runtime.py", "test_ids": ["RuntimeTests.test_ok"]}
        ]
        trusted_source_sha256 = {"test_runtime.py": "b" * 64}
        expected_receipt = {
            "schema_version": TRUSTED_TEST_RECEIPT_SCHEMA_VERSION,
            "status": "completed",
            **candidate_binding,
            "trusted_inventory": trusted_inventory,
            "trusted_source_sha256": trusted_source_sha256,
            "expected_test_count": 1,
            "executed_test_count": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
        }
        completed = subprocess.CompletedProcess(
            args=["trusted-child"],
            returncode=TRUSTED_TEST_CHILD_SUCCESS_EXIT,
            stdout=(
                TRUSTED_TEST_RECEIPT_SENTINEL
                + json.dumps(
                    expected_receipt, sort_keys=True, separators=(",", ":")
                )
                + "\n"
            ),
            stderr="",
        )
        self.assertEqual(
            _validated_trusted_child_receipt(
                completed,
                trusted_inventory,
                trusted_source_sha256,
                candidate_binding,
            ),
            expected_receipt,
        )

    def test_workflow_tests_avoid_python_310_parenthesized_context_managers(
        self,
    ) -> None:
        source = Path(__file__).resolve(strict=True).read_text(encoding="utf-8")
        parenthesized_with_lines = [
            source.count("\n", 0, match.start()) + 1
            for match in re.finditer(r"(?m)^[ \t]*with[ \t]+\(", source)
        ]

        self.assertEqual(
            parenthesized_with_lines,
            [],
            "workflow tests must avoid Python 3.10-only parenthesized "
            "multiple-context-manager syntax",
        )

    def test_trusted_checkout_requires_an_explicit_candidate_root(self) -> None:
        original = os.environ.pop(REQUIRED_CI_CANDIDATE_ROOT_ENV, None)
        try:
            with self.assertRaisesRegex(AssertionError, "required in the trusted"):
                required_ci_repository_root(Path("/example/.required-ci"))
        finally:
            if original is not None:
                os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = original

    def test_candidate_root_must_be_an_absolute_real_candidate_directory(
        self,
    ) -> None:
        original = os.environ.get(REQUIRED_CI_CANDIDATE_ROOT_ENV)
        original_workspace = os.environ.get("GITHUB_WORKSPACE")
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                workspace = Path(temporary_directory).resolve(strict=True)
                os.environ["GITHUB_WORKSPACE"] = str(workspace)
                trusted_root = workspace / ".required-ci"
                candidate_root = workspace / ".candidate"
                trusted_root.mkdir()
                candidate_root.mkdir()
                for invalid in (".candidate", str(workspace / "candidate")):
                    with self.subTest(invalid=invalid):
                        os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = invalid
                        with self.assertRaises(AssertionError):
                            required_ci_repository_root(trusted_root)

                os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = str(candidate_root)
                self.assertEqual(
                    required_ci_repository_root(trusted_root),
                    candidate_root.resolve(),
                )
        finally:
            if original is None:
                os.environ.pop(REQUIRED_CI_CANDIDATE_ROOT_ENV, None)
            else:
                os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = original
            if original_workspace is None:
                os.environ.pop("GITHUB_WORKSPACE", None)
            else:
                os.environ["GITHUB_WORKSPACE"] = original_workspace

    def test_trusted_checkout_rejects_a_decoy_candidate_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            workspace = root / "workspace"
            trusted_root = workspace / ".required-ci"
            candidate_root = workspace / ".candidate"
            decoy_root = root / "decoy" / ".candidate"
            trusted_root.mkdir(parents=True)
            candidate_root.mkdir()
            decoy_root.mkdir(parents=True)
            with mock.patch.dict(
                os.environ,
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(decoy_root),
                },
                clear=False,
            ):
                with self.assertRaisesRegex(
                    AssertionError, "mandated candidate checkout"
                ):
                    required_ci_repository_root(trusted_root)

                os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = str(candidate_root)
                self.assertEqual(
                    required_ci_repository_root(trusted_root), candidate_root
                )

    def test_workspace_context_rejects_coordinated_trusted_and_candidate_decoys(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve(strict=True)
            workspace = root / "workspace"
            trusted_root = workspace / ".required-ci"
            candidate_root = workspace / ".candidate"
            decoy_workspace = root / "decoy"
            decoy_trusted_root = decoy_workspace / ".required-ci"
            decoy_candidate_root = decoy_workspace / ".candidate"
            for checkout in (
                trusted_root,
                candidate_root,
                decoy_trusted_root,
                decoy_candidate_root,
            ):
                checkout.mkdir(parents=True)

            with mock.patch.dict(
                os.environ,
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(decoy_candidate_root),
                },
                clear=False,
            ):
                with self.assertRaisesRegex(
                    AssertionError, "trusted checkout.*GitHub workspace"
                ):
                    required_ci_repository_root(decoy_trusted_root)

                os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = str(candidate_root)
                self.assertEqual(
                    required_ci_repository_root(trusted_root), candidate_root
                )

    def test_formal_entry_binds_candidate_sha_to_github_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory).resolve(strict=True)
            trusted_root = workspace / ".required-ci"
            candidate_root = workspace / ".candidate"
            trusted_root.mkdir()
            candidate_root.mkdir()
            script = str(Path(__file__).resolve(strict=True))
            formal_entries = {
                "structure": [script, TRUSTED_STRUCTURE_VALIDATOR_FLAG],
                "supervisor": [script, TRUSTED_TEST_SUPERVISOR_FLAG],
                "child": [
                    script,
                    TRUSTED_TEST_CHILD_FLAG,
                    str(trusted_root),
                ],
            }
            caller_event_shas = {
                "push": "a" * 40,
                "pull-request-merge": "b" * 40,
                "workflow-call-caller": "c" * 40,
            }
            self.assertEqual(
                TRUSTED_VALIDATOR_ENV[REQUIRED_CI_CANDIDATE_SHA_ENV],
                "${{ github.sha }}",
            )
            self.assertEqual(
                CANDIDATE_CHECKOUT_INPUTS["ref"], "${{ github.sha }}"
            )
            for entry_name, argv in formal_entries.items():
                for event_name, github_sha in caller_event_shas.items():
                    with self.subTest(entry=entry_name, event=event_name), mock.patch.object(
                        sys, "argv", argv
                    ), mock.patch.dict(
                        os.environ,
                        {
                            "GITHUB_WORKSPACE": str(workspace),
                            "GITHUB_SHA": github_sha,
                            REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                            REQUIRED_CI_CANDIDATE_SHA_ENV: github_sha,
                        },
                        clear=False,
                    ):
                        self.assertEqual(
                            required_ci_repository_root(trusted_root),
                            candidate_root,
                        )
                        os.environ[REQUIRED_CI_CANDIDATE_SHA_ENV] = "d" * 40
                        with self.assertRaisesRegex(
                            AssertionError, "candidate SHA must equal GITHUB_SHA"
                        ):
                            required_ci_repository_root(trusted_root)

            with mock.patch.object(
                sys,
                "argv",
                formal_entries["structure"],
            ), mock.patch.dict(
                os.environ,
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    REQUIRED_CI_CANDIDATE_ROOT_ENV: str(candidate_root),
                    REQUIRED_CI_CANDIDATE_SHA_ENV: "a" * 40,
                },
                clear=False,
            ):
                os.environ.pop("GITHUB_SHA", None)
                with self.assertRaisesRegex(
                    AssertionError, "requires the GitHub candidate SHA binding"
                ):
                    required_ci_repository_root(trusted_root)

    def test_private_distribution_is_identified_without_repository_files(self) -> None:
        root = Path("/example/repository")
        self.assertEqual(
            (
                root,
                root / "personal_codex",
                Path("personal_codex"),
                "private",
            ),
            distribution_contract_context(
                root / "personal_codex/skills/waited-delivery"
            ),
        )

    def test_private_workflow_harness_separates_checkout_and_content_roots(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            checkout_root = Path(temporary_directory).resolve(strict=True)
            tests_root = (
                checkout_root
                / "personal_codex/skills/waited-delivery/tests"
            )
            tests_root.mkdir(parents=True)
            workflow_test_path = tests_root / "test_required_ci_workflow.py"
            support_path = tests_root / "required_ci_candidate.py"
            shutil.copyfile(Path(__file__).resolve(strict=True), workflow_test_path)
            shutil.copyfile(TRUSTED_CANDIDATE_SUPPORT_PATH, support_path)
            workflows_root = checkout_root / ".github/workflows"
            workflows_root.mkdir(parents=True)
            (workflows_root / "caller.yml").write_text(
                "jobs:\n"
                "  required:\n"
                "    uses: ./.github/workflows/required-ci.yml\n",
                encoding="utf-8",
            )
            module_name = "_required_ci_private_workflow_harness"
            support_module_name = "required_ci_candidate"
            support_module_was_loaded = support_module_name in sys.modules
            previous_required_candidate = sys.modules.get("required_ci_candidate")
            try:
                spec = importlib.util.spec_from_file_location(
                    module_name, workflow_test_path
                )
                if spec is None or spec.loader is None:
                    raise AssertionError("private workflow harness cannot be loaded")
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                with mock.patch.dict(os.environ, {}, clear=False):
                    for key in (
                        REQUIRED_CI_CANDIDATE_ROOT_ENV,
                        REQUIRED_CI_CANDIDATE_SHA_ENV,
                        REQUIRED_CI_ISOLATION_MODE_ENV,
                    ):
                        os.environ.pop(key, None)
                    spec.loader.exec_module(module)

                inventory = module._direct_test_inventory(
                    checkout_root, "private trusted"
                )
                manifest = module._trusted_test_source_manifest(checkout_root)
                callers = module.required_ci_callers_in_repository(checkout_root)
            finally:
                sys.modules.pop(module_name, None)
                if support_module_was_loaded:
                    sys.modules[support_module_name] = previous_required_candidate
                else:
                    sys.modules.pop(support_module_name, None)

            self.assertIs(
                sys.modules.get("required_ci_candidate"),
                previous_required_candidate,
            )

        self.assertTrue(inventory)
        self.assertIn(
            "personal_codex/skills/waited-delivery/tests/required_ci_candidate.py",
            manifest,
        )
        self.assertEqual(callers[0][0], Path(".github/workflows/caller.yml"))

    def test_entry_wraps_only_the_required_linux_helper_tests(self) -> None:
        if DISTRIBUTION_PROFILE == "private":
            self.skipTest(
                "repository-only required CI contract is not packaged in the "
                "private skill-only distribution"
            )
        checkouts = validate_required_ci_repository(REPO_ROOT)
        self.assertEqual(len(checkouts), 2)

    def test_invalid_plain_workflow_names_fail_closed(self) -> None:
        if DISTRIBUTION_PROFILE == "private":
            self.skipTest(
                "repository-only required CI contract is not packaged in the "
                "private skill-only distribution"
            )
        workflow_path = REPO_ROOT / ".github/workflows/required-ci.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        invalid_names = {
            "nested mapping separator": "name: Required CI: disabled\n",
            "missing separator whitespace": "name:Required CI\n",
        }

        for name, invalid_name in invalid_names.items():
            with self.subTest(name=name):
                invalid_workflow = workflow.replace(
                    "name: Required CI\n", invalid_name, 1
                )
                with self.assertRaises(AssertionError):
                    validate_required_workflow(invalid_workflow)


if __name__ == "__main__":
    if sys.argv[1:] == [TRUSTED_STRUCTURE_VALIDATOR_FLAG]:
        raise SystemExit(_trusted_structure_validator_main())
    if sys.argv[1:] == [TRUSTED_TEST_SUPERVISOR_FLAG]:
        raise SystemExit(_trusted_test_supervisor_main())
    if len(sys.argv) == 3 and sys.argv[1] == TRUSTED_TEST_CHILD_FLAG:
        raise SystemExit(_trusted_test_child_main(sys.argv[2]))
    if sys.argv[1:] == [CI_STRICT_RUNTIME_LIVE_FLAG]:
        raise SystemExit(_strict_runtime_live_main())
    unittest.main()
