import ast
import contextlib
import io
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


def distribution_contract_context(skill_root: Path) -> tuple[Path, str]:
    if skill_root.parts[-3:] == ("personal_codex", "skills", "waited-delivery"):
        return skill_root.parents[2], "private"
    if skill_root.parts[-2:] == ("skills", "waited-delivery"):
        return skill_root.parents[1], "canonical"
    raise AssertionError(f"unsupported waited-delivery skill layout: {skill_root}")


SKILL_ROOT = Path(__file__).resolve().parents[1]
TRUSTED_REPO_ROOT, DISTRIBUTION_PROFILE = distribution_contract_context(SKILL_ROOT)
EXPECTED_REPOSITORY = "Joey-Tools/codex-waited-delivery"
EXPECTED_TEST_TIMEOUT_MINUTES = "10"
REQUIRED_CI_CANDIDATE_ROOT_ENV = "REQUIRED_CI_CANDIDATE_ROOT"
CANDIDATE_TESTS_RELATIVE_PATH = Path("skills/waited-delivery/tests")
TRUSTED_TEST_SUITE_TIMEOUT_SECONDS = 180
TRUSTED_TEST_CHILD_SUCCESS_EXIT = 73
TRUSTED_TEST_RECEIPT_SCHEMA_VERSION = 1
TRUSTED_TEST_RECEIPT_SENTINEL = "REQUIRED_CI_TRUSTED_TESTS_COMPLETED:"
TRUSTED_TEST_SUPERVISOR_FLAG = "--run-trusted-tests"
TRUSTED_TEST_CHILD_FLAG = "--run-trusted-test-suite"
REPOSITORY_GUARD = (
    "      - name: Reject unexpected repository\n"
    f"        if: ${{{{ github.repository != '{EXPECTED_REPOSITORY}' }}}}\n"
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
    REQUIRED_CI_CANDIDATE_ROOT_ENV: "${{ github.workspace }}/.candidate"
}
CANDIDATE_COMPILE_COMMAND = (
    'python3 -I -m py_compile "$GITHUB_WORKSPACE"/'
    ".candidate/skills/waited-delivery/scripts/*.py"
)
TRUSTED_VALIDATOR_COMMAND = (
    'python3 -I "$GITHUB_WORKSPACE/.required-ci/skills/waited-delivery/tests/'
    'test_required_ci_workflow.py"'
)
TRUSTED_TEST_SUPERVISOR_COMMAND = (
    'python3 -I "$GITHUB_WORKSPACE/.required-ci/skills/waited-delivery/tests/'
    f'test_required_ci_workflow.py" {TRUSTED_TEST_SUPERVISOR_FLAG}'
)
CANDIDATE_CHECKOUT_STEP = (
    "      - name: Check out candidate\n"
    "        uses: actions/checkout@v4\n"
    "        with:\n"
    f"          repository: {EXPECTED_REPOSITORY}\n"
    "          ref: ${{ github.sha }}\n"
    "          path: .candidate\n"
    "          persist-credentials: false\n"
)
TRUSTED_CHECKOUT_STEP = (
    "      - name: Check out trusted Required CI source\n"
    "        uses: actions/checkout@v4\n"
    "        with:\n"
    "          repository: ${{ job.workflow_repository }}\n"
    "          ref: ${{ job.workflow_sha }}\n"
    "          path: .required-ci\n"
    "          persist-credentials: false\n"
)
PYTHON_SETUP_STEP = (
    "      - uses: actions/setup-python@v5\n"
    "        with:\n"
    '          python-version: "3.x"\n'
)
TRUSTED_TEST_SUPERVISOR_STEP = (
    "      - name: Run trusted Required CI tests\n"
    "        env:\n"
    "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
    "        run: |\n"
    f"          {TRUSTED_TEST_SUPERVISOR_COMMAND}\n"
)
REQUIRED_EXECUTION_STEPS = (
    "      - name: Compile candidate Python helpers\n"
    "        run: |\n"
    f"          {CANDIDATE_COMPILE_COMMAND}\n"
    "      - name: Validate Required CI structure\n"
    "        env:\n"
    "          REQUIRED_CI_CANDIDATE_ROOT: ${{ github.workspace }}/.candidate\n"
    "        run: |\n"
    f"          {TRUSTED_VALIDATOR_COMMAND}\n"
    f"{TRUSTED_TEST_SUPERVISOR_STEP}"
)


def required_ci_repository_root(trusted_repo_root: Path) -> Path:
    candidate_root_value = os.environ.get(REQUIRED_CI_CANDIDATE_ROOT_ENV)
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
    if not resolved.is_dir():
        raise AssertionError(
            f"{REQUIRED_CI_CANDIDATE_ROOT_ENV} must select a directory"
        )
    return resolved


REPO_ROOT = required_ci_repository_root(TRUSTED_REPO_ROOT)


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

    tests_root = resolved_repo_root / CANDIDATE_TESTS_RELATIVE_PATH
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


def _trusted_test_suite_receipt(
    trusted_repo_root: Path, candidate_root: Path
) -> dict[str, object]:
    trusted_inventory = _direct_test_inventory(trusted_repo_root, "trusted")
    expected_test_ids = _inventory_test_ids(trusted_inventory)
    trusted_tests_root = (
        trusted_repo_root.resolve(strict=True) / CANDIDATE_TESTS_RELATIVE_PATH
    )
    _assert_candidate_absent_from_sys_path(candidate_root)

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
    return {
        "schema_version": TRUSTED_TEST_RECEIPT_SCHEMA_VERSION,
        "status": "completed",
        "trusted_inventory": trusted_inventory,
        "expected_test_count": len(expected_test_ids),
        "executed_test_count": result.testsRun,
        **result_counts,
    }


def _bounded_failure_text(value: str, limit: int = 2000) -> str:
    normalized = value.replace("\x00", "\\0")
    if len(normalized) <= limit:
        return normalized
    return normalized[:limit] + "...[truncated]"


def _validated_trusted_child_receipt(
    completed: subprocess.CompletedProcess[str], trusted_inventory: list[dict[str, object]]
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
        "trusted_inventory": trusted_inventory,
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
        receipt = json.loads(completed.stdout.removeprefix(TRUSTED_TEST_RECEIPT_SENTINEL))
    except (json.JSONDecodeError, TypeError) as error:
        raise AssertionError(
            "trusted Required CI child returned a malformed completion receipt"
        ) from error
    if receipt != expected_receipt:
        raise AssertionError(
            "trusted Required CI child completion receipt is not exact"
        )
    return receipt


def supervise_trusted_required_ci_tests(
    trusted_repo_root: Path, candidate_root: Path
) -> dict[str, object]:
    _assert_candidate_absent_from_sys_path(candidate_root)
    trusted_inventory = _direct_test_inventory(trusted_repo_root, "trusted")
    candidate_static_inventory = _direct_test_inventory(candidate_root, "candidate")
    _require_expected_test_inventory(trusted_inventory, candidate_static_inventory)

    child_environment = os.environ.copy()
    child_environment.pop("PYTHONHOME", None)
    child_environment.pop("PYTHONPATH", None)
    child_environment[REQUIRED_CI_CANDIDATE_ROOT_ENV] = str(
        candidate_root.resolve(strict=True)
    )
    trusted_supervisor = Path(__file__).resolve(strict=True)
    try:
        trusted_supervisor_source = trusted_supervisor.read_bytes()
    except OSError as error:
        raise AssertionError("trusted candidate test supervisor cannot be read") from error
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(trusted_supervisor),
                TRUSTED_TEST_CHILD_FLAG,
                str(trusted_repo_root.resolve(strict=True)),
            ],
            cwd=trusted_repo_root.resolve(strict=True),
            env=child_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=TRUSTED_TEST_SUITE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise AssertionError(
            "trusted Required CI tests did not complete before the fixed timeout"
        ) from error
    receipt = _validated_trusted_child_receipt(completed, trusted_inventory)

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
    if (
        _direct_test_inventory(candidate_root, "candidate")
        != candidate_static_inventory
    ):
        raise AssertionError("candidate static test inventory changed during execution")
    return receipt


def _trusted_test_child_main(trusted_repo_root_value: str) -> int:
    try:
        trusted_repo_root = Path(trusted_repo_root_value)
        if (
            not trusted_repo_root.is_absolute()
            or trusted_repo_root.name != ".required-ci"
        ):
            raise AssertionError("trusted test root must be an absolute .required-ci path")
        receipt = _trusted_test_suite_receipt(trusted_repo_root, REPO_ROOT)
    except BaseException as error:
        message = _bounded_failure_text(f"{type(error).__name__}: {error}")
        print(f"trusted Required CI child failed: {message}", file=sys.stderr)
        return 1
    canonical_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    print(f"{TRUSTED_TEST_RECEIPT_SENTINEL}{canonical_receipt}")
    return TRUSTED_TEST_CHILD_SUCCESS_EXIT


def _trusted_test_supervisor_main() -> int:
    try:
        receipt = supervise_trusted_required_ci_tests(TRUSTED_REPO_ROOT, REPO_ROOT)
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


_REQUIRED_CI_LOCAL_CALL = "./.github/workflows/required-ci.yml"
_REQUIRED_CI_REMOTE_REPOSITORY_PREFIX = f"{EXPECTED_REPOSITORY}/"
_REQUIRED_CI_REMOTE_WORKFLOW_PREFIX = ".github/workflows/required-ci.yml@"


def _is_required_ci_call_target(uses: str) -> bool:
    if uses == _REQUIRED_CI_LOCAL_CALL:
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
    callers: list[tuple[Path, int, str]] = []
    for workflow_path in workflow_paths:
        if workflow_path == canonical_leaf or not workflow_path.is_file():
            continue
        workflow = workflow_path.read_text(encoding="utf-8")
        for line_number, uses in _workflow_job_uses_values(workflow):
            if _is_required_ci_call_target(uses):
                callers.append(
                    (workflow_path.relative_to(repo_root), line_number, uses)
                )
    return callers


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
    expected_body = [" " * (header_indent + 2) + expected_command]
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
    if len(steps) != 7:
        raise AssertionError("test job must contain exactly the seven required steps")

    guard = _require_step_properties(
        steps[0], step_indent, ["name", "if", "run"], "repository guard"
    )
    _require_scalar(guard["name"], "Reject unexpected repository", "guard name")
    _require_scalar(
        guard["if"],
        f"${{{{ github.repository != '{EXPECTED_REPOSITORY}' }}}}",
        "guard condition",
    )
    _require_scalar(guard["run"], "exit 1", "guard command")

    candidate_checkout = _require_step_properties(
        steps[1], step_indent, ["name", "uses", "with"], "candidate checkout step"
    )
    _require_scalar(
        candidate_checkout["name"], "Check out candidate", "candidate checkout name"
    )
    _require_scalar(
        candidate_checkout["uses"], "actions/checkout@v4", "candidate checkout action"
    )
    _require_exact_mapping(
        candidate_checkout["with"],
        CANDIDATE_CHECKOUT_INPUTS,
        "candidate checkout inputs",
    )

    trusted_checkout = _require_step_properties(
        steps[2], step_indent, ["name", "uses", "with"], "trusted checkout step"
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
    _require_exact_mapping(
        trusted_checkout["with"],
        TRUSTED_CHECKOUT_INPUTS,
        "trusted checkout inputs",
    )

    setup = _require_step_properties(
        steps[3], step_indent, ["uses", "with"], "Python setup step"
    )
    _require_scalar(setup["uses"], "actions/setup-python@v5", "Python setup action")
    _require_exact_mapping(
        setup["with"], {"python-version": "3.x"}, "Python setup inputs"
    )

    compile_step = _require_step_properties(
        steps[4], step_indent, ["name", "run"], "compile step"
    )
    _require_scalar(
        compile_step["name"],
        "Compile candidate Python helpers",
        "compile step name",
    )
    _require_run_block(
        lines,
        compile_step["run"],
        CANDIDATE_COMPILE_COMMAND,
        "compile step command",
    )

    validator_step = _require_step_properties(
        steps[5], step_indent, ["name", "env", "run"], "validator step"
    )
    _require_scalar(
        validator_step["name"],
        "Validate Required CI structure",
        "validator step name",
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
        steps[6], step_indent, ["name", "env", "run"], "test step"
    )
    _require_scalar(
        test_step["name"],
        "Run trusted Required CI tests",
        "test step name",
    )
    _require_exact_mapping(
        test_step["env"], TRUSTED_VALIDATOR_ENV, "test supervisor environment"
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


def validate_required_ci_repository(repo_root: Path) -> list[str]:
    workflow_path = repo_root / ".github/workflows/required-ci.yml"
    if workflow_path.is_symlink() or not workflow_path.is_file():
        raise AssertionError(
            "candidate repository must contain an ordinary required-ci.yml"
        )
    try:
        workflow = workflow_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise AssertionError("candidate required-ci.yml cannot be read") from error
    checkouts = validate_required_workflow(workflow)
    callers = required_ci_callers_in_repository(repo_root)
    if callers:
        raise AssertionError(
            "candidate repository must not contain another Required CI caller"
        )
    return checkouts


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
            "    timeout-minutes: 10\n"
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
            "quoted integer": '"10"',
            "expression": "${{ vars.REQUIRED_CI_TIMEOUT_MINUTES }}",
            "over GitHub maximum": "361",
            "different positive integer": "11",
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
            'tests/test_required_ci_workflow.py"'
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
                "python3 -I skills/waited-delivery/tests/test_required_ci_workflow.py",
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
            "functional supervisor changes candidate cwd": workflow.replace(
                TRUSTED_TEST_SUPERVISOR_COMMAND,
                "cd \"$GITHUB_WORKSPACE/.candidate\" && "
                "python3 -I ../.required-ci/skills/waited-delivery/tests/"
                "test_required_ci_workflow.py --run-trusted-tests",
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
                    "$GITHUB_WORKSPACE/.required-ci/",
                    "$GITHUB_WORKSPACE/.candidate/",
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
                    " --run-trusted-tests", "", 1
                ),
                1,
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
            'tests/test_required_ci_workflow.py"'
        )
        insecure_workflow = secure_workflow.replace(
            TRUSTED_VALIDATOR_COMMAND, candidate_validator_command, 1
        )
        self.assertNotEqual(insecure_workflow, secure_workflow)

        for state in ("deleted", "replaced"):
            with self.subTest(state=state):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    candidate_root = Path(temporary_directory) / ".candidate"
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
                    if state == "replaced":
                        candidate_validator.parent.mkdir(parents=True)
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
    def write_test_module(repo_root: Path, name: str, content: str) -> None:
        path = repo_root / "skills/waited-delivery/tests" / name
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

    def prepare_roots(self, temporary_directory: str) -> tuple[Path, Path]:
        root = Path(temporary_directory).resolve(strict=True)
        trusted_root = root / ".required-ci"
        candidate_root = root / ".candidate"
        self.write_test_module(
            trusted_root,
            "test_required.py",
            self.required_module(),
        )
        (candidate_root / "skills/waited-delivery/tests").mkdir(parents=True)
        return trusted_root, candidate_root

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

            receipt = supervise_trusted_required_ci_tests(
                trusted_root, candidate_root
            )

        self.assertEqual(
            set(receipt),
            {
                "schema_version",
                "status",
                "trusted_inventory",
                "expected_test_count",
                "executed_test_count",
                "failures",
                "errors",
                "skipped",
                "expected_failures",
                "unexpected_successes",
            },
        )
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(receipt["status"], "completed")
        self.assertEqual(receipt["expected_test_count"], 2)
        self.assertEqual(receipt["executed_test_count"], 2)

    def test_supervisor_child_argv_and_environment_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            self.write_test_module(
                candidate_root, "test_required.py", self.required_module()
            )
            actual_run = subprocess.run
            captured_calls: list[tuple[list[str], dict[str, object]]] = []

            def recording_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                captured_calls.append((command, kwargs.copy()))
                return actual_run(command, **kwargs)

            with mock.patch.object(subprocess, "run", side_effect=recording_run):
                receipt = supervise_trusted_required_ci_tests(
                    trusted_root, candidate_root
                )

        self.assertEqual(receipt["status"], "completed")
        self.assertEqual(len(captured_calls), 1)
        command, options = captured_calls[0]
        self.assertEqual(
            command,
            [
                sys.executable,
                "-I",
                str(Path(__file__).resolve(strict=True)),
                TRUSTED_TEST_CHILD_FLAG,
                str(trusted_root),
            ],
        )
        self.assertEqual(options["cwd"], trusted_root)
        child_environment = options["env"]
        self.assertIsInstance(child_environment, dict)
        self.assertEqual(
            child_environment[REQUIRED_CI_CANDIDATE_ROOT_ENV], str(candidate_root)
        )
        self.assertNotIn("PYTHONHOME", child_environment)
        self.assertNotIn("PYTHONPATH", child_environment)

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

            receipt = supervise_trusted_required_ci_tests(
                trusted_root, candidate_root
            )

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

                    receipt = supervise_trusted_required_ci_tests(
                        trusted_root, candidate_root
                    )

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

            receipt = supervise_trusted_required_ci_tests(trusted_root, candidate_root)

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

            receipt = supervise_trusted_required_ci_tests(trusted_root, candidate_root)

            self.assertEqual(receipt["status"], "completed")
            self.assertFalse(canary.exists())

    def test_supervisor_rejects_an_existing_empty_test_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            trusted_root, candidate_root = self.prepare_roots(temporary_directory)
            tests_root = candidate_root / "skills/waited-delivery/tests"
            (tests_root / "README.txt").write_text("no tests\n", encoding="utf-8")

            with self.assertRaisesRegex(AssertionError, "expected test inventory"):
                supervise_trusted_required_ci_tests(trusted_root, candidate_root)

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

            receipt = supervise_trusted_required_ci_tests(trusted_root, candidate_root)

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
                supervise_trusted_required_ci_tests(trusted_root, candidate_root)

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

            receipt = supervise_trusted_required_ci_tests(trusted_root, candidate_root)

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
                        supervise_trusted_required_ci_tests(
                            trusted_root, candidate_root
                        )

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
                        supervise_trusted_required_ci_tests(
                            trusted_root, candidate_root
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
        try:
            for invalid in (".candidate", "/example/candidate"):
                with self.subTest(invalid=invalid):
                    os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = invalid
                    with self.assertRaises(AssertionError):
                        required_ci_repository_root(Path("/example/.required-ci"))

            with tempfile.TemporaryDirectory() as temporary_directory:
                candidate_root = Path(temporary_directory) / ".candidate"
                candidate_root.mkdir()
                os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = str(candidate_root)
                self.assertEqual(
                    required_ci_repository_root(Path("/example/.required-ci")),
                    candidate_root.resolve(),
                )
        finally:
            if original is None:
                os.environ.pop(REQUIRED_CI_CANDIDATE_ROOT_ENV, None)
            else:
                os.environ[REQUIRED_CI_CANDIDATE_ROOT_ENV] = original

    def test_private_distribution_is_identified_without_repository_files(self) -> None:
        root = Path("/example/repository")
        self.assertEqual(
            (root, "private"),
            distribution_contract_context(
                root / "personal_codex/skills/waited-delivery"
            ),
        )

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
    if sys.argv[1:] == [TRUSTED_TEST_SUPERVISOR_FLAG]:
        raise SystemExit(_trusted_test_supervisor_main())
    if len(sys.argv) == 3 and sys.argv[1] == TRUSTED_TEST_CHILD_FLAG:
        raise SystemExit(_trusted_test_child_main(sys.argv[2]))
    unittest.main()
