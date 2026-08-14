from pathlib import Path
import json
import re
import unittest


def distribution_contract_context(skill_root: Path) -> tuple[Path, str]:
    if skill_root.parts[-3:] == ("personal_codex", "skills", "waited-delivery"):
        return skill_root.parents[2], "private"
    if skill_root.parts[-2:] == ("skills", "waited-delivery"):
        return skill_root.parents[1], "canonical"
    raise AssertionError(f"unsupported waited-delivery skill layout: {skill_root}")


SKILL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT, DISTRIBUTION_PROFILE = distribution_contract_context(SKILL_ROOT)
EXPECTED_REPOSITORY = "Joey-Tools/codex-waited-delivery"
REPOSITORY_GUARD = (
    "      - name: Reject unexpected repository\n"
    f"        if: ${{{{ github.repository != '{EXPECTED_REPOSITORY}' }}}}\n"
    "        run: exit 1"
)


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
            key = fragment[:index].strip()
            if not _PLAIN_KEY.fullmatch(key):
                raise AssertionError(
                    f"unsupported or malformed mapping key on line {line_number}"
                )
            return key, fragment[index + 1 :].strip()
    if flow_stack:
        raise AssertionError(f"unclosed flow shape on line {line_number}")
    raise AssertionError(f"expected a mapping entry on line {line_number}")


def _plain_scalar(value: str, line_number: int) -> str:
    if not value:
        raise AssertionError(f"missing scalar value on line {line_number}")
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


_EXPECTED_CHECKOUT_INPUTS = {
    "repository": EXPECTED_REPOSITORY,
    "ref": "${{ github.sha }}",
    "persist-credentials": "false",
}


def _validate_checkout_inputs(
    entries: list[tuple[int, int, str]], step_indent: int
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
    if actual != _EXPECTED_CHECKOUT_INPUTS:
        raise AssertionError(
            "checkout inputs must be exactly repository, ref, and "
            "persist-credentials with the required values"
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
                _validate_checkout_inputs(step_entries, step_indent)
                if step_number == 0:
                    raise AssertionError(
                        "checkout step is missing its repository guard"
                    )
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
    _, jobs = _workflow_job_blocks(workflow)
    if [job_id for job_id, _ in jobs] != ["test"]:
        raise AssertionError("workflow must contain exactly the test job")
    _validate_permissions(workflow, jobs)
    checkouts = checkout_steps(workflow, validate_contract=True)
    if not checkouts:
        raise AssertionError("workflow must contain a checkout step")
    return checkouts


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
            "permissions:\n"
            "  contents: read\n"
            "# jobs:\n"
            "#   release:\n"
            "jobs:\n"
            "  # release: this remains a comment\n"
            "  test: # the only real job\n"
            "    steps:\n"
            "      - name: Ordinary text\n"
            "        run: |\n"
            "          echo 'release: # not a job'\n"
            "          echo 'permissions: write-all'\n"
            f"{REPOSITORY_GUARD}\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            f"          repository: {EXPECTED_REPOSITORY}\n"
            "          ref: ${{ github.sha }}\n"
            "          persist-credentials: false\n"
        )

        self.assertEqual(top_level_job_ids(workflow), ["test"])
        self.assertEqual(len(validate_required_workflow(workflow)), 1)


class RequiredCiWorkflowTests(unittest.TestCase):
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
        workflow_path = REPO_ROOT / ".github/workflows/required-ci.yml"
        workflow = workflow_path.read_text(encoding="utf-8")

        self.assertIn(
            "on:\n  workflow_call:\n\npermissions:\n",
            workflow,
        )
        self.assertIn("runs-on: ubuntu-latest", workflow)
        checkout = validate_required_workflow(workflow)
        self.assertGreater(len(checkout), 0)
        self.assertNotIn("repository: ${{ github.repository }}", workflow)
        self.assertNotIn("inputs.repository", workflow)
        self.assertNotIn("inputs.ref", workflow)
        self.assertIn(
            "python3 -m py_compile skills/waited-delivery/scripts/*.py",
            workflow,
        )
        self.assertIn(
            "python3 -m unittest discover -s skills/waited-delivery/tests",
            workflow,
        )
        for forbidden in (
            "pull_request:",
            "pull_request_target:",
            "push:",
            "macos-latest",
            "secrets.",
        ):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
