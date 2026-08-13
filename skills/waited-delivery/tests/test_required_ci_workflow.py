from pathlib import Path
import unittest


def distribution_contract_context(skill_root: Path) -> tuple[Path, str]:
    if skill_root.parts[-3:] == ("personal_codex", "skills", "waited-delivery"):
        return skill_root.parents[2], "private"
    if skill_root.parts[-2:] == ("skills", "waited-delivery"):
        return skill_root.parents[1], "canonical"
    raise AssertionError(f"unsupported waited-delivery skill layout: {skill_root}")


SKILL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT, DISTRIBUTION_PROFILE = distribution_contract_context(SKILL_ROOT)


def top_level_job_ids(workflow: str) -> list[str]:
    in_jobs = False
    job_ids: list[str] = []
    for line in workflow.splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if in_jobs and line and not line.startswith(" "):
            break
        if (
            in_jobs
            and line.startswith("  ")
            and not line.startswith("    ")
            and line.endswith(":")
        ):
            job_ids.append(line[2:-1])
    return job_ids


def checkout_steps(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    steps: list[str] = []
    for index, line in enumerate(lines):
        if not line.lstrip().startswith("- uses: actions/checkout@"):
            continue
        indent = len(line) - len(line.lstrip())
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and (
                candidate_indent < indent
                or (
                    candidate_indent == indent
                    and candidate.lstrip().startswith("- ")
                )
            ):
                break
            end += 1
        steps.append("\n".join(lines[index:end]))
    return steps


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
            "on:\n"
            "  workflow_call:\n"
            "\n"
            "permissions:\n",
            workflow,
        )
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertEqual(top_level_job_ids(workflow), ["test"])
        self.assertIn("runs-on: ubuntu-latest", workflow)
        checkout = checkout_steps(workflow)
        self.assertGreater(len(checkout), 0)
        self.assertEqual(
            workflow.count("repository: ${{ github.repository }}"), len(checkout)
        )
        self.assertEqual(workflow.count("ref: ${{ github.sha }}"), len(checkout))
        self.assertEqual(workflow.count("persist-credentials: false"), len(checkout))
        for step in checkout:
            self.assertIn("repository: ${{ github.repository }}", step)
            self.assertIn("ref: ${{ github.sha }}", step)
            self.assertEqual(step.count("persist-credentials: false"), 1)
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
            "contents: write",
            "id-" + "token: write",
            "statuses: write",
        ):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
