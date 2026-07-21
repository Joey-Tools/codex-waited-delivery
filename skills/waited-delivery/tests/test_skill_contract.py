from __future__ import annotations

import pathlib
import unittest


SKILL_PATH = pathlib.Path(__file__).resolve().parents[1] / "SKILL.md"
README_PATH = pathlib.Path(__file__).resolve().parents[3] / "README.md"
DEPENDENCIES_PATH = (
    pathlib.Path(__file__).resolve().parents[3] / "docs" / "DEPENDENCIES.md"
)


class SkillContractTest(unittest.TestCase):
    def test_uses_unified_single_reviewer_contract(self) -> None:
        skill = SKILL_PATH.read_text(encoding="utf-8")

        self.assertIn("$review-orchestration-playbook", skill)
        self.assertIn(
            "directly launches exactly one fresh/clear-context Codex `reviewer` agent",
            skill,
        )
        self.assertIn("The parent owns the named internal single review", skill)
        self.assertIn(
            "must not mark `internal_review` or `external_review` as passed", skill
        )
        self.assertIn(
            "dirty or untracked implementation state cannot count as reviewed", skill
        )
        self.assertIn("rejects a review `passed` result", skill)
        self.assertIn("before the child is terminal", skill)
        self.assertIn("terminal reviewer evidence is missing", skill)
        self.assertIn("`close-open-phases` cannot mark review phases passed", skill)
        self.assertIn("exact nonblank id", skill)
        self.assertIn("every invocation revalidates any passed review", skill)
        self.assertIn("any invocation that sees a terminal child", skill)
        self.assertIn("requires the `internal_review` phase", skill)
        self.assertIn("before review `passed` or terminal finalization", skill)
        self.assertIn("clean/frozen workspace", skill)
        self.assertIn("applicable `AGENTS.md` and repository guidance", skill)
        self.assertIn(
            "discover the diff and necessary nearby context itself with tools", skill
        )
        self.assertIn("Do not precompute or paste the full diff", skill)
        self.assertIn("low-level compatibility/diagnostic tooling only", skill)
        self.assertIn(
            "cannot start, satisfy, substitute for, or count as the named internal "
            "single review",
            skill,
        )
        self.assertIn("lifecycle does not add a reviewer", skill)
        self.assertNotIn("transport/runtime mechanism for that same", skill)
        for retired_entrypoint in (
            "$pr-readiness-review-workflow",
            "$external-review-playbook",
            "`codex-review`",
            "`codex-readonly`",
            "`codex-parallel`",
        ):
            with self.subTest(retired_entrypoint=retired_entrypoint):
                self.assertNotIn(retired_entrypoint, skill)

        for retired_semantics in (
            "Internal review should prefer the pinned Codex lane",
            "use the retained frozen workspace with the clean-context `reviewer` agent",
            "retained frozen workspace",
            "clean-context fallback",
            "explicit weaker fallback",
        ):
            with self.subTest(retired_semantics=retired_semantics):
                self.assertNotIn(retired_semantics, skill)

    def test_documents_helper_as_transport_not_reviewer(self) -> None:
        dependencies = DEPENDENCIES_PATH.read_text(encoding="utf-8")
        normalized = " ".join(dependencies.split())

        self.assertIn("low-level compatibility/diagnostic tooling", normalized)
        self.assertIn(
            "cannot start, satisfy, substitute for, or count as the named internal "
            "single review",
            normalized,
        )
        self.assertIn("fresh/clear-context Codex `reviewer` agent", normalized)
        self.assertIn(
            "owned by the parent after the delivery child returns", normalized
        )
        self.assertIn(
            "dirty or untracked implementation state cannot count as reviewed",
            normalized,
        )
        self.assertIn("rejects a review `passed` result", normalized)
        self.assertIn("before the child is terminal", normalized)
        self.assertIn("terminal reviewer evidence is missing", normalized)
        self.assertIn("Bulk phase closure cannot mark review phases passed", normalized)
        self.assertNotIn("default fallback review helper", normalized)

        readme = " ".join(README_PATH.read_text(encoding="utf-8").split())
        self.assertIn("compatibility/diagnostic dependency", readme)
        self.assertNotIn("review transport/runtime dependency", readme)


if __name__ == "__main__":
    unittest.main()
