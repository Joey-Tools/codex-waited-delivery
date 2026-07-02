from __future__ import annotations

import pathlib
import unittest


SKILL_PATH = pathlib.Path(__file__).resolve().parents[1] / "SKILL.md"


class SkillContractTest(unittest.TestCase):
    def test_uses_canonical_review_orchestration_contract(self) -> None:
        skill = SKILL_PATH.read_text(encoding="utf-8")

        self.assertIn("$review-orchestration-playbook", skill)
        self.assertIn(
            "isolated_review stateful start --reviewer codex "
            "--base-ref <base_sha> --head-ref <head_sha>",
            skill,
        )
        for retired_entrypoint in (
            "$pr-readiness-review-workflow",
            "$external-review-playbook",
            "`codex-review`",
            "`codex-readonly`",
            "`codex-parallel`",
        ):
            with self.subTest(retired_entrypoint=retired_entrypoint):
                self.assertNotIn(retired_entrypoint, skill)


if __name__ == "__main__":
    unittest.main()
