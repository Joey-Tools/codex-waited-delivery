from __future__ import annotations

import pathlib
import tempfile
import unittest


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILL_PATH = SKILL_ROOT / "SKILL.md"
DISTRIBUTION_PROFILE_BY_SKILL_LAYOUT = {
    pathlib.Path("skills/waited-delivery"): "canonical",
    pathlib.Path("personal_codex/skills/waited-delivery"): "private",
}


def distribution_contract_context(
    skill_root: pathlib.Path,
) -> tuple[pathlib.Path, str]:
    layouts = sorted(
        DISTRIBUTION_PROFILE_BY_SKILL_LAYOUT.items(),
        key=lambda item: len(item[0].parts),
        reverse=True,
    )
    for layout, profile in layouts:
        layout_depth = len(layout.parts)
        if skill_root.parts[-layout_depth:] != layout.parts:
            continue
        repo_root = skill_root.parents[layout_depth - 1]
        if repo_root / layout != skill_root:
            continue
        return repo_root, profile
    raise AssertionError(f"unsupported waited-delivery skill layout: {skill_root}")


REPO_ROOT, DISTRIBUTION_PROFILE = distribution_contract_context(SKILL_ROOT)
README_PATH = REPO_ROOT / "README.md"
DEPENDENCIES_PATH = REPO_ROOT / "docs" / "DEPENDENCIES.md"


def require_canonical_documentation(
    test_case: unittest.TestCase,
    *,
    profile: str = DISTRIBUTION_PROFILE,
    documentation_paths: tuple[pathlib.Path, ...] = (
        README_PATH,
        DEPENDENCIES_PATH,
    ),
) -> None:
    if profile == "private":
        test_case.skipTest(
            "repository-level dependency documentation is not packaged in "
            "the private skill-only distribution"
        )
    if profile != "canonical":
        test_case.fail(f"unsupported waited-delivery distribution profile: {profile}")
    missing_paths = tuple(path for path in documentation_paths if not path.exists())
    if missing_paths:
        test_case.fail(
            "canonical dependency documentation is missing: "
            + ", ".join(str(path) for path in missing_paths)
        )


class SkillContractTest(unittest.TestCase):
    def test_distribution_profile_matches_skill_layout(self) -> None:
        self.assertIn(
            DISTRIBUTION_PROFILE,
            set(DISTRIBUTION_PROFILE_BY_SKILL_LAYOUT.values()),
        )
        self.assertEqual(
            (REPO_ROOT, DISTRIBUTION_PROFILE),
            distribution_contract_context(SKILL_ROOT),
        )

    def test_private_skill_layout_selects_private_profile(self) -> None:
        root = pathlib.Path("/example/repository")
        skill_root = root / "personal_codex" / "skills" / "waited-delivery"
        self.assertEqual(
            (root, "private"),
            distribution_contract_context(skill_root),
        )

    def test_private_distribution_skips_repository_documentation(self) -> None:
        with self.assertRaises(unittest.SkipTest):
            require_canonical_documentation(
                self,
                profile="private",
                documentation_paths=(
                    pathlib.Path("/not-packaged/README.md"),
                    pathlib.Path("/not-packaged/docs/DEPENDENCIES.md"),
                ),
            )

    def test_partial_repository_documentation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            readme = root / "README.md"
            readme.write_text("canonical\n", encoding="utf-8")
            with self.assertRaises(AssertionError):
                require_canonical_documentation(
                    self,
                    profile="canonical",
                    documentation_paths=(
                        readme,
                        root / "docs" / "DEPENDENCIES.md",
                    ),
                )

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
        require_canonical_documentation(self)
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
