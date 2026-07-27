from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from _subprocess_test_support import run_before_stdin_eof


LEGACY_ADAPTER = (
    Path(__file__).resolve().parents[3]
    / "legacy-hook-shims"
    / "waited-delivery"
    / "scripts"
    / "waited_delivery_hook_adapter.py"
)
HISTORICAL_TARGET_ADAPTER = (
    Path(__file__).resolve().parents[3]
    / "skills"
    / "waited-delivery"
    / "scripts"
    / "waited_delivery_hook_adapter.py"
)


class LegacyHookShimTests(unittest.TestCase):
    def _invoke_registered_hook(
        self,
        adapter: Path,
        *,
        root: Path,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "HOME": str(root),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        return subprocess.run(
            [
                sys.executable,
                str(adapter),
                "stop-hook",
                "--enable-compat-hook",
            ],
            check=False,
            cwd=root,
            env=environment,
            input="{not valid hook JSON\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )

    def _assert_inert(self, completed: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "{}\n")
        self.assertEqual(completed.stderr, "")

    def test_legacy_paths_are_identical_and_not_discoverable_skills(self) -> None:
        legacy_asset_root = LEGACY_ADAPTER.parents[1]
        historical_target_root = HISTORICAL_TARGET_ADAPTER.parents[1]

        self.assertTrue(LEGACY_ADAPTER.is_file())
        self.assertTrue(HISTORICAL_TARGET_ADAPTER.is_file())
        self.assertEqual(
            LEGACY_ADAPTER.read_bytes(),
            HISTORICAL_TARGET_ADAPTER.read_bytes(),
        )
        self.assertEqual(
            LEGACY_ADAPTER.stat().st_mode & 0o777,
            HISTORICAL_TARGET_ADAPTER.stat().st_mode & 0o777,
        )
        self.assertTrue(os.access(HISTORICAL_TARGET_ADAPTER, os.X_OK))
        self.assertFalse((legacy_asset_root / "SKILL.md").exists())
        self.assertFalse((historical_target_root / "SKILL.md").exists())
        self.assertNotIn("skills", legacy_asset_root.parts[-2:])

    def test_every_legacy_invocation_is_inert_and_fail_open(self) -> None:
        invocations = (
            (),
            ("user-prompt-submit-hook",),
            ("stop-hook",),
            ("stop-hook", "--enable-compat-hook"),
            ("--malformed", "value"),
        )
        for arguments in invocations:
            with self.subTest(arguments=arguments):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    environment = {
                        "HOME": str(root),
                        "PATH": os.environ.get("PATH", ""),
                        "PYTHONDONTWRITEBYTECODE": "1",
                    }
                    for adapter in (LEGACY_ADAPTER, HISTORICAL_TARGET_ADAPTER):
                        completed = subprocess.run(
                            [sys.executable, str(adapter), *arguments],
                            check=False,
                            cwd=root,
                            env=environment,
                            input="{not valid hook JSON\n",
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=5,
                        )
                        self._assert_inert(completed)
                    self.assertEqual(list(root.iterdir()), [])

    def test_direct_repo_link_keeps_registered_legacy_hook_reachable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            installed_skills = root / ".codex" / "skills"
            installed_skills.mkdir(parents=True)
            (installed_skills / "waited-delivery").symlink_to(
                HISTORICAL_TARGET_ADAPTER.parents[1],
                target_is_directory=True,
            )
            registered_adapter = (
                installed_skills
                / "waited-delivery"
                / "scripts"
                / "waited_delivery_hook_adapter.py"
            )

            self._assert_inert(
                self._invoke_registered_hook(registered_adapter, root=root)
            )
            self.assertFalse(
                (installed_skills / "waited-delivery" / "SKILL.md").exists()
            )

    def test_aggregate_and_overlay_installations_keep_shim_inert(self) -> None:
        for profile in ("aggregate", "overlay"):
            with self.subTest(profile=profile):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    release_source = (
                        root
                        / profile
                        / "personal_codex"
                        / "legacy-hook-shims"
                        / "waited-delivery"
                    )
                    shutil.copytree(
                        LEGACY_ADAPTER.parents[1],
                        release_source,
                    )
                    installed_target = root / "home" / ".codex" / "skills"
                    installed_target.mkdir(parents=True)
                    (installed_target / "waited-delivery").symlink_to(
                        release_source,
                        target_is_directory=True,
                    )
                    registered_adapter = (
                        installed_target
                        / "waited-delivery"
                        / "scripts"
                        / "waited_delivery_hook_adapter.py"
                    )

                    self._assert_inert(
                        self._invoke_registered_hook(registered_adapter, root=root)
                    )
                    self.assertFalse((release_source / "SKILL.md").exists())

    def test_removed_link_retirement_stays_two_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            release_target = (
                root
                / "release"
                / "personal_codex"
                / "legacy-hook-shims"
                / "waited-delivery"
            )
            shutil.copytree(
                LEGACY_ADAPTER.parents[1],
                release_target,
            )
            installed_target = root / "home" / ".codex" / "skills"
            installed_target.mkdir(parents=True)
            legacy_link = installed_target / "waited-delivery"
            legacy_link.symlink_to(release_target, target_is_directory=True)
            registered_adapter = (
                legacy_link / "scripts" / "waited_delivery_hook_adapter.py"
            )
            migrate_active_skill = {
                "id": "migrate-waited-delivery-to-inert-shim",
                "source": "personal_codex/skills/waited-delivery",
                "target": "skills/waited-delivery",
                "kind": "skill",
                "replacement_target": "skills/waited-delivery",
            }
            retire_inert_shim = {
                "id": "retire-waited-delivery-inert-shim",
                "source": "personal_codex/legacy-hook-shims/waited-delivery",
                "target": "skills/waited-delivery",
                "kind": "directory",
                "replacement_target": "skills/change-delivery-workflow",
            }
            phase_one_manifest = {
                "links": [
                    {
                        "source": retire_inert_shim["source"],
                        "target": retire_inert_shim["target"],
                        "kind": retire_inert_shim["kind"],
                    }
                ],
                "removed_links": [migrate_active_skill],
            }
            phase_two_manifest = {
                "links": [],
                "removed_links": [
                    migrate_active_skill,
                    retire_inert_shim,
                ],
            }

            effective_hook_commands = [str(registered_adapter)]
            self.assertTrue(effective_hook_commands)
            self.assertEqual(
                phase_one_manifest["links"][0]["target"],
                "skills/waited-delivery",
            )
            self.assertEqual(
                phase_one_manifest["removed_links"],
                [migrate_active_skill],
            )
            self._assert_inert(
                self._invoke_registered_hook(registered_adapter, root=root)
            )
            self.assertTrue(legacy_link.exists())

            effective_hook_commands.clear()
            self.assertEqual(effective_hook_commands, [])
            self.assertEqual(phase_two_manifest["links"], [])
            self.assertEqual(
                phase_two_manifest["removed_links"],
                [migrate_active_skill, retire_inert_shim],
            )
            legacy_link.unlink()
            self.assertFalse(legacy_link.exists())

    def test_legacy_shim_exits_before_stdin_eof(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            environment = {
                "HOME": str(root),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            for adapter in (LEGACY_ADAPTER, HISTORICAL_TARGET_ADAPTER):
                completed = run_before_stdin_eof(
                    [
                        sys.executable,
                        str(adapter),
                        "stop-hook",
                        "--enable-compat-hook",
                    ],
                    cwd=root,
                    env=environment,
                    # Keep the writer open with zero bytes so even read(1) blocks.
                    input_text="",
                )
                self._assert_inert(completed)
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
