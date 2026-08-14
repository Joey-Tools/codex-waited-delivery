from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence


CANDIDATE_ROOT_ENV = "REQUIRED_CI_CANDIDATE_ROOT"
CANDIDATE_SHA_ENV = "REQUIRED_CI_CANDIDATE_SHA"
CANDIDATE_PROCESS_TIMEOUT_SECONDS = 30
CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES = 1024 * 1024
CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS = 5
CANDIDATE_GIT_TIMEOUT_SECONDS = 15
CANDIDATE_GIT_OUTPUT_LIMIT_BYTES = 1024 * 1024
CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES = 4 * 1024 * 1024
CANDIDATE_SCRIPT_RELATIVE_PATHS = (
    Path("skills/waited-delivery/scripts/waited_delivery_bridge.py"),
    Path("skills/waited-delivery/scripts/waited_delivery_hook_adapter.py"),
    Path("skills/waited-delivery/scripts/waited_delivery_runner.py"),
)
_CANDIDATE_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
_TRUSTED_REPO_ROOT = Path(__file__).resolve(strict=True).parents[3]


def _resolve_trusted_git() -> str:
    selected = shutil.which("git")
    if selected is None:
        raise AssertionError("trusted runner PATH does not provide Git")
    path = Path(selected)
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise AssertionError("trusted Git executable cannot be resolved") from error
    if not resolved.is_absolute() or not stat.S_ISREG(metadata.st_mode):
        raise AssertionError("trusted Git executable must be an absolute ordinary file")
    return str(resolved)


TRUSTED_GIT_EXECUTABLE = _resolve_trusted_git()
_GIT_SAFE_ARGUMENTS = (
    "--no-pager",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "advice.graftFileDeprecated=false",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.commitGraph=false",
    "-c",
    "core.multiPackIndex=false",
    "-c",
    "diff.external=",
)


def candidate_repository_root() -> Path:
    value = os.environ.get(CANDIDATE_ROOT_ENV)
    if value is None:
        if _TRUSTED_REPO_ROOT.name == ".required-ci":
            raise AssertionError(
                f"{CANDIDATE_ROOT_ENV} is required in the trusted checkout"
            )
        return _TRUSTED_REPO_ROOT

    root = Path(value)
    if not root.is_absolute() or root.name != ".candidate":
        raise AssertionError(
            f"{CANDIDATE_ROOT_ENV} must be an absolute .candidate path"
        )
    if root.is_symlink():
        raise AssertionError(f"{CANDIDATE_ROOT_ENV} must not select a symlink")
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            f"{CANDIDATE_ROOT_ENV} must select an existing directory"
        ) from error
    if resolved != root or not resolved.is_dir():
        raise AssertionError(
            f"{CANDIDATE_ROOT_ENV} must select a canonical directory"
        )
    return resolved


def _candidate_git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_GRAFT_FILE": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
    )
    return environment


def candidate_git_argv(root: Path, *arguments: str) -> list[str]:
    return [
        TRUSTED_GIT_EXECUTABLE,
        *_GIT_SAFE_ARGUMENTS,
        "-C",
        str(root),
        *arguments,
    ]


def _run_candidate_git(
    root: Path,
    *arguments: str,
    output_limit: int = CANDIDATE_GIT_OUTPUT_LIMIT_BYTES,
) -> bytes:
    command = candidate_git_argv(root, *arguments)
    try:
        completed = subprocess.run(
            command,
            env=_candidate_git_environment(),
            check=False,
            capture_output=True,
            timeout=CANDIDATE_GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise AssertionError("candidate Git validation exceeded its fixed timeout") from error
    if completed.returncode != 0:
        stderr = completed.stderr[:2000].decode("utf-8", errors="replace")
        raise AssertionError(
            f"candidate Git validation failed with exit {completed.returncode}: {stderr}"
        )
    if completed.stderr:
        stderr = completed.stderr[:2000].decode("utf-8", errors="replace")
        raise AssertionError(f"candidate Git validation wrote stderr: {stderr}")
    if len(completed.stdout) > output_limit:
        raise AssertionError("candidate Git validation exceeded its output limit")
    return completed.stdout


def _parse_candidate_sha(value: str, description: str) -> str:
    if _CANDIDATE_SHA_PATTERN.fullmatch(value) is None:
        raise AssertionError(f"{description} must be a lowercase 40-hex commit SHA")
    return value


def expected_candidate_sha(root: Path) -> tuple[str, bool]:
    value = os.environ.get(CANDIDATE_SHA_ENV)
    if value is not None:
        return _parse_candidate_sha(value, CANDIDATE_SHA_ENV), True
    if _TRUSTED_REPO_ROOT.name == ".required-ci":
        raise AssertionError(
            f"{CANDIDATE_SHA_ENV} is required in the trusted checkout"
        )
    head = _run_candidate_git(root, "rev-parse", "--verify", "HEAD^{commit}")
    try:
        decoded = head.decode("ascii")
    except UnicodeDecodeError as error:
        raise AssertionError("candidate HEAD is not ASCII") from error
    return _parse_candidate_sha(decoded.removesuffix("\n"), "candidate HEAD"), False


def _ordinary_candidate_file(root: Path, relative_path: Path) -> Path:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise AssertionError("candidate file path must be repository-relative")
    path = root / relative_path
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise AssertionError(f"candidate file is missing: {relative_path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or resolved != path
        or root not in resolved.parents
    ):
        raise AssertionError(
            f"candidate file must be an ordinary single-link file: {relative_path}"
        )
    if metadata.st_size > CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES:
        raise AssertionError(f"candidate file exceeds its size limit: {relative_path}")
    return path


def candidate_path(relative_path: str | Path) -> Path:
    root = candidate_repository_root()
    relative = Path(relative_path)
    path = root / relative
    if relative.is_absolute() or ".." in relative.parts:
        raise AssertionError("candidate path must be repository-relative")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise AssertionError(f"candidate path is missing: {relative}") from error
    if resolved != path or (resolved != root and root not in resolved.parents):
        raise AssertionError(f"candidate path escapes the candidate root: {relative}")
    return resolved


def candidate_script(name: str) -> Path:
    if Path(name).name != name:
        raise AssertionError("candidate script name must be a basename")
    relative = Path("skills/waited-delivery/scripts") / name
    if relative not in CANDIDATE_SCRIPT_RELATIVE_PATHS:
        raise AssertionError(f"unexpected candidate script: {name}")
    return _ordinary_candidate_file(candidate_repository_root(), relative)


def _candidate_script_manifest(root: Path) -> dict[str, str]:
    scripts_root = root / "skills/waited-delivery/scripts"
    try:
        entries = sorted(scripts_root.iterdir(), key=lambda entry: entry.name)
    except OSError as error:
        raise AssertionError("candidate scripts directory cannot be enumerated") from error
    expected_names = sorted(path.name for path in CANDIDATE_SCRIPT_RELATIVE_PATHS)
    if [entry.name for entry in entries] != expected_names:
        raise AssertionError("candidate scripts directory inventory is not exact")

    manifest: dict[str, str] = {}
    for relative_path in CANDIDATE_SCRIPT_RELATIVE_PATHS:
        path = _ordinary_candidate_file(root, relative_path)
        size_output = _run_candidate_git(
            root,
            "cat-file",
            "-s",
            f"HEAD:{relative_path.as_posix()}",
            output_limit=128,
        )
        try:
            tracked_size = int(size_output.decode("ascii").removesuffix("\n"))
        except (UnicodeDecodeError, ValueError) as error:
            raise AssertionError(
                f"candidate tracked size is malformed: {relative_path}"
            ) from error
        if tracked_size < 0 or tracked_size > CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES:
            raise AssertionError(
                f"candidate tracked file exceeds its size limit: {relative_path}"
            )
        tracked_bytes = _run_candidate_git(
            root,
            "cat-file",
            "blob",
            f"HEAD:{relative_path.as_posix()}",
            output_limit=CANDIDATE_SCRIPT_SIZE_LIMIT_BYTES,
        )
        try:
            working_bytes = path.read_bytes()
        except OSError as error:
            raise AssertionError(f"candidate file cannot be read: {relative_path}") from error
        if len(tracked_bytes) != tracked_size or working_bytes != tracked_bytes:
            raise AssertionError(
                f"candidate implementation bytes do not match HEAD: {relative_path}"
            )
        manifest[relative_path.as_posix()] = hashlib.sha256(working_bytes).hexdigest()
    return manifest


def candidate_checkout_binding(
    root: Path,
    candidate_sha: str,
    *,
    require_clean: bool,
) -> dict[str, object]:
    canonical_root = candidate_repository_root()
    if root.resolve(strict=True) != canonical_root:
        raise AssertionError("candidate checkout binding root is not canonical")
    candidate_sha = _parse_candidate_sha(candidate_sha, "candidate SHA")

    expected_toplevel = f"{canonical_root}\n".encode()
    expected_head = f"{candidate_sha}\n".encode()
    toplevel = _run_candidate_git(canonical_root, "rev-parse", "--show-toplevel")
    head_before = _run_candidate_git(
        canonical_root, "rev-parse", "--verify", "HEAD^{commit}"
    )
    if toplevel != expected_toplevel or head_before != expected_head:
        raise AssertionError("candidate checkout root or HEAD does not match the workflow")
    if require_clean:
        status_before = _run_candidate_git(
            canonical_root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
            "--ignore-submodules=none",
        )
        if status_before:
            raise AssertionError("candidate checkout is not exactly clean before execution")

    script_manifest = _candidate_script_manifest(canonical_root)
    head_after = _run_candidate_git(
        canonical_root, "rev-parse", "--verify", "HEAD^{commit}"
    )
    if head_after != expected_head:
        raise AssertionError("candidate checkout HEAD changed during validation")
    if require_clean:
        status_after = _run_candidate_git(
            canonical_root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
            "--ignore-submodules=none",
        )
        if status_after:
            raise AssertionError("candidate checkout changed during validation")
    return {
        "candidate_root": str(canonical_root),
        "candidate_sha": candidate_sha,
        "candidate_script_sha256": script_manifest,
    }


def _candidate_child_resource_limits() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (
            CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES,
            CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES,
        ),
    )


def _kill_candidate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=CANDIDATE_PROCESS_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise AssertionError("candidate process group could not be reaped") from error


def _candidate_process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError as error:
        raise AssertionError("candidate process group cannot be inspected") from error
    return True


def _read_bounded_output(output_file, description: str) -> str:
    output_file.flush()
    size = output_file.tell()
    if size > CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES:
        raise AssertionError(f"candidate {description} exceeded its fixed limit")
    output_file.seek(0)
    data = output_file.read(CANDIDATE_PROCESS_OUTPUT_LIMIT_BYTES + 1)
    if len(data) != size:
        raise AssertionError(f"candidate {description} could not be read completely")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AssertionError(f"candidate {description} is not valid UTF-8") from error


def _validated_candidate_script(root: Path, script: Path) -> None:
    try:
        relative_script = script.relative_to(root)
    except ValueError as error:
        raise AssertionError("candidate subprocess script escapes the candidate root") from error
    if relative_script not in CANDIDATE_SCRIPT_RELATIVE_PATHS:
        raise AssertionError("candidate subprocess script is not in the fixed inventory")
    if _ordinary_candidate_file(root, relative_script) != script:
        raise AssertionError("candidate subprocess script path is not canonical")


def _run_candidate_process(
    script: Path,
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    root = candidate_repository_root()
    candidate_sha, require_clean = expected_candidate_sha(root)
    before = candidate_checkout_binding(
        root, candidate_sha, require_clean=require_clean
    )
    _validated_candidate_script(root, script)

    exact_command = list(command)
    child_environment = dict(os.environ if env is None else env)
    child_environment.pop("PYTHONHOME", None)
    child_environment.pop("PYTHONPATH", None)
    child_environment.pop(CANDIDATE_ROOT_ENV, None)
    child_environment.pop(CANDIDATE_SHA_ENV, None)

    with tempfile.TemporaryDirectory(prefix="required-ci-candidate-cwd-") as neutral_cwd:
        child_cwd = Path(neutral_cwd) if cwd is None else cwd
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                exact_command,
                cwd=str(child_cwd),
                env=child_environment,
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
                preexec_fn=_candidate_child_resource_limits,
            )
            timed_out = False
            try:
                process.communicate(
                    None if input_text is None else input_text.encode("utf-8"),
                    timeout=CANDIDATE_PROCESS_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_candidate_process_group(process)

            lingering_group = _candidate_process_group_exists(process.pid)
            if lingering_group:
                _kill_candidate_process_group(process)
            stdout = _read_bounded_output(stdout_file, "stdout")
            stderr = _read_bounded_output(stderr_file, "stderr")
            returncode = process.returncode

    after = candidate_checkout_binding(root, candidate_sha, require_clean=require_clean)
    if after != before:
        raise AssertionError("candidate checkout binding changed during subprocess")
    if timed_out:
        raise AssertionError("candidate subprocess exceeded its fixed timeout")
    if lingering_group:
        raise AssertionError("candidate subprocess left an active process group")
    if type(returncode) is not int:
        raise AssertionError("candidate subprocess did not produce a return code")
    return subprocess.CompletedProcess(exact_command, returncode, stdout, stderr)


def run_candidate_python(
    script: Path,
    arguments: Sequence[str] = (),
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-I", str(script), *arguments]
    return _run_candidate_process(
        script,
        command,
        cwd=cwd,
        env=env,
        input_text=input_text,
    )


def run_candidate_hook_fault_probe(
    script: Path,
    faults: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    input_text: str,
) -> subprocess.CompletedProcess[str]:
    if script.name != "waited_delivery_hook_adapter.py":
        raise AssertionError("candidate hook fault probe requires the hook adapter")
    exact_faults = tuple(faults)
    if exact_faults not in (("continuation",), ("continuation", "fallback")):
        raise AssertionError("candidate hook fault probe has an invalid fault sequence")
    trusted_probe = Path(__file__).resolve(strict=True)
    try:
        trusted_probe_source = trusted_probe.read_bytes()
    except OSError as error:
        raise AssertionError("trusted hook fault probe cannot be read") from error
    command = [
        sys.executable,
        "-I",
        "-B",
        str(trusted_probe),
        "--hook-fault-probe",
        str(script),
        ",".join(exact_faults),
    ]
    completed = _run_candidate_process(
        script,
        command,
        env=env,
        input_text=input_text,
    )
    try:
        final_probe_source = trusted_probe.read_bytes()
    except OSError as error:
        raise AssertionError("trusted hook fault probe became unreadable") from error
    if final_probe_source != trusted_probe_source:
        raise AssertionError("trusted hook fault probe changed during execution")
    return completed


def _hook_fault_probe_main(adapter_value: str, fault_value: str) -> int:
    adapter_path = Path(adapter_value)
    if (
        not adapter_path.is_absolute()
        or adapter_path.name != "waited_delivery_hook_adapter.py"
    ):
        raise AssertionError("candidate hook fault probe requires an absolute script path")
    faults = tuple(fault_value.split(","))
    if faults not in (("continuation",), ("continuation", "fallback")):
        raise AssertionError("candidate hook fault probe has an invalid fault sequence")
    spec = importlib.util.spec_from_file_location(
        "_required_ci_candidate_hook_adapter", adapter_path
    )
    if spec is None or spec.loader is None:
        raise AssertionError("candidate hook adapter cannot be loaded for the fault probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    observed_faults: list[str] = []

    def injected_continuation_failure(*_args, **_kwargs):
        observed_faults.append("continuation")
        raise RuntimeError("required-ci injected continuation failure")

    def injected_fallback_failure(*_args, **_kwargs):
        observed_faults.append("fallback")
        raise RuntimeError("required-ci injected fallback failure")

    module._build_stop_continuation_prompt = injected_continuation_failure
    if "fallback" in faults:
        module._build_stop_fallback_prompt = injected_fallback_failure
    original_argv = sys.argv
    try:
        sys.argv = [str(adapter_path), "stop-hook"]
        try:
            result = module.main()
        except SystemExit as error:
            raise AssertionError(
                "candidate hook adapter bypassed the trusted probe return path"
            ) from error
    finally:
        sys.argv = original_argv
    if tuple(observed_faults) != faults:
        raise AssertionError("candidate hook adapter skipped the injected fault sequence")
    if type(result) is not int:
        raise AssertionError("candidate hook adapter returned a non-integer status")
    return result


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--hook-fault-probe":
        raise SystemExit(_hook_fault_probe_main(sys.argv[2], sys.argv[3]))
    raise SystemExit("required_ci_candidate.py is a trusted support module")
