from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from conftest import base_input, base_policy
from release_proof_mcp.policy import TrustedPolicy
from release_proof_mcp.report import ReportBuilder
from release_proof_mcp.request import VerificationRequest
from release_proof_mcp.runner import (
    CommandCancelled,
    CommandTimeout,
    OutputLimitExceeded,
    ProcessRunner,
    ToolUnavailable,
)
from release_proof_mcp.verifier import ReleaseVerifier


def test_process_tree_timeout_terminates_group_and_bounded_drainage() -> None:
    script = (
        "import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        "print('descendant-started',flush=True);time.sleep(30)"
    )
    runner = ProcessRunner(timeout_seconds=5, reader_timeout_seconds=0.1, environment={})
    started = time.monotonic()

    with pytest.raises(CommandTimeout):
        runner.run([sys.executable, "-c", script], timeout=0.15)

    assert time.monotonic() - started < 2.0


def test_descendant_pipes_after_normal_parent_exit_have_bounded_cleanup() -> None:
    script = (
        "import subprocess,sys;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        "print('parent-done',flush=True)"
    )
    runner = ProcessRunner(timeout_seconds=2, reader_timeout_seconds=0.1, environment={})
    started = time.monotonic()

    result = runner.run([sys.executable, "-c", script])

    assert result.stdout == b"parent-done\n"
    assert time.monotonic() - started < 2.0


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_real_process_output_limit_is_enforced(stream: str) -> None:
    descriptor = 1 if stream == "stdout" else 2
    runner = ProcessRunner(output_limit_bytes=128, environment={})

    with pytest.raises(OutputLimitExceeded):
        runner.run([sys.executable, "-c", f"import os;os.write({descriptor},b'x'*10000)"])


def test_real_process_stderr_is_redacted() -> None:
    github_token = "ghp_" + "c" * 36
    text = f"token=supersecret Bearer bearer-secret GH_TOKEN=env-secret {github_token}"
    runner = ProcessRunner(environment={"GH_TOKEN": "env-secret"})

    result = runner.run([sys.executable, "-c", f"import sys;print({text!r},file=sys.stderr)"])

    for secret in ("supersecret", "bearer-secret", "env-secret", github_token):
        assert secret not in result.stderr


def test_real_process_cancellation_terminates_command() -> None:
    cancelled = threading.Event()
    timer = threading.Timer(0.1, cancelled.set)
    runner = ProcessRunner(timeout_seconds=30, reader_timeout_seconds=0.1, environment={})
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(CommandCancelled):
            runner.run(
                [sys.executable, "-c", "import time;time.sleep(30)"],
                cancel_event=cancelled,
            )
    finally:
        timer.cancel()

    assert time.monotonic() - started < 2.0


def test_real_process_uses_no_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    real_popen = subprocess.Popen
    captured: dict[str, object] = {}

    def spy(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        captured.update(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spy)
    result = ProcessRunner(environment={}).run([sys.executable, "-c", "print('ok')"])

    assert result.stdout == b"ok\n"
    assert captured["shell"] is False


def test_real_process_missing_tool_maps_to_tool_unavailable() -> None:
    with pytest.raises(ToolUnavailable):
        ProcessRunner(environment={}).run(["/definitely/not/a/release-proof-tool"])


def test_all_tool_version_stdout_is_redacted_with_real_process_runner(
    tmp_path: Path,
) -> None:
    github_token = "github_pat_" + "d" * 30
    payload = (
        f"development token=token-secret Authorization: Basic authorization-secret "
        f"Bearer bearer-secret GH_TOKEN=env-secret {github_token}"
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    scripts = {
        "gh": f"print({payload!r})",
        "crane": f"print({payload!r})",
        "kubectl": f"print({json.dumps({'clientVersion': {'gitVersion': payload}})!r})",
        "cosign": f"print({payload!r})",
    }
    for name, body in scripts.items():
        executable = bin_dir / name
        executable.write_text(f"#!{sys.executable}\n{body}\n")
        executable.chmod(0o700)
    runner = ProcessRunner(
        environment={"PATH": str(bin_dir), "GH_TOKEN": "env-secret"},
        timeout_seconds=2,
    )
    request = VerificationRequest.from_dict(base_input())
    policy_value = base_policy()
    policy_value["require_cosign_signature"] = True
    policy = TrustedPolicy.from_dict("production", policy_value)
    report = ReportBuilder(request, policy, "2026-11-18T12:00:00Z")
    verifier = ReleaseVerifier(runner)

    verifier._discover_tools(request, report, policy)
    receipt = report.finalize("2026-11-18T12:00:01Z")
    serialized = json.dumps(receipt, sort_keys=True)

    for secret in ("token-secret", "authorization-secret", "bearer-secret", "env-secret", github_token):
        assert secret not in serialized
    assert "[REDACTED]" in serialized
