from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

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
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        "print(f'parent-done:{child.pid}',flush=True)"
    )
    runner = ProcessRunner(timeout_seconds=2, reader_timeout_seconds=0.1, environment={})
    started = time.monotonic()

    result = runner.run([sys.executable, "-c", script])

    marker, descendant_pid = result.stdout.decode("ascii").strip().split(":")
    assert marker == "parent-done"
    assert time.monotonic() - started < 2.0

    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel32.GetExitCodeProcess.restype = ctypes.c_int32
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int32
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            handle = kernel32.OpenProcess(0x1000, False, int(descendant_pid))
            if not handle:
                if ctypes.get_last_error() == 87:
                    break
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                exit_code = ctypes.c_uint32()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if exit_code.value != 259:
                    break
            finally:
                kernel32.CloseHandle(handle)
            time.sleep(0.02)
        else:
            pytest.fail("The descendant survived after its parent exited")

    if os.name == "posix":
        detached_script = (
            "import subprocess,sys;"
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(2)'],start_new_session=True);"
            "print('parent-done',flush=True)"
        )
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="did not close"):
            runner.run([sys.executable, "-c", detached_script])
        assert time.monotonic() - started < 1.5


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


@pytest.mark.parametrize("failure_attempt", [1, 2])
def test_reader_start_failure_cleans_up_started_resources(
    monkeypatch: pytest.MonkeyPatch,
    failure_attempt: int,
) -> None:
    real_popen = subprocess.Popen
    real_start = threading.Thread.start
    processes: list[subprocess.Popen[bytes]] = []
    started_threads: list[threading.Thread] = []
    start_attempts = 0

    def capture_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    def fail_reader_start(thread: threading.Thread) -> None:
        nonlocal start_attempts
        start_attempts += 1
        if start_attempts == failure_attempt:
            raise RuntimeError("reader start failed")
        real_start(thread)
        started_threads.append(thread)

    monkeypatch.setattr(subprocess, "Popen", capture_process)
    monkeypatch.setattr(threading.Thread, "start", fail_reader_start)
    runner = ProcessRunner(reader_timeout_seconds=0.1, environment={})

    with pytest.raises(RuntimeError, match="reader start failed"):
        runner.run([sys.executable, "-c", "import time;time.sleep(30)"])

    assert len(started_threads) == failure_attempt - 1
    assert all(not thread.is_alive() for thread in started_threads)
    assert processes[0].returncode is not None
    assert processes[0].stdout is not None and processes[0].stdout.closed
    assert processes[0].stderr is not None and processes[0].stderr.closed


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object startup")
def test_windows_job_setup_failure_never_executes_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from release_proof_mcp import runner as runner_module

    marker = tmp_path / "payload-executed"
    script = f"from pathlib import Path;Path({str(marker)!r}).write_text('executed')"
    real_popen = subprocess.Popen
    real_wait = subprocess.Popen.wait
    processes: list[subprocess.Popen[bytes]] = []

    def capture_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", capture_process)
    monkeypatch.setattr(runner_module, "WindowsJob", Mock(side_effect=OSError(5, "injected")))

    with pytest.raises(runner_module.RunnerError, match="safe process cleanup"):
        ProcessRunner(environment={}).run([sys.executable, "-c", script])

    real_wait(processes[0], timeout=2)
    assert not marker.exists()
    assert processes[0].stdout is not None and processes[0].stdout.closed
    assert processes[0].stderr is not None and processes[0].stderr.closed


def test_unexpected_wait_failure_kills_and_cleans_up_readers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = subprocess.Popen
    real_wait = subprocess.Popen.wait
    real_start = threading.Thread.start
    processes: list[subprocess.Popen[bytes]] = []
    wait_calls: list[subprocess.Popen[bytes]] = []
    started_threads: list[threading.Thread] = []

    def capture_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    def fail_wait(process: subprocess.Popen[bytes], **kwargs: object) -> int:
        wait_calls.append(process)
        raise RuntimeError("unexpected wait failure")

    def capture_start(thread: threading.Thread) -> None:
        real_start(thread)
        started_threads.append(thread)

    monkeypatch.setattr(subprocess, "Popen", capture_process)
    monkeypatch.setattr(real_popen, "wait", fail_wait)
    monkeypatch.setattr(threading.Thread, "start", capture_start)
    runner = ProcessRunner(reader_timeout_seconds=0.1, environment={})

    with pytest.raises(RuntimeError, match="unexpected wait failure"):
        runner.run([sys.executable, "-c", "import time;time.sleep(30)"])

    real_wait(processes[0], timeout=1)
    assert wait_calls == [processes[0], processes[0]]
    assert processes[0].returncode is not None
    assert len(started_threads) == 2
    assert all(not thread.is_alive() for thread in started_threads)


def test_cancellation_at_process_exit_boundary_does_not_return_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancelled = threading.Event()
    real_popen = subprocess.Popen
    real_wait = subprocess.Popen.wait
    processes: list[subprocess.Popen[bytes]] = []

    def capture_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    def cancel_after_wait(process: subprocess.Popen[bytes], **kwargs: object) -> int:
        result = real_wait(process, **kwargs)
        cancelled.set()
        return result

    monkeypatch.setattr(subprocess, "Popen", capture_process)
    monkeypatch.setattr(real_popen, "wait", cancel_after_wait)

    with pytest.raises(CommandCancelled):
        ProcessRunner(environment={}).run(
            [sys.executable, "-c", "print('done')"], cancel_event=cancelled
        )

    assert processes[0].returncode is not None


def test_cancellation_after_reader_drain_does_not_return_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancelled = threading.Event()
    runner = ProcessRunner(environment={})
    real_finish_readers = runner._finish_readers

    def cancel_after_drain(*args: object) -> None:
        real_finish_readers(*args)
        cancelled.set()

    monkeypatch.setattr(runner, "_finish_readers", cancel_after_drain)

    with pytest.raises(CommandCancelled):
        runner.run([sys.executable, "-c", "print('done')"], cancel_event=cancelled)


def test_real_process_uses_no_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    real_popen = subprocess.Popen
    captured: dict[str, object] = {}

    def spy(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        captured.update(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spy)
    result = ProcessRunner(environment={}).run([sys.executable, "-c", "print('ok')"])

    assert result.stdout == b"ok" + os.linesep.encode("ascii")
    assert captured["shell"] is False


def test_real_process_missing_tool_maps_to_tool_unavailable() -> None:
    with pytest.raises(ToolUnavailable):
        ProcessRunner(environment={}).run(["/definitely/not/a/release-proof-tool"])


def test_all_tool_version_stdout_is_redacted_with_real_process_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
        if os.name == "nt":
            executable = bin_dir / f"{name}.bat"
            executable.write_text(
                "@echo off\r\n"
                + subprocess.list2cmdline([sys.executable, "-c", body])
                + "\r\n"
            )
        else:
            executable = bin_dir / name
            executable.write_text(f"#!{sys.executable}\n{body}\n")
            executable.chmod(0o700)
    if os.name == "nt":
        real_popen = subprocess.Popen

        def resolve_fixture_tool(args, **kwargs):
            command, *arguments = args
            if command in scripts:
                command = str(bin_dir / f"{command}.bat")
            return real_popen([command, *arguments], **kwargs)

        monkeypatch.setattr(subprocess, "Popen", resolve_fixture_tool)
    runner = ProcessRunner(
        environment={"PATH": str(bin_dir), "GH_TOKEN": "env-secret"},
        timeout_seconds=2,
    )
    gh_result = runner.run(["gh", "--version"])
    assert gh_result.stdout.startswith(b"development"), gh_result.stderr
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
