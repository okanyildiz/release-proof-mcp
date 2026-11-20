from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from conftest import Harness
from release_proof_mcp import consumer as consumer_module
from release_proof_mcp import evidence_package as package_module
from release_proof_mcp import runner as runner_module
from test_evidence_package import publish, verify


def _windows_namespace() -> SimpleNamespace:
    return SimpleNamespace(**{**vars(os), "name": "nt"})


def test_windows_package_write_does_not_use_posix_permissions(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(package_module, "os", _windows_namespace())
    monkeypatch.setattr(
        package_module.os,
        "fchmod",
        Mock(side_effect=AttributeError("fchmod is unavailable on Windows")),
        raising=False,
    )

    package_module._write_new_file(tmp_path / "receipt.json", b"{}")

    assert (tmp_path / "receipt.json").read_bytes() == b"{}"


def test_windows_package_reader_avoids_directory_descriptors(
    tmp_path: Path, harness: Harness, monkeypatch
) -> None:
    case = publish(harness, tmp_path / "operator")
    monkeypatch.setattr(consumer_module, "os", _windows_namespace())
    real_open = consumer_module.os.open

    def checked_open(path, flags, **kwargs):
        assert "dir_fd" not in kwargs
        return real_open(path, flags)

    monkeypatch.setattr(consumer_module.os, "open", checked_open)

    decision = verify(case)

    assert decision["allow"] is True
    assert decision["reason"] == "OK"


def test_windows_package_root_symlink_is_rejected(
    tmp_path: Path, harness: Harness, monkeypatch
) -> None:
    case = publish(harness, tmp_path / "operator")
    monkeypatch.setattr(consumer_module, "os", _windows_namespace())
    link = tmp_path / "package-link"
    link.symlink_to(case.path, target_is_directory=True)

    decision = consumer_module.verify_evidence_package(link, **case.options)

    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_FILE_INVALID"


def test_windows_forced_stream_cleanup_closes_stream_objects(monkeypatch) -> None:
    monkeypatch.setattr(runner_module, "os", _windows_namespace())
    process = SimpleNamespace(stdout=io.BytesIO(), stderr=io.BytesIO())

    runner_module.ProcessRunner._close_process_streams(process)

    assert process.stdout.closed
    assert process.stderr.closed


def test_taskkill_failure_falls_back_to_process_kill(monkeypatch) -> None:
    monkeypatch.setattr(runner_module, "os", _windows_namespace())
    monkeypatch.setattr(
        runner_module.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 1)),
    )
    process = Mock(pid=1234)

    runner_module.ProcessRunner()._kill_process_group(process)

    process.kill.assert_called_once_with()


def test_inactive_windows_job_still_uses_root_process_cleanup(monkeypatch) -> None:
    monkeypatch.setattr(runner_module, "os", _windows_namespace())
    taskkill = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(runner_module.subprocess, "run", taskkill)
    job = Mock()
    job.terminate.return_value = False
    process = Mock(pid=1234)

    runner_module.ProcessRunner()._kill_process_group(process, job)

    taskkill.assert_called_once()
    process.kill.assert_not_called()
