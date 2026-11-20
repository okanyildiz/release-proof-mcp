from __future__ import annotations

import io
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from release_proof_mcp import evidence_package as package_module
from release_proof_mcp import runner as runner_module


def test_windows_package_write_does_not_use_posix_permissions(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        package_module,
        "os",
        SimpleNamespace(**{**vars(__import__("os")), "name": "nt"}),
    )
    monkeypatch.setattr(
        package_module.os,
        "fchmod",
        Mock(side_effect=AttributeError("fchmod is unavailable on Windows")),
    )

    package_module._write_new_file(tmp_path / "receipt.json", b"{}")

    assert (tmp_path / "receipt.json").read_bytes() == b"{}"


def test_windows_forced_stream_cleanup_closes_stream_objects(monkeypatch) -> None:
    monkeypatch.setattr(
        runner_module,
        "os",
        SimpleNamespace(**{**vars(__import__("os")), "name": "nt"}),
    )
    process = SimpleNamespace(stdout=io.BytesIO(), stderr=io.BytesIO())

    runner_module.ProcessRunner._close_process_streams(process)

    assert process.stdout.closed
    assert process.stderr.closed


def test_taskkill_failure_falls_back_to_process_kill(monkeypatch) -> None:
    monkeypatch.setattr(
        runner_module,
        "os",
        SimpleNamespace(**{**vars(__import__("os")), "name": "nt"}),
    )
    monkeypatch.setattr(
        runner_module.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 1)),
    )
    process = Mock(pid=1234)

    runner_module.ProcessRunner()._kill_process_group(process)

    process.kill.assert_called_once_with()
