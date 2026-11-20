from __future__ import annotations

from pathlib import Path

import pytest

from release_proof_mcp import cli as cli_module
from release_proof_mcp.demo import DemoRunner, run_demo


def test_demo_runs_signed_allow_tamper_failed_and_unknown(capsys) -> None:
    status = run_demo()
    lines = capsys.readouterr().out.strip().splitlines()

    assert status == 0
    assert len(lines) == 6
    assert all(line.startswith("[SIMULATED]") for line in lines)
    assert "Verified signed receipt: id=" in lines[0]
    assert "Independent consumer: allow=True, reason=OK" in lines[1]
    assert "One-byte tamper: allow=False, reason=RECEIPT_INVALID" in lines[2]
    assert "Digest mismatch: status=failed, reason=TAG_MOVED" in lines[3]
    assert "Registry unavailable: status=unknown, reason=REGISTRY_UNAVAILABLE" in lines[4]
    assert "No network, provider, cluster, or external signing service was used" in lines[5]


def test_demo_ignores_configured_package_root_and_writes_no_keys(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    package_root = tmp_path / "must-not-exist"
    monkeypatch.setenv("RELEASE_PROOF_EVIDENCE_PACKAGE_ROOT", str(package_root))
    monkeypatch.chdir(tmp_path)

    status = cli_module.main(["demo"])

    assert status == 0
    assert not package_root.exists()
    assert not list(tmp_path.rglob("*.pem"))
    assert not list(tmp_path.rglob("*.key"))
    assert capsys.readouterr().out.startswith("[SIMULATED]")


def test_demo_runner_rejects_unrouted_commands() -> None:
    with pytest.raises(AssertionError, match="Unexpected non-simulated command"):
        DemoRunner().run(["gh", "api", "repos/acme/other"])


def test_demo_rejects_extra_arguments(capsys) -> None:
    status = cli_module.main(["demo", "--unexpected"])

    assert status == 2
    assert capsys.readouterr().out == ""
