from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from conftest import Harness, policy_store
from release_proof_mcp import capture as capture_module
from release_proof_mcp import cli as cli_module
from release_proof_mcp.verifier import ReleaseVerifier
from test_evidence_package import PACKAGE_FILENAMES, set_valid_attestation
from test_signed_mcp import SIGNING_ENVIRONMENT
from test_signing import ISSUER, KEYID, NONCE, PRIVATE_KEY


@pytest.fixture(autouse=True)
def clear_signing_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in SIGNING_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)


def invoke(
    harness: Harness,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    *extra: str,
    signing=None,
    package_root: Path | None = None,
) -> tuple[int, str, str]:
    request = tmp_path / "request.json"
    request.write_text(json.dumps(harness.request), encoding="utf-8")
    monkeypatch.setenv("RELEASE_PROOF_POLICY_PROFILE", "production")
    if package_root is not None:
        monkeypatch.setenv("RELEASE_PROOF_EVIDENCE_PACKAGE_ROOT", str(package_root))
    else:
        monkeypatch.delenv("RELEASE_PROOF_EVIDENCE_PACKAGE_ROOT", raising=False)
    status = cli_module.main(
        ["capture", "--request", str(request), *extra],
        verifier_factory=lambda: ReleaseVerifier(harness.runner),
        policy_store=policy_store(),
        signing=signing,
        receipt_signer=cli_module.sign_receipt,
    )
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def test_capture_test_environment_is_isolated() -> None:
    assert all(name not in os.environ for name in SIGNING_ENVIRONMENT)


def test_capture_verified_unsigned_receipt_on_stdout(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    status, stdout, stderr = invoke(harness, tmp_path, monkeypatch, capsys)

    receipt = json.loads(stdout)
    assert status == 0
    assert receipt["status"] == "verified"
    assert "proof" not in receipt
    assert stderr == ""


def test_capture_failed_receipt_has_exit_one(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    harness.set_attestation([], returncode=1, stderr="no attestations found")

    status, stdout, stderr = invoke(harness, tmp_path, monkeypatch, capsys)

    receipt = json.loads(stdout)
    assert status == 1
    assert receipt["status"] == "failed"
    assert receipt["reasons"]
    assert stderr == ""


def test_capture_unknown_receipt_has_exit_one(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    harness.runner.route(["gh", "--version"], "gh version 2.101.0")

    status, stdout, stderr = invoke(harness, tmp_path, monkeypatch, capsys)

    receipt = json.loads(stdout)
    assert status == 1
    assert receipt["status"] == "unknown"
    assert receipt["missing_coverage"]
    assert stderr == ""


def test_capture_uses_shared_signed_package_path(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    set_valid_attestation(harness)
    root = tmp_path / "packages"

    status, stdout, _stderr = invoke(
        harness,
        tmp_path,
        monkeypatch,
        capsys,
        signing=(PRIVATE_KEY, ISSUER, KEYID),
        package_root=root,
    )

    receipt = json.loads(stdout)
    assert status == 0
    assert receipt["status"] == "verified"
    assert "proof" in receipt
    package = root / receipt["receipt_id"]
    assert {item.name for item in package.iterdir()} == PACKAGE_FILENAMES
    assert json.loads((package / "receipt.json").read_text()) == receipt


def test_capture_nonce_file(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    nonce = tmp_path / "nonce.txt"
    nonce.write_text(NONCE, encoding="ascii")

    status, stdout, _stderr = invoke(
        harness, tmp_path, monkeypatch, capsys, "--nonce-file", str(nonce)
    )

    assert status == 0
    assert json.loads(stdout)["consumer_nonce"] == NONCE


def test_capture_out_never_overwrites(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    output = tmp_path / "receipt.json"
    first_status, first_stdout, _ = invoke(
        harness, tmp_path, monkeypatch, capsys, "--out", str(output)
    )
    original = output.read_bytes()
    second_status, second_stdout, second_stderr = invoke(
        harness, tmp_path, monkeypatch, capsys, "--out", str(output)
    )

    assert first_status == 0
    assert first_stdout == ""
    assert second_status == 2
    assert second_stdout == ""
    assert "no receipt was emitted" in second_stderr
    assert output.read_bytes() == original
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600


def test_capture_invalid_request_has_no_receipt(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    request = tmp_path / "request.json"
    request.write_text("{not-json", encoding="utf-8")
    monkeypatch.setenv("RELEASE_PROOF_POLICY_PROFILE", "production")

    status = cli_module.main(["capture", "--request", str(request)])
    captured = capsys.readouterr()

    assert status == 2
    assert captured.out == ""
    assert "no receipt was emitted" in captured.err


def test_capture_size_limit_has_no_receipt(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(cli_module, "MAX_RECEIPT_BYTES", 1)

    status, stdout, stderr = invoke(harness, tmp_path, monkeypatch, capsys)

    assert status == 2
    assert stdout == ""
    assert "no receipt was emitted" in stderr


def test_signing_failure_never_returns_unsigned_receipt(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    def fail_signing(*args, **kwargs):
        raise ValueError("signing failed")

    monkeypatch.setattr(cli_module, "sign_receipt", fail_signing)

    status, stdout, stderr = invoke(
        harness,
        tmp_path,
        monkeypatch,
        capsys,
        signing=(PRIVATE_KEY, ISSUER, KEYID),
    )

    assert status == 2
    assert stdout == ""
    assert "no receipt was emitted" in stderr


def test_package_signing_failure_preserves_error_channel_and_filesystem(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    set_valid_attestation(harness)
    root = tmp_path / "packages"

    def fail_signing(*args, **kwargs):
        raise ValueError("package-signing-canary")

    monkeypatch.setattr("release_proof_mcp.evidence_package.sign_receipt", fail_signing)

    status, stdout, stderr = invoke(
        harness,
        tmp_path,
        monkeypatch,
        capsys,
        signing=(PRIVATE_KEY, ISSUER, KEYID),
        package_root=root,
    )

    assert status == 2
    assert stdout == ""
    assert stderr == "error: command failed; no receipt was emitted\n"
    assert not root.exists()


def test_empty_package_root_is_rejected_before_verification(
    tmp_path: Path, harness: Harness, monkeypatch, capsys
) -> None:
    request = tmp_path / "request.json"
    request.write_text(json.dumps(harness.request), encoding="utf-8")
    monkeypatch.setenv("RELEASE_PROOF_EVIDENCE_PACKAGE_ROOT", "")
    calls = []

    def fail_if_called(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("capture must not be called")

    monkeypatch.setattr(cli_module, "capture_release", fail_if_called)
    original_mode = tmp_path.stat().st_mode & 0o777

    status = cli_module.main(["capture", "--request", str(request)])
    captured = capsys.readouterr()

    assert status == 2
    assert captured.out == ""
    assert calls == []
    assert tmp_path.stat().st_mode & 0o777 == original_mode
