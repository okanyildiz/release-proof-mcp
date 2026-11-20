from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from release_proof_mcp.consumer import MAX_CONSUMER_FILE_BYTES
from release_proof_mcp.consumer_cli import main
from release_proof_mcp.signing import sign_receipt
from test_signing import (
    ISSUER,
    KEYID,
    NONCE,
    POLICY_HASH,
    PRIVATE_KEY,
    nonverified_receipt,
    public_key_pem,
    unsigned_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
DECISION_FIELDS = {
    "allow",
    "decision_id",
    "receipt_id",
    "receipt_digest",
    "policy_hash",
    "reason",
    "evaluated_at",
}


def timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def write_cli_inputs(tmp_path: Path, **receipt_overrides: Any) -> dict[str, Path]:
    now = datetime.now(timezone.utc)
    status = receipt_overrides.pop("status", "verified")
    receipt = (
        nonverified_receipt(status)
        if status != "verified"
        else unsigned_receipt()
    )
    receipt.update(receipt_overrides)
    receipt["started_at"] = timestamp(now - timedelta(seconds=60))
    receipt["completed_at"] = timestamp(now - timedelta(seconds=30))
    receipt["evidence"]["commit"]["sensitive_marker"] = "DO_NOT_PRINT_FULL_EVIDENCE"
    signed = sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID, clock=lambda: now)
    receipt_path = tmp_path / "receipt.json"
    key_path = tmp_path / "trusted-public.pem"
    expectations_path = tmp_path / "expectations.json"
    receipt_path.write_text(json.dumps(signed), encoding="utf-8")
    key_path.write_bytes(public_key_pem())
    expectations_path.write_text(
        json.dumps({"subject": receipt["subject"], "verifier": receipt["verifier"]}),
        encoding="utf-8",
    )
    return {
        "receipt": receipt_path,
        "key": key_path,
        "expectations": expectations_path,
    }


def cli_arguments(paths: dict[str, Path], **overrides: str) -> list[str]:
    values = {
        "keyid": KEYID,
        "issuer": ISSUER,
        "policy_hash": POLICY_HASH,
        "nonce": NONCE,
        "max_age": "300",
    }
    values.update(overrides)
    return [
        str(paths["receipt"]),
        "--trusted-public-key",
        str(paths["key"]),
        "--keyid",
        values["keyid"],
        "--expectations",
        str(paths["expectations"]),
        "--issuer",
        values["issuer"],
        "--policy-hash",
        values["policy_hash"],
        "--nonce",
        values["nonce"],
        "--max-age",
        values["max_age"],
    ]


def run_cli(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(ROOT / "src") + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    return subprocess.run(
        [sys.executable, "-m", "release_proof_mcp.consumer_cli", *arguments],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_verified_receipt_allows_in_separate_cli_process(tmp_path: Path) -> None:
    paths = write_cli_inputs(tmp_path)

    result = run_cli(cli_arguments(paths))

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    decision = json.loads(result.stdout)
    assert decision["allow"] is True
    assert decision["reason"] == "OK"
    assert set(decision) == DECISION_FIELDS
    assert str(uuid.UUID(decision["decision_id"])) == decision["decision_id"]
    assert decision["policy_hash"] == POLICY_HASH
    assert "DO_NOT_PRINT_FULL_EVIDENCE" not in result.stdout
    assert "evidence" not in decision


def test_policy_rejection_has_exit_one_and_bounded_json(tmp_path: Path) -> None:
    paths = write_cli_inputs(tmp_path)

    result = run_cli(cli_arguments(paths, nonce="Ab09_-abcdefghijklmnopqrstuv"))

    assert result.returncode == 1
    decision = json.loads(result.stdout)
    assert decision["allow"] is False
    assert decision["reason"] == "NONCE_MISMATCH"
    assert set(decision) == DECISION_FIELDS
    assert "DO_NOT_PRINT_FULL_EVIDENCE" not in result.stdout


def test_failed_signed_receipt_has_exit_one(tmp_path: Path) -> None:
    paths = write_cli_inputs(tmp_path, status="failed")

    result = run_cli(cli_arguments(paths))

    assert result.returncode == 1
    assert json.loads(result.stdout)["reason"] == "STATUS_NOT_VERIFIED"


def test_duplicate_receipt_json_has_exit_two_without_echoing_input(tmp_path: Path) -> None:
    paths = write_cli_inputs(tmp_path)
    paths["receipt"].write_text(
        '{"schema_version":"first","schema_version":"second",'
        '"private":"DO_NOT_PRINT_PRIVATE_DATA"}',
        encoding="utf-8",
    )

    result = run_cli(cli_arguments(paths))

    assert result.returncode == 2
    decision = json.loads(result.stdout)
    assert decision["allow"] is False
    assert decision["reason"] == "INPUT_ERROR"
    assert set(decision) == DECISION_FIELDS
    assert "DO_NOT_PRINT_PRIVATE_DATA" not in result.stdout
    assert "DO_NOT_PRINT_PRIVATE_DATA" not in result.stderr


def test_duplicate_expectation_json_has_exit_two(tmp_path: Path) -> None:
    paths = write_cli_inputs(tmp_path)
    paths["expectations"].write_text(
        '{"subject":{"repo":"acme/shop"},"subject":{"repo":"acme/other"}}',
        encoding="utf-8",
    )

    result = run_cli(cli_arguments(paths))

    assert result.returncode == 2
    assert json.loads(result.stdout)["reason"] == "INPUT_ERROR"


def test_invalid_utf8_and_nonfinite_json_have_exit_two(tmp_path: Path) -> None:
    for content in (b"\xff", b'{"number":1e999}'):
        paths = write_cli_inputs(tmp_path)
        paths["receipt"].write_bytes(content)
        result = run_cli(cli_arguments(paths))
        assert result.returncode == 2
        assert json.loads(result.stdout)["reason"] == "INPUT_ERROR"


@pytest.mark.parametrize("input_name", ["receipt", "expectations", "key"])
def test_consumer_files_over_two_mib_are_rejected_with_bounded_output(
    tmp_path: Path, input_name: str
) -> None:
    paths = write_cli_inputs(tmp_path)
    paths[input_name].write_bytes(b"x" * (MAX_CONSUMER_FILE_BYTES + 1))

    result = run_cli(cli_arguments(paths))

    assert result.returncode == 2
    assert len(result.stdout) < 1024
    assert json.loads(result.stdout)["reason"] == "INPUT_ERROR"


def test_cli_expectations_require_full_subject_and_verifier(tmp_path: Path) -> None:
    paths = write_cli_inputs(tmp_path)
    value = json.loads(paths["expectations"].read_text())
    del value["subject"]["pinned_artifact"]
    paths["expectations"].write_text(json.dumps(value))

    omitted_artifact = run_cli(cli_arguments(paths))
    value = json.loads(paths["expectations"].read_text())
    value["subject"] = unsigned_receipt()["subject"]
    del value["verifier"]
    paths["expectations"].write_text(json.dumps(value))
    missing_verifier = run_cli(cli_arguments(paths))

    assert omitted_artifact.returncode == 1
    assert json.loads(omitted_artifact.stdout)["reason"] == "SUBJECT_EXPECTATION_INVALID"
    assert missing_verifier.returncode == 2
    assert json.loads(missing_verifier.stdout)["reason"] == "INPUT_ERROR"


def test_usage_error_returns_two_as_json(capsys: Any) -> None:
    exit_code = main([])

    assert exit_code == 2
    decision = json.loads(capsys.readouterr().out)
    assert decision["allow"] is False
    assert decision["reason"] == "USAGE_ERROR"
    assert set(decision) == DECISION_FIELDS


def test_invalid_public_key_and_missing_file_are_input_errors(tmp_path: Path) -> None:
    paths = write_cli_inputs(tmp_path)
    paths["key"].write_bytes(b"not a PEM public key")
    invalid_key = run_cli(cli_arguments(paths))
    paths["receipt"].unlink()
    missing_receipt = run_cli(cli_arguments(paths))

    assert invalid_key.returncode == 2
    assert json.loads(invalid_key.stdout)["reason"] == "INPUT_ERROR"
    assert missing_receipt.returncode == 2
    assert json.loads(missing_receipt.stdout)["reason"] == "INPUT_ERROR"
