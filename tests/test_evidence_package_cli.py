from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from conftest import Harness
from test_consumer_cli import cli_arguments, run_cli
from release_proof_mcp.receipt_validation import canonical_json_bytes
from release_proof_mcp.signing import sign_receipt
from test_evidence_package import (
    BUNDLE_FILE,
    RECEIPT_FILE,
    PackageCase,
    publish,
    refresh_manifest_attachments,
)
from test_signing import ISSUER, KEYID, PRIVATE_KEY, public_key_pem

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


@pytest.fixture
def cli_case(tmp_path: Path, harness: Harness) -> tuple[PackageCase, dict[str, Path]]:
    case = publish(harness, tmp_path / "operator")
    now = datetime.now(timezone.utc)
    receipt = copy.deepcopy(case.receipt)
    receipt["started_at"] = (now - timedelta(seconds=60)).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    receipt["completed_at"] = (now - timedelta(seconds=30)).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    unsigned = {
        key: value
        for key, value in receipt.items()
        if key not in {"proof", "proof_metadata"}
    }
    case.receipt = sign_receipt(
        unsigned, PRIVATE_KEY, ISSUER, KEYID, clock=lambda: now
    )
    (case.path / RECEIPT_FILE).write_bytes(canonical_json_bytes(case.receipt))
    key = tmp_path / "trusted-public.pem"
    expectations = tmp_path / "expectations.json"
    key.write_bytes(public_key_pem())
    expectations.write_text(
        json.dumps(
            {
                "subject": case.receipt["subject"],
                "verifier": case.receipt["verifier"],
            }
        ),
        encoding="utf-8",
    )
    return case, {"receipt": case.path, "key": key, "expectations": expectations}


def arguments(paths: dict[str, Path], **overrides: str) -> list[str]:
    return cli_arguments(paths, **overrides)


def run_without_provider_credentials(arguments_value: list[str], home: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for name in list(environment):
        if (
            name.startswith(("RELEASE_PROOF_OPENBAO_", "OPENBAO", "VAULT_"))
            or name
            in {
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GHCR_REGISTRY_TOKEN",
                "DOCKER_AUTH_CONFIG",
                "COSIGN_PASSWORD",
                "KUBECONFIG",
            }
        ):
            environment.pop(name, None)
    environment["PATH"] = ""
    environment["HOME"] = str(home)
    environment["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "release_proof_mcp.consumer_cli", *arguments_value],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def assert_bounded_decision(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert len(result.stdout) < 1024
    decision = json.loads(result.stdout)
    assert set(decision) == DECISION_FIELDS
    return decision


def test_package_allows_in_separate_process_without_provider_credentials(
    cli_case: tuple[PackageCase, dict[str, Path]], tmp_path: Path
) -> None:
    case, paths = cli_case

    result = run_without_provider_credentials(arguments(paths), tmp_path / "empty-home")

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    decision = assert_bounded_decision(result)
    assert decision["allow"] is True
    assert decision["reason"] == "OK"
    assert decision["receipt_id"] == case.receipt["receipt_id"]
    assert "buildDefinition" not in result.stdout
    assert "resolvedDependencies" not in result.stdout


def test_standalone_package_bearing_receipt_requires_package(
    cli_case: tuple[PackageCase, dict[str, Path]],
) -> None:
    case, paths = cli_case
    paths["receipt"] = case.path / "receipt.json"

    result = run_cli(arguments(paths))

    assert result.returncode == 1
    decision = assert_bounded_decision(result)
    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_REQUIRED"


def test_package_tamper_is_exit_one_without_printing_raw_contents(
    cli_case: tuple[PackageCase, dict[str, Path]],
) -> None:
    case, paths = cli_case
    marker = "DO_NOT_PRINT_PRIVATE_PACKAGE_CONTENT"
    (case.path / BUNDLE_FILE).write_text(
        json.dumps({"private": marker}), encoding="utf-8"
    )
    refresh_manifest_attachments(case.path)

    result = run_cli(arguments(paths))

    assert result.returncode == 1
    assert result.stderr == ""
    decision = assert_bounded_decision(result)
    assert decision["allow"] is False
    assert decision["reason"] == "BUNDLE_ATTACHMENT_MISMATCH"
    assert marker not in result.stdout
    assert marker not in result.stderr


def test_malformed_package_json_is_a_denial_not_a_usage_error(
    cli_case: tuple[PackageCase, dict[str, Path]],
) -> None:
    case, paths = cli_case
    (case.path / "receipt.json").write_bytes(
        b'{"schema_version":"first","schema\\u005fversion":"second"}'
    )

    result = run_cli(arguments(paths))

    assert result.returncode == 1
    assert assert_bounded_decision(result)["reason"] == "PACKAGE_JSON_INVALID"


def test_empty_package_directory_is_denied(
    cli_case: tuple[PackageCase, dict[str, Path]],
) -> None:
    case, paths = cli_case
    for item in case.path.iterdir():
        item.unlink()

    result = run_cli(arguments(paths))

    assert result.returncode == 1
    assert assert_bounded_decision(result)["reason"] == "PACKAGE_FILE_SET_INVALID"


def test_zip_input_is_rejected_as_input_error(
    cli_case: tuple[PackageCase, dict[str, Path]],
) -> None:
    _case, paths = cli_case
    archive = paths["receipt"].parent / "evidence.zip"
    archive.write_bytes(b"PK\x03\x04DO_NOT_EXTRACT")
    paths["receipt"] = archive

    result = run_cli(arguments(paths))

    assert result.returncode == 2
    assert result.stderr == ""
    decision = assert_bounded_decision(result)
    assert decision["allow"] is False
    assert decision["reason"] == "INPUT_ERROR"
    assert "DO_NOT_EXTRACT" not in result.stdout


def test_symlinked_package_path_is_an_input_error(
    cli_case: tuple[PackageCase, dict[str, Path]], tmp_path: Path
) -> None:
    case, paths = cli_case
    link = tmp_path / "package-link"
    link.symlink_to(case.path, target_is_directory=True)
    paths["receipt"] = link

    result = run_cli(arguments(paths))

    assert result.returncode == 2
    assert assert_bounded_decision(result)["reason"] == "INPUT_ERROR"


def test_fifo_receipt_path_is_an_input_error(
    cli_case: tuple[PackageCase, dict[str, Path]], tmp_path: Path
) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs are not available on this host")
    _case, paths = cli_case
    fifo = tmp_path / "receipt-fifo"
    os.mkfifo(fifo)
    paths["receipt"] = fifo

    result = run_cli(arguments(paths))

    assert result.returncode == 2
    assert assert_bounded_decision(result)["reason"] == "INPUT_ERROR"


def test_wrong_nonce_for_package_has_exit_one(
    cli_case: tuple[PackageCase, dict[str, Path]],
) -> None:
    _case, paths = cli_case

    result = run_cli(
        arguments(paths, nonce="Ab09_-abcdefghijklmnopqrstuv")
    )

    assert result.returncode == 1
    decision = assert_bounded_decision(result)
    assert decision["allow"] is False
    assert decision["reason"] == "NONCE_MISMATCH"
    assert decision["policy_hash"] is not None
