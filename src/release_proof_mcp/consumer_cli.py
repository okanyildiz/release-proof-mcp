from __future__ import annotations

import argparse
import json
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .consumer import read_bounded_file, load_strict_json_file, verify_receipt


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise _UsageError


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except _UsageError:
        return _print_input_error("USAGE_ERROR")

    try:
        public_key = _load_public_key(args.trusted_public_key)
        receipt = load_strict_json_file(args.receipt)
        expectation_value = load_strict_json_file(args.expectations)
        expected_subject, expected_verifier = _expectations(expectation_value)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        return _print_input_error("INPUT_ERROR")

    decision = verify_receipt(
        receipt,
        {args.keyid: public_key},
        expected_issuer=args.issuer,
        expected_subject=expected_subject,
        expected_policy_hash=args.policy_hash,
        expected_verifier=expected_verifier,
        expected_nonce=args.nonce,
        now=datetime.now(timezone.utc),
        max_age_seconds=args.max_age,
    )
    print(
        json.dumps(
            decision,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    )
    return 0 if decision["allow"] else 1


def load_ed25519_public_key(path: str | Path) -> Ed25519PublicKey:
    return _load_public_key(path)


def _load_public_key(path: str | Path) -> Ed25519PublicKey:
    key = load_pem_public_key(read_bounded_file(path))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("The trusted key must be an Ed25519 public key.")
    return key


def _expectations(value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {"subject", "verifier"}:
        raise ValueError("Expectations require exactly subject and verifier objects.")
    subject = value["subject"]
    verifier = value["verifier"]
    if not isinstance(subject, dict) or not isinstance(verifier, dict):
        raise ValueError("Expected subject and verifier must be objects.")
    return subject, verifier


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("max-age must be nonnegative")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        description=(
            "Verify one signed release receipt with an explicitly loaded Ed25519 PEM public key. "
            "Receipt and expectation JSON files are limited to 2 MiB."
        )
    )
    parser.add_argument("receipt", help="signed receipt JSON path")
    parser.add_argument(
        "--trusted-public-key",
        "--public-key",
        dest="trusted_public_key",
        required=True,
        help="trusted Ed25519 public key PEM path",
    )
    parser.add_argument("--keyid", required=True, help="trusted key identifier")
    parser.add_argument(
        "--expectations",
        "--expectation",
        dest="expectations",
        required=True,
        help="JSON file containing complete subject and verifier objects",
    )
    parser.add_argument("--issuer", required=True, help="expected receipt issuer")
    parser.add_argument("--policy-hash", required=True, help="expected SHA-256 policy hash")
    parser.add_argument("--nonce", required=True, help="fresh consumer challenge")
    parser.add_argument(
        "--max-age",
        required=True,
        type=_nonnegative_int,
        help="maximum receipt age in seconds",
    )
    return parser


def _print_input_error(reason: str) -> int:
    decision = {
        "allow": False,
        "decision_id": str(uuid.uuid4()),
        "receipt_id": None,
        "receipt_digest": None,
        "policy_hash": None,
        "reason": reason,
        "evaluated_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    print(json.dumps(decision, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
