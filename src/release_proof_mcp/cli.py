from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from .capture import (
    MAX_RECEIPT_BYTES,
    CaptureResult,
    SigningConfiguration,
    capture_release,
    load_policy_store,
    verifier_from_environment,
)
from .consumer import load_strict_json_file, read_bounded_file
from .demo import run_demo
from .mcp import _environment_signing_configuration
from .policy import PolicyStore
from .signing import sign_receipt


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise _UsageError


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="release-proof", description="Capture release deployment evidence.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    capture = subcommands.add_parser(
        "capture",
        help="verify one release and emit its receipt JSON",
    )
    capture.add_argument("--request", required=True, help="MCP tool arguments as a JSON file")
    capture.add_argument("--nonce-file", help="file containing a fresh consumer nonce")
    capture.add_argument("--out", help="new receipt output file; existing files are never replaced")
    subcommands.add_parser(
        "demo",
        help="run the signed evidence flow entirely on simulated data",
    )
    return parser


def _read_nonce(path: str | Path) -> str:
    raw = read_bounded_file(path)
    try:
        return raw.decode("ascii").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise ValueError("Nonce file must contain ASCII base64url text") from error


def _write_new_output(path: str | Path, raw: bytes) -> None:
    output_path = Path(path)
    parent = output_path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("Output parent must be a real directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output_path, flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Receipt output did not advance")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(output_path)
        except OSError:
            pass
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _emit(captured: CaptureResult, out: str | None) -> None:
    encoded = captured.encoded + b"\n"
    if out is not None:
        _write_new_output(out, encoded)
    else:
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()


def _run_capture(
    args: argparse.Namespace,
    *,
    verifier_factory: Any = None,
    policy_store: PolicyStore | None = None,
    signing: SigningConfiguration | None = None,
    receipt_signer: Any = sign_receipt,
) -> int:
    arguments = load_strict_json_file(args.request)
    if not isinstance(arguments, dict):
        raise ValueError("Capture request must be a JSON object")
    if args.nonce_file:
        arguments["consumer_nonce"] = _read_nonce(args.nonce_file)
    policies = policy_store or load_policy_store()
    verifier = (
        verifier_from_environment()
        if verifier_factory is None
        else verifier_factory()
    )
    captured = capture_release(
        arguments,
        policy_store=policies,
        verifier=verifier,
        active_profile=os.environ.get("RELEASE_PROOF_POLICY_PROFILE"),
        signing=(
            _environment_signing_configuration() if signing is None else signing
        ),
        evidence_package_root=os.environ.get("RELEASE_PROOF_EVIDENCE_PACKAGE_ROOT"),
        max_receipt_bytes=MAX_RECEIPT_BYTES,
        receipt_signer=receipt_signer,
    )
    _emit(captured, args.out)
    return 0 if captured.receipt["status"] == "verified" else 1


def main(
    argv: Sequence[str] | None = None,
    *,
    verifier_factory: Any = None,
    policy_store: PolicyStore | None = None,
    signing: SigningConfiguration | None = None,
    receipt_signer: Any = sign_receipt,
) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command == "demo":
            return run_demo()
        if args.command != "capture":
            raise _UsageError
        return _run_capture(
            args,
            verifier_factory=verifier_factory,
            policy_store=policy_store,
            signing=signing,
            receipt_signer=receipt_signer,
        )
    except Exception:
        sys.stderr.write("error: command failed; no receipt was emitted\n")
        sys.stderr.flush()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
