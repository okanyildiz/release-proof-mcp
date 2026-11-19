from __future__ import annotations

import json
import math
import os
import sys
import threading
import time
from typing import Any, BinaryIO, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .version import __version__
from .policy import PolicyConfigurationError, PolicyStore
from .request import INPUT_SCHEMA, ValidationError, VerificationRequest
from .signers.openbao import (
    DEFAULT_OPENBAO_TIMEOUT_SECONDS,
    OpenBaoTransitSigner,
    load_openbao_public_key,
)
from .signing import ReceiptSigner, load_ed25519_private_key, sign_receipt
from .verifier import ReleaseVerifier

PROTOCOL_VERSION = "2025-06-18"
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 512 * 1024
WORKER_SHUTDOWN_SECONDS = 130.0
MAX_CONCURRENT_CALLS = 4

RECEIPT_PROOF_GUIDANCE = (
    "The receipt document itself is not a cryptographic signature. `proof` exists only when "
    "DSSE signing is explicitly configured; absence of `proof` means unsigned regardless of "
    "schema_version, receipt_id, or status. Never infer proof from failed/verified status alone."
)

TOOL_DEFINITION = {
    "name": "verify_release_deployment",
    "description": (
        "Read-only verification of GitHub source/review/run/release evidence, GitHub artifact "
        "provenance, GHCR digests, and Kubernetes running image IDs under an operator-supplied "
        "server-side policy profile. A verified result is not a claim that software is secure. "
        + RECEIPT_PROOF_GUIDANCE
    ),
    "inputSchema": INPUT_SCHEMA,
}


class MCPServer:
    def __init__(
        self,
        verifier_factory: Callable[[], ReleaseVerifier] | None = None,
        *,
        policy_store: PolicyStore | None = None,
        policy_file: str | None = None,
        policy_profile: str | None = None,
        notification_sink: Callable[[dict[str, Any]], None] | None = None,
        max_concurrent_calls: int = MAX_CONCURRENT_CALLS,
        signer: Ed25519PrivateKey | ReceiptSigner | None = None,
        signing_issuer: str | None = None,
        signing_keyid: str | None = None,
    ) -> None:
        if (
            not isinstance(max_concurrent_calls, int)
            or isinstance(max_concurrent_calls, bool)
            or max_concurrent_calls < 1
        ):
            raise ValueError("max_concurrent_calls must be a positive integer")
        signing = _injected_signing_configuration(
            signer, signing_issuer, signing_keyid
        )
        if signing is None:
            signing = _environment_signing_configuration()
        self._signing = signing
        self.verifier_factory = (
            self._default_verifier if verifier_factory is None else verifier_factory
        )
        self.policy_store = policy_store
        self.policy_file = policy_file
        self.policy_profile = policy_profile
        self.notification_sink = notification_sink
        self.max_concurrent_calls = max_concurrent_calls
        self._lifecycle = "new"
        self._lifecycle_lock = threading.Lock()
        self._cancel_events: dict[Any, threading.Event] = {}
        self._cancel_lock = threading.Lock()
        self._workers: set[threading.Thread] = set()
        self._active_request_ids: set[str | int] = set()
        self._worker_lock = threading.Lock()
        self._write_lock = threading.Lock()

    def _default_verifier(self) -> ReleaseVerifier:
        return ReleaseVerifier(
            verifier_instance_id=os.environ.get("RELEASE_PROOF_VERIFIER_INSTANCE_ID"),
            build_digest=os.environ.get("RELEASE_PROOF_BUILD_DIGEST"),
        )

    def handle(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        is_notification = "id" not in message
        if not is_notification and not _valid_request_id(request_id):
            return _error(None, -32600, "Invalid Request")
        method = message.get("method")
        if not isinstance(method, str):
            return None if is_notification else _error(request_id, -32600, "Invalid Request")
        if is_notification:
            if method == "notifications/initialized":
                with self._lifecycle_lock:
                    if self._lifecycle == "initialized":
                        self._lifecycle = "ready"
            elif method == "notifications/cancelled":
                self._cancel(message)
            return None
        if method == "initialize":
            return self._initialize(request_id, message.get("params"))
        if method == "ping":
            return _result(request_id, {})
        if not self._is_ready():
            return _error(request_id, -32600, "Server is not initialized")
        if method == "tools/list":
            return _result(request_id, {"tools": [TOOL_DEFINITION]})
        if method == "tools/call":
            return self._handle_tool_call(request_id, message.get("params"))
        return _error(request_id, -32601, "Method not found")

    def _initialize(self, request_id: Any, params: Any) -> dict[str, Any]:
        with self._lifecycle_lock:
            if self._lifecycle != "new":
                return _error(request_id, -32600, "Server is already initialized")
            if not _valid_initialize_params(params):
                return _error(request_id, -32602, "Invalid initialize parameters")
            self._lifecycle = "initialized"
        return _result(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "release-proof-mcp", "version": __version__},
                "instructions": (
                    "Use verify_release_deployment for read-only evidence under the server operator's "
                    "active trusted policy. Both failed and unknown mean not verified. "
                    + RECEIPT_PROOF_GUIDANCE
                ),
            },
        )

    def _is_ready(self) -> bool:
        with self._lifecycle_lock:
            return self._lifecycle == "ready"

    def _handle_tool_call(
        self,
        request_id: Any,
        params: Any,
        *,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any] | None:
        owns_cancel_event = cancel_event is None
        if cancel_event is None:
            cancel_event = self._ensure_cancel_event(request_id)
        try:
            try:
                if not isinstance(params, dict) or params.get("name") != TOOL_DEFINITION["name"]:
                    response = _error(request_id, -32602, "Unknown tool or invalid tool parameters")
                else:
                    progress_token = _progress_token(params)
                    active_profile = self.policy_profile or os.environ.get("RELEASE_PROOF_POLICY_PROFILE")
                    policy = self._policies().select(active_profile)
                    request = VerificationRequest.from_dict(
                        params.get("arguments"),
                        signer_workflow_default=policy.signer_workflow,
                        signer_digest_default=policy.signer_digest,
                    )
                    progress = (
                        self._progress_callback(progress_token, cancel_event)
                        if progress_token is not None
                        else None
                    )
                    report = self.verifier_factory().verify(
                        request,
                        policy,
                        cancel_event=cancel_event,
                        progress=progress,
                    )
                    if self._signing is not None:
                        signer, signing_issuer, signing_keyid = self._signing
                        report = sign_receipt(
                            report,
                            signer,
                            signing_issuer,
                            signing_keyid,
                            cancel_event=cancel_event,
                        )
                    encoded = json.dumps(
                        report, sort_keys=True, separators=(",", ":"), allow_nan=False
                    )
                    if len(encoded.encode("utf-8")) > MAX_RECEIPT_BYTES:
                        response = _error(
                            request_id,
                            -32603,
                            "Verification receipt exceeded the size limit; no evidence claim was returned",
                        )
                    else:
                        response = _result(
                            request_id,
                            {
                                "content": [{"type": "text", "text": encoded}],
                                "structuredContent": report,
                                "isError": False,
                            },
                        )
            except ValidationError as error:
                response = _error(request_id, -32602, str(error))
            except PolicyConfigurationError:
                response = _error(
                    request_id,
                    -32603,
                    "Trusted policy is unavailable or the requested profile is not configured",
                )
            except Exception:
                response = _error(
                    request_id,
                    -32603,
                    "Verification failed internally; no evidence claim was produced",
                )
            return None if cancel_event.is_set() else response
        finally:
            if owns_cancel_event:
                self._remove_cancel_event(request_id, cancel_event)

    def _policies(self) -> PolicyStore:
        if self.policy_store is not None:
            return self.policy_store
        path = self.policy_file or os.environ.get("RELEASE_PROOF_POLICY_FILE")
        if not path:
            raise PolicyConfigurationError("Trusted policy is not configured.")
        return PolicyStore.from_file(path)

    def _ensure_cancel_event(self, request_id: Any) -> threading.Event:
        with self._cancel_lock:
            event = self._cancel_events.get(request_id)
            if event is None:
                event = threading.Event()
                self._cancel_events[request_id] = event
            return event

    def _remove_cancel_event(self, request_id: Any, event: threading.Event) -> None:
        with self._cancel_lock:
            if self._cancel_events.get(request_id) is event:
                self._cancel_events.pop(request_id, None)

    def _cancel(self, message: dict[str, Any]) -> None:
        params = message.get("params")
        request_id = params.get("requestId") if isinstance(params, dict) else None
        if not _valid_request_id(request_id):
            return
        with self._cancel_lock:
            event = self._cancel_events.get(request_id)
        if event is not None:
            event.set()

    def _cancel_all(self) -> None:
        with self._cancel_lock:
            events = list(self._cancel_events.values())
        for event in events:
            event.set()

    def _progress_callback(
        self, token: str | int, cancel_event: threading.Event
    ) -> Callable[[str], None]:
        counter = 0

        def progress(stage: str) -> None:
            nonlocal counter
            if cancel_event.is_set():
                return
            counter += 1
            self._notify(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {
                        "progressToken": token,
                        "progress": counter,
                        "message": stage,
                    },
                }
            )

        return progress

    def _notify(self, notification: dict[str, Any]) -> None:
        if self.notification_sink is not None:
            self.notification_sink(notification)

    def serve(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
        input_stream = sys.stdin.buffer if stdin is None else stdin
        output_stream = sys.stdout.buffer if stdout is None else stdout
        if self.notification_sink is None:
            self.notification_sink = lambda notification: self._write(output_stream, notification)
        try:
            while True:
                line = input_stream.readline(MAX_MESSAGE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_MESSAGE_BYTES:
                    while not line.endswith(b"\n"):
                        line = input_stream.readline(MAX_MESSAGE_BYTES + 1)
                        if not line:
                            break
                    self._write(
                        output_stream,
                        _error(None, -32600, "Request exceeds the message size limit"),
                    )
                    continue
                if not line.strip():
                    continue
                try:
                    message = json.loads(
                        line.decode("utf-8"), parse_constant=_reject_json_constant
                    )
                except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError):
                    self._write(output_stream, _error(None, -32700, "Parse error"))
                    continue
                if (
                    isinstance(message, dict)
                    and message.get("jsonrpc") == "2.0"
                    and message.get("method") == "tools/call"
                    and "id" in message
                    and _valid_request_id(message.get("id"))
                    and self._is_ready()
                ):
                    request_id = message["id"]
                    with self._worker_lock:
                        duplicate = request_id in self._active_request_ids
                        at_capacity = (
                            not duplicate and len(self._workers) >= self.max_concurrent_calls
                        )
                        if not duplicate and not at_capacity:
                            cancel_event = threading.Event()

                            def run_worker(
                                message: dict[str, Any] = message,
                                cancel_event: threading.Event = cancel_event,
                            ) -> None:
                                try:
                                    self._handle_and_write(
                                        message, output_stream, cancel_event=cancel_event
                                    )
                                finally:
                                    with self._worker_lock:
                                        self._workers.discard(threading.current_thread())
                                        self._active_request_ids.discard(message["id"])

                            worker = threading.Thread(target=run_worker, daemon=True)
                            with self._cancel_lock:
                                self._cancel_events[request_id] = cancel_event
                            self._workers.add(worker)
                            self._active_request_ids.add(request_id)
                    if duplicate:
                        self._write(output_stream, _error(request_id, -32600, "Invalid Request"))
                        continue
                    if at_capacity:
                        self._write(output_stream, _error(request_id, -32000, "Server busy"))
                        continue
                    try:
                        worker.start()
                    except Exception:
                        with self._worker_lock:
                            self._workers.discard(worker)
                            self._active_request_ids.discard(request_id)
                        self._remove_cancel_event(request_id, cancel_event)
                        self._write(
                            output_stream,
                            _error(request_id, -32603, "Unable to start verification worker"),
                        )
                    continue
                response = self.handle(message)
                if response is not None:
                    self._write(output_stream, response)
        finally:
            self._cancel_all()
            deadline = time.monotonic() + WORKER_SHUTDOWN_SECONDS
            with self._worker_lock:
                workers = list(self._workers)
            for worker in workers:
                worker.join(timeout=max(0.0, deadline - time.monotonic()))

    def _handle_and_write(
        self,
        message: dict[str, Any],
        output: BinaryIO,
        *,
        cancel_event: threading.Event | None = None,
    ) -> None:
        request_id = message["id"]
        if cancel_event is None:
            cancel_event = self._ensure_cancel_event(request_id)
        try:
            response = self._handle_tool_call(
                request_id, message.get("params"), cancel_event=cancel_event
            )
            if response is not None and not cancel_event.is_set():
                self._write(output, response)
        finally:
            self._remove_cancel_event(request_id, cancel_event)

    def _write(self, stream: BinaryIO, response: dict[str, Any]) -> None:
        encoded = json.dumps(
            response, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8") + b"\n"
        with self._write_lock:
            stream.write(encoded)
            stream.flush()


SigningBackend = Ed25519PrivateKey | ReceiptSigner
SigningConfiguration = tuple[SigningBackend, str, str]

FILE_SIGNING_ENVIRONMENT = (
    "RELEASE_PROOF_SIGNING_KEY_FILE",
    "RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY",
)
SHARED_SIGNING_ENVIRONMENT = (
    "RELEASE_PROOF_SIGNING_ISSUER",
    "RELEASE_PROOF_SIGNING_KEY_ID",
)
OPENBAO_SIGNING_ENVIRONMENT = (
    "RELEASE_PROOF_OPENBAO_ADDRESS",
    "RELEASE_PROOF_OPENBAO_TRANSIT_MOUNT",
    "RELEASE_PROOF_OPENBAO_KEY_NAME",
    "RELEASE_PROOF_OPENBAO_KEY_VERSION",
    "RELEASE_PROOF_OPENBAO_PUBLIC_KEY_FILE",
    "RELEASE_PROOF_OPENBAO_TOKEN",
    "RELEASE_PROOF_OPENBAO_KUBERNETES_ROLE",
    "RELEASE_PROOF_OPENBAO_CA_FILE",
    "RELEASE_PROOF_OPENBAO_TIMEOUT_SECONDS",
    "RELEASE_PROOF_OPENBAO_ALLOW_INSECURE_LOOPBACK",
)


def _injected_signing_configuration(
    signer: SigningBackend | None,
    signing_issuer: str | None,
    signing_keyid: str | None,
) -> SigningConfiguration | None:
    supplied = (
        signer is not None,
        signing_issuer is not None,
        signing_keyid is not None,
    )
    if not any(supplied):
        return None
    if not all(supplied):
        raise ValueError(
            "signer, signing_issuer, and signing_keyid must be supplied together"
        )
    if not isinstance(signer, (Ed25519PrivateKey, ReceiptSigner)):
        raise ValueError("signer must be an Ed25519 private key or ReceiptSigner")
    if not isinstance(signing_issuer, str) or not signing_issuer.strip():
        raise ValueError("signing_issuer must be a nonempty string")
    if not isinstance(signing_keyid, str) or not signing_keyid.strip():
        raise ValueError("signing_keyid must be a nonempty string")
    return signer, signing_issuer, signing_keyid


def _environment_signing_configuration() -> SigningConfiguration | None:
    names = (
        *FILE_SIGNING_ENVIRONMENT,
        *SHARED_SIGNING_ENVIRONMENT,
        *OPENBAO_SIGNING_ENVIRONMENT,
    )
    values = {name: os.environ.get(name) for name in names}
    if all(value is None for value in values.values()):
        return None
    file_configured = any(values[name] is not None for name in FILE_SIGNING_ENVIRONMENT)
    openbao_configured = any(
        values[name] is not None for name in OPENBAO_SIGNING_ENVIRONMENT
    )
    if file_configured and openbao_configured:
        raise ValueError("File and OpenBao signing backends are mutually exclusive")
    if file_configured:
        return _file_signing_configuration(values)
    if openbao_configured:
        return _openbao_signing_configuration(values)
    raise ValueError("A signing backend is required with signing identity settings")


def _file_signing_configuration(
    values: dict[str, str | None],
) -> SigningConfiguration:
    key_file = _required_setting(values, "RELEASE_PROOF_SIGNING_KEY_FILE")
    issuer = _required_setting(values, "RELEASE_PROOF_SIGNING_ISSUER")
    keyid = _required_setting(values, "RELEASE_PROOF_SIGNING_KEY_ID")
    if values["RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY"] != "1":
        raise ValueError("File signing keys require explicit opt-in")
    return load_ed25519_private_key(key_file), issuer, keyid


def _openbao_signing_configuration(
    values: dict[str, str | None],
) -> SigningConfiguration:
    address = _required_setting(values, "RELEASE_PROOF_OPENBAO_ADDRESS")
    transit_mount = _required_setting(
        values, "RELEASE_PROOF_OPENBAO_TRANSIT_MOUNT"
    )
    key_name = _required_setting(values, "RELEASE_PROOF_OPENBAO_KEY_NAME")
    key_version = _positive_integer_setting(
        values, "RELEASE_PROOF_OPENBAO_KEY_VERSION"
    )
    public_key_file = _required_setting(
        values, "RELEASE_PROOF_OPENBAO_PUBLIC_KEY_FILE"
    )
    issuer = _required_setting(values, "RELEASE_PROOF_SIGNING_ISSUER")
    keyid = _required_setting(values, "RELEASE_PROOF_SIGNING_KEY_ID")
    token = values["RELEASE_PROOF_OPENBAO_TOKEN"]
    kubernetes_role = values["RELEASE_PROOF_OPENBAO_KUBERNETES_ROLE"]
    if (token is None) == (kubernetes_role is None):
        raise ValueError(
            "Configure exactly one of RELEASE_PROOF_OPENBAO_TOKEN or "
            "RELEASE_PROOF_OPENBAO_KUBERNETES_ROLE"
        )
    timeout_setting = values["RELEASE_PROOF_OPENBAO_TIMEOUT_SECONDS"]
    timeout_seconds = (
        DEFAULT_OPENBAO_TIMEOUT_SECONDS
        if timeout_setting is None
        else _positive_float(timeout_setting, "RELEASE_PROOF_OPENBAO_TIMEOUT_SECONDS")
    )
    public_key = load_openbao_public_key(public_key_file)
    signer = OpenBaoTransitSigner(
        address=address,
        transit_mount=transit_mount,
        key_name=key_name,
        key_version=key_version,
        keyid=keyid,
        public_key=public_key,
        token=token,
        kubernetes_role=kubernetes_role,
        ca_file=values["RELEASE_PROOF_OPENBAO_CA_FILE"],
        timeout_seconds=timeout_seconds,
        allow_insecure_loopback=(
            values["RELEASE_PROOF_OPENBAO_ALLOW_INSECURE_LOOPBACK"] == "1"
        ),
    )
    return signer, issuer, keyid


def _required_setting(
    values: dict[str, str | None], name: str
) -> str:
    value = values[name]
    if value is None or not value.strip():
        raise ValueError(f"{name} is required")
    return value


def _positive_integer_setting(
    values: dict[str, str | None], name: str
) -> int:
    value = _required_setting(values, name)
    if not value.isascii() or not value.isdigit() or value.startswith("0"):
        raise ValueError(f"{name} must be a positive integer")
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"{name} must be a positive integer") from None


def _positive_float(value: str, name: str) -> float:
    try:
        parsed = float(value)
    except ValueError:
        raise ValueError(f"{name} must be positive and finite") from None
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{name} must be positive and finite")
    return parsed


def _valid_request_id(request_id: Any) -> bool:
    return isinstance(request_id, str) or (
        isinstance(request_id, int) and not isinstance(request_id, bool)
    )


def _valid_initialize_params(params: Any) -> bool:
    if not isinstance(params, dict):
        return False
    protocol_version = params.get("protocolVersion")
    capabilities = params.get("capabilities")
    client_info = params.get("clientInfo")
    return (
        isinstance(protocol_version, str)
        and bool(protocol_version)
        and isinstance(capabilities, dict)
        and isinstance(client_info, dict)
        and isinstance(client_info.get("name"), str)
        and bool(client_info.get("name"))
        and isinstance(client_info.get("version"), str)
        and bool(client_info.get("version"))
    )


def _progress_token(params: dict[str, Any]) -> str | int | None:
    metadata = params.get("_meta")
    if not isinstance(metadata, dict) or "progressToken" not in metadata:
        return None
    token = metadata["progressToken"]
    if not _valid_request_id(token):
        raise ValidationError("Invalid _meta progressToken")
    if isinstance(token, str):
        try:
            token_size = len(token.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise ValidationError("Invalid _meta progressToken") from error
        if token_size > 256:
            raise ValidationError("_meta progressToken exceeds 256 UTF-8 bytes")
    return token


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
