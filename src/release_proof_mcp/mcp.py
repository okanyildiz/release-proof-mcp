from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import Any, BinaryIO, Callable

from .policy import PolicyConfigurationError, PolicyStore
from .request import INPUT_SCHEMA, ValidationError, VerificationRequest
from .verifier import ReleaseVerifier

PROTOCOL_VERSION = "2025-06-18"
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 512 * 1024
WORKER_SHUTDOWN_SECONDS = 130.0

TOOL_DEFINITION = {
    "name": "verify_release_deployment",
    "description": (
        "Read-only verification of GitHub source/review/run/release evidence, GitHub artifact "
        "provenance, GHCR digests, and Kubernetes running image IDs under an operator-supplied "
        "server-side policy profile. A verified result is not a claim that software is secure."
    ),
    "inputSchema": INPUT_SCHEMA,
}


class MCPServer:
    def __init__(
        self,
        verifier_factory: Callable[[], ReleaseVerifier] = ReleaseVerifier,
        *,
        policy_store: PolicyStore | None = None,
        policy_file: str | None = None,
        policy_profile: str | None = None,
        notification_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.verifier_factory = verifier_factory
        self.policy_store = policy_store
        self.policy_file = policy_file
        self.policy_profile = policy_profile
        self.notification_sink = notification_sink
        self._cancel_events: dict[Any, threading.Event] = {}
        self._cancel_lock = threading.Lock()
        self._write_lock = threading.Lock()

    def handle(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, -32600, "Invalid Request")
        method = message.get("method")
        request_id = message.get("id")
        is_notification = "id" not in message
        if not isinstance(method, str):
            return None if is_notification else _error(request_id, -32600, "Invalid Request")
        if is_notification:
            if method == "notifications/cancelled":
                self._cancel(message)
            return None
        if method == "initialize":
            return _result(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "release-proof-mcp", "version": "0.1.0"},
                    "instructions": (
                        "Use verify_release_deployment for read-only evidence under the server operator's "
                        "active trusted policy. Both failed and unknown mean not verified."
                    ),
                },
            )
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            return _result(request_id, {"tools": [TOOL_DEFINITION]})
        if method == "tools/call":
            return self._handle_tool_call(request_id, message.get("params"))
        return _error(request_id, -32601, "Method not found")

    def _handle_tool_call(self, request_id: Any, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict) or params.get("name") != TOOL_DEFINITION["name"]:
            return _error(request_id, -32602, "Unknown tool or invalid tool parameters")
        try:
            hash(request_id)
        except TypeError:
            return _error(None, -32600, "Invalid Request")
        cancel_event = self._ensure_cancel_event(request_id)
        try:
            request = VerificationRequest.from_dict(params.get("arguments"))
            active_profile = self.policy_profile or os.environ.get("RELEASE_PROOF_POLICY_PROFILE")
            policy = self._policies().select(active_profile)
            metadata = params.get("_meta")
            progress_token = metadata.get("progressToken") if isinstance(metadata, dict) else None
            progress = (
                self._progress_callback(progress_token)
                if progress_token is not None
                else None
            )
            report = self.verifier_factory().verify(
                request,
                policy,
                cancel_event=cancel_event,
                progress=progress,
            )
            encoded = json.dumps(
                report, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
            if len(encoded.encode("utf-8")) > MAX_RECEIPT_BYTES:
                return _error(
                    request_id,
                    -32603,
                    "Verification receipt exceeded the size limit; no evidence claim was returned",
                )
            return _result(
                request_id,
                {
                    "content": [{"type": "text", "text": encoded}],
                    "structuredContent": report,
                    "isError": False,
                },
            )
        except ValidationError as error:
            return _error(request_id, -32602, str(error))
        except PolicyConfigurationError:
            return _error(
                request_id,
                -32603,
                "Trusted policy is unavailable or the requested profile is not configured",
            )
        except Exception:
            return _error(request_id, -32603, "Verification failed internally; no evidence claim was produced")
        finally:
            with self._cancel_lock:
                if self._cancel_events.get(request_id) is cancel_event:
                    self._cancel_events.pop(request_id, None)

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

    def _cancel(self, message: dict[str, Any]) -> None:
        params = message.get("params")
        request_id = params.get("requestId") if isinstance(params, dict) else None
        try:
            hash(request_id)
        except TypeError:
            return
        with self._cancel_lock:
            event = self._cancel_events.get(request_id)
        if event is not None:
            event.set()

    def _progress_callback(self, token: Any) -> Callable[[str], None]:
        counter = 0

        def progress(stage: str) -> None:
            nonlocal counter
            counter += 1
            self._notify(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {
                        "progressToken": token,
                        "progress": counter,
                        "total": 11,
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
        workers: list[threading.Thread] = []
        while True:
            line = input_stream.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_MESSAGE_BYTES:
                self._write(output_stream, _error(None, -32600, "Request exceeds the message size limit"))
                continue
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._write(output_stream, _error(None, -32700, "Parse error"))
                continue
            if (
                isinstance(message, dict)
                and message.get("method") == "tools/call"
                and "id" in message
            ):
                try:
                    hash(message.get("id"))
                    self._ensure_cancel_event(message.get("id"))
                except TypeError:
                    pass
                worker = threading.Thread(
                    target=self._handle_and_write,
                    args=(message, output_stream),
                    daemon=True,
                )
                workers.append(worker)
                worker.start()
                continue
            response = self.handle(message)
            if response is not None:
                self._write(output_stream, response)
        deadline = time.monotonic() + WORKER_SHUTDOWN_SECONDS
        for worker in workers:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))

    def _handle_and_write(self, message: dict[str, Any], output: BinaryIO) -> None:
        response = self.handle(message)
        if response is not None:
            self._write(output, response)

    def _write(self, stream: BinaryIO, response: dict[str, Any]) -> None:
        encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
        with self._write_lock:
            stream.write(encoded)
            stream.flush()


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
