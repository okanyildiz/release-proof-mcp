from __future__ import annotations

import json
import sys
from typing import Any, BinaryIO, Callable

from .request import INPUT_SCHEMA, ValidationError, VerificationRequest
from .verifier import ReleaseVerifier

PROTOCOL_VERSION = "2025-06-18"
MAX_MESSAGE_BYTES = 1024 * 1024

TOOL_DEFINITION = {
    "name": "verify_release_deployment",
    "description": (
        "Read-only, point-in-time verification of GitHub source/review/run/release evidence, "
        "GitHub artifact provenance, GHCR digests, and Kubernetes running image IDs. "
        "A verified result is not a claim that software is secure."
    ),
    "inputSchema": INPUT_SCHEMA,
}


class MCPServer:
    def __init__(self, verifier_factory: Callable[[], ReleaseVerifier] = ReleaseVerifier) -> None:
        self.verifier_factory = verifier_factory

    def handle(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, -32600, "Invalid Request")
        method = message.get("method")
        request_id = message.get("id")
        is_notification = "id" not in message
        if not isinstance(method, str):
            return None if is_notification else _error(request_id, -32600, "Invalid Request")
        if is_notification:
            return None
        if method == "initialize":
            return _result(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "release-proof-mcp", "version": "0.1.0"},
                    "instructions": (
                        "Use verify_release_deployment for read-only evidence. "
                        "Both failed and unknown mean not verified."
                    ),
                },
            )
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            return _result(request_id, {"tools": [TOOL_DEFINITION]})
        if method == "tools/call":
            params = message.get("params")
            if not isinstance(params, dict) or params.get("name") != TOOL_DEFINITION["name"]:
                return _error(request_id, -32602, "Unknown tool or invalid tool parameters")
            try:
                request = VerificationRequest.from_dict(params.get("arguments"))
                report = self.verifier_factory().verify(request)
            except ValidationError as error:
                return _error(request_id, -32602, str(error))
            except Exception:
                return _error(request_id, -32603, "Verification failed internally; no evidence claim was produced")
            return _result(
                request_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(report, sort_keys=True, separators=(",", ":")),
                        }
                    ],
                    "structuredContent": report,
                    "isError": False,
                },
            )
        return _error(request_id, -32601, "Method not found")

    def serve(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
        input_stream = sys.stdin.buffer if stdin is None else stdin
        output_stream = sys.stdout.buffer if stdout is None else stdout
        while True:
            line = input_stream.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                return
            if len(line) > MAX_MESSAGE_BYTES:
                self._write(output_stream, _error(None, -32600, "Request exceeds the message size limit"))
                continue
            if not line.strip():
                continue
            try:
                message = json.loads(line)
                response = self.handle(message)
            except (json.JSONDecodeError, UnicodeDecodeError):
                response = _error(None, -32700, "Parse error")
            if response is not None:
                self._write(output_stream, response)

    @staticmethod
    def _write(stream: BinaryIO, response: dict[str, Any]) -> None:
        stream.write(json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n")
        stream.flush()


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
