from __future__ import annotations

import io
import json
from datetime import datetime, timezone

from conftest import Harness, base_input
from release_proof_mcp.mcp import MAX_MESSAGE_BYTES, MCPServer, PROTOCOL_VERSION
from release_proof_mcp.verifier import ReleaseVerifier


def request(request_id: int, method: str, params: dict | None = None) -> dict:
    value = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        value["params"] = params
    return value


def test_initialize_and_exactly_one_tool() -> None:
    server = MCPServer()

    initialized = server.handle(request(1, "initialize"))
    listed = server.handle(request(2, "tools/list"))

    assert initialized["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert initialized["result"]["capabilities"] == {"tools": {"listChanged": False}}
    tools = listed["result"]["tools"]
    assert len(tools) == 1
    assert tools[0]["name"] == "verify_release_deployment"
    assert tools[0]["inputSchema"]["additionalProperties"] is False
    assert "read-only" in tools[0]["description"].lower()


def test_notifications_do_not_get_responses() -> None:
    server = MCPServer()

    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_method_and_tool_are_json_rpc_errors() -> None:
    server = MCPServer()

    method = server.handle(request(1, "resources/list"))
    tool = server.handle(request(2, "tools/call", {"name": "deploy_release", "arguments": {}}))

    assert method["error"]["code"] == -32601
    assert tool["error"]["code"] == -32602


def test_invalid_tool_arguments_are_invalid_params() -> None:
    server = MCPServer()

    response = server.handle(
        request(1, "tools/call", {"name": "verify_release_deployment", "arguments": {"repo": "acme/shop"}})
    )

    assert response["error"]["code"] == -32602
    assert "Missing required field" in response["error"]["message"]


def test_tool_call_returns_structured_content_and_bounded_text(harness: Harness) -> None:
    server = MCPServer(
        lambda: ReleaseVerifier(
            harness.runner,
            clock=lambda: datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc),
        )
    )

    response = server.handle(
        request(
            7,
            "tools/call",
            {"name": "verify_release_deployment", "arguments": base_input()},
        )
    )

    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["status"] == "verified"
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    assert result["content"][0]["type"] == "text"


def test_stdio_server_uses_newline_delimited_json_rpc() -> None:
    messages = b"\n".join(
        [
            json.dumps(request(1, "initialize")).encode(),
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
            json.dumps(request(2, "ping")).encode(),
        ]
    ) + b"\n"
    output = io.BytesIO()

    MCPServer().serve(io.BytesIO(messages), output)

    lines = output.getvalue().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["id"] == 1
    assert json.loads(lines[1]) == {"jsonrpc": "2.0", "id": 2, "result": {}}
    assert not output.getvalue().startswith(b"Content-Length")


def test_stdio_parse_error_and_size_limit() -> None:
    output = io.BytesIO()
    oversized = b" " * (MAX_MESSAGE_BYTES + 1) + b"\n"

    MCPServer().serve(io.BytesIO(b"not-json\n" + oversized), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert responses[0]["error"]["code"] == -32700
    assert any("size limit" in item["error"]["message"] for item in responses[1:])


def test_malformed_json_rpc_request_is_rejected() -> None:
    response = MCPServer().handle([])

    assert response["error"]["code"] == -32600
