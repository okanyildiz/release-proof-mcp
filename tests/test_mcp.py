from __future__ import annotations

import io
import json
import threading
from datetime import datetime, timezone

from conftest import Harness, base_input, policy_store
from release_proof_mcp.mcp import (
    MAX_MESSAGE_BYTES,
    MAX_RECEIPT_BYTES,
    MCPServer,
    PROTOCOL_VERSION,
)
from release_proof_mcp.verifier import ReleaseVerifier


def request(request_id: int, method: str, params: dict | None = None) -> dict:
    value = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        value["params"] = params
    return value


def real_verifier(harness: Harness) -> ReleaseVerifier:
    return ReleaseVerifier(
        harness.runner,
        clock=lambda: datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc),
    )


def test_initialize_and_exactly_one_tool_without_policy_arguments() -> None:
    server = MCPServer()

    initialized = server.handle(request(1, "initialize"))
    listed = server.handle(request(2, "tools/list"))

    assert initialized["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert initialized["result"]["capabilities"] == {"tools": {"listChanged": False}}
    tools = listed["result"]["tools"]
    assert len(tools) == 1
    assert tools[0]["name"] == "verify_release_deployment"
    assert tools[0]["inputSchema"]["additionalProperties"] is False
    assert not {"review", "release", "require_cosign_signature", "policy_profile"} & set(
        tools[0]["inputSchema"]["properties"]
    )
    assert "read-only" in tools[0]["description"].lower()


def test_notifications_do_not_get_responses() -> None:
    server = MCPServer()

    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.handle({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 99},
    }) is None


def test_unknown_method_and_tool_are_json_rpc_errors() -> None:
    server = MCPServer()

    method = server.handle(request(1, "resources/list"))
    tool = server.handle(request(2, "tools/call", {"name": "deploy_release", "arguments": {}}))

    assert method["error"]["code"] == -32601
    assert tool["error"]["code"] == -32602


def test_invalid_tool_arguments_are_invalid_params() -> None:
    server = MCPServer(policy_store=policy_store())

    response = server.handle(
        request(1, "tools/call", {"name": "verify_release_deployment", "arguments": {"repo": "acme/shop"}})
    )

    assert response["error"]["code"] == -32602
    assert "Missing required field" in response["error"]["message"]


def test_tool_call_requires_operator_policy() -> None:
    response = MCPServer().handle(
        request(1, "tools/call", {"name": "verify_release_deployment", "arguments": base_input()})
    )

    assert response["error"]["code"] == -32603
    assert "Trusted policy" in response["error"]["message"]


def test_tool_call_returns_structured_content_and_bounded_text(harness: Harness) -> None:
    server = MCPServer(lambda: real_verifier(harness), policy_store=policy_store())

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
    assert result["structuredContent"]["effective_policy"]["profile"] == "production"
    assert result["structuredContent"]["policy_hash"].startswith("sha256:")
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    assert result["content"][0]["type"] == "text"
    assert len(result["content"][0]["text"].encode()) <= MAX_RECEIPT_BYTES


def test_mcp_progress_notifications_are_emitted(harness: Harness) -> None:
    notifications: list[dict] = []
    server = MCPServer(
        lambda: real_verifier(harness),
        policy_store=policy_store(),
        notification_sink=notifications.append,
    )

    response = server.handle(request(
        8,
        "tools/call",
        {
            "name": "verify_release_deployment",
            "arguments": base_input(),
            "_meta": {"progressToken": "release-8"},
        },
    ))

    assert response["result"]["structuredContent"]["status"] == "verified"
    assert len(notifications) == 10
    assert all(item["method"] == "notifications/progress" for item in notifications)
    assert notifications[0]["params"]["progressToken"] == "release-8"
    assert [item["params"]["progress"] for item in notifications] == list(range(1, 11))


def test_stdio_tool_call_can_be_cancelled_without_blocking_other_requests() -> None:
    class BlockingVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            assert cancel_event.wait(2), "cancellation notification did not reach verification"
            return {"status": "unknown", "policy": policy.profile}

    tool = request(9, "tools/call", {"name": "verify_release_deployment", "arguments": base_input()})
    cancel = {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 9},
    }
    messages = b"\n".join(
        [json.dumps(tool).encode(), json.dumps(cancel).encode(), json.dumps(request(10, "ping")).encode()]
    ) + b"\n"
    output = io.BytesIO()
    server = MCPServer(BlockingVerifier, policy_store=policy_store())

    server.serve(io.BytesIO(messages), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    ping = next(item for item in responses if item.get("id") == 10)
    completed = next(item for item in responses if item.get("id") == 9)
    assert ping["result"] == {}
    assert completed["result"]["structuredContent"]["status"] == "unknown"


def test_oversized_receipt_is_not_returned() -> None:
    class HugeVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            return {"status": "verified", "data": "x" * MAX_RECEIPT_BYTES}

    response = MCPServer(HugeVerifier, policy_store=policy_store()).handle(
        request(11, "tools/call", {"name": "verify_release_deployment", "arguments": base_input()})
    )

    assert response["error"]["code"] == -32603
    assert "size limit" in response["error"]["message"]
    assert "result" not in response


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
