from __future__ import annotations

import io
import json
import threading
import time
from datetime import datetime, timezone
from typing import Any

import pytest

from conftest import Harness, base_input, policy_store
from release_proof_mcp.mcp import (
    MAX_MESSAGE_BYTES,
    MAX_RECEIPT_BYTES,
    MCPServer,
    PROTOCOL_VERSION,
)
from release_proof_mcp.verifier import ReleaseVerifier


def request(request_id: Any, method: str, params: dict | None = None) -> dict:
    value = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        value["params"] = params
    return value


def initialize_params(protocol_version: str = PROTOCOL_VERSION) -> dict:
    return {
        "protocolVersion": protocol_version,
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "1.0.0"},
    }


def initialize(
    server: MCPServer, *, ready: bool = True, protocol_version: str = PROTOCOL_VERSION
) -> dict:
    response = server.handle(request(1, "initialize", initialize_params(protocol_version)))
    if ready and "error" not in response:
        assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    return response


def real_verifier(harness: Harness) -> ReleaseVerifier:
    return ReleaseVerifier(
        harness.runner,
        clock=lambda: datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc),
    )


def test_initialize_and_exactly_one_tool_without_policy_arguments() -> None:
    server = MCPServer()

    initialized = initialize(server)
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


@pytest.mark.parametrize(
    "params",
    [
        None,
        [],
        {},
        {"protocolVersion": "", "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}},
        {"protocolVersion": 1, "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}},
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": [], "clientInfo": {"name": "c", "version": "1"}},
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}},
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": []},
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "", "version": "1"}},
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": 1, "version": "1"}},
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "c", "version": ""}},
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "c", "version": None}},
    ],
)
def test_initialize_requires_valid_client_and_capabilities(params: Any) -> None:
    server = MCPServer()

    response = server.handle(request(5, "initialize", params))
    premature = server.handle(request(6, "tools/list"))

    assert response["id"] == 5
    assert response["error"]["code"] == -32602
    assert premature["error"]["code"] == -32600


def test_lifecycle_requires_initialized_notification_and_allows_ping() -> None:
    server = MCPServer()

    assert server.handle(request(1, "tools/list"))["error"]["code"] == -32600
    assert server.handle(request(2, "ping"))["result"] == {}
    assert initialize(server, ready=False)["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert server.handle(request(3, "resources/list"))["error"]["code"] == -32600
    assert server.handle(request(4, "ping"))["result"] == {}

    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    assert server.handle(request(5, "tools/list"))["result"]["tools"]
    assert server.handle(request(6, "initialize", initialize_params()))["error"]["code"] == -32600


def test_well_formed_newer_protocol_request_falls_back_to_supported_version() -> None:
    server = MCPServer()

    response = initialize(server, protocol_version="2026-01-01")

    assert response["result"]["protocolVersion"] == "2025-06-18"
    assert server.handle(request(2, "tools/list"))["result"]["tools"]


@pytest.mark.parametrize("request_id", [None, 1.5, True, False, [], {}])
def test_invalid_json_rpc_request_ids_are_rejected_with_null_error_id(request_id: Any) -> None:
    response = MCPServer().handle(request(request_id, "ping"))

    assert response["id"] is None
    assert response["error"]["code"] == -32600


@pytest.mark.parametrize("request_id", [0, -1, "", "request-1"])
def test_string_and_integer_request_ids_are_accepted(request_id: Any) -> None:
    response = MCPServer().handle(request(request_id, "ping"))

    assert response["id"] == request_id
    assert response["result"] == {}


def test_cancellation_request_ids_use_the_same_validation() -> None:
    server = MCPServer()
    event = server._ensure_cancel_event(7)

    for request_id in (None, 1.5, True, [], {}):
        assert server.handle({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": request_id},
        }) is None
        assert not event.is_set()

    assert server.handle({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 7},
    }) is None
    assert event.is_set()
    server._remove_cancel_event(7, event)


def test_notifications_do_not_get_responses() -> None:
    server = MCPServer()
    initialize(server, ready=False)

    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.handle({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 99},
    }) is None


def test_unknown_method_and_tool_are_json_rpc_errors() -> None:
    server = MCPServer()
    initialize(server)

    method = server.handle(request(1, "resources/list"))
    tool = server.handle(request(2, "tools/call", {"name": "deploy_release", "arguments": {}}))

    assert method["error"]["code"] == -32601
    assert tool["error"]["code"] == -32602
    assert server._cancel_events == {}


def test_invalid_tool_arguments_are_invalid_params() -> None:
    server = MCPServer(policy_store=policy_store())
    initialize(server)

    response = server.handle(
        request(1, "tools/call", {"name": "verify_release_deployment", "arguments": {"repo": "acme/shop"}})
    )

    assert response["error"]["code"] == -32602
    assert "Missing required field" in response["error"]["message"]
    assert server._cancel_events == {}


def test_tool_call_requires_operator_policy() -> None:
    server = MCPServer()
    initialize(server)

    response = server.handle(
        request(1, "tools/call", {"name": "verify_release_deployment", "arguments": base_input()})
    )

    assert response["error"]["code"] == -32603
    assert "Trusted policy" in response["error"]["message"]


def test_tool_call_returns_structured_content_and_bounded_text(harness: Harness) -> None:
    server = MCPServer(lambda: real_verifier(harness), policy_store=policy_store())
    initialize(server)

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


def test_tool_call_inherits_omitted_signer_from_operator_policy(harness: Harness) -> None:
    server = MCPServer(lambda: real_verifier(harness), policy_store=policy_store())
    initialize(server)
    arguments = base_input()
    arguments.pop("signer_workflow")
    arguments.pop("signer_digest")

    response = server.handle(request(
        17,
        "tools/call",
        {"name": "verify_release_deployment", "arguments": arguments},
    ))

    assert response["result"]["structuredContent"]["status"] == "verified"


def test_mcp_progress_notifications_are_emitted(harness: Harness) -> None:
    notifications: list[dict] = []
    server = MCPServer(
        lambda: real_verifier(harness),
        policy_store=policy_store(),
        notification_sink=notifications.append,
    )
    initialize(server)

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
    assert notifications
    assert all(item["method"] == "notifications/progress" for item in notifications)
    assert all(item["params"]["progressToken"] == "release-8" for item in notifications)
    updates = [item["params"]["progress"] for item in notifications]
    assert all(type(update) is int and update >= 0 for update in updates)
    assert all(later > earlier for earlier, later in zip(updates, updates[1:]))
    assert all("total" not in item["params"] for item in notifications)


@pytest.mark.parametrize(
    "token", [None, True, False, 1.5, [], {}, "x" * 257, "é" * 129, "\ud800"]
)
def test_invalid_progress_tokens_are_invalid_params(token: Any) -> None:
    server = MCPServer(policy_store=policy_store())
    initialize(server)

    response = server.handle(request(
        8,
        "tools/call",
        {
            "name": "verify_release_deployment",
            "arguments": base_input(),
            "_meta": {"progressToken": token},
        },
    ))

    assert response["error"]["code"] == -32602
    assert server._cancel_events == {}


@pytest.mark.parametrize("token", ["é" * 128, 0, -7])
def test_valid_progress_tokens_have_no_inaccurate_total(token: Any) -> None:
    class ProgressVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            progress("checking")
            return {"status": "unknown"}

    notifications: list[dict] = []
    server = MCPServer(
        ProgressVerifier, policy_store=policy_store(), notification_sink=notifications.append
    )
    initialize(server)

    response = server.handle(request(
        8,
        "tools/call",
        {
            "name": "verify_release_deployment",
            "arguments": base_input(),
            "_meta": {"progressToken": token},
        },
    ))

    assert response["result"]["structuredContent"]["status"] == "unknown"
    assert notifications[0]["params"]["progressToken"] == token
    assert "total" not in notifications[0]["params"]


def test_stdio_tool_call_can_be_cancelled_without_blocking_other_requests() -> None:
    class BlockingVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            assert cancel_event.wait(2), "cancellation notification did not reach verification"
            progress("after cancellation")
            return {"status": "unknown", "policy": policy.profile}

    tool = request(9, "tools/call", {
        "name": "verify_release_deployment",
        "arguments": base_input(),
        "_meta": {"progressToken": "release-9"},
    })
    cancel = {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 9},
    }
    messages = b"\n".join([
        json.dumps(request(1, "initialize", initialize_params())).encode(),
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
        json.dumps(tool).encode(),
        json.dumps(cancel).encode(),
        json.dumps(request(10, "ping")).encode(),
    ]) + b"\n"
    output = io.BytesIO()
    server = MCPServer(BlockingVerifier, policy_store=policy_store())

    server.serve(io.BytesIO(messages), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    ping = next(item for item in responses if item.get("id") == 10)
    assert ping["result"] == {}
    assert all(item.get("id") != 9 for item in responses)
    assert all(item.get("method") != "notifications/progress" for item in responses)
    assert server._cancel_events == {}
    assert server._workers == set()
    assert server._active_request_ids == set()


def test_oversized_receipt_is_not_returned() -> None:
    class HugeVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            return {"status": "verified", "data": "x" * MAX_RECEIPT_BYTES}

    server = MCPServer(HugeVerifier, policy_store=policy_store())
    initialize(server)

    response = server.handle(
        request(11, "tools/call", {"name": "verify_release_deployment", "arguments": base_input()})
    )

    assert response["error"]["code"] == -32603
    assert "size limit" in response["error"]["message"]
    assert "result" not in response


def ndjson(messages: list[dict]) -> list[bytes]:
    return [json.dumps(message).encode() + b"\n" for message in messages]


class DrainWorkersInput(io.BytesIO):
    def __init__(self, data: bytes, server: MCPServer, drain_from: int) -> None:
        super().__init__(data)
        self.server = server
        self.drain_from = drain_from

    def readline(self, size: int = -1) -> bytes:
        if self.tell() >= self.drain_from:
            deadline = time.monotonic() + 2
            while True:
                with self.server._worker_lock:
                    idle = not self.server._workers
                if idle:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError("stdio workers did not drain")
                time.sleep(0.001)
        return super().readline(size)


def test_stdio_server_uses_newline_delimited_json_rpc() -> None:
    messages = b"".join(ndjson([
        request(1, "initialize", initialize_params()),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request(2, "ping"),
    ]))
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


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":NaN}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":Infinity}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":-Infinity}',
        b"[" * 2000 + b"]" * 2000,
        b'{"jsonrpc":"2.0","id":' + b"1" * 5000 + b',"method":"ping"}',
    ],
)
def test_stdio_parse_failures_do_not_stop_the_read_loop(payload: bytes) -> None:
    following_ping = json.dumps(request(99, "ping")).encode() + b"\n"
    output = io.BytesIO()

    MCPServer().serve(io.BytesIO(payload + b"\n" + following_ping), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert responses[0]["id"] is None
    assert responses[0]["error"]["code"] == -32700
    assert responses[1] == {"jsonrpc": "2.0", "id": 99, "result": {}}


def test_stdio_oversized_frame_discards_valid_ping_in_its_tail() -> None:
    discarded_ping = json.dumps(request(70, "ping")).encode()
    oversized = b" " * (MAX_MESSAGE_BYTES + 1) + discarded_ping + b"\n"
    following_ping = json.dumps(request(71, "ping")).encode() + b"\n"
    output = io.BytesIO()

    MCPServer().serve(io.BytesIO(oversized + following_ping), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(responses) == 2
    assert responses[0]["id"] is None
    assert "size limit" in responses[0]["error"]["message"]
    assert responses[1] == {"jsonrpc": "2.0", "id": 71, "result": {}}
    assert all(item.get("id") != 70 for item in responses)


def test_outbound_encoder_rejects_non_finite_numbers() -> None:
    server = MCPServer()

    for value in (float("nan"), float("inf"), float("-inf")):
        output = io.BytesIO()
        with pytest.raises(ValueError):
            server._write(output, {"jsonrpc": "2.0", "id": 1, "result": {"value": value}})
        assert output.getvalue() == b""


def test_stdio_non_finite_verifier_output_returns_an_internal_error() -> None:
    class NonFiniteVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            return {"status": "verified", "value": float("nan")}

    server = MCPServer(NonFiniteVerifier, policy_store=policy_store())
    lines = ndjson([
        request(1, "initialize", initialize_params()),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request(20, "tools/call", {
            "name": "verify_release_deployment",
            "arguments": base_input(),
        }),
        request(21, "ping"),
    ])
    output = io.BytesIO()
    input_stream = DrainWorkersInput(b"".join(lines), server, sum(map(len, lines[:2])))

    server.serve(input_stream, output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    failed = next(item for item in responses if item.get("id") == 20)
    assert failed["error"]["code"] == -32603
    assert "result" not in failed
    assert next(item for item in responses if item.get("id") == 21)["result"] == {}
    assert b"NaN" not in output.getvalue()
    assert b"Infinity" not in output.getvalue()


def test_stdio_concurrent_overload_is_rejected_while_ping_remains_responsive() -> None:
    started = 0
    started_lock = threading.Lock()
    all_started = threading.Event()

    class BlockingVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            nonlocal started
            with started_lock:
                started += 1
                if started == 4:
                    all_started.set()
            assert cancel_event.wait(2), "EOF did not cancel active verification"
            return {"status": "unknown"}

    class OverloadInput(io.BytesIO):
        def readline(self, size: int = -1) -> bytes:
            if self.tell() == overload_offset:
                assert all_started.wait(2), "four workers did not become active"
            return super().readline(size)

    tool_calls = [
        request(request_id, "tools/call", {
            "name": "verify_release_deployment",
            "arguments": base_input(),
        })
        for request_id in range(10, 15)
    ]
    lines = ndjson([
        request(1, "initialize", initialize_params()),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        *tool_calls,
        request(15, "ping"),
    ])
    overload_offset = sum(map(len, lines[:6]))
    server = MCPServer(BlockingVerifier, policy_store=policy_store())
    output = io.BytesIO()

    server.serve(OverloadInput(b"".join(lines)), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    busy = next(item for item in responses if item.get("id") == 14)
    assert busy["error"]["code"] == -32000
    assert next(item for item in responses if item.get("id") == 15)["result"] == {}
    assert all(item.get("id") not in {10, 11, 12, 13} for item in responses)
    assert started == 4
    assert server._workers == set()
    assert server._active_request_ids == set()
    assert server._cancel_events == {}


def test_stdio_workers_and_cancel_events_do_not_accumulate() -> None:
    class FastVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            return {"status": "unknown"}

    calls = [
        request(request_id, "tools/call", {
            "name": "verify_release_deployment",
            "arguments": base_input(),
        })
        for request_id in range(30, 36)
    ]
    calls.extend([
        request(36, "tools/call", {"name": "unknown", "arguments": {}}),
        request(37, "tools/call", {
            "name": "verify_release_deployment",
            "arguments": {},
        }),
    ])
    lines = ndjson([
        request(1, "initialize", initialize_params()),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        *calls,
    ])
    server = MCPServer(FastVerifier, policy_store=policy_store(), max_concurrent_calls=1)
    output = io.BytesIO()
    input_stream = DrainWorkersInput(b"".join(lines), server, sum(map(len, lines[:2])))

    server.serve(input_stream, output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(responses) == 9
    assert all(
        next(item for item in responses if item.get("id") == request_id)["result"]["structuredContent"]
        ["status"] == "unknown"
        for request_id in range(30, 36)
    )
    assert next(item for item in responses if item.get("id") == 36)["error"]["code"] == -32602
    assert next(item for item in responses if item.get("id") == 37)["error"]["code"] == -32602
    assert all(item["error"]["code"] != -32000 for item in responses if "error" in item)
    assert server._workers == set()
    assert server._active_request_ids == set()
    assert server._cancel_events == {}


def test_stdio_thread_start_failure_cleans_up_and_keeps_serving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_start(self) -> None:
        raise RuntimeError("cannot start thread")

    monkeypatch.setattr(threading.Thread, "start", fail_start)
    lines = ndjson([
        request(1, "initialize", initialize_params()),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request(40, "tools/call", {
            "name": "verify_release_deployment",
            "arguments": base_input(),
        }),
        request(41, "ping"),
    ])
    server = MCPServer(policy_store=policy_store())
    output = io.BytesIO()

    server.serve(io.BytesIO(b"".join(lines)), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert next(item for item in responses if item.get("id") == 40)["error"]["code"] == -32603
    assert next(item for item in responses if item.get("id") == 41)["result"] == {}
    assert server._workers == set()
    assert server._active_request_ids == set()
    assert server._cancel_events == {}


def test_stdio_invalid_tool_id_does_not_create_worker_or_cancellation_state() -> None:
    lines = ndjson([
        request(1, "initialize", initialize_params()),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request(1.5, "tools/call", {
            "name": "verify_release_deployment",
            "arguments": base_input(),
        }),
        request(42, "ping"),
    ])
    server = MCPServer(policy_store=policy_store())
    output = io.BytesIO()

    server.serve(io.BytesIO(b"".join(lines)), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    invalid = responses[1]
    assert invalid["id"] is None
    assert invalid["error"]["code"] == -32600
    assert responses[2]["id"] == 42
    assert server._workers == set()
    assert server._active_request_ids == set()
    assert server._cancel_events == {}


def test_stdio_duplicate_id_is_rejected_without_sharing_cancellation_state() -> None:
    cancel_events: list[threading.Event] = []
    events_lock = threading.Lock()
    first_started = threading.Event()
    second_started = threading.Event()
    release_first = threading.Event()
    second_cancelled = threading.Event()

    class BlockingVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            with events_lock:
                invocation = len(cancel_events)
                cancel_events.append(cancel_event)
            if invocation == 0:
                first_started.set()
                assert release_first.wait(2), "first call was not released"
                return {"status": "unknown", "invocation": "first"}
            if invocation == 1:
                second_started.set()
                assert cancel_event.wait(2), "second call did not receive cancellation"
                second_cancelled.set()
                return {"status": "unknown", "invocation": "second"}
            raise AssertionError("duplicate request reached the verifier")

    class ScriptedInput(io.BytesIO):
        def readline(self, size: int = -1) -> bytes:
            position = self.tell()
            if position == duplicate_offset:
                assert first_started.wait(2), "first call did not become active"
            elif position == second_call_offset:
                release_first.set()
                deadline = time.monotonic() + 2
                while True:
                    with server._worker_lock:
                        drained = not server._workers and not server._active_request_ids
                    if drained:
                        break
                    if time.monotonic() >= deadline:
                        raise AssertionError("first call did not finish cleanly")
                    time.sleep(0.001)
            elif position == cancel_offset:
                assert second_started.wait(2), "second call did not become active"
            return super().readline(size)

    tool = request(60, "tools/call", {
        "name": "verify_release_deployment",
        "arguments": base_input(),
    })
    cancel = {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 60},
    }
    lines = ndjson([
        request(1, "initialize", initialize_params()),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        tool,
        tool,
        request(61, "ping"),
        tool,
        cancel,
    ])
    duplicate_offset = sum(map(len, lines[:3]))
    second_call_offset = sum(map(len, lines[:5]))
    cancel_offset = sum(map(len, lines[:6]))
    server = MCPServer(BlockingVerifier, policy_store=policy_store())
    output = io.BytesIO()

    server.serve(ScriptedInput(b"".join(lines)), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(responses) == 4
    assert responses[1]["id"] == 60
    assert responses[1]["error"]["code"] == -32600
    assert responses[1]["error"]["message"] == "Invalid Request"
    assert responses[2] == {"jsonrpc": "2.0", "id": 61, "result": {}}
    assert responses[3]["id"] == 60
    assert responses[3]["result"]["structuredContent"]["invocation"] == "first"
    assert len(cancel_events) == 2
    assert cancel_events[0] is not cancel_events[1]
    assert not cancel_events[0].is_set()
    assert second_cancelled.is_set()
    assert server._workers == set()
    assert server._active_request_ids == set()
    assert server._cancel_events == {}


def test_stdio_ping_broken_pipe_cancels_and_joins_active_worker() -> None:
    started = threading.Event()
    cancelled = threading.Event()
    broken_pipe = BrokenPipeError("test broken pipe")

    class BlockingVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            started.set()
            assert cancel_event.wait(2), "broken pipe did not cancel verification"
            cancelled.set()
            return {"status": "unknown"}

    class BrokenPipeOutput(io.BytesIO):
        def write(self, data: bytes) -> int:
            if json.loads(data).get("id") == 71:
                raise broken_pipe
            return super().write(data)

    class StartedInput(io.BytesIO):
        def readline(self, size: int = -1) -> bytes:
            if self.tell() == ping_offset:
                assert started.wait(2), "tool worker did not become active"
            return super().readline(size)

    lines = ndjson([
        request(1, "initialize", initialize_params()),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request(70, "tools/call", {
            "name": "verify_release_deployment",
            "arguments": base_input(),
        }),
        request(71, "ping"),
    ])
    ping_offset = sum(map(len, lines[:3]))
    server = MCPServer(BlockingVerifier, policy_store=policy_store())
    output = BrokenPipeOutput()

    with pytest.raises(BrokenPipeError) as caught:
        server.serve(StartedInput(b"".join(lines)), output)

    assert caught.value is broken_pipe
    assert cancelled.is_set()
    assert server._workers == set()
    assert server._active_request_ids == set()
    assert server._cancel_events == {}


def test_malformed_json_rpc_request_is_rejected() -> None:
    response = MCPServer().handle([])

    assert response["error"]["code"] == -32600
