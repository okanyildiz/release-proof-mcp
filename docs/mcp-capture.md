# Appendix: raw stdio MCP capture

Use the [CLI-centered flow in section 7](../GUIDE.md#7-capture-a-receipt-with-the-cli) for normal capture. This advanced example shows the underlying MCP protocol for clients that need direct control of the stdio lifecycle.

The inline Python starts the real server, completes `initialize` and `notifications/initialized`, calls `verify_release_deployment`, and keeps stdin open until the matching tool response arrives. It handles JSON-RPC errors, skips notifications, serializes `result.structuredContent` without changing its fields, and writes owner-only files. Run it in the configured producer environment after replacing the sanitized expectations and installation paths.

The transport is strict newline-delimited JSON-RPC 2.0, not `Content-Length` framing. The client waits for the matching initialization response and checks protocol version `2025-06-18` before sending the initialized notification and tool call. Each response is limited to 2 MiB with a 150-second timeout. After the tool response, the `finally` block closes stdin to begin clean server shutdown, waits up to 140 seconds, then escalates to terminate and kill if necessary.

```sh
/absolute/path/release-proof-mcp/.venv/bin/python - <<'PY'
import json
import os
import select
import subprocess
import time
import uuid
from pathlib import Path

SERVER = "/absolute/path/release-proof-mcp/.venv/bin/release-proof-mcp"
EXPECTATIONS = "/secure/consumer/config/consumer-expectations.json"
NONCE = "/secure/work/consumer-nonce.txt"
RECEIPT_ROOT = "/secure/receipts"
PACKAGE_ROOT = "/secure/evidence/packages"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
RESPONSE_TIMEOUT = 150

with open(EXPECTATIONS, "r", encoding="utf-8") as source:
    expectation = json.load(source)
subject = expectation["subject"]
if subject["artifact_input"] != subject["pinned_artifact"]:
    raise ValueError("This capture example requires digest-form artifact input")
nonce = Path(NONCE).read_text(encoding="ascii").rstrip("\r\n")
arguments = {
    key: subject[key]
    for key in (
        "repo",
        "expected_commit",
        "workflow",
        "source_ref",
        "kube_context",
        "namespace",
        "deployment",
        "container",
    )
}
arguments["artifact"] = subject["artifact_input"]
arguments["consumer_nonce"] = nonce
if subject["expected_run"] is not None:
    arguments["expected_run"] = subject["expected_run"]

process = subprocess.Popen(
    [SERVER],
    cwd="/absolute/path/release-proof-mcp",
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    bufsize=0,
)
if process.stdin is None or process.stdout is None:
    raise RuntimeError("MCP pipes were not created")


def send(message):
    frame = json.dumps(
        message, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii") + b"\n"
    process.stdin.write(frame)
    process.stdin.flush()


def response_for(request_id):
    deadline = time.monotonic() + RESPONSE_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Timed out waiting for the MCP response")
        ready, _, _ = select.select([process.stdout], [], [], remaining)
        if not ready:
            raise TimeoutError("Timed out waiting for the MCP response")
        line = process.stdout.readline(MAX_RESPONSE_BYTES + 1)
        if not line:
            raise RuntimeError("MCP server closed stdout before responding")
        if len(line) > MAX_RESPONSE_BYTES:
            raise ValueError("MCP response exceeds the capture limit")
        message = json.loads(line.decode("utf-8"))
        if not isinstance(message, dict):
            raise ValueError("MCP response is not an object")
        if "id" not in message:
            continue
        if message.get("id") != request_id:
            raise ValueError("MCP response has an unexpected request ID")
        if "error" in message:
            error = message["error"]
            raise RuntimeError(
                f"MCP JSON-RPC error {error.get('code')}: {error.get('message')}"
            )
        result = message.get("result")
        if not isinstance(result, dict):
            raise ValueError("MCP response has no object result")
        return result


def write_private(path, data, overwrite):
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


try:
    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "release-proof-capture", "version": "1"},
        },
    })
    initialized = response_for(1)
    if initialized.get("protocolVersion") != "2025-06-18":
        raise ValueError("MCP protocol version mismatch")
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "verify_release_deployment",
            "arguments": arguments,
        },
    })
    result = response_for(2)
    if result.get("isError") is not False:
        raise RuntimeError("MCP tool returned an error result")
    receipt = result.get("structuredContent")
    if not isinstance(receipt, dict):
        raise ValueError("MCP tool result has no structuredContent receipt")
    receipt_id = receipt.get("receipt_id")
    parsed_id = uuid.UUID(receipt_id) if isinstance(receipt_id, str) else None
    if parsed_id is None or parsed_id.version != 4 or str(parsed_id) != receipt_id:
        raise ValueError("Receipt has no canonical UUID4 receipt_id")
    encoded = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    write_private(f"{RECEIPT_ROOT}/{receipt_id}.json", encoded, overwrite=False)
    write_private("/secure/work/current-receipt-id", receipt_id.encode("ascii"), overwrite=True)
    print(f"receipt_id={receipt_id}")
    print(f"receipt_file={RECEIPT_ROOT}/{receipt_id}.json")
    if "evidence_package" in receipt:
        print(f"package_directory={PACKAGE_ROOT}/{receipt_id}")
    else:
        print("package_directory=none; retain the signed audit receipt")
finally:
    try:
        process.stdin.close()
    except BrokenPipeError:
        pass
    try:
        process.wait(timeout=140)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    process.stdout.close()
PY
```

Do **not** treat `release-proof-mcp > /secure/receipts/receipt.json` as sufficient. Server stdout carries JSON-RPC envelopes and can carry multiple messages, including notifications. It is not a bare receipt channel. The consumer requires the signed receipt object from `structuredContent` or the exported package, not an initialization response or protocol transcript.

A JSON-RPC error produces no evidence claim. A successful tool response whose receipt has `status=failed` or `unknown` is still saved as an audit receipt, signed when signing is configured, but the consumer will deny it. The CLI and this MCP example use the same policy, verification, signing, and optional evidence-package capture path. See [package creation and location](../GUIDE.md#package-creation-and-location) for export behavior and the five package files.
