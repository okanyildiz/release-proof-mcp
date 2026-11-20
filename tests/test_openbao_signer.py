from __future__ import annotations

import base64
import copy
import http.client
import json
import logging
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from conftest import policy_store
from release_proof_mcp.mcp import (
    FILE_SIGNING_ENVIRONMENT,
    OPENBAO_SIGNING_ENVIRONMENT,
    SHARED_SIGNING_ENVIRONMENT,
    MCPServer,
)
from release_proof_mcp.signers.openbao import (
    MAX_OPENBAO_RESPONSE_BYTES,
    OpenBaoCancelledError,
    OpenBaoError,
    OpenBaoHTTPError,
    OpenBaoTimeoutError,
    OpenBaoTransitSigner,
)
from test_signed_mcp import StaticVerifier, call_receipt
from test_signing import ISSUER, PAYLOAD_TYPE, dsse_pae

PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = PRIVATE_KEY.public_key()
WRONG_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
KEY_VERSION = 7
KEYID = f"release-proof-openbao/v{KEY_VERSION}"
TOKEN = "s.unit-test-token"
MESSAGE = b"DSSEv1 exact raw input\x00\xfb\xff"
REAL_HTTP_CONNECTION = http.client.HTTPConnection


@dataclass
class RecordedRequest:
    host: str
    port: int | None
    timeout: float
    context: ssl.SSLContext | None
    method: str
    path: str
    body: bytes
    headers: dict[str, str]

    @property
    def json(self) -> dict[str, Any]:
        return json.loads(self.body)


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.body = body
        self.status = status
        self.headers = headers or {}
        self.offset = 0

    def getheader(self, name: str) -> str | None:
        return self.headers.get(name)

    def read(self, size: int = -1) -> bytes:
        end = len(self.body) if size < 0 else min(len(self.body), self.offset + size)
        chunk = self.body[self.offset : end]
        self.offset = end
        return chunk


class FakeConnection:
    handler: Callable[[RecordedRequest], FakeResponse]
    requests: list[RecordedRequest] = []
    instances: list[FakeConnection] = []

    def __init__(
        self,
        host: str,
        port: int | None = None,
        *,
        timeout: float,
        context: ssl.SSLContext | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.sock = None
        self.closed = False
        self.response: FakeResponse | None = None
        type(self).instances.append(self)

    def request(
        self, method: str, path: str, *, body: bytes, headers: dict[str, str]
    ) -> None:
        request = RecordedRequest(
            self.host,
            self.port,
            self.timeout,
            self.context,
            method,
            path,
            body,
            headers,
        )
        type(self).requests.append(request)
        self.response = type(self).handler(request)

    def connect(self) -> None:
        pass

    def getresponse(self) -> FakeResponse:
        assert self.response is not None
        return self.response

    def close(self) -> None:
        self.closed = True

    @classmethod
    def reset(cls) -> None:
        cls.requests = []
        cls.instances = []
        cls.handler = lambda request: FakeResponse(
            signature_response(base64.b64decode(request.json["input"], validate=True))
        )


@pytest.fixture(autouse=True)
def fake_transport(monkeypatch: pytest.MonkeyPatch) -> type[FakeConnection]:
    FakeConnection.reset()
    monkeypatch.setattr(http.client, "HTTPConnection", FakeConnection)
    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConnection)
    return FakeConnection


@pytest.fixture(autouse=True)
def clear_signing_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        *FILE_SIGNING_ENVIRONMENT,
        *SHARED_SIGNING_ENVIRONMENT,
        *OPENBAO_SIGNING_ENVIRONMENT,
    ):
        monkeypatch.delenv(name, raising=False)


def signature_response(
    message: bytes,
    *,
    signer: Ed25519PrivateKey = PRIVATE_KEY,
    version: int = KEY_VERSION,
) -> bytes:
    signature = signer.sign(message)
    value = f"vault:v{version}:{base64.b64encode(signature).decode('ascii')}"
    return json.dumps({"data": {"signature": value}}, separators=(",", ":")).encode()


def make_signer(**overrides: Any) -> OpenBaoTransitSigner:
    options: dict[str, Any] = {
        "address": "https://openbao.example:8200",
        "transit_mount": "transit",
        "key_name": "release-proof",
        "key_version": KEY_VERSION,
        "keyid": KEYID,
        "public_key": PUBLIC_KEY,
        "token": TOKEN,
        "timeout_seconds": 2.0,
    }
    options.update(overrides)
    return OpenBaoTransitSigner(**options)


def public_key_pem(signer: Ed25519PrivateKey = PRIVATE_KEY) -> bytes:
    return signer.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


def set_remote_environment(
    monkeypatch: pytest.MonkeyPatch,
    public_key_file: Path,
    **overrides: str | None,
) -> None:
    values: dict[str, str | None] = {
        "RELEASE_PROOF_OPENBAO_ADDRESS": "https://openbao.example:8200",
        "RELEASE_PROOF_OPENBAO_TRANSIT_MOUNT": "transit",
        "RELEASE_PROOF_OPENBAO_KEY_NAME": "release-proof",
        "RELEASE_PROOF_OPENBAO_KEY_VERSION": str(KEY_VERSION),
        "RELEASE_PROOF_OPENBAO_PUBLIC_KEY_FILE": str(public_key_file),
        "RELEASE_PROOF_OPENBAO_TOKEN": TOKEN,
        "RELEASE_PROOF_SIGNING_ISSUER": ISSUER,
        "RELEASE_PROOF_SIGNING_KEY_ID": KEYID,
    }
    values.update(overrides)
    for name, value in values.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def test_exact_pae_standard_base64_body_path_and_version() -> None:
    signer = make_signer(transit_mount="team/transit west", key_name="release/prod key")

    signature = signer.sign(MESSAGE)

    assert signature == PRIVATE_KEY.sign(MESSAGE)
    assert len(signature) == 64
    PUBLIC_KEY.verify(signature, MESSAGE)
    assert len(FakeConnection.requests) == 1
    request = FakeConnection.requests[0]
    assert request.method == "POST"
    assert request.path == "/v1/team%2Ftransit%20west/sign/release%2Fprod%20key"
    assert request.body == (
        b'{"input":"'
        + base64.b64encode(MESSAGE)
        + b'","key_version":7,"hash_algorithm":"none","prehashed":false}'
    )
    assert request.headers["X-Vault-Token"] == TOKEN
    assert request.headers["Content-Type"] == "application/json"
    assert FakeConnection.instances[0].auto_open is False


@pytest.mark.parametrize(
    "body",
    [
        b"not-json",
        b"[]",
        b"{}",
        b'{"data":{}}',
        b'{"data":NaN}',
        b'{"data":{"value":1e999}}',
        b'{"data":{},"data":{}}',
    ],
)
def test_malformed_duplicate_and_nonfinite_responses_are_rejected(body: bytes) -> None:
    FakeConnection.handler = lambda _request: FakeResponse(body)

    with pytest.raises(OpenBaoError):
        make_signer().sign(MESSAGE)


def test_duplicate_signature_member_is_rejected() -> None:
    value = json.loads(signature_response(MESSAGE))["data"]["signature"]
    body = (
        b'{"data":{"signature":"'
        + value.encode()
        + b'","signature":"'
        + value.encode()
        + b'"}}'
    )
    FakeConnection.handler = lambda _request: FakeResponse(body)

    with pytest.raises(OpenBaoError):
        make_signer().sign(MESSAGE)


def test_oversized_response_and_declared_length_are_rejected() -> None:
    for response in (
        FakeResponse(b" " * (MAX_OPENBAO_RESPONSE_BYTES + 1)),
        FakeResponse(
            b"{}",
            headers={"Content-Length": str(MAX_OPENBAO_RESPONSE_BYTES + 1)},
        ),
    ):
        FakeConnection.handler = lambda _request, response=response: response
        with pytest.raises(OpenBaoError, match="size limit"):
            make_signer().sign(MESSAGE)


@pytest.mark.parametrize(
    "value",
    [
        None,
        1,
        "",
        "vault:v6:AA==",
        "vault:v07:AA==",
        "vault:v7:not-base64",
        "vault:v7:" + base64.b64encode(b"x" * 63).decode(),
        "vault:v7:" + base64.b64encode(b"x" * 64).decode().rstrip("="),
        "vault:v7:" + base64.b64encode(b"x" * 64).decode() + "\n",
    ],
)
def test_only_strict_matching_vault_signature_is_accepted(value: Any) -> None:
    body = json.dumps({"data": {"signature": value}}).encode()
    FakeConnection.handler = lambda _request: FakeResponse(body)

    with pytest.raises(OpenBaoError):
        make_signer().sign(MESSAGE)


def test_wrong_key_signature_fails_pinned_local_verification() -> None:
    FakeConnection.handler = lambda _request: FakeResponse(
        signature_response(MESSAGE, signer=WRONG_PRIVATE_KEY)
    )

    with pytest.raises(OpenBaoError, match="pinned public key"):
        make_signer().sign(MESSAGE)


@pytest.mark.parametrize("status", [401, 403, 429, 500, 502, 503])
def test_http_failures_do_not_fallback(status: int) -> None:
    FakeConnection.handler = lambda _request: FakeResponse(b"secret", status=status)

    with pytest.raises(OpenBaoHTTPError) as caught:
        make_signer().sign(MESSAGE)

    assert caught.value.status == status
    assert "secret" not in str(caught.value)
    assert len(FakeConnection.requests) == 1


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_never_followed(status: int) -> None:
    FakeConnection.handler = lambda _request: FakeResponse(
        b"{}", status=status, headers={"Location": "https://other.example/sign"}
    )

    with pytest.raises(OpenBaoHTTPError):
        make_signer().sign(MESSAGE)

    assert len(FakeConnection.requests) == 1
    assert all(request.host == "openbao.example" for request in FakeConnection.requests)


def test_timeout_and_cancellation_before_and_after_request() -> None:
    def timeout(_request: RecordedRequest) -> FakeResponse:
        raise TimeoutError

    FakeConnection.handler = timeout
    with pytest.raises(OpenBaoTimeoutError):
        make_signer().sign(MESSAGE)

    FakeConnection.reset()
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(OpenBaoCancelledError):
        make_signer().sign(MESSAGE, cancel_event=cancelled)
    assert FakeConnection.requests == []

    def cancel_after_request(request: RecordedRequest) -> FakeResponse:
        cancelled.set()
        return signature_response_for(request)

    cancelled.clear()
    FakeConnection.handler = cancel_after_request
    with pytest.raises(OpenBaoCancelledError):
        make_signer().sign(MESSAGE, cancel_event=cancelled)
    assert len(FakeConnection.requests) == 1
    assert FakeConnection.instances[0].closed


def signature_response_for(request: RecordedRequest) -> FakeResponse:
    message = base64.b64decode(request.json["input"], validate=True)
    return FakeResponse(signature_response(message))


def test_https_uses_hostname_verification_and_operator_ca(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = ssl.create_default_context
    ca_files: list[str | None] = []

    def context(cafile: str | None = None) -> ssl.SSLContext:
        ca_files.append(cafile)
        return original()

    monkeypatch.setattr(ssl, "create_default_context", context)
    signer = make_signer(ca_file="operator-ca.pem")

    signer.sign(MESSAGE)

    assert ca_files == ["operator-ca.pem"]
    context_value = FakeConnection.requests[0].context
    assert context_value is not None
    assert context_value.check_hostname is True
    assert context_value.verify_mode == ssl.CERT_REQUIRED


def test_invalid_ca_file_fails_at_startup(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="CA bundle"):
        make_signer(ca_file=tmp_path / "missing-ca.pem")


@pytest.mark.parametrize(
    ("address", "allowed"),
    [
        ("ftp://openbao.example", False),
        ("http://openbao.example", True),
        ("http://127.0.0.1:8200", False),
        ("http://localhost:8200", False),
        ("http://[::1]:8200", False),
        ("http://127.0.0.1.example", True),
        ("http://user@127.0.0.1", True),
    ],
)
def test_https_and_loopback_rules(address: str, allowed: bool) -> None:
    with pytest.raises(ValueError):
        make_signer(address=address, allow_insecure_loopback=allowed)


@pytest.mark.parametrize("address", ["http://127.0.0.1:8200", "http://localhost:8200", "http://[::1]:8200"])
def test_explicit_insecure_loopback_is_allowed(address: str) -> None:
    signer = make_signer(address=address, allow_insecure_loopback=True)

    signer.sign(MESSAGE)

    assert FakeConnection.requests[-1].context is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"token": None},
        {"kubernetes_role": "release-proof"},
        {"key_version": 0},
        {"key_version": True},
        {"timeout_seconds": 0},
        {"timeout_seconds": float("nan")},
        {"public_key": object()},
        {"address": "https://openbao.example/path"},
        {"address": "https://user:password@openbao.example"},
        {"transit_mount": ""},
        {"key_name": ".."},
        {"keyid": ""},
    ],
)
def test_invalid_adapter_configuration_is_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        make_signer(**overrides)


def test_kubernetes_login_expiry_and_renewal(tmp_path: Path) -> None:
    token_file = tmp_path / "service-account-token"
    token_file.write_bytes(b"service-account-jwt\n")
    login_count = 0

    def handler(request: RecordedRequest) -> FakeResponse:
        nonlocal login_count
        if request.path == "/v1/auth/kubernetes/login":
            login_count += 1
            assert "X-Vault-Token" not in request.headers
            assert request.json == {
                "role": "release-proof-role",
                "jwt": "service-account-jwt",
            }
            return FakeResponse(
                json.dumps(
                    {
                        "auth": {
                            "client_token": f"s.renewable-{login_count}",
                            "lease_duration": 100,
                        }
                    }
                ).encode()
            )
        assert request.headers["X-Vault-Token"] == f"s.renewable-{login_count}"
        return signature_response_for(request)

    FakeConnection.handler = handler
    signer = make_signer(
        token=None,
        kubernetes_role="release-proof-role",
        kubernetes_token_file=token_file,
    )
    now = 1000.0
    signer._monotonic = lambda: now

    signer.sign(MESSAGE)
    now = 1079.0
    signer.sign(MESSAGE)
    now = 1080.0
    signer.sign(MESSAGE)

    assert login_count == 2
    assert [request.path for request in FakeConnection.requests] == [
        "/v1/auth/kubernetes/login",
        "/v1/transit/sign/release-proof",
        "/v1/transit/sign/release-proof",
        "/v1/auth/kubernetes/login",
        "/v1/transit/sign/release-proof",
    ]
    assert all("export" not in request.path for request in FakeConnection.requests)


def test_kubernetes_login_is_lazy_and_malformed_login_fails(tmp_path: Path) -> None:
    signer = make_signer(
        token=None,
        kubernetes_role="release-proof-role",
        kubernetes_token_file=tmp_path / "missing-token",
    )
    assert FakeConnection.requests == []

    with pytest.raises(OpenBaoError):
        signer.sign(MESSAGE)
    assert FakeConnection.requests == []

    token_file = tmp_path / "token"
    token_file.write_text("service-account-jwt")
    FakeConnection.handler = lambda _request: FakeResponse(
        b'{"auth":{"client_token":"s.token","lease_duration":0}}'
    )
    with pytest.raises(OpenBaoError):
        make_signer(
            token=None,
            kubernetes_role="release-proof-role",
            kubernetes_token_file=token_file,
        ).sign(MESSAGE)


def test_tokens_pae_and_response_secrets_are_not_logged(caplog: Any) -> None:
    caplog.set_level(logging.DEBUG)
    secret_token = "s.do-not-log-token"
    secret_pae = b"do-not-log-pae"
    FakeConnection.handler = lambda _request: FakeResponse(
        b'{"data":"do-not-log-response"}'
    )

    with pytest.raises(OpenBaoError) as caught:
        make_signer(token=secret_token).sign(secret_pae)

    for output in (caplog.text, str(caught.value)):
        assert secret_token not in output
        assert secret_pae.decode() not in output
        assert "do-not-log-response" not in output


def test_mcp_remote_environment_loads_key_without_startup_network_and_signs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = tmp_path / "openbao-public.pem"
    key_file.write_bytes(public_key_pem())
    set_remote_environment(monkeypatch, key_file)

    server = MCPServer(StaticVerifier, policy_store=policy_store())
    assert FakeConnection.requests == []

    response = call_receipt(server)

    receipt = response["result"]["structuredContent"]
    assert receipt["proof"]["keyid"] == KEYID
    envelope = receipt["proof"]["envelope"]
    payload = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
    PUBLIC_KEY.verify(signature, dsse_pae(PAYLOAD_TYPE.encode("ascii"), payload))
    request = FakeConnection.requests[0]
    assert request.json["input"] == base64.b64encode(
        dsse_pae(PAYLOAD_TYPE.encode("ascii"), payload)
    ).decode("ascii")
    assert request.json["key_version"] == KEY_VERSION


@pytest.mark.parametrize(
    "missing",
    [
        "RELEASE_PROOF_OPENBAO_ADDRESS",
        "RELEASE_PROOF_OPENBAO_TRANSIT_MOUNT",
        "RELEASE_PROOF_OPENBAO_KEY_NAME",
        "RELEASE_PROOF_OPENBAO_KEY_VERSION",
        "RELEASE_PROOF_OPENBAO_PUBLIC_KEY_FILE",
        "RELEASE_PROOF_OPENBAO_TOKEN",
        "RELEASE_PROOF_SIGNING_ISSUER",
        "RELEASE_PROOF_SIGNING_KEY_ID",
    ],
)
def test_mcp_any_incomplete_remote_configuration_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    key_file = tmp_path / "openbao-public.pem"
    key_file.write_bytes(public_key_pem())
    set_remote_environment(monkeypatch, key_file)
    monkeypatch.delenv(missing)

    with pytest.raises(ValueError):
        MCPServer()
    assert FakeConnection.requests == []


@pytest.mark.parametrize("name", OPENBAO_SIGNING_ENVIRONMENT)
def test_mcp_any_isolated_remote_setting_fails(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setenv(name, "1")

    with pytest.raises(ValueError):
        MCPServer()


def test_mcp_file_and_remote_backends_are_mutually_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = tmp_path / "openbao-public.pem"
    key_file.write_bytes(public_key_pem())
    set_remote_environment(monkeypatch, key_file)
    monkeypatch.setenv("RELEASE_PROOF_SIGNING_KEY_FILE", "development-key.pem")
    monkeypatch.setenv("RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY", "1")

    with pytest.raises(ValueError, match="mutually exclusive"):
        MCPServer()


def test_mcp_remote_authentication_is_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = tmp_path / "openbao-public.pem"
    key_file.write_bytes(public_key_pem())
    set_remote_environment(
        monkeypatch, key_file, RELEASE_PROOF_OPENBAO_KUBERNETES_ROLE="role"
    )

    with pytest.raises(ValueError, match="exactly one"):
        MCPServer()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RELEASE_PROOF_OPENBAO_KEY_VERSION", "0"),
        ("RELEASE_PROOF_OPENBAO_KEY_VERSION", "1.5"),
        ("RELEASE_PROOF_OPENBAO_TIMEOUT_SECONDS", "nan"),
        ("RELEASE_PROOF_OPENBAO_TIMEOUT_SECONDS", "0"),
    ],
)
def test_mcp_remote_numeric_configuration_is_validated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    key_file = tmp_path / "openbao-public.pem"
    key_file.write_bytes(public_key_pem())
    set_remote_environment(monkeypatch, key_file, **{name: value})

    with pytest.raises(ValueError):
        MCPServer()


def test_mcp_remote_outage_never_returns_unsigned_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = tmp_path / "openbao-public.pem"
    key_file.write_bytes(public_key_pem())
    set_remote_environment(monkeypatch, key_file)

    def outage(_request: RecordedRequest) -> FakeResponse:
        raise OSError("offline")

    FakeConnection.handler = outage
    server = MCPServer(StaticVerifier, policy_store=policy_store())

    response = call_receipt(server)

    assert response["error"]["code"] == -32603
    assert "result" not in response
    assert len(FakeConnection.requests) == 1
    assert all("export" not in request.path for request in FakeConnection.requests)


@pytest.mark.parametrize("stage", ["headers", "body"])
def test_network_timeout_covers_drip_fed_response(
    stage: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(http.client, "HTTPConnection", REAL_HTTP_CONNECTION)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    port = listener.getsockname()[1]
    payload = signature_response(MESSAGE)
    response_headers = (
        f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n"
        "Content-Type: application/json\r\n\r\n"
    ).encode()

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    request += chunk
                if stage == "headers":
                    for byte in response_headers:
                        connection.sendall(bytes([byte]))
                        time.sleep(0.03)
                else:
                    connection.sendall(response_headers)
                    for byte in payload:
                        connection.sendall(bytes([byte]))
                        time.sleep(0.03)
        except OSError:
            pass

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    signer = make_signer(
        address=f"http://127.0.0.1:{port}",
        timeout_seconds=0.1,
        allow_insecure_loopback=True,
    )
    started = time.monotonic()
    try:
        with pytest.raises(OpenBaoTimeoutError):
            signer.sign(MESSAGE)
        assert time.monotonic() - started < 1.0
    finally:
        listener.close()
        server.join(timeout=2)
    assert not server.is_alive()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and any(
        thread.name == "release-proof-openbao-http" and thread.is_alive()
        for thread in threading.enumerate()
    ):
        time.sleep(0.01)
    assert not any(
        thread.name == "release-proof-openbao-http" and thread.is_alive()
        for thread in threading.enumerate()
    )


def test_kubernetes_auth_lock_wait_is_cancellable(tmp_path: Path) -> None:
    token_file = tmp_path / "service-account-token"
    token_file.write_text("unit-test-jwt")
    signer = make_signer(
        token=None,
        kubernetes_role="release-proof",
        kubernetes_token_file=token_file,
    )
    cancelled = threading.Event()
    outcome: list[Exception] = []
    signer._auth_lock.acquire()

    def call() -> None:
        try:
            signer.sign(MESSAGE, cancel_event=cancelled)
        except Exception as error:
            outcome.append(error)

    worker = threading.Thread(target=call)
    worker.start()
    try:
        time.sleep(0.05)
        cancelled.set()
        worker.join(timeout=1)
    finally:
        signer._auth_lock.release()
        worker.join(timeout=1)

    assert not worker.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], OpenBaoCancelledError)
    assert FakeConnection.requests == []


def test_cancel_during_connect_cannot_send_late_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_connect = threading.Event()
    requests: list[RecordedRequest] = []

    class StalledSocket:
        def settimeout(self, timeout: float) -> None:
            pass

        def shutdown(self, how: int) -> None:
            pass

    class StalledConnection:
        def __init__(
            self,
            host: str,
            port: int | None = None,
            *,
            timeout: float,
            context: ssl.SSLContext | None = None,
        ) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout
            self.context = context
            self.sock: StalledSocket | None = None
            self.closed = False

        def connect(self) -> None:
            release_connect.wait()
            self.sock = StalledSocket()

        def request(
            self, method: str, path: str, *, body: bytes, headers: dict[str, str]
        ) -> None:
            requests.append(
                RecordedRequest(
                    self.host, self.port, self.timeout, self.context, method, path, body, headers
                )
            )

        def getresponse(self) -> FakeResponse:
            raise AssertionError("A cancelled request must not reach getresponse")

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(http.client, "HTTPConnection", StalledConnection)
    signer = make_signer(
        address="http://127.0.0.1:8200",
        timeout_seconds=2,
        allow_insecure_loopback=True,
    )
    cancelled = threading.Event()
    outcome: list[Exception] = []

    def first_call() -> None:
        try:
            signer.sign(MESSAGE, cancel_event=cancelled)
        except Exception as error:
            outcome.append(error)

    caller = threading.Thread(target=first_call)
    caller.start()
    time.sleep(0.05)
    cancelled.set()
    caller.join(timeout=1)

    assert not caller.is_alive()
    assert len(outcome) == 1 and isinstance(outcome[0], OpenBaoCancelledError)
    with pytest.raises(OpenBaoError, match="still shutting down"):
        signer.sign(MESSAGE)

    release_connect.set()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and any(
        worker.is_alive() for worker in signer._network_workers
    ):
        time.sleep(0.01)

    assert all(not worker.is_alive() for worker in signer._network_workers)
    assert requests == []
    assert not any(
        thread.name == "release-proof-openbao-http" and thread.is_alive()
        for thread in threading.enumerate()
    )


def test_concurrent_callers_admit_only_one_network_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_connect = threading.Event()
    requests: list[RecordedRequest] = []

    class StalledConnection:
        def __init__(
            self,
            host: str,
            port: int | None = None,
            *,
            timeout: float,
            context: ssl.SSLContext | None = None,
        ) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout
            self.context = context
            self.sock = None

        def connect(self) -> None:
            release_connect.wait()

        def request(
            self, method: str, path: str, *, body: bytes, headers: dict[str, str]
        ) -> None:
            requests.append(
                RecordedRequest(
                    self.host, self.port, self.timeout, self.context, method, path, body, headers
                )
            )

        def getresponse(self) -> FakeResponse:
            raise AssertionError("Cancelled calls must not reach getresponse")

        def close(self) -> None:
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", StalledConnection)
    signer = make_signer(
        address="http://127.0.0.1:8200",
        timeout_seconds=2,
        allow_insecure_loopback=True,
    )
    cancelled = threading.Event()
    start = threading.Barrier(7)
    outcomes: list[Exception] = []

    def call() -> None:
        try:
            start.wait()
            signer.sign(MESSAGE, cancel_event=cancelled)
        except Exception as error:
            outcomes.append(error)

    callers = [threading.Thread(target=call) for _ in range(6)]
    for caller in callers:
        caller.start()
    start.wait()
    time.sleep(0.1)

    assert len(outcomes) == 5
    assert all("still shutting down" in str(error) for error in outcomes)
    assert len(signer._network_workers) == 1

    cancelled.set()
    release_connect.set()
    for caller in callers:
        caller.join(timeout=1)

    assert all(not caller.is_alive() for caller in callers)
    assert len(outcomes) == 6
    assert requests == []
    assert all(not worker.is_alive() for worker in signer._network_workers)

