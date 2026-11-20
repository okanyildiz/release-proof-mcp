from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import math
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

MAX_OPENBAO_RESPONSE_BYTES = 1024 * 1024
MAX_OPENBAO_PUBLIC_KEY_BYTES = 16 * 1024
MAX_SERVICE_ACCOUNT_TOKEN_BYTES = 64 * 1024
DEFAULT_KUBERNETES_TOKEN_FILE = (
    "/var/run/secrets/kubernetes.io/serviceaccount/token"
)
DEFAULT_OPENBAO_TIMEOUT_SECONDS = 10.0
_READ_CHUNK_BYTES = 64 * 1024
_WAIT_INTERVAL_SECONDS = 0.025
_WORKER_JOIN_GRACE_SECONDS = 0.05
_HTTP_WORKER_NAME = "release-proof-openbao-http"


class OpenBaoError(RuntimeError):
    pass


class OpenBaoTimeoutError(OpenBaoError):
    pass


class OpenBaoCancelledError(OpenBaoError):
    pass


class OpenBaoHTTPError(OpenBaoError):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"OpenBao request returned HTTP status {status}.")


def load_openbao_public_key(path: str | Path) -> Ed25519PublicKey:
    try:
        with Path(path).open("rb") as key_file:
            encoded = key_file.read(MAX_OPENBAO_PUBLIC_KEY_BYTES + 1)
        if len(encoded) > MAX_OPENBAO_PUBLIC_KEY_BYTES:
            raise ValueError("OpenBao public key file exceeds the size limit.")
        key = load_pem_public_key(encoded)
    except (OSError, TypeError, ValueError, UnsupportedAlgorithm) as error:
        raise ValueError("Invalid OpenBao Ed25519 public key configuration.") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Invalid OpenBao Ed25519 public key configuration.")
    return key


class OpenBaoTransitSigner:
    """Sign exact messages with a pinned OpenBao Transit Ed25519 key.

    The keyid ends in /v{key_version} and changes on rotation. Network calls run
    in supervised daemon workers; deadlines and cancellation close their sockets
    to interrupt in-flight operations.
    """

    def __init__(
        self,
        *,
        address: str,
        transit_mount: str,
        key_name: str,
        key_version: int,
        keyid: str,
        public_key: Ed25519PublicKey,
        token: str | None = None,
        kubernetes_role: str | None = None,
        kubernetes_token_file: str | Path = DEFAULT_KUBERNETES_TOKEN_FILE,
        ca_file: str | Path | None = None,
        timeout_seconds: float = DEFAULT_OPENBAO_TIMEOUT_SECONDS,
        allow_insecure_loopback: bool = False,
    ) -> None:
        self._scheme, self._host, self._port = _parse_address(
            address, allow_insecure_loopback
        )
        self._mount = _url_segment(transit_mount, "transit mount")
        self._key_name = _url_segment(key_name, "key name")
        if (
            not isinstance(key_version, int)
            or isinstance(key_version, bool)
            or key_version < 1
        ):
            raise ValueError("OpenBao key_version must be a positive integer.")
        self.key_version = key_version
        if (
            not isinstance(keyid, str)
            or not keyid.strip()
            or len(keyid) > 256
            or not keyid.endswith(f"/v{key_version}")
        ):
            raise ValueError("OpenBao keyid must end in /v{key_version}.")
        self.keyid = keyid
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("An Ed25519 public key must be pinned for OpenBao signing.")
        self._public_key = public_key
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("OpenBao timeout_seconds must be positive and finite.")
        self._timeout_seconds = float(timeout_seconds)
        if (token is None) == (kubernetes_role is None):
            raise ValueError(
                "Configure exactly one of an OpenBao token or Kubernetes role."
            )
        if token is not None:
            _validate_token(token, "OpenBao token")
        if kubernetes_role is not None:
            _validate_role(kubernetes_role)
        self._kubernetes_role = kubernetes_role
        self._kubernetes_token_file = Path(kubernetes_token_file)
        self._token = token
        self._token_expires_at = math.inf if token is not None else 0.0
        self._renew_at = math.inf if token is not None else 0.0
        self._auth_lock = threading.Lock()
        self._network_workers_lock = threading.Lock()
        self._network_workers: set[threading.Thread] = set()
        self._monotonic = time.monotonic
        self._ssl_context: ssl.SSLContext | None = None
        if self._scheme == "https":
            try:
                self._ssl_context = ssl.create_default_context(
                    cafile=str(ca_file) if ca_file is not None else None
                )
            except (OSError, ssl.SSLError) as error:
                raise ValueError("Invalid OpenBao CA bundle configuration.") from error
            self._ssl_context.check_hostname = True
            self._ssl_context.verify_mode = ssl.CERT_REQUIRED
        elif ca_file is not None:
            raise ValueError("An OpenBao CA bundle requires HTTPS.")
        self._sign_path = f"/v1/{self._mount}/sign/{self._key_name}"

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def sign(
        self,
        message: bytes,
        *,
        cancel_event: threading.Event | None = None,
    ) -> bytes:
        if not isinstance(message, bytes):
            raise ValueError("OpenBao signing input must be bytes.")
        deadline = self._monotonic() + self._timeout_seconds
        self._check_cancelled(cancel_event)
        token = self._authentication_token(cancel_event, deadline)
        response = self._post_json(
            self._sign_path,
            {
                "input": base64.b64encode(message).decode("ascii"),
                "key_version": self.key_version,
                "hash_algorithm": "none",
                "prehashed": False,
            },
            token=token,
            cancel_event=cancel_event,
            deadline=deadline,
        )
        self._check_cancelled(cancel_event)
        signature = _signature_from_response(response, self.key_version)
        try:
            self._public_key.verify(signature, message)
        except (InvalidSignature, ValueError) as error:
            raise OpenBaoError(
                "OpenBao returned a signature rejected by the pinned public key."
            ) from error
        self._check_cancelled(cancel_event)
        return signature

    def _authentication_token(
        self, cancel_event: threading.Event | None, deadline: float
    ) -> str:
        if self._kubernetes_role is None:
            if self._token is None:
                raise OpenBaoError("OpenBao authentication is unavailable.")
            return self._token
        while not self._auth_lock.acquire(
            timeout=min(_WAIT_INTERVAL_SECONDS, self._remaining(deadline))
        ):
            self._check_cancelled(cancel_event)
        try:
            now = self._monotonic()
            if (
                self._token is not None
                and now < self._token_expires_at
                and now < self._renew_at
            ):
                return self._token
            service_account_token = self._read_service_account_token()
            response = self._post_json(
                "/v1/auth/kubernetes/login",
                {"role": self._kubernetes_role, "jwt": service_account_token},
                token=None,
                cancel_event=cancel_event,
                deadline=deadline,
            )
            token, lease_duration = _login_token_and_lease(response)
            obtained_at = self._monotonic()
            expires_at = obtained_at + lease_duration
            if not math.isfinite(expires_at):
                raise OpenBaoError("OpenBao Kubernetes login lease is invalid.")
            self._token = token
            self._token_expires_at = expires_at
            self._renew_at = expires_at - min(60.0, lease_duration / 5.0)
            return token
        finally:
            self._auth_lock.release()

    def _read_service_account_token(self) -> str:
        try:
            with self._kubernetes_token_file.open("rb") as token_file:
                raw = token_file.read(MAX_SERVICE_ACCOUNT_TOKEN_BYTES + 1)
            if len(raw) > MAX_SERVICE_ACCOUNT_TOKEN_BYTES:
                raise ValueError("Service-account token exceeds the size limit.")
            token = raw.decode("ascii").strip()
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise OpenBaoError("Unable to load the service-account token.") from error
        try:
            _validate_token(token, "service-account token")
        except ValueError as error:
            raise OpenBaoError("Service-account token is invalid.") from error
        return token

    def _post_json(
        self,
        path: str,
        value: dict[str, Any],
        *,
        token: str | None,
        cancel_event: threading.Event | None,
        deadline: float,
    ) -> dict[str, Any]:
        self._check_cancelled(cancel_event)
        body = json.dumps(
            value, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if token is not None:
            headers["X-Vault-Token"] = token
        connection = self._new_connection(self._remaining(deadline))
        done = threading.Event()
        outcome: list[tuple[bool, Any]] = []
        active_sockets: list[Any] = []

        def run() -> None:
            try:
                result = self._perform_post_json(
                    connection,
                    path,
                    body,
                    headers,
                    active_sockets,
                    cancel_event,
                    deadline,
                )
            except Exception as error:
                outcome.append((False, error))
            else:
                outcome.append((True, result))
            finally:
                self._close_connection(connection)
                done.set()

        worker = threading.Thread(
            target=run, name=_HTTP_WORKER_NAME, daemon=True
        )
        with self._network_workers_lock:
            self._network_workers = {
                pending for pending in self._network_workers if pending.is_alive()
            }
            if self._network_workers:
                self._close_connection(connection)
                raise OpenBaoError(
                    "An earlier OpenBao request is still shutting down; refusing to start another request."
                )
            self._network_workers.add(worker)
            try:
                worker.start()
            except Exception:
                self._network_workers.discard(worker)
                self._close_connection(connection)
                raise OpenBaoError("Unable to start the OpenBao request worker.") from None
        try:
            while True:
                self._check_cancelled(cancel_event)
                remaining = self._remaining(deadline)
                if not done.wait(min(_WAIT_INTERVAL_SECONDS, remaining)):
                    continue
                self._check_cancelled(cancel_event)
                self._remaining(deadline)
                if not outcome:
                    raise OpenBaoError("OpenBao request worker ended without a result.")
                succeeded, result = outcome[0]
                if succeeded:
                    return result
                raise result
        except (OpenBaoTimeoutError, OpenBaoCancelledError):
            if not done.is_set():
                self._interrupt_connection(connection, active_sockets)
            worker.join(_WORKER_JOIN_GRACE_SECONDS)
            raise

    def _perform_post_json(
        self,
        connection: http.client.HTTPConnection,
        path: str,
        body: bytes,
        headers: dict[str, str],
        active_sockets: list[Any],
        cancel_event: threading.Event | None,
        deadline: float,
    ) -> dict[str, Any]:
        try:
            self._set_timeout(connection, self._remaining(deadline))
            connection.connect()
            connection.auto_open = False
            sock = getattr(connection, "sock", None)
            if sock is not None:
                active_sockets.append(sock)
            self._check_cancelled(cancel_event)
            self._set_timeout(connection, self._remaining(deadline))
            connection.request("POST", path, body=body, headers=headers)
            self._check_cancelled(cancel_event)
            self._set_timeout(connection, self._remaining(deadline))
            response = connection.getresponse()
            if response.status != 200:
                raise OpenBaoHTTPError(response.status)
            raw = self._read_response(connection, response, deadline)
            self._check_cancelled(cancel_event)
            return _strict_json_object(raw)
        except TimeoutError:
            raise OpenBaoTimeoutError("OpenBao request timed out.") from None
        except (OSError, http.client.HTTPException):
            raise OpenBaoError("OpenBao request failed.") from None

    @staticmethod
    def _interrupt_connection(
        connection: http.client.HTTPConnection, active_sockets: list[Any]
    ) -> None:
        sockets = [getattr(connection, "sock", None), *active_sockets]
        for sock in sockets:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except (AttributeError, OSError):
                    pass
        OpenBaoTransitSigner._close_connection(connection)

    @staticmethod
    def _close_connection(connection: http.client.HTTPConnection) -> None:
        try:
            connection.close()
        except (OSError, http.client.HTTPException):
            pass

    def _new_connection(self, timeout: float) -> http.client.HTTPConnection:
        if self._scheme == "https":
            return http.client.HTTPSConnection(
                self._host,
                self._port,
                timeout=timeout,
                context=self._ssl_context,
            )
        return http.client.HTTPConnection(
            self._host, self._port, timeout=timeout
        )

    def _read_response(
        self,
        connection: http.client.HTTPConnection,
        response: http.client.HTTPResponse,
        deadline: float,
    ) -> bytes:
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                raise OpenBaoError("OpenBao response framing is invalid.") from None
            if declared < 0 or declared > MAX_OPENBAO_RESPONSE_BYTES:
                raise OpenBaoError("OpenBao response exceeds the size limit.")
        chunks: list[bytes] = []
        size = 0
        while True:
            self._set_timeout(connection, self._remaining(deadline))
            chunk = response.read(
                min(_READ_CHUNK_BYTES, MAX_OPENBAO_RESPONSE_BYTES + 1 - size)
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_OPENBAO_RESPONSE_BYTES:
                raise OpenBaoError("OpenBao response exceeds the size limit.")
        return b"".join(chunks)

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise OpenBaoTimeoutError("OpenBao request timed out.")
        return remaining

    @staticmethod
    def _set_timeout(connection: http.client.HTTPConnection, timeout: float) -> None:
        connection.timeout = timeout
        sock = getattr(connection, "sock", None)
        if sock is not None:
            sock.settimeout(timeout)

    @staticmethod
    def _check_cancelled(cancel_event: threading.Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise OpenBaoCancelledError("OpenBao signing was cancelled.")


def _parse_address(
    address: str, allow_insecure_loopback: bool
) -> tuple[str, str, int | None]:
    if (
        not isinstance(address, str)
        or not address
        or address != address.strip()
        or not isinstance(allow_insecure_loopback, bool)
    ):
        raise ValueError("OpenBao address and loopback configuration are invalid.")
    try:
        parsed = urlsplit(address)
        port = parsed.port
    except ValueError as error:
        raise ValueError("OpenBao address is invalid.") from error
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("OpenBao address must be an HTTPS origin without a path.")
    hostname = parsed.hostname
    if parsed.scheme == "http" and not (
        allow_insecure_loopback and _is_loopback_hostname(hostname)
    ):
        raise ValueError(
            "Plain HTTP OpenBao access requires explicit loopback opt-in."
        )
    return parsed.scheme, hostname, port


def _is_loopback_hostname(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _url_segment(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or value in {".", ".."}
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"OpenBao {name} is invalid.")
    return quote(value, safe="")


def _validate_token(token: str, name: str) -> None:
    if (
        not isinstance(token, str)
        or not token
        or len(token) > MAX_SERVICE_ACCOUNT_TOKEN_BYTES
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        raise ValueError(f"{name} is invalid.")


def _validate_role(role: str) -> None:
    if (
        not isinstance(role, str)
        or not role.strip()
        or len(role) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in role)
    ):
        raise ValueError("OpenBao Kubernetes role is invalid.")


def _signature_from_response(response: dict[str, Any], key_version: int) -> bytes:
    data = response.get("data")
    value = data.get("signature") if isinstance(data, dict) else None
    prefix = f"vault:v{key_version}:"
    if not isinstance(value, str) or not value.startswith(prefix):
        raise OpenBaoError("OpenBao signature response is invalid.")
    encoded = value[len(prefix) :]
    try:
        signature = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raise OpenBaoError("OpenBao signature response is invalid.") from None
    if (
        len(signature) != 64
        or base64.b64encode(signature).decode("ascii") != encoded
    ):
        raise OpenBaoError("OpenBao signature response is invalid.")
    return signature


def _login_token_and_lease(response: dict[str, Any]) -> tuple[str, float]:
    auth = response.get("auth")
    token = auth.get("client_token") if isinstance(auth, dict) else None
    lease = auth.get("lease_duration") if isinstance(auth, dict) else None
    try:
        _validate_token(token, "OpenBao login token")
    except (TypeError, ValueError):
        raise OpenBaoError("OpenBao Kubernetes login response is invalid.") from None
    if (
        isinstance(lease, bool)
        or not isinstance(lease, (int, float))
        or not math.isfinite(lease)
        or lease <= 0
    ):
        raise OpenBaoError("OpenBao Kubernetes login lease is invalid.")
    return token, float(lease)


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_nonfinite,
            parse_float=_finite_float,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        OverflowError,
        RecursionError,
    ):
        raise OpenBaoError("OpenBao returned invalid JSON.") from None
    if not isinstance(value, dict):
        raise OpenBaoError("OpenBao JSON response must be an object.")
    return value


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key.")
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> Any:
    raise ValueError("Non-finite JSON number.")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Non-finite JSON number.")
    return result
