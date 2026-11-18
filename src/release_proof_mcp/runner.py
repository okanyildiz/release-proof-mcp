from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Mapping, Sequence

SECRET_ENV_NAMES = (
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GHCR_REGISTRY_TOKEN",
    "DOCKER_AUTH_CONFIG",
    "COSIGN_PASSWORD",
)
BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
AUTH_RE = re.compile(r"(?i)(authorization[\"'\s:=]+)([^\r\n,;]+)")
TOKEN_RE = re.compile(r"(?i)((?:token|password|secret)[\"'\s:=]+)([^\s,;]+)")
GITHUB_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"
)


class RunnerError(RuntimeError):
    pass


class ToolUnavailable(RunnerError):
    pass


class CommandTimeout(RunnerError):
    pass


class CommandCancelled(RunnerError):
    pass


class OutputLimitExceeded(RunnerError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""
    stderr: str = ""

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", errors="strict")


class ProcessRunner:
    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        output_limit_bytes: int = 8 * 1024 * 1024,
        environment: Mapping[str, str] | None = None,
        reader_timeout_seconds: float = 0.25,
    ) -> None:
        if timeout_seconds <= 0 or output_limit_bytes < 1 or reader_timeout_seconds <= 0:
            raise ValueError("Process timeouts must be positive and the output limit must be nonzero.")
        self.timeout_seconds = timeout_seconds
        self.output_limit_bytes = output_limit_bytes
        self.environment = dict(os.environ if environment is None else environment)
        self.reader_timeout_seconds = reader_timeout_seconds

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> CommandResult:
        if not argv or not all(isinstance(part, str) and part for part in argv):
            raise ValueError("Command arguments must be nonempty strings.")
        timeout_seconds = self.timeout_seconds if timeout is None else timeout
        if timeout_seconds < 0:
            raise ValueError("Command timeout cannot be negative.")
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=self.environment,
                start_new_session=os.name == "posix",
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    if os.name == "nt"
                    else 0
                ),
            )
        except (FileNotFoundError, PermissionError, OSError) as error:
            raise ToolUnavailable(f"Unable to execute {argv[0]}.") from error

        assert process.stdout is not None
        assert process.stderr is not None
        stdout_reader = _BoundedReader(process.stdout, self.output_limit_bytes)
        stderr_reader = _BoundedReader(process.stderr, self.output_limit_bytes)
        readers = (stdout_reader, stderr_reader)
        stdout_thread = threading.Thread(target=stdout_reader.read, daemon=True)
        stderr_thread = threading.Thread(target=stderr_reader.read, daemon=True)
        threads = (stdout_thread, stderr_thread)
        for thread in threads:
            thread.start()
        try:
            self._wait_for_exit(process, argv[0], timeout_seconds, cancel_event)
        except (CommandTimeout, CommandCancelled):
            self._kill_process_group(process)
            self._bounded_reap(process)
            self._finish_readers(process, threads, readers, argv[0])
            raise

        self._finish_readers(process, threads, readers, argv[0])
        if stdout_reader.truncated or stderr_reader.truncated:
            raise OutputLimitExceeded(f"Command output exceeded the configured limit: {argv[0]}.")
        stderr = stderr_reader.data.decode("utf-8", errors="replace")
        return CommandResult(
            returncode=process.returncode,
            stdout=stdout_reader.data,
            stderr=redact(stderr, self.environment),
        )

    def _wait_for_exit(
        self,
        process: subprocess.Popen[bytes],
        command: str,
        timeout_seconds: float,
        cancel_event: threading.Event | None,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise CommandCancelled(f"Command was cancelled: {command}.")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CommandTimeout(f"Command timed out: {command}.")
            try:
                process.wait(timeout=min(remaining, 0.05))
                return
            except subprocess.TimeoutExpired:
                continue

    def _finish_readers(
        self,
        process: subprocess.Popen[bytes],
        threads: tuple[threading.Thread, threading.Thread],
        readers: tuple["_BoundedReader", "_BoundedReader"],
        command: str,
    ) -> None:
        if self._join_readers(threads, self.reader_timeout_seconds):
            self._check_reader_errors(readers, command)
            return
        self._kill_process_group(process)
        self._bounded_reap(process)
        if self._join_readers(threads, self.reader_timeout_seconds):
            self._check_reader_errors(readers, command)
            return
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    os.close(stream.fileno())
                except (OSError, ValueError):
                    pass
        self._join_readers(threads, 0.05)
        raise RunnerError(f"Command output streams did not close within the cleanup deadline: {command}.")

    def _bounded_reap(self, process: subprocess.Popen[bytes]) -> None:
        try:
            process.wait(timeout=self.reader_timeout_seconds)
        except subprocess.TimeoutExpired:
            pass

    def _kill_process_group(self, process: subprocess.Popen[bytes]) -> None:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
                return
            except ProcessLookupError:
                return
            except (PermissionError, OSError):
                pass
        elif os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.reader_timeout_seconds,
                    check=False,
                    shell=False,
                )
                return
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass

    @staticmethod
    def _join_readers(threads: tuple[threading.Thread, threading.Thread], timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        return all(not thread.is_alive() for thread in threads)

    @staticmethod
    def _check_reader_errors(
        readers: tuple["_BoundedReader", "_BoundedReader"], command: str
    ) -> None:
        if any(reader.error is not None for reader in readers):
            raise RunnerError(f"Command output could not be drained safely: {command}.")


class _BoundedReader:
    def __init__(self, stream: object, limit: int) -> None:
        self.stream = stream
        self.limit = limit
        self.data = b""
        self.truncated = False
        self.error: Exception | None = None

    def read(self) -> None:
        chunks: list[bytes] = []
        retained = 0
        total = 0
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if retained < self.limit:
                    keep = chunk[: self.limit - retained]
                    chunks.append(keep)
                    retained += len(keep)
        except (OSError, ValueError) as error:
            self.error = error
        finally:
            self.truncated = total > self.limit
            self.data = b"".join(chunks)
            try:
                self.stream.close()
            except (OSError, ValueError):
                pass


def redact(text: str, environment: Mapping[str, str] | None = None) -> str:
    result = GITHUB_TOKEN_RE.sub("[REDACTED]", text)
    if environment:
        secrets: list[str] = []
        for name, secret in environment.items():
            upper_name = name.upper()
            if (
                name in SECRET_ENV_NAMES
                or upper_name.endswith(("_TOKEN", "_PASSWORD", "_SECRET", "_KEY"))
                or "AUTHORIZATION" in upper_name
            ) and secret and len(secret) >= 4:
                secrets.append(secret)
        for secret in sorted(set(secrets), key=len, reverse=True):
            result = result.replace(secret, "[REDACTED]")
    result = BEARER_RE.sub("Bearer [REDACTED]", result)
    result = AUTH_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
    result = TOKEN_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
    return result[:8192]
