from __future__ import annotations

import os
import re
import subprocess
import threading
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
AUTH_RE = re.compile(r"(?i)(authorization[\"'\s:=]+)([^\s,;]+)")
TOKEN_RE = re.compile(r"(?i)((?:token|password|secret)[\"'\s:=]+)([^\s,;]+)")


class RunnerError(RuntimeError):
    pass


class ToolUnavailable(RunnerError):
    pass


class CommandTimeout(RunnerError):
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
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.output_limit_bytes = output_limit_bytes
        self.environment = dict(os.environ if environment is None else environment)

    def run(self, argv: Sequence[str], *, timeout: float | None = None) -> CommandResult:
        if not argv or not all(isinstance(part, str) and part for part in argv):
            raise ValueError("Command arguments must be nonempty strings.")
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=self.environment,
            )
        except (FileNotFoundError, PermissionError, OSError) as error:
            raise ToolUnavailable(f"Unable to execute {argv[0]}.") from error

        assert process.stdout is not None
        assert process.stderr is not None
        stdout_reader = _BoundedReader(process.stdout, self.output_limit_bytes)
        stderr_reader = _BoundedReader(process.stderr, self.output_limit_bytes)
        stdout_thread = threading.Thread(target=stdout_reader.read, daemon=True)
        stderr_thread = threading.Thread(target=stderr_reader.read, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        try:
            process.wait(timeout=self.timeout_seconds if timeout is None else timeout)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            stdout_thread.join()
            stderr_thread.join()
            raise CommandTimeout(f"Command timed out: {argv[0]}.") from error
        stdout_thread.join()
        stderr_thread.join()
        if stdout_reader.truncated or stderr_reader.truncated:
            raise OutputLimitExceeded(f"Command output exceeded the configured limit: {argv[0]}.")
        stderr = stderr_reader.data.decode("utf-8", errors="replace")
        return CommandResult(
            returncode=process.returncode,
            stdout=stdout_reader.data,
            stderr=redact(stderr, self.environment),
        )


class _BoundedReader:
    def __init__(self, stream: object, limit: int) -> None:
        self.stream = stream
        self.limit = limit
        self.data = b""
        self.truncated = False

    def read(self) -> None:
        chunks: list[bytes] = []
        retained = 0
        total = 0
        while True:
            chunk = self.stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if retained < self.limit:
                keep = chunk[: self.limit - retained]
                chunks.append(keep)
                retained += len(keep)
        self.truncated = total > self.limit
        self.data = b"".join(chunks)
        self.stream.close()


def redact(text: str, environment: Mapping[str, str] | None = None) -> str:
    result = text
    if environment:
        for name in SECRET_ENV_NAMES:
            secret = environment.get(name)
            if secret and len(secret) >= 4:
                result = result.replace(secret, "[REDACTED]")
    result = BEARER_RE.sub("Bearer [REDACTED]", result)
    result = AUTH_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
    result = TOKEN_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
    return result[:8192]
