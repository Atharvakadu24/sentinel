"""Hardened, bounded subprocess execution utility for static analysis scanners.

Implements Blueprint Section 10.3 (Process constraints) and Threat Mitigations
T2 (Subprocess isolation) and T13 (Worker concurrency and bounded execution).
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import IO, Any

logger = logging.getLogger("sentinel.worker.subprocess")

# Substrings identifying sensitive environment variable keys that MUST NEVER be passed to child processes
_PROHIBITED_ENV_SUBSTRINGS: tuple[str, ...] = (
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "KEY",
    "DATABASE",
    "DB_",
    "CREDENTIAL",
    "AUTH",
    "SESSION",
    "GITHUB",
    "ANTHROPIC",
    "GEMINI",
    "SENTRY",
    "AWS_",
    "PRIVATE",
    "API_KEY",
    "FINGERPRINT",
    "SENTINEL_",
)

# Standard essential system variables safe for child process execution
_SAFE_SYSTEM_ENV_KEYS: tuple[str, ...] = (
    "SystemRoot",
    "WINDIR",
    "PATHEXT",
    "COMSPEC",
    "SYSTEMDRIVE",
    "PATH",
    "LANG",
    "LC_ALL",
    "TERM",
)


class CommandStatus(str, Enum):
    """Execution status outcome for bounded subprocess commands."""

    SUCCESS = "success"
    NONZERO_EXIT = "nonzero_exit"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    EXECUTABLE_NOT_FOUND = "executable_not_found"
    ERROR = "error"


class SubprocessRunnerError(Exception):
    """Base exception for subprocess runner failures."""

    def __init__(self, message: str, result: CommandResult | None = None) -> None:
        super().__init__(message)
        self.result = result


class CommandNotFoundError(SubprocessRunnerError):
    """Raised when the specified executable is not found on the system."""


class CommandTimeoutError(SubprocessRunnerError):
    """Raised when the child process exceeds its configured execution timeout."""


class OutputLimitExceededError(SubprocessRunnerError):
    """Raised when process output exceeds the configured maximum byte limit."""


class NonzeroExitCodeError(SubprocessRunnerError):
    """Raised when the command terminates with a non-zero exit status."""


@dataclass(frozen=True)
class CommandResult:
    """Typed, immutable result of a bounded subprocess execution.

    Contains execution outcome, exit code, bounded streams, and timing metadata.
    """

    command: tuple[str, ...]
    status: CommandStatus
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    duration_ms: float
    timed_out: bool = False
    output_limit_exceeded: bool = False
    executable_not_found: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def stdout_text(self) -> str:
        """Decode stdout as UTF-8 string with replacement of invalid characters."""
        return self.stdout.decode("utf-8", errors="replace")

    @property
    def stderr_text(self) -> str:
        """Decode stderr as UTF-8 string with replacement of invalid characters."""
        return self.stderr.decode("utf-8", errors="replace")

    @property
    def is_success(self) -> bool:
        """Return True if command finished with clean zero exit code without error."""
        return self.status == CommandStatus.SUCCESS and self.exit_code == 0

    def raise_for_status(self) -> None:
        """Raise a dedicated typed exception if the command failed, timed out, or exceeded limits."""
        cmd_name = self.command[0] if self.command else "unknown"
        if self.executable_not_found:
            raise CommandNotFoundError(f"Command executable not found: '{cmd_name}'", result=self)
        if self.timed_out:
            raise CommandTimeoutError(
                f"Command '{cmd_name}' timed out after {self.duration_ms:.1f}ms",
                result=self,
            )
        if self.output_limit_exceeded:
            raise OutputLimitExceededError(
                f"Command '{cmd_name}' exceeded maximum output limit ({len(self.stdout) + len(self.stderr)} bytes captured)",
                result=self,
            )
        if self.exit_code is not None and self.exit_code != 0:
            raise NonzeroExitCodeError(
                f"Command '{cmd_name}' failed with exit code {self.exit_code}",
                result=self,
            )
        if self.status != CommandStatus.SUCCESS:
            raise SubprocessRunnerError(
                f"Command '{cmd_name}' failed with status: {self.status.value}",
                result=self,
            )


def build_sanitized_env(
    cwd: Path,
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Construct an isolated, sanitized environment dictionary for child process execution.

    Guarantees:
    - Never inherits application secrets, database URLs, GitHub tokens, or API keys.
    - Preserves essential platform variables required for process launch (e.g. SystemRoot, PATHEXT).
    - Sets TMP, TEMP, and TMPDIR to point to the designated workspace working directory.
    - Sets HOME to the designated working directory.
    - Rejects any caller-supplied extra_env keys containing sensitive patterns.

    Args:
        cwd: Working directory Path for the subprocess.
        extra_env: Optional non-sensitive environment variables to add.

    Returns:
        Sanitized environment dictionary suitable for subprocess.Popen.
    """
    clean_env: dict[str, str] = {}

    # 1. Inherit safe system platform variables
    for key, val in os.environ.items():
        # Check against safe whitelist
        is_safe_key = any(key.lower() == safe.lower() for safe in _SAFE_SYSTEM_ENV_KEYS)
        if not is_safe_key:
            continue

        # Verify key does not contain sensitive substrings
        key_upper = key.upper()
        if any(bad in key_upper for bad in _PROHIBITED_ENV_SUBSTRINGS):
            continue

        clean_env[key] = val

    # 2. Platform-specific defaults
    if "PATH" not in clean_env:
        if sys.platform == "win32":
            clean_env["PATH"] = os.environ.get("PATH", r"C:\Windows\System32;C:\Windows")
        else:
            clean_env["PATH"] = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")

    cwd_str = str(cwd.resolve())
    clean_env["TMP"] = cwd_str
    clean_env["TEMP"] = cwd_str
    clean_env["TMPDIR"] = cwd_str

    if sys.platform != "win32":
        clean_env["HOME"] = cwd_str
        clean_env["LANG"] = "C.UTF-8"
        clean_env["LC_ALL"] = "C.UTF-8"
    else:
        clean_env["USERPROFILE"] = cwd_str

    # 3. Merge caller-supplied extra_env with strict secret validation
    if extra_env:
        for k, v in extra_env.items():
            k_clean = str(k).strip()
            k_upper = k_clean.upper()
            if any(bad in k_upper for bad in _PROHIBITED_ENV_SUBSTRINGS):
                raise ValueError(
                    f"Refusing to pass environment variable '{k_clean}' matching sensitive pattern"
                )
            clean_env[k_clean] = str(v)

    # 4. Final safety scrub: ensure no prohibited keys slipped in
    scrubbed: dict[str, str] = {}
    for k, v in clean_env.items():
        k_upper = k.upper()
        if not any(bad in k_upper for bad in _PROHIBITED_ENV_SUBSTRINGS):
            scrubbed[k] = v

    return scrubbed


def _terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    """Terminate the process group/tree gracefully (SIGTERM on POSIX, terminate on Windows)."""
    if sys.platform != "win32":
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            try:
                proc.terminate()
            except (ProcessLookupError, OSError):
                pass
    else:
        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass


def _force_kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    """Forcefully kill the process group/tree (SIGKILL on POSIX, kill on Windows)."""
    if sys.platform != "win32":
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
    else:
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass


def run_command_bounded(
    args: Sequence[str],
    *,
    cwd: str | Path,
    timeout_sec: float | None = None,
    max_output_bytes: int = 10 * 1024 * 1024,
    env: Mapping[str, str] | None = None,
    terminate_on_output_limit: bool = True,
    check: bool = False,
) -> CommandResult:
    """Execute an external command with strict boundaries, streaming caps, and timeout safety.

    Guarantees:
    - shell=False strictly enforced; arguments must be a sequence of non-empty strings.
    - stdin is detached (subprocess.DEVNULL) to prevent interactive hangs.
    - Uses an explicitly constructed, sanitized environment without ambient secrets.
    - Starts in an isolated process group/session where supported.
    - Enforces timeout_sec and terminates entire process group cleanly upon expiration.
    - Streams stdout and stderr concurrently without deadlock.
    - Caps combined stream buffers at max_output_bytes during reading.
    - Guarantees child process termination and stream cleanup across all exit paths.
    - Never exposes environment variable values or raw tokens in logs or errors.

    Note on Resource Limits:
    POSIX resource limits (e.g. setrlimit) are unsafe inside multi-threaded Python processes
    as preexec_fn deadlocks heap locks. Hard memory/CPU bounds must be enforced at the
    container sandbox boundary, while this runner enforces wall-clock timeouts, stream byte caps,
    process group termination, and stdin detachment.

    Args:
        args: Sequence of command arguments (e.g. ['semgrep', 'scan', '--json', '.']).
        cwd: Directory where the command must be executed.
        timeout_sec: Optional maximum execution wall-clock time in seconds.
        max_output_bytes: Maximum combined bytes retained across stdout and stderr (default 10 MB).
        env: Optional dictionary of additional non-sensitive environment variables.
        terminate_on_output_limit: If True, terminates the process once output cap is exceeded.
        check: If True, raises a typed exception if command fails, times out, or exceeds limits.

    Returns:
        CommandResult dataclass capturing status, exit code, bounded streams, and duration.

    Raises:
        ValueError: If arguments or cwd are invalid, or env contains prohibited secrets.
        CommandNotFoundError: If check=True and the executable does not exist.
        CommandTimeoutError: If check=True and execution exceeds timeout_sec.
        OutputLimitExceededError: If check=True and output cap is reached.
        NonzeroExitCodeError: If check=True and exit status is non-zero.
        SubprocessRunnerError: If check=True and an unhandled execution error occurs.
    """
    # 1. Validate argument sequence
    if isinstance(args, (str, bytes)):
        raise TypeError("args must be a sequence of strings, not a string or bytes")
    if not args:
        raise ValueError("args sequence cannot be empty")

    clean_args: list[str] = []
    for idx, arg in enumerate(args):
        if not isinstance(arg, str):
            raise TypeError(f"args[{idx}] must be a string, got '{type(arg).__name__}'")
        if not arg:
            raise ValueError(f"args[{idx}] cannot be an empty string")
        clean_args.append(arg)

    # 2. Validate working directory
    resolved_cwd = Path(cwd).resolve()
    if not resolved_cwd.is_dir():
        raise ValueError(f"Working directory '{cwd}' does not exist or is not a directory")

    if timeout_sec is not None and (isinstance(timeout_sec, bool) or timeout_sec <= 0):
        raise ValueError("timeout_sec must be a positive number")

    if isinstance(max_output_bytes, bool) or max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be a positive integer")

    # 3. Construct sanitized environment
    sanitized_env = build_sanitized_env(cwd=resolved_cwd, extra_env=env)

    # 4. Configure subprocess launch arguments
    popen_kwargs: dict[str, Any] = {
        "args": clean_args,
        "cwd": str(resolved_cwd),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": sanitized_env,
        "shell": False,
    }

    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True
    else:
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    start_mono = time.monotonic()

    # 5. Launch process
    try:
        proc = subprocess.Popen(**popen_kwargs)
    except FileNotFoundError:
        duration_ms = (time.monotonic() - start_mono) * 1000.0
        result = CommandResult(
            command=tuple(clean_args),
            status=CommandStatus.EXECUTABLE_NOT_FOUND,
            exit_code=None,
            stdout=b"",
            stderr=b"",
            duration_ms=duration_ms,
            executable_not_found=True,
        )
        if check:
            result.raise_for_status()
        return result
    except Exception as exc:
        duration_ms = (time.monotonic() - start_mono) * 1000.0
        result = CommandResult(
            command=tuple(clean_args),
            status=CommandStatus.ERROR,
            exit_code=None,
            stdout=b"",
            stderr=b"",
            duration_ms=duration_ms,
        )
        if check:
            raise SubprocessRunnerError(
                f"Failed to launch command '{clean_args[0]}': {exc}", result=result
            ) from exc
        return result

    # 6. Set up deadlock-free bounded streaming readers
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    total_stdout = [0]
    total_stderr = [0]
    stdout_truncated = [False]
    stderr_truncated = [False]
    stop_event = threading.Event()
    limit_reached_event = threading.Event()

    def _stream_reader(
        stream: IO[bytes] | None,
        chunks: list[bytes],
        counter: list[int],
        truncated_flag: list[bool],
    ) -> None:
        if stream is None:
            return
        try:
            while not stop_event.is_set():
                chunk = stream.read(8192)
                if not chunk:
                    break

                current_total = total_stdout[0] + total_stderr[0]
                remaining = max_output_bytes - current_total

                if remaining <= 0:
                    truncated_flag[0] = True
                    limit_reached_event.set()
                    break

                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    counter[0] += remaining
                    truncated_flag[0] = True
                    limit_reached_event.set()
                    break
                else:
                    chunks.append(chunk)
                    counter[0] += len(chunk)
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    t_out = threading.Thread(
        target=_stream_reader,
        args=(proc.stdout, stdout_chunks, total_stdout, stdout_truncated),
        name=f"subproc-stdout-{proc.pid}",
        daemon=True,
    )
    t_err = threading.Thread(
        target=_stream_reader,
        args=(proc.stderr, stderr_chunks, total_stderr, stderr_truncated),
        name=f"subproc-stderr-{proc.pid}",
        daemon=True,
    )
    t_out.start()
    t_err.start()

    timed_out = False
    output_limit_exceeded = False
    deadline = (start_mono + timeout_sec) if timeout_sec is not None else None

    # 7. Polling and lifecycle monitoring
    try:
        while True:
            # Check if output limit was reached
            if limit_reached_event.is_set() or stdout_truncated[0] or stderr_truncated[0]:
                output_limit_exceeded = True
                if terminate_on_output_limit:
                    logger.warning(
                        "Command '%s' exceeded max output byte limit of %d; terminating",
                        clean_args[0],
                        max_output_bytes,
                    )
                    _terminate_process_group(proc)
                    break

            # Check if execution timed out
            now_mono = time.monotonic()
            if deadline is not None and now_mono >= deadline:
                timed_out = True
                logger.warning(
                    "Command '%s' exceeded timeout of %.1fs; terminating process group",
                    clean_args[0],
                    timeout_sec,
                )
                _terminate_process_group(proc)
                break

            # Check if process naturally exited
            if proc.poll() is not None:
                break

            time.sleep(0.01)

    finally:
        # Guarantee child process is terminated and reaped even if caller encounters an exception
        if proc.poll() is None:
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                _force_kill_process_group(proc)
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass

        stop_event.set()
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)

    duration_ms = (time.monotonic() - start_mono) * 1000.0
    stdout_data = b"".join(stdout_chunks)
    stderr_data = b"".join(stderr_chunks)

    # Re-verify output limit exceeded in case readers filled buffers as process exited
    if stdout_truncated[0] or stderr_truncated[0] or limit_reached_event.is_set():
        output_limit_exceeded = True

    # 8. Classify outcome
    if timed_out:
        status = CommandStatus.TIMEOUT
    elif output_limit_exceeded:
        status = CommandStatus.OUTPUT_LIMIT_EXCEEDED
    elif proc.returncode == 0:
        status = CommandStatus.SUCCESS
    else:
        status = CommandStatus.NONZERO_EXIT

    result = CommandResult(
        command=tuple(clean_args),
        status=status,
        exit_code=proc.returncode,
        stdout=stdout_data,
        stderr=stderr_data,
        duration_ms=duration_ms,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        executable_not_found=False,
        stdout_truncated=stdout_truncated[0],
        stderr_truncated=stderr_truncated[0],
    )

    if check:
        result.raise_for_status()

    return result
