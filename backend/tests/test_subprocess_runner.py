"""Unit tests for hardened, bounded subprocess runner (Milestone 1 / Part B).

Validates:
- Successful execution using sys.executable.
- Argument-vector handling with spaces and special characters.
- Strict prevention of shell interpretation.
- Explicit working directory and sanitized environment.
- stdin detached behavior.
- Timeout and child-process termination.
- Output cap enforcement for stdout and stderr.
- Missing executable handling.
- Nonzero exit code handling.
- No deadlocks when both streams produce output.
- Process cleanup after failures.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from collections.abc import Generator
from pathlib import Path

import pytest

from app.worker.subprocess_runner import (
    CommandNotFoundError,
    CommandResult,
    CommandStatus,
    CommandTimeoutError,
    NonzeroExitCodeError,
    OutputLimitExceededError,
    SubprocessRunnerError,
    build_sanitized_env,
    run_command_bounded,
)


@pytest.fixture
def run_dir() -> Generator[Path, None, None]:
    """Provide an isolated temporary working directory for subprocess tests."""
    with tempfile.TemporaryDirectory(prefix="sentinel-subproc-") as tmp:
        yield Path(tmp).resolve()


class TestSubprocessRunnerExecution:
    """Core execution and argument handling tests."""

    def test_successful_execution(self, run_dir: Path) -> None:
        """Run a standard harmless Python command and verify typed output, exit code, and timing."""
        cmd = [sys.executable, "-c", "print('hello from subprocess')"]
        result = run_command_bounded(cmd, cwd=run_dir)

        assert isinstance(result, CommandResult)
        assert result.status == CommandStatus.SUCCESS
        assert result.is_success is True
        assert result.exit_code == 0
        assert result.stdout_text.strip() == "hello from subprocess"
        assert result.stderr_text == ""
        assert result.duration_ms > 0
        assert result.timed_out is False
        assert result.output_limit_exceeded is False
        assert result.executable_not_found is False

    def test_argument_vector_handling_with_spaces_and_special_chars(self, run_dir: Path) -> None:
        """Arguments with spaces, quotes, and punctuation are delivered intact without shell mangling."""
        arg1 = "value with multiple spaces"
        arg2 = "quote\"'and$special*chars"
        arg3 = "--flag=foo;bar&&baz"

        script = "import sys\nfor a in sys.argv[1:]:\n    print(f'ARG:{a}')\n"
        cmd = [sys.executable, "-c", script, arg1, arg2, arg3]
        result = run_command_bounded(cmd, cwd=run_dir)

        assert result.is_success is True
        lines = result.stdout_text.strip().splitlines()
        assert lines == [f"ARG:{arg1}", f"ARG:{arg2}", f"ARG:{arg3}"]

    def test_no_shell_interpretation(self, run_dir: Path) -> None:
        """Shell operators (&&, ||, ;, pipes) inside arguments are never interpreted as shell commands."""
        marker_file = run_dir / "pwned.txt"
        # If passed to shell, this would create marker_file
        malicious_arg = f"dummy && touch {marker_file}"
        cmd = [sys.executable, "-c", "import sys; print(sys.argv[1])", malicious_arg]

        result = run_command_bounded(cmd, cwd=run_dir)
        assert result.is_success is True
        assert not marker_file.exists()
        assert result.stdout_text.strip() == malicious_arg

    def test_string_args_rejected(self, run_dir: Path) -> None:
        """Passing a single string instead of a sequence of arguments raises TypeError."""
        with pytest.raises(TypeError, match="must be a sequence of strings"):
            run_command_bounded("python -c print(1)", cwd=run_dir)  # type: ignore[arg-type]

    def test_empty_args_rejected(self, run_dir: Path) -> None:
        """Empty command list or empty argument elements are rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            run_command_bounded([], cwd=run_dir)

        with pytest.raises(ValueError, match="cannot be an empty string"):
            run_command_bounded([sys.executable, ""], cwd=run_dir)

    def test_nonexistent_working_directory_rejected(self) -> None:
        """Passing a nonexistent cwd raises ValueError."""
        with pytest.raises(ValueError, match="does not exist"):
            run_command_bounded([sys.executable, "-c", "pass"], cwd="/nonexistent_dir_12345")


class TestEnvironmentSanitization:
    """Security tests verifying environment isolation and secret redaction."""

    def test_explicit_cwd_and_sanitized_environment(self, run_dir: Path) -> None:
        """Child process receives cwd as current working directory and cannot see host application secrets."""
        # Inject simulated application secrets into os.environ
        os.environ["SECRET_KEY"] = "super-secret-key-12345"
        os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost:5432/db"
        os.environ["GITHUB_TOKEN"] = "ghp_1234567890abcdef"
        os.environ["SENTINEL_SESSION_SECRET"] = "secret-session-token"

        try:
            script = "import os, json\nprint(os.getcwd())\nprint(json.dumps(dict(os.environ)))\n"
            result = run_command_bounded([sys.executable, "-c", script], cwd=run_dir)
            assert result.is_success is True

            lines = result.stdout_text.strip().splitlines()
            reported_cwd = Path(lines[0]).resolve()
            env_dump = lines[1]

            assert reported_cwd == run_dir.resolve()
            # Ensure none of the sensitive tokens leaked into child process environment
            assert "super-secret-key-12345" not in env_dump
            assert "postgresql" not in env_dump
            assert "ghp_1234567890abcdef" not in env_dump
            assert "secret-session-token" not in env_dump
            assert "SECRET_KEY" not in env_dump
            assert "DATABASE_URL" not in env_dump
            assert "GITHUB_TOKEN" not in env_dump
        finally:
            os.environ.pop("SECRET_KEY", None)
            os.environ.pop("DATABASE_URL", None)
            os.environ.pop("GITHUB_TOKEN", None)
            os.environ.pop("SENTINEL_SESSION_SECRET", None)

    def test_extra_env_rejects_sensitive_keys(self, run_dir: Path) -> None:
        """Attempting to supply environment variables with sensitive names raises ValueError."""
        with pytest.raises(ValueError, match="Refusing to pass environment variable"):
            run_command_bounded(
                [sys.executable, "-c", "pass"],
                cwd=run_dir,
                env={"MY_SECRET_KEY": "forbidden"},
            )

        with pytest.raises(ValueError, match="Refusing to pass environment variable"):
            run_command_bounded(
                [sys.executable, "-c", "pass"],
                cwd=run_dir,
                env={"DATABASE_NAME": "forbidden"},
            )

    def test_safe_extra_env_passed_successfully(self, run_dir: Path) -> None:
        """Benign custom environment variables are delivered to child process."""
        result = run_command_bounded(
            [sys.executable, "-c", "import os; print(os.environ.get('SCAN_MODE'))"],
            cwd=run_dir,
            env={"SCAN_MODE": "FAST_VERIFY"},
        )
        assert result.is_success is True
        assert result.stdout_text.strip() == "FAST_VERIFY"

    def test_build_sanitized_env_utility(self, run_dir: Path) -> None:
        """build_sanitized_env constructs clean dict, points temp and home to cwd, and rejects secrets."""
        env = build_sanitized_env(cwd=run_dir, extra_env={"SAFE_VAR": "value"})
        assert env["SAFE_VAR"] == "value"
        assert env["TMP"] == str(run_dir.resolve())
        assert env["TEMP"] == str(run_dir.resolve())
        assert env["TMPDIR"] == str(run_dir.resolve())
        assert not any("SECRET" in k for k in env)

        with pytest.raises(ValueError, match="Refusing to pass environment variable"):
            build_sanitized_env(cwd=run_dir, extra_env={"API_KEY": "leaked"})


class TestStreamingAndLimits:
    """Tests for stdin detachment, stream limits, and deadlock avoidance."""

    def test_stdin_is_detached(self, run_dir: Path) -> None:
        """stdin is detached (subprocess.DEVNULL) and immediately reports EOF without hanging."""
        script = "import sys\ndata = sys.stdin.read()\nprint(f'STDIN_LEN:{len(data)}')\n"
        result = run_command_bounded(
            [sys.executable, "-c", script],
            cwd=run_dir,
            timeout_sec=5.0,
        )
        assert result.is_success is True
        assert result.stdout_text.strip() == "STDIN_LEN:0"

    def test_output_cap_enforcement_for_stdout(self, run_dir: Path) -> None:
        """When stdout exceeds max_output_bytes, the stream is capped and process is terminated."""
        # Output 50,000 bytes, but cap at 500 bytes
        script = "import sys\nsys.stdout.write('A' * 50000)\nsys.stdout.flush()\n"
        result = run_command_bounded(
            [sys.executable, "-c", script],
            cwd=run_dir,
            max_output_bytes=500,
            timeout_sec=5.0,
        )

        assert result.output_limit_exceeded is True
        assert result.status == CommandStatus.OUTPUT_LIMIT_EXCEEDED
        assert result.stdout_truncated is True
        assert len(result.stdout) <= 500

        with pytest.raises(OutputLimitExceededError):
            result.raise_for_status()

    def test_output_cap_enforcement_for_stderr(self, run_dir: Path) -> None:
        """When stderr exceeds max_output_bytes, stream is capped and process is terminated."""
        script = "import sys\nsys.stderr.write('E' * 50000)\nsys.stderr.flush()\n"
        result = run_command_bounded(
            [sys.executable, "-c", script],
            cwd=run_dir,
            max_output_bytes=500,
            timeout_sec=5.0,
        )

        assert result.output_limit_exceeded is True
        assert result.status == CommandStatus.OUTPUT_LIMIT_EXCEEDED
        assert result.stderr_truncated is True
        assert len(result.stderr) <= 500

    def test_no_deadlocks_when_both_streams_produce_large_output(self, run_dir: Path) -> None:
        """Simultaneous heavy stdout and stderr generation does not deadlock pipe buffers."""
        script = (
            "import sys\n"
            "chunk = 'X' * 4096\n"
            "for _ in range(50):\n"
            "    sys.stdout.write(chunk)\n"
            "    sys.stderr.write(chunk)\n"
            "sys.stdout.flush()\n"
            "sys.stderr.flush()\n"
        )
        result = run_command_bounded(
            [sys.executable, "-c", script],
            cwd=run_dir,
            max_output_bytes=1024 * 1024,  # 1 MB limit
            timeout_sec=5.0,
        )

        assert result.is_success is True
        assert len(result.stdout) == 4096 * 50
        assert len(result.stderr) == 4096 * 50


class TestErrorAndTimeoutHandling:
    """Tests for timeouts, process termination, missing binaries, and nonzero exit codes."""

    def test_timeout_and_child_process_termination(self, run_dir: Path) -> None:
        """Command exceeding timeout_sec is terminated cleanly and classified as CommandStatus.TIMEOUT."""
        script = "import time\ntime.sleep(10)\n"
        t0 = time.monotonic()
        result = run_command_bounded(
            [sys.executable, "-c", script],
            cwd=run_dir,
            timeout_sec=0.2,
        )
        elapsed = time.monotonic() - t0

        assert result.status == CommandStatus.TIMEOUT
        assert result.timed_out is True
        assert result.is_success is False
        assert elapsed < 5.0, f"Command did not terminate promptly: took {elapsed:.2f}s"

        with pytest.raises(CommandTimeoutError):
            result.raise_for_status()

    def test_missing_executable_handling(self, run_dir: Path) -> None:
        """Nonexistent binary is cleanly reported as EXECUTABLE_NOT_FOUND without unhandled exception."""
        cmd = ["this_executable_definitely_does_not_exist_xyz123"]
        result = run_command_bounded(cmd, cwd=run_dir)

        assert result.status == CommandStatus.EXECUTABLE_NOT_FOUND
        assert result.executable_not_found is True
        assert result.exit_code is None
        assert result.is_success is False

        with pytest.raises(
            CommandNotFoundError, match="this_executable_definitely_does_not_exist_xyz123"
        ) as exc:
            result.raise_for_status()
        assert isinstance(exc.value, SubprocessRunnerError)

        # check=True raises directly
        with pytest.raises(CommandNotFoundError):
            run_command_bounded(cmd, cwd=run_dir, check=True)

    def test_nonzero_exit_code_handling(self, run_dir: Path) -> None:
        """Non-zero exit code is captured and classified as NONZERO_EXIT with streams intact."""
        script = "import sys\nsys.stderr.write('fatal syntax error\\n')\nsys.exit(42)\n"
        result = run_command_bounded([sys.executable, "-c", script], cwd=run_dir)

        assert result.status == CommandStatus.NONZERO_EXIT
        assert result.exit_code == 42
        assert result.is_success is False
        assert "fatal syntax error" in result.stderr_text

        with pytest.raises(NonzeroExitCodeError, match="exit code 42"):
            result.raise_for_status()

    def test_check_flag_raises_on_nonzero_exit(self, run_dir: Path) -> None:
        """check=True causes run_command_bounded to raise NonzeroExitCodeError on failure."""
        with pytest.raises(NonzeroExitCodeError) as exc_info:
            run_command_bounded(
                [sys.executable, "-c", "import sys; sys.exit(7)"],
                cwd=run_dir,
                check=True,
            )
        assert exc_info.value.result is not None
        assert exc_info.value.result.exit_code == 7
