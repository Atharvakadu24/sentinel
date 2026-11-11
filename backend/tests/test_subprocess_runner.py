"""Unit tests for hardened, bounded subprocess runner (Milestone 1 / Part B).

Validates:
- Successful execution using sys.executable.
- Argument-vector handling with spaces and special characters.
- Strict prevention of shell interpretation.
- Explicit working directory and sanitized environment.
- Stricter argument validation for max_output_bytes and timeout_sec.
- Dangerous environment override rejection (PYTHONPATH, LD_PRELOAD, etc.).
- Rejection of dangerous overrides even when prefixed (SEMGREP_PYTHONPATH, GITLEAKS_LD_PRELOAD, etc.).
- Allowlist enforcement for caller-supplied environment variables.
- stdin detached behavior.
- Output cap enforcement and thread-safe combined limit across simultaneous streams.
- Stream reader failure handling without false successful outcomes.
- Timeout and child-process termination across process groups and process trees.
- POSIX graceful SIGTERM escalation to SIGKILL with stored PGID tracking.
- POSIX child termination and escalation to SIGKILL even when parent exits first.
- POSIX zombie vs active process distinction and execution heartbeat verification.
- Windows Job Object pre-execution containment, descendant termination, and failure cleanup.
- Missing executable and nonzero exit code handling.
- No deadlocks when both streams produce output.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from app.worker.subprocess_runner import (
    CommandNotFoundError,
    CommandResult,
    CommandStatus,
    CommandTimeoutError,
    NonzeroExitCodeError,
    OutputLimitExceededError,
    SubprocessRunnerError,
    _is_dangerous_override,
    build_sanitized_env,
    run_command_bounded,
)


@pytest.fixture
def run_dir() -> Generator[Path, None, None]:
    """Provide an isolated temporary working directory for subprocess tests."""
    with tempfile.TemporaryDirectory(prefix="sentinel-subproc-", ignore_cleanup_errors=True) as tmp:
        yield Path(tmp).resolve()


def _is_posix_process_running(pid: int) -> bool:
    """Check if a POSIX process is actively running (distinguishing active processes from zombies).

    Returns:
        False if the process is completely terminated or in zombie/dead state.
        True if the process is still actively executing.
    """
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, OSError):
        return False

    # Check Linux /proc/{pid}/status for exact state
    proc_status = Path(f"/proc/{pid}/status")
    if proc_status.is_file():
        try:
            for line in proc_status.read_text().splitlines():
                if line.startswith("State:"):
                    state = line.split()[1]
                    # Z (zombie) and X (dead) mean the process has terminated
                    return state not in ("Z", "X")
        except (OSError, IndexError):
            return False

    # Fallback on macOS/BSD: ps -o stat= -p {pid}
    try:
        out = subprocess.check_output(
            ["ps", "-o", "stat=", "-p", str(pid)],
            stderr=subprocess.DEVNULL,
        )
        stat = out.decode().strip()
        return bool(stat and not stat.startswith("Z"))
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False


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
        assert result.reader_error is False

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
        malicious_arg = f"dummy && touch {marker_file}"
        cmd = [sys.executable, "-c", "import sys; print(sys.argv[1])", malicious_arg]

        result = run_command_bounded(cmd, cwd=run_dir)
        assert result.is_success is True
        assert not marker_file.exists()
        assert result.stdout_text.strip() == malicious_arg

    def test_string_args_rejected(self, run_dir: Path) -> None:
        """Passing a single string instead of a sequence of arguments raises ValueError."""
        with pytest.raises(ValueError, match="must be a sequence of strings"):
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

    def test_argument_validation_max_output_bytes(self, run_dir: Path) -> None:
        """max_output_bytes must be a positive integer; floats, booleans, and non-positives are rejected."""
        cmd = [sys.executable, "-c", "pass"]

        for invalid in (True, False, 100.5, 0, -1, -500, "1000"):
            with pytest.raises(ValueError, match="max_output_bytes must be a positive integer"):
                run_command_bounded(cmd, cwd=run_dir, max_output_bytes=invalid)  # type: ignore[arg-type]

        # Valid positive integer succeeds
        res = run_command_bounded(cmd, cwd=run_dir, max_output_bytes=1024)
        assert res.is_success is True

    def test_argument_validation_timeout_sec(self, run_dir: Path) -> None:
        """timeout_sec must be a finite positive number; booleans, NaN, inf, and non-positives are rejected."""
        cmd = [sys.executable, "-c", "pass"]

        for invalid in (True, False, 0, -1, -0.5, float("nan"), float("inf"), float("-inf"), "5"):
            with pytest.raises(ValueError, match="timeout_sec must be a finite positive number"):
                run_command_bounded(cmd, cwd=run_dir, timeout_sec=invalid)  # type: ignore[arg-type]

        # Valid finite positive number succeeds
        res = run_command_bounded(cmd, cwd=run_dir, timeout_sec=5.0)
        assert res.is_success is True


class TestEnvironmentSanitization:
    """Security tests verifying environment isolation and secret redaction."""

    def test_explicit_cwd_and_sanitized_environment(self, run_dir: Path) -> None:
        """Child process receives cwd as current working directory and cannot see host application secrets."""
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

    def test_dangerous_env_overrides_rejected(self, run_dir: Path) -> None:
        """Dangerous environment variables that subvert interpreters, linkers, or workspaces are rejected."""
        dangerous_keys = (
            "PYTHONPATH",
            "PYTHONHOME",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "LD_LIBRARY_PATH",
            "TMP",
            "USERPROFILE",
            "NODE_OPTIONS",
        )
        for key in dangerous_keys:
            with pytest.raises(ValueError, match="dangerous override prohibited") as exc_info:
                run_command_bounded(
                    [sys.executable, "-c", "pass"],
                    cwd=run_dir,
                    env={key: "/evil/injected/path"},
                )
            # Ensure the injected value is never echoed in the exception message
            assert "/evil/injected/path" not in str(exc_info.value)

    @pytest.mark.parametrize(
        "var_name",
        [
            "SEMGREP_PYTHONPATH",
            "SEMGREP_PYTHONHOME",
            "GITLEAKS_LD_PRELOAD",
            "GITLEAKS_LD_LIBRARY_PATH",
            "SCAN_DYLD_INSERT_LIBRARIES",
            "SCAN_DYLD_LIBRARY_PATH",
            "SEMGREP_NODE_OPTIONS",
            "GITLEAKS_PERL5LIB",
            "SCAN_JAVA_TOOL_OPTIONS",
            "SEMGREP_TMP",
            "SCAN_USERPROFILE",
            "SCAN_CUSTOM_LD_PRELOAD",
            "SEMGREP_EXTRA_PYTHONHOME",
        ],
    )
    def test_dangerous_prefixed_env_overrides_rejected(self, run_dir: Path, var_name: str) -> None:
        """Dangerous runtime and interpreter overrides with allowed prefixes are strictly rejected."""
        evil_val = "/evil/injected/payload/12345"
        with pytest.raises(ValueError, match="dangerous override prohibited") as exc_info:
            run_command_bounded(
                [sys.executable, "-c", "pass"],
                cwd=run_dir,
                env={var_name: evil_val},
            )
        assert evil_val not in str(exc_info.value)
        assert var_name in str(exc_info.value)

    def test_unapproved_extra_env_rejected(self, run_dir: Path) -> None:
        """Arbitrary environment variables not in the approved allowlist are rejected."""
        with pytest.raises(ValueError, match="not in approved environment allowlist"):
            run_command_bounded(
                [sys.executable, "-c", "pass"],
                cwd=run_dir,
                env={"UNAPPROVED_CUSTOM_VAR": "val"},
            )

    def test_approved_scanner_env_vars_work(self, run_dir: Path) -> None:
        """Approved scanner and platform variables are safely passed to the subprocess."""
        approved_env = {
            "SCAN_MODE": "FAST_VERIFY",
            "CI": "true",
            "NO_COLOR": "1",
            "SEMGREP_RULES_TEST": "custom_rules",
            "GITLEAKS_CONFIG_TEST": "config.toml",
        }
        script = (
            "import os\n"
            "print(os.environ.get('SCAN_MODE'))\n"
            "print(os.environ.get('CI'))\n"
            "print(os.environ.get('NO_COLOR'))\n"
            "print(os.environ.get('SEMGREP_RULES_TEST'))\n"
            "print(os.environ.get('GITLEAKS_CONFIG_TEST'))\n"
        )
        result = run_command_bounded(
            [sys.executable, "-c", script],
            cwd=run_dir,
            env=approved_env,
        )
        assert result.is_success is True
        lines = result.stdout_text.strip().splitlines()
        assert lines == ["FAST_VERIFY", "true", "1", "custom_rules", "config.toml"]

    def test_prohibited_pattern_takes_precedence_over_allowed_prefix(self, run_dir: Path) -> None:
        """A sensitive key matching a permitted prefix (e.g. SEMGREP_SECRET_KEY) is rejected."""
        with pytest.raises(ValueError, match="matching sensitive pattern") as exc_info:
            run_command_bounded(
                [sys.executable, "-c", "pass"],
                cwd=run_dir,
                env={"SEMGREP_SECRET_KEY": "supersecret"},
            )
        assert "supersecret" not in str(exc_info.value)

    def test_build_sanitized_env_direct(self, run_dir: Path) -> None:
        """Direct unit test of build_sanitized_env dictionary construction."""
        env = build_sanitized_env(cwd=run_dir, extra_env={"CI": "1"})
        assert env["CI"] == "1"
        assert env["TMP"] == str(run_dir.resolve())
        assert env["TEMP"] == str(run_dir.resolve())
        assert "SECRET_KEY" not in env

    def test_is_dangerous_override_direct(self) -> None:
        """Direct unit test of _is_dangerous_override helper."""
        assert _is_dangerous_override("LD_PRELOAD") is True
        assert _is_dangerous_override("SEMGREP_PYTHONPATH") is True
        assert _is_dangerous_override("GITLEAKS_LD_LIBRARY_PATH") is True
        assert _is_dangerous_override("SCAN_DYLD_INSERT_LIBRARIES") is True
        assert _is_dangerous_override("SEMGREP_RULES_TEST") is False
        assert _is_dangerous_override("GITLEAKS_CONFIG_TEST") is False
        assert _is_dangerous_override("SCAN_MODE") is False


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

    def test_strict_combined_output_limit_simultaneous_streams(self, run_dir: Path) -> None:
        """Simultaneous heavy stdout and stderr generation strictly honors combined max_output_bytes."""
        script = (
            "import sys, threading\n"
            "def write_out():\n"
            "    for _ in range(200):\n"
            "        sys.stdout.write('A' * 100)\n"
            "        sys.stdout.flush()\n"
            "def write_err():\n"
            "    for _ in range(200):\n"
            "        sys.stderr.write('B' * 100)\n"
            "        sys.stderr.flush()\n"
            "t1 = threading.Thread(target=write_out)\n"
            "t2 = threading.Thread(target=write_err)\n"
            "t1.start(); t2.start()\n"
            "t1.join(); t2.join()\n"
        )
        limit = 1000
        result = run_command_bounded(
            [sys.executable, "-c", script],
            cwd=run_dir,
            max_output_bytes=limit,
            timeout_sec=5.0,
        )

        assert result.output_limit_exceeded is True
        assert result.status == CommandStatus.OUTPUT_LIMIT_EXCEEDED
        total_captured = len(result.stdout) + len(result.stderr)
        assert total_captured <= limit, f"Captured {total_captured} exceeded limit of {limit}"
        assert total_captured > 0

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

    def test_stream_reader_failure_does_not_mask_as_success(self, run_dir: Path) -> None:
        """Stream reader failure causes status=ERROR and is_success=False even if process exited 0."""
        orig_popen = subprocess.Popen

        class FaultyStream:
            def read(self, *args: Any) -> bytes:
                raise OSError("Simulated broken pipe during streaming read")

            def close(self) -> None:
                pass

        def mock_popen(*args: Any, **kwargs: Any) -> Any:
            proc = orig_popen(*args, **kwargs)
            proc.stdout = FaultyStream()  # type: ignore[assignment]
            return proc

        with patch("subprocess.Popen", side_effect=mock_popen):
            result = run_command_bounded(
                [sys.executable, "-c", "print('hello')"],
                cwd=run_dir,
            )
            assert result.status == CommandStatus.ERROR
            assert result.is_success is False
            assert result.reader_error is True

            with pytest.raises(SubprocessRunnerError, match="stream reader error"):
                result.raise_for_status()


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

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX process group termination test")
    def test_posix_sigterm_escalation_to_sigkill(self, run_dir: Path) -> None:
        """POSIX process that ignores SIGTERM is escalated to SIGKILL and terminated within grace period."""
        script = (
            "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(30)\n"
        )
        t0 = time.monotonic()
        result = run_command_bounded(
            [sys.executable, "-c", script],
            cwd=run_dir,
            timeout_sec=0.3,
        )
        elapsed = time.monotonic() - t0

        assert result.status == CommandStatus.TIMEOUT
        assert result.timed_out is True
        assert result.is_success is False
        assert elapsed < 5.0, f"Process did not terminate promptly: took {elapsed:.2f}s"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX process group termination test")
    def test_posix_descendants_killed_even_if_parent_exits_first(self, run_dir: Path) -> None:
        """POSIX descendants in the process group are terminated even if the parent exits first."""
        heartbeat_file = run_dir / "child_heartbeat.txt"
        child_script = (
            "import subprocess, sys, time\n"
            "child_code = (\n"
            "    'import time, pathlib\\n'\n"
            f"    'hb = pathlib.Path({str(heartbeat_file)!r})\\n'\n"
            "    'for i in range(600):\\n'\n"
            "    '    hb.write_text(str(i))\\n'\n"
            "    '    time.sleep(0.05)\\n'\n"
            ")\n"
            "p = subprocess.Popen([sys.executable, '-c', child_code])\n"
            "print(f'CHILD_PID:{p.pid}', flush=True)\n"
            "sys.exit(0)\n"
        )
        child_pid: int | None = None
        try:
            result = run_command_bounded(
                [sys.executable, "-c", child_script],
                cwd=run_dir,
            )
            assert result.is_success is True
            lines = result.stdout_text.strip().splitlines()
            child_pids = [line.split(":")[1] for line in lines if line.startswith("CHILD_PID:")]
            assert child_pids, f"Child PID was not captured! Full stdout: {result.stdout_text!r}"
            child_pid = int(child_pids[0])

            time.sleep(0.2)

            # 1. Verify child is not actively executing (dead or zombie, not running)
            assert not _is_posix_process_running(child_pid), (
                f"Child PID {child_pid} is still actively executing!"
            )

            # 2. Verify heartbeat counter ceased advancing
            if heartbeat_file.exists():
                hb1 = heartbeat_file.read_text().strip()
                time.sleep(0.15)
                hb2 = heartbeat_file.read_text().strip()
                assert hb1 == hb2, (
                    f"Heartbeat continued advancing ({hb1} -> {hb2}), child still running!"
                )
        finally:
            if child_pid is not None:
                try:
                    sigkill = getattr(signal, "SIGKILL", 9)
                    os.kill(child_pid, sigkill)
                except (ProcessLookupError, OSError):
                    pass

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX process group termination test")
    def test_posix_child_ignoring_sigterm_escalates_to_sigkill_when_parent_exits(
        self, run_dir: Path
    ) -> None:
        """POSIX child that ignores SIGTERM is escalated to SIGKILL and terminated when parent exits."""
        heartbeat_file = run_dir / "child_sigterm_ign_heartbeat.txt"
        child_script = (
            "import signal, subprocess, sys, time\n"
            "child_code = (\n"
            "    'import signal, time, pathlib\\n'\n"
            "    'signal.signal(signal.SIGTERM, signal.SIG_IGN)\\n'\n"
            f"    'hb = pathlib.Path({str(heartbeat_file)!r})\\n'\n"
            "    'for i in range(600):\\n'\n"
            "    '    hb.write_text(str(i))\\n'\n"
            "    '    time.sleep(0.05)\\n'\n"
            ")\n"
            "p = subprocess.Popen([sys.executable, '-c', child_code])\n"
            "print(f'CHILD_PID:{p.pid}', flush=True)\n"
            "sys.exit(0)\n"
        )
        child_pid: int | None = None
        try:
            t0 = time.monotonic()
            result = run_command_bounded(
                [sys.executable, "-c", child_script],
                cwd=run_dir,
            )
            elapsed = time.monotonic() - t0
            assert result.is_success is True

            lines = result.stdout_text.strip().splitlines()
            child_pids = [line.split(":")[1] for line in lines if line.startswith("CHILD_PID:")]
            assert child_pids, f"Child PID was not captured! Full stdout: {result.stdout_text!r}"
            child_pid = int(child_pids[0])

            # Cleanup should have escalated to SIGKILL within bounded grace period + kill timeout
            assert elapsed < 5.0, f"Cleanup took too long: {elapsed:.2f}s"

            time.sleep(0.2)

            # 1. Verify child process is dead or zombie, not actively executing
            assert not _is_posix_process_running(child_pid), (
                f"Child PID {child_pid} ignoring SIGTERM was not killed by SIGKILL escalation!"
            )

            # 2. Verify heartbeat counter ceased advancing
            if heartbeat_file.exists():
                hb1 = heartbeat_file.read_text().strip()
                time.sleep(0.15)
                hb2 = heartbeat_file.read_text().strip()
                assert hb1 == hb2, (
                    f"Heartbeat continued advancing ({hb1} -> {hb2}) despite SIGKILL escalation!"
                )
        finally:
            if child_pid is not None:
                try:
                    sigkill = getattr(signal, "SIGKILL", 9)
                    os.kill(child_pid, sigkill)
                except (ProcessLookupError, OSError):
                    pass

    @pytest.mark.skipif(
        sys.platform != "win32", reason="Windows Job Object process-tree termination test"
    )
    def test_windows_job_object_process_tree_termination(self, run_dir: Path) -> None:
        """Windows Job Object terminates entire process tree including spawned grandchildren upon timeout."""
        import ctypes
        from ctypes import wintypes

        parent_script = (
            "import subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "print('GRANDCHILD_PID:' + str(p.pid), flush=True)\n"
            "time.sleep(60)\n"
        )
        grandchild_pid: int | None = None
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.GetExitCodeProcess.restype = wintypes.BOOL
        k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k32.TerminateProcess.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL

        try:
            result = run_command_bounded(
                [sys.executable, "-c", parent_script],
                cwd=run_dir,
                timeout_sec=0.5,
            )
            assert result.status == CommandStatus.TIMEOUT
            assert result.timed_out is True

            # Parse grandchild PID from output - REQUIRE it to be captured
            lines = result.stdout_text.strip().splitlines()
            grandchild_pids = [
                line.split(":")[1] for line in lines if line.startswith("GRANDCHILD_PID:")
            ]
            assert grandchild_pids, (
                f"Grandchild PID was not captured in stdout! Full stdout: {result.stdout_text!r}, stderr: {result.stderr_text!r}"
            )
            grandchild_pid = int(grandchild_pids[0])

            # Wait briefly for kernel job object termination to take effect
            time.sleep(0.3)

            # Verify that the grandchild process is no longer active
            # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            h_proc = k32.OpenProcess(0x1000, False, grandchild_pid)
            if h_proc:
                try:
                    code = wintypes.DWORD()
                    success = k32.GetExitCodeProcess(h_proc, ctypes.byref(code))
                    assert success, "GetExitCodeProcess failed on grandchild handle"
                    STILL_ACTIVE = 259
                    assert code.value != STILL_ACTIVE, (
                        f"Grandchild PID {grandchild_pid} is still running (exit code {code.value})!"
                    )
                finally:
                    k32.CloseHandle(h_proc)
        finally:
            # Safe test cleanup: ensure test cannot leave orphaned processes even if assertions fail
            if grandchild_pid is not None:
                try:
                    # PROCESS_TERMINATE = 0x0001
                    h_kill = k32.OpenProcess(0x0001, False, grandchild_pid)
                    if h_kill:
                        k32.TerminateProcess(h_kill, 99)
                        k32.CloseHandle(h_kill)
                except Exception:  # noqa: S110, BLE001
                    pass

    @pytest.mark.skipif(
        sys.platform != "win32", reason="Windows Job Object process-tree termination test"
    )
    def test_windows_job_object_descendants_killed_even_if_parent_exits_first(
        self, run_dir: Path
    ) -> None:
        """Windows Job Object terminates descendant processes even when parent exits with code 0."""
        import ctypes
        from ctypes import wintypes

        parent_script = (
            "import subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "print('GRANDCHILD_PID:' + str(p.pid), flush=True)\n"
            "sys.exit(0)\n"
        )
        grandchild_pid: int | None = None
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.GetExitCodeProcess.restype = wintypes.BOOL
        k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k32.TerminateProcess.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL

        try:
            result = run_command_bounded(
                [sys.executable, "-c", parent_script],
                cwd=run_dir,
            )
            assert result.status == CommandStatus.SUCCESS
            assert result.exit_code == 0

            lines = result.stdout_text.strip().splitlines()
            grandchild_pids = [
                line.split(":")[1] for line in lines if line.startswith("GRANDCHILD_PID:")
            ]
            assert grandchild_pids, (
                f"Grandchild PID was not captured in stdout! Full stdout: {result.stdout_text!r}, stderr: {result.stderr_text!r}"
            )
            grandchild_pid = int(grandchild_pids[0])

            time.sleep(0.3)

            # Verify that the grandchild process is no longer active
            h_proc = k32.OpenProcess(0x1000, False, grandchild_pid)
            if h_proc:
                try:
                    code = wintypes.DWORD()
                    success = k32.GetExitCodeProcess(h_proc, ctypes.byref(code))
                    assert success, "GetExitCodeProcess failed on grandchild handle"
                    STILL_ACTIVE = 259
                    assert code.value != STILL_ACTIVE, (
                        f"Grandchild PID {grandchild_pid} is still running (exit code {code.value})!"
                    )
                finally:
                    k32.CloseHandle(h_proc)
        finally:
            if grandchild_pid is not None:
                try:
                    h_kill = k32.OpenProcess(0x0001, False, grandchild_pid)
                    if h_kill:
                        k32.TerminateProcess(h_kill, 99)
                        k32.CloseHandle(h_kill)
                except Exception:  # noqa: S110, BLE001
                    pass

    @pytest.mark.skipif(
        sys.platform != "win32", reason="Windows Job Object containment failure test"
    )
    def test_windows_job_object_creation_failure_aborts_without_launch(self, run_dir: Path) -> None:
        """When Windows Job Object creation fails, execution aborts with ERROR without running uncontained."""
        with patch("app.worker.subprocess_runner._create_windows_job_object", return_value=None):
            result = run_command_bounded(
                [sys.executable, "-c", "print('should not run')"],
                cwd=run_dir,
            )
            assert result.status == CommandStatus.ERROR
            assert result.is_success is False
            assert result.stdout == b""

            with pytest.raises(
                SubprocessRunnerError, match="process-tree containment could not be established"
            ):
                run_command_bounded(
                    [sys.executable, "-c", "print('should not run')"],
                    cwd=run_dir,
                    check=True,
                )

    @pytest.mark.skipif(
        sys.platform != "win32", reason="Windows Job Object containment failure test"
    )
    def test_windows_job_object_assignment_failure_terminates_launched_process(
        self, run_dir: Path
    ) -> None:
        """When Job Object assignment fails, the launched process is immediately killed and leaves no live process."""
        import ctypes
        from ctypes import wintypes

        captured_pid: list[int] = []

        def mock_assign(job_handle: Any, proc: subprocess.Popen[bytes]) -> bool:
            captured_pid.append(proc.pid)
            return False

        with patch("app.worker.subprocess_runner._assign_process_to_job", side_effect=mock_assign):
            result = run_command_bounded(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                cwd=run_dir,
            )
            assert result.status == CommandStatus.ERROR
            assert result.is_success is False
            assert len(captured_pid) == 1
            pid = captured_pid[0]

            # Verify that the launched process was killed and is no longer active
            k32 = ctypes.windll.kernel32
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            k32.OpenProcess.restype = wintypes.HANDLE
            k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            k32.GetExitCodeProcess.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            k32.CloseHandle.restype = wintypes.BOOL

            time.sleep(0.1)
            h = k32.OpenProcess(0x1000, False, pid)
            if h:
                try:
                    code = wintypes.DWORD()
                    k32.GetExitCodeProcess(h, ctypes.byref(code))
                    STILL_ACTIVE = 259
                    assert code.value != STILL_ACTIVE, (
                        f"Process {pid} is still active after assignment failure!"
                    )
                finally:
                    k32.CloseHandle(h)

            with pytest.raises(
                SubprocessRunnerError, match="process-tree containment could not be established"
            ):
                run_command_bounded(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    cwd=run_dir,
                    check=True,
                )

    @pytest.mark.skipif(
        sys.platform != "win32", reason="Windows Job Object containment failure test"
    )
    def test_windows_job_object_resumption_failure_terminates_launched_process(
        self, run_dir: Path
    ) -> None:
        """When Job Object process resumption fails, the launched process is immediately killed and leaves no live process."""
        import ctypes
        from ctypes import wintypes

        captured_pid: list[int] = []

        def mock_resume(proc: subprocess.Popen[bytes]) -> bool:
            captured_pid.append(proc.pid)
            return False

        with patch("app.worker.subprocess_runner._resume_windows_process", side_effect=mock_resume):
            result = run_command_bounded(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                cwd=run_dir,
            )
            assert result.status == CommandStatus.ERROR
            assert result.is_success is False
            assert len(captured_pid) == 1
            pid = captured_pid[0]

            # Verify that the launched process was killed and is no longer active
            k32 = ctypes.windll.kernel32
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            k32.OpenProcess.restype = wintypes.HANDLE
            k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            k32.GetExitCodeProcess.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            k32.CloseHandle.restype = wintypes.BOOL

            time.sleep(0.1)
            h = k32.OpenProcess(0x1000, False, pid)
            if h:
                try:
                    code = wintypes.DWORD()
                    k32.GetExitCodeProcess(h, ctypes.byref(code))
                    STILL_ACTIVE = 259
                    assert code.value != STILL_ACTIVE, (
                        f"Process {pid} is still active after resumption failure!"
                    )
                finally:
                    k32.CloseHandle(h)

            with pytest.raises(SubprocessRunnerError, match="Failed to resume process"):
                run_command_bounded(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    cwd=run_dir,
                    check=True,
                )

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object handle cleanup test")
    def test_windows_job_object_cleanup_closes_handles(self, run_dir: Path) -> None:
        """Verify that Job Object handle is cleanly closed upon command completion."""
        import app.worker.subprocess_runner as subproc_module

        close_calls: list[Any] = []
        orig_close = subproc_module._close_windows_job_object

        def spy_close(job_handle: Any) -> bool:
            close_calls.append(job_handle)
            return orig_close(job_handle)

        with patch("app.worker.subprocess_runner._close_windows_job_object", side_effect=spy_close):
            res = run_command_bounded(
                [sys.executable, "-c", "print('clean')"],
                cwd=run_dir,
            )
            assert res.is_success is True
            assert len(close_calls) >= 1
            assert close_calls[0] is not None

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
        ):
            result.raise_for_status()

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

    def test_reader_thread_start_failure_terminates_process_and_closes_resources(
        self, run_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Failure starting pipe-reader threads terminates launched child and closes handles/pipes cleanly."""
        import ctypes
        import threading

        import app.worker.subprocess_runner as subproc_module

        launched_procs: list[subprocess.Popen[bytes]] = []
        orig_popen = subprocess.Popen

        def spy_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            proc = orig_popen(*args, **kwargs)
            launched_procs.append(proc)
            return proc

        closed_jobs: list[Any] = []
        orig_close_job = subproc_module._close_windows_job_object

        def spy_close_job(job_handle: Any) -> bool:
            closed_jobs.append(job_handle)
            return orig_close_job(job_handle)

        start_count = 0
        orig_start = threading.Thread.start

        def fail_second_thread_start(self_thread: threading.Thread) -> None:
            nonlocal start_count
            start_count += 1
            if start_count == 2:
                raise RuntimeError("simulated thread exhaustion")
            orig_start(self_thread)

        monkeypatch.setattr(subprocess, "Popen", spy_popen)
        monkeypatch.setattr(subproc_module, "_close_windows_job_object", spy_close_job)
        monkeypatch.setattr(threading.Thread, "start", fail_second_thread_start)

        with pytest.raises(RuntimeError, match="simulated thread exhaustion"):
            run_command_bounded(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                cwd=run_dir,
                timeout_sec=5.0,
            )

        assert len(launched_procs) == 1
        proc = launched_procs[0]
        assert proc.poll() is not None
        assert proc.stdout is not None and proc.stdout.closed
        assert proc.stderr is not None and proc.stderr.closed

        if sys.platform == "win32":
            assert len(closed_jobs) == 1
            kernel32 = ctypes.windll.kernel32
            h = kernel32.OpenProcess(0x0400, False, proc.pid)
            if h:
                try:
                    code = ctypes.c_uint32()
                    kernel32.GetExitCodeProcess(h, ctypes.byref(code))
                    assert code.value != 259
                finally:
                    kernel32.CloseHandle(h)

    def test_terminate_on_output_limit_false_drains_to_eof_without_sigpipe(
        self, run_dir: Path
    ) -> None:
        """When terminate_on_output_limit=False, reader drains unread pipe bytes to EOF cleanly."""
        script = (
            "import sys\n"
            "chunk = b'X' * 4096\n"
            "try:\n"
            "    for _ in range(64):\n"
            "        sys.stdout.buffer.write(chunk)\n"
            "    sys.stdout.buffer.flush()\n"
            "except BrokenPipeError:\n"
            "    sys.exit(42)\n"
            "sys.exit(0)\n"
        )
        res = run_command_bounded(
            [sys.executable, "-c", script],
            cwd=run_dir,
            max_output_bytes=8192,
            terminate_on_output_limit=False,
            timeout_sec=10.0,
        )
        assert res.status == CommandStatus.OUTPUT_LIMIT_EXCEEDED
        assert res.output_limit_exceeded is True
        assert res.stdout_truncated is True
        assert res.exit_code == 0
        assert len(res.stdout) + len(res.stderr) <= 8192
