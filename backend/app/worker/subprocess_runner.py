"""Hardened, bounded subprocess execution utility for static analysis scanners.

Implements Blueprint Section 10.3 (Process constraints) and Threat Mitigations
T2 (Subprocess isolation) and T13 (Worker concurrency and bounded execution).
"""

from __future__ import annotations

import logging
import math
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

# Dangerous environment variable overrides that could subvert interpreter, dynamic linker, or sandbox isolation
_DANGEROUS_OVERRIDE_ENV_KEYS: frozenset[str] = frozenset(
    {
        # Dynamic linker and library preloading hijacking
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        # Language runtime code injection
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONEXECUTABLE",
        "PYTHONUSERBASE",
        "PYTHONOPTIMIZE",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PERL5LIB",
        "PERL5OPT",
        "PERLLIB",
        "RUBYLIB",
        "RUBYOPT",
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "PROMPT_COMMAND",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "CLASSPATH",
        "GLIBC_TUNABLES",
        # Workspace isolation preservation
        "TMP",
        "TEMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
    }
)

# Standard essential system variables safe to inherit for child process execution
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

# Approved exact environment variable names for caller-supplied extra_env
_ALLOWED_EXTRA_ENV_EXACT: frozenset[str] = frozenset(
    {
        "CI",
        "NO_COLOR",
        "COLOR",
        "SCAN_MODE",
        "TERM",
        "LANG",
        "LC_ALL",
        "TZ",
        "VERBOSITY",
        "QUIET",
        "DEBUG",
    }
)

# Approved prefixes for caller-supplied tool configurations
_ALLOWED_EXTRA_ENV_PREFIXES: tuple[str, ...] = (
    "SEMGREP_",
    "GITLEAKS_",
    "SCAN_",
)


# Windows Job Object infrastructure for process-tree containment
_k32: Any = None
_ntdll: Any = None
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JobObjectExtendedLimitInformation = 9
_CREATE_SUSPENDED = 0x00000004
_TH32CS_SNAPTHREAD = 0x00000004
_THREAD_SUSPEND_RESUME = 0x0002

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryLimit", ctypes.c_size_t),
            ("PeakJobMemoryLimit", ctypes.c_size_t),
        ]

    class _THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    # Explicit ctypes argtypes and restypes for Windows APIs using pointer-sized HANDLE
    _k32 = ctypes.windll.kernel32

    _k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _k32.CreateJobObjectW.restype = wintypes.HANDLE

    _k32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _k32.SetInformationJobObject.restype = wintypes.BOOL

    _k32.AssignProcessToJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
    ]
    _k32.AssignProcessToJobObject.restype = wintypes.BOOL

    _k32.TerminateJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.UINT,
    ]
    _k32.TerminateJobObject.restype = wintypes.BOOL

    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL

    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    _k32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _k32.Thread32First.restype = wintypes.BOOL

    _k32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _k32.Thread32Next.restype = wintypes.BOOL

    _k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenThread.restype = wintypes.HANDLE

    _k32.ResumeThread.argtypes = [wintypes.HANDLE]
    _k32.ResumeThread.restype = wintypes.DWORD

    _ntdll = getattr(ctypes.windll, "ntdll", None)
    if _ntdll and hasattr(_ntdll, "NtResumeProcess"):
        _ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        _ntdll.NtResumeProcess.restype = wintypes.LONG


def _create_windows_job_object() -> Any:
    """Create a Windows Job Object configured to terminate all descendant processes on close.

    Returns:
        Pointer-sized job handle or None if creation/configuration fails.
    """
    if sys.platform != "win32" or _k32 is None:
        return None
    try:
        from ctypes import wintypes

        h_job = _k32.CreateJobObjectW(None, None)
        if not h_job:
            err = _k32.GetLastError()
            logger.error("Failed to create Windows Job Object: WinError %d", err)
            return None

        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        success = _k32.SetInformationJobObject(
            wintypes.HANDLE(h_job),
            _JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not success:
            err = _k32.GetLastError()
            logger.error("Failed to configure Windows Job Object limit flags: WinError %d", err)
            _k32.CloseHandle(wintypes.HANDLE(h_job))
            return None
        return h_job
    except Exception as exc:  # noqa: BLE001
        logger.error("Exception creating Windows Job Object: %s", exc)
        return None


def _assign_process_to_job(job_handle: Any, proc: subprocess.Popen[bytes]) -> bool:
    """Assign a subprocess to a Windows Job Object.

    Returns:
        True if successfully assigned, False otherwise.
    """
    if sys.platform != "win32" or not job_handle or _k32 is None:
        return False
    try:
        from ctypes import wintypes

        raw_handle = getattr(proc, "_handle", None)
        if raw_handle is None:
            logger.error("Cannot assign process %s to Job Object: proc._handle is None", proc.pid)
            return False
        h_proc = wintypes.HANDLE(int(raw_handle))
        h_job = wintypes.HANDLE(job_handle)
        success = _k32.AssignProcessToJobObject(h_job, h_proc)
        if not success:
            err = _k32.GetLastError()
            logger.error(
                "Failed to assign process %s to Windows Job Object: WinError %d",
                proc.pid,
                err,
            )
            return False
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Exception assigning process %s to Windows Job Object: %s", proc.pid, exc)
        return False


def _resume_windows_process(proc: subprocess.Popen[bytes]) -> bool:
    """Resume execution of a suspended Windows process.

    Uses NtResumeProcess if available; falls back to enumerating process threads
    via CreateToolhelp32Snapshot and calling ResumeThread.

    Returns:
        True if process threads were successfully resumed, False otherwise.
    """
    if sys.platform != "win32" or _k32 is None:
        return True

    from ctypes import wintypes

    raw_handle = getattr(proc, "_handle", None)
    if raw_handle is None:
        return False

    # Primary strategy: NtResumeProcess from ntdll
    if _ntdll and hasattr(_ntdll, "NtResumeProcess"):
        try:
            h_proc = wintypes.HANDLE(int(raw_handle))
            status = _ntdll.NtResumeProcess(h_proc)
            if status == 0:  # STATUS_SUCCESS
                return True
            logger.warning(
                "NtResumeProcess failed for process %d with NTSTATUS 0x%08X",
                proc.pid,
                status & 0xFFFFFFFF,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("NtResumeProcess exception for process %d: %s", proc.pid, exc)

    # Fallback strategy: Win32 CreateToolhelp32Snapshot + OpenThread + ResumeThread
    try:
        h_snap = _k32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if not h_snap or h_snap == wintypes.HANDLE(-1).value:
            return False

        te = _THREADENTRY32()
        te.dwSize = ctypes.sizeof(_THREADENTRY32)
        resumed_any = False
        try:
            if _k32.Thread32First(h_snap, ctypes.byref(te)):
                while True:
                    if te.th32OwnerProcessID == proc.pid:
                        ht = _k32.OpenThread(_THREAD_SUSPEND_RESUME, False, te.th32ThreadID)
                        if ht:
                            try:
                                prev_count = _k32.ResumeThread(ht)
                                if prev_count != 0xFFFFFFFF:
                                    resumed_any = True
                            finally:
                                _k32.CloseHandle(ht)
                    if not _k32.Thread32Next(h_snap, ctypes.byref(te)):
                        break
        finally:
            _k32.CloseHandle(h_snap)

        return resumed_any
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to resume threads for process %d: %s", proc.pid, exc)
        return False


def _close_windows_job_object(job_handle: Any) -> bool:
    """Close the Windows Job Object handle (terminating contained descendant processes)."""
    if sys.platform != "win32" or not job_handle or _k32 is None:
        return False
    try:
        from ctypes import wintypes

        success = _k32.CloseHandle(wintypes.HANDLE(job_handle))
        if not success:
            err = _k32.GetLastError()
            logger.debug("CloseHandle on Job Object returned WinError %d", err)
            return False
        return True
    except Exception as exc:  # noqa: BLE001
        logger.debug("Exception closing Windows Job Object: %s", exc)
        return False


def _terminate_windows_job_object(job_handle: Any, exit_code: int = 1) -> bool:
    """Terminate all processes assigned to the Windows Job Object."""
    if sys.platform != "win32" or not job_handle or _k32 is None:
        return False
    try:
        from ctypes import wintypes

        success = _k32.TerminateJobObject(wintypes.HANDLE(job_handle), exit_code)
        if not success:
            err = _k32.GetLastError()
            logger.debug("TerminateJobObject returned WinError %d", err)
            return False
        return True
    except Exception as exc:  # noqa: BLE001
        logger.debug("Exception terminating Windows Job Object: %s", exc)
        return False


def _is_posix_pg_alive(pgid: int | None) -> bool:
    """Check if any process in the POSIX process group is still alive.

    Guarantees:
    - Avoids signaling unrelated process groups (requires pgid > 1).
    - Uses stored PGID directly without relying on the parent process surviving.
    - Handles ProcessLookupError, PermissionError, and OSError safely.
    """
    if sys.platform == "win32" or pgid is None or pgid <= 1:
        return False
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Group exists but caller lacks permission to signal it
        return True
    except OSError:
        return False


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
    reader_error: bool = False

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
        if self.reader_error or self.status == CommandStatus.ERROR:
            raise SubprocessRunnerError(
                f"Command '{cmd_name}' encountered an execution or stream reader error",
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


def _is_dangerous_override(key: str) -> bool:
    """Determine whether an environment variable name constitutes a dangerous override.

    Detects interpreter hijacking, dynamic-linker preloading, shell injection,
    and workspace escaping variables even when prefixed with approved tool
    prefixes (e.g. SEMGREP_PYTHONPATH, GITLEAKS_LD_PRELOAD, SCAN_DYLD_INSERT_LIBRARIES).
    """
    k_upper = key.strip().upper()
    if k_upper in _DANGEROUS_OVERRIDE_ENV_KEYS:
        return True

    # 1. Check if stripping any approved prefix leaves a dangerous override key
    for prefix in _ALLOWED_EXTRA_ENV_PREFIXES:
        if k_upper.startswith(prefix):
            remainder = k_upper[len(prefix) :]
            if remainder in _DANGEROUS_OVERRIDE_ENV_KEYS:
                return True
            for dangerous in _DANGEROUS_OVERRIDE_ENV_KEYS:
                if remainder.endswith(f"_{dangerous}"):
                    return True

    # 2. Check if any dangerous compound runtime / linker / shell identifier appears as a token segment
    # (Token segment matching avoids false positives for short substrings like "ENV" in "ENVIRONMENT" or "TMP" in "TEMPLATES")
    key_tokens = [tok for tok in k_upper.split("_") if tok]
    for dangerous in _DANGEROUS_OVERRIDE_ENV_KEYS:
        danger_tokens = [tok for tok in dangerous.split("_") if tok]
        len_danger = len(danger_tokens)
        for i in range(len(key_tokens) - len_danger + 1):
            if key_tokens[i : i + len_danger] == danger_tokens:
                return True

    return False


def build_sanitized_env(
    cwd: Path,
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Construct an isolated, sanitized environment dictionary for child process execution.

    Guarantees:
    - Never inherits application secrets, database URLs, GitHub tokens, or API keys.
    - Preserves essential platform variables required for process launch (e.g. SystemRoot, PATHEXT).
    - Sets TMP, TEMP, and TMPDIR to point to the designated workspace working directory.
    - Sets HOME/USERPROFILE to the designated working directory.
    - Rejects dangerous override variables (e.g. PYTHONPATH, LD_PRELOAD, DYLD_INSERT_LIBRARIES).
    - Enforces an explicit allowlist for caller-supplied environment variables.
    - Never echoes variable values in exceptions or logs.

    Args:
        cwd: Working directory Path for the subprocess.
        extra_env: Optional non-sensitive environment variables to add.

    Returns:
        Sanitized environment dictionary suitable for subprocess.Popen.
    """
    clean_env: dict[str, str] = {}

    # 1. Inherit safe system platform variables
    for key, val in os.environ.items():
        is_safe_key = any(key.lower() == safe.lower() for safe in _SAFE_SYSTEM_ENV_KEYS)
        if not is_safe_key:
            continue

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

    # 3. Merge caller-supplied extra_env with strict security validation
    if extra_env:
        for k, v in extra_env.items():
            if not isinstance(k, str) or not k.strip():
                raise ValueError("Environment variable name must be a non-empty string")
            k_clean = k.strip()
            k_upper = k_clean.upper()

            # Reject sensitive substrings
            if any(bad in k_upper for bad in _PROHIBITED_ENV_SUBSTRINGS):
                raise ValueError(
                    f"Refusing to pass environment variable '{k_clean}' matching sensitive pattern"
                )

            # Reject dangerous overrides (including prefixed variants)
            if _is_dangerous_override(k_clean):
                raise ValueError(
                    f"Refusing to pass environment variable '{k_clean}': dangerous override prohibited"
                )

            # Enforce allowlist for caller-supplied variables
            is_allowed = k_upper in _ALLOWED_EXTRA_ENV_EXACT or any(
                k_upper.startswith(prefix) for prefix in _ALLOWED_EXTRA_ENV_PREFIXES
            )
            if not is_allowed:
                raise ValueError(
                    f"Refusing to pass environment variable '{k_clean}': not in approved environment allowlist"
                )

            clean_env[k_clean] = str(v)

    # 4. Final safety scrub: ensure no prohibited keys slipped in
    scrubbed: dict[str, str] = {}
    for k, v in clean_env.items():
        k_upper = k.upper()
        if not any(bad in k_upper for bad in _PROHIBITED_ENV_SUBSTRINGS):
            scrubbed[k] = v

    return scrubbed


class _OutputBudget:
    """Thread-safe coordinator tracking and enforcing combined stream output limit."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self.retained_bytes = 0
        self._lock = threading.Lock()
        self.limit_exceeded = False

    def reserve(self, chunk: bytes) -> tuple[bytes, bool]:
        """Reserve byte budget for incoming chunk atomically.

        Returns:
            Tuple of (retained_slice, is_truncated).
        """
        with self._lock:
            if self.retained_bytes >= self.max_bytes:
                self.limit_exceeded = True
                return (b"", True)

            remaining = self.max_bytes - self.retained_bytes
            if len(chunk) > remaining:
                retained = chunk[:remaining]
                self.retained_bytes += remaining
                self.limit_exceeded = True
                return (retained, True)

            self.retained_bytes += len(chunk)
            return (chunk, False)


def _terminate_process_tree(
    proc: subprocess.Popen[bytes],
    *,
    grace_period_sec: float = 0.5,
    kill_timeout_sec: float = 1.0,
    job_handle: Any = None,
    pgid: int | None = None,
) -> None:
    """Terminate the process group/tree gracefully, escalating to SIGKILL on POSIX or terminating Job Object on Windows.

    Guarantees:
    - POSIX: Sends SIGTERM to the process group (using stored pgid even if parent exited),
      waits for bounded grace period, verifies whether any descendants remain alive,
      and escalates to SIGKILL.
    - Windows: Terminates all processes assigned to the Job Object and process handle.
    """
    if sys.platform != "win32":
        target_pgid = (
            pgid if (pgid is not None and pgid > 1) else (proc.pid if proc.pid > 1 else None)
        )

        # 1. Graceful termination: send SIGTERM to entire process group
        if target_pgid is not None:
            try:
                os.killpg(target_pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                logger.warning(
                    "Permission denied sending SIGTERM to process group %d: %s",
                    target_pgid,
                    exc,
                )
            except OSError as exc:
                logger.debug("Error sending SIGTERM to process group %d: %s", target_pgid, exc)

        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass

        # 2. Bounded grace period: wait and check if any processes in group remain alive
        deadline = time.monotonic() + grace_period_sec
        pg_alive = True
        while time.monotonic() < deadline:
            proc_done = proc.poll() is not None
            pg_done = True
            if target_pgid is not None:
                pg_done = not _is_posix_pg_alive(target_pgid)
            if proc_done and pg_done:
                pg_alive = False
                break
            time.sleep(0.02)

        # 3. Escalate to SIGKILL if processes remain in process group
        if pg_alive:
            if target_pgid is not None:
                try:
                    os.killpg(target_pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError as exc:
                    logger.warning(
                        "Permission denied sending SIGKILL to process group %d: %s",
                        target_pgid,
                        exc,
                    )
                except OSError as exc:
                    logger.debug("Error sending SIGKILL to process group %d: %s", target_pgid, exc)

            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass

        try:
            proc.wait(timeout=kill_timeout_sec)
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Bounded wait for remaining process group cleanup
        if target_pgid is not None:
            kill_deadline = time.monotonic() + kill_timeout_sec
            while time.monotonic() < kill_deadline and _is_posix_pg_alive(target_pgid):
                time.sleep(0.02)
    else:
        # Windows: Terminate via Job Object and process handle
        if job_handle:
            _terminate_windows_job_object(job_handle, 1)

        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass

        try:
            proc.wait(timeout=grace_period_sec)
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
            try:
                proc.wait(timeout=kill_timeout_sec)
            except (subprocess.TimeoutExpired, OSError):
                pass


def _terminate_process_group(proc: subprocess.Popen[bytes], pgid: int | None = None) -> None:
    """Terminate the process group/tree gracefully (backward-compatible helper)."""
    _terminate_process_tree(proc, grace_period_sec=0.2, kill_timeout_sec=0.5, pgid=pgid)


def _force_kill_process_group(proc: subprocess.Popen[bytes], pgid: int | None = None) -> None:
    """Forcefully kill the process group/tree (backward-compatible helper)."""
    _terminate_process_tree(proc, grace_period_sec=0.0, kill_timeout_sec=0.5, pgid=pgid)


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
    - Starts in an isolated process group/session on POSIX with stored PGID tracking.
    - On Windows, enforces pre-execution containment via Job Object before scanner execution.
    - Enforces timeout_sec and terminates entire process group/tree cleanly upon expiration.
    - Streams stdout and stderr concurrently without deadlock.
    - Caps combined stream buffers at max_output_bytes using thread-safe budget coordination.
    - Safely records stream reader failures and prevents false successful command outcomes.
    - Guarantees child process tree termination and stream cleanup across all exit paths.
    - Closes handles on every success and failure path.
    - Never exposes environment variable values or raw tokens in logs or errors.

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
        ValueError: If arguments, cwd, timeout_sec, or max_output_bytes are invalid,
                    or env contains prohibited secrets or dangerous overrides.
        CommandNotFoundError: If check=True and the executable does not exist.
        CommandTimeoutError: If check=True and execution exceeds timeout_sec.
        OutputLimitExceededError: If check=True and output cap is reached.
        NonzeroExitCodeError: If check=True and exit status is non-zero.
        SubprocessRunnerError: If check=True and an unhandled execution, containment, or reader error occurs.
    """
    # 1. Validate argument sequence
    if isinstance(args, (str, bytes)):
        raise ValueError("args must be a sequence of strings, not a string or bytes")  # noqa: TRY004
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

    # 3. Validate timeout_sec: require finite positive number, explicitly rejecting booleans, NaN, and inf
    if timeout_sec is not None and (
        isinstance(timeout_sec, bool)
        or not isinstance(timeout_sec, (int, float))
        or not math.isfinite(timeout_sec)
        or timeout_sec <= 0
    ):
        raise ValueError("timeout_sec must be a finite positive number")

    # 4. Validate max_output_bytes: require positive integer, explicitly rejecting booleans and floats
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or max_output_bytes <= 0
    ):
        raise ValueError("max_output_bytes must be a positive integer")

    # 5. Construct sanitized environment
    sanitized_env = build_sanitized_env(cwd=resolved_cwd, extra_env=env)

    # 6. Configure subprocess launch arguments
    popen_kwargs: dict[str, Any] = {
        "args": clean_args,
        "cwd": str(resolved_cwd),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": sanitized_env,
        "shell": False,
    }

    start_mono = time.monotonic()
    h_job: Any = None
    proc: subprocess.Popen[bytes] | None = None
    stored_pgid: int | None = None
    t_out: threading.Thread | None = None
    t_err: threading.Thread | None = None
    t_out_started = False
    t_err_started = False

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_truncated = [False]
    stderr_truncated = [False]
    stop_event = threading.Event()
    limit_reached_event = threading.Event()
    reader_failed_event = threading.Event()
    reader_errors: list[str] = []
    reader_error_lock = threading.Lock()
    budget = _OutputBudget(max_output_bytes)

    timed_out = False
    output_limit_exceeded = False
    deadline = (start_mono + timeout_sec) if timeout_sec is not None else None

    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True
    else:
        # Pre-execution containment: Create Job Object before launching process
        h_job = _create_windows_job_object()
        if h_job is None:
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
                    f"Failed to create Windows Job Object for command '{clean_args[0]}': process-tree containment could not be established",
                    result=result,
                )
            return result

        # Launch suspended so process cannot execute or spawn descendants before Job Object assignment
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED

    def _stream_reader(
        stream: IO[bytes] | None,
        chunks: list[bytes],
        truncated_flag: list[bool],
        stream_name: str,
    ) -> None:
        if stream is None:
            return
        draining = False
        try:
            while True:
                if stop_event.is_set() and limit_reached_event.is_set():
                    break
                chunk = stream.read(8192)
                if not chunk:
                    break

                if draining:
                    continue

                retained, is_truncated = budget.reserve(chunk)
                if retained:
                    chunks.append(retained)

                if is_truncated:
                    truncated_flag[0] = True
                    limit_reached_event.set()
                    if terminate_on_output_limit:
                        break
                    draining = True
        except Exception as exc:  # noqa: BLE001
            with reader_error_lock:
                reader_errors.append(f"{stream_name} reader error: {type(exc).__name__}")
            reader_failed_event.set()
            logger.error(
                "Subprocess %s stream reader failed on command '%s': %s",
                stream_name,
                clean_args[0],
                type(exc).__name__,
            )
        finally:
            try:
                stream.close()
            except Exception:  # noqa: S110, BLE001
                pass

    # Outer lifecycle guard spans process launch, Win32 Job setup, pipe readers, polling, and cleanup
    try:
        # 7. Launch process with pre-execution containment
        try:
            proc = subprocess.Popen(**popen_kwargs)
            if sys.platform != "win32":
                stored_pgid = proc.pid
            else:
                # Assign process to Job Object while still suspended
                assigned = _assign_process_to_job(h_job, proc)
                if not assigned:
                    # Terminate and clean up process immediately on assignment failure
                    try:
                        proc.kill()
                        proc.wait(timeout=1.0)
                    except Exception:  # noqa: S110, BLE001
                        pass
                    _close_windows_job_object(h_job)
                    h_job = None
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
                            f"Failed to assign process {proc.pid} to Windows Job Object for command '{clean_args[0]}': process-tree containment could not be established",
                            result=result,
                        )
                    return result

                # Resume process now that containment is established
                resumed = _resume_windows_process(proc)
                if not resumed:
                    try:
                        proc.kill()
                        proc.wait(timeout=1.0)
                    except Exception:  # noqa: S110, BLE001
                        pass
                    _terminate_windows_job_object(h_job, 1)
                    _close_windows_job_object(h_job)
                    h_job = None
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
                            f"Failed to resume process {proc.pid} after Job Object assignment for command '{clean_args[0]}'",
                            result=result,
                        )
                    return result
        except FileNotFoundError:
            if h_job is not None:
                _close_windows_job_object(h_job)
                h_job = None
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
        except SubprocessRunnerError:
            raise
        except Exception as exc:
            if h_job is not None:
                _close_windows_job_object(h_job)
                h_job = None
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

        # 8. Set up thread-safe deadlock-free bounded streaming readers
        t_out = threading.Thread(
            target=_stream_reader,
            args=(proc.stdout, stdout_chunks, stdout_truncated, "stdout"),
            name=f"subproc-stdout-{proc.pid}",
            daemon=True,
        )
        t_err = threading.Thread(
            target=_stream_reader,
            args=(proc.stderr, stderr_chunks, stderr_truncated, "stderr"),
            name=f"subproc-stderr-{proc.pid}",
            daemon=True,
        )
        t_out.start()
        t_out_started = True
        t_err.start()
        t_err_started = True

        # 9. Polling and lifecycle monitoring
        while True:
            # Check if output limit was reached
            if limit_reached_event.is_set() or stdout_truncated[0] or stderr_truncated[0]:
                output_limit_exceeded = True
                if terminate_on_output_limit:
                    logger.warning(
                        "Command '%s' exceeded max output byte limit of %d; terminating process tree",
                        clean_args[0],
                        max_output_bytes,
                    )
                    _terminate_process_tree(proc, job_handle=h_job, pgid=stored_pgid)
                    break

            # Check if stream reader failed
            if reader_failed_event.is_set():
                logger.warning(
                    "Command '%s' encountered stream reader failure; terminating process tree",
                    clean_args[0],
                )
                _terminate_process_tree(proc, job_handle=h_job, pgid=stored_pgid)
                break

            # Check if execution timed out
            now_mono = time.monotonic()
            if deadline is not None and now_mono >= deadline:
                timed_out = True
                logger.warning(
                    "Command '%s' exceeded timeout of %.1fs; terminating process tree",
                    clean_args[0],
                    timeout_sec,
                )
                _terminate_process_tree(proc, job_handle=h_job, pgid=stored_pgid)
                break

            # Check if process naturally exited
            if proc.poll() is not None:
                break

            time.sleep(0.01)

    finally:
        # Guarantee child process and any descendant processes are terminated and reaped
        if proc is not None:
            try:
                is_alive = proc.poll() is None
                if sys.platform != "win32" and not is_alive and stored_pgid is not None:
                    is_alive = _is_posix_pg_alive(stored_pgid)

                if is_alive:
                    _terminate_process_tree(proc, job_handle=h_job, pgid=stored_pgid)
            except Exception:  # noqa: S110, BLE001
                pass

        # On Windows, ensure Job Object termination and handle closure happens before joining reader threads
        # so any descendant processes holding pipe handles open are terminated and pipes reach EOF
        if h_job is not None:
            try:
                if proc is not None:
                    _terminate_windows_job_object(h_job, 1)
            except Exception:  # noqa: S110, BLE001
                pass
            try:
                _close_windows_job_object(h_job)
            except Exception:  # noqa: S110, BLE001
                pass
            h_job = None

        stop_event.set()
        for thread, started in ((t_out, t_out_started), (t_err, t_err_started)):
            if thread is not None and started:
                try:
                    thread.join(timeout=1.0)
                except Exception:  # noqa: S110, BLE001
                    pass

        if proc is not None:
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:  # noqa: S110, BLE001
                        pass

    duration_ms = (time.monotonic() - start_mono) * 1000.0
    stdout_data = b"".join(stdout_chunks)
    stderr_data = b"".join(stderr_chunks)

    # Re-verify output limit exceeded in case readers filled buffers as process exited
    if stdout_truncated[0] or stderr_truncated[0] or limit_reached_event.is_set():
        output_limit_exceeded = True

    has_reader_error = bool(reader_errors) or reader_failed_event.is_set()

    # 10. Classify outcome
    if timed_out:
        status = CommandStatus.TIMEOUT
    elif output_limit_exceeded:
        status = CommandStatus.OUTPUT_LIMIT_EXCEEDED
    elif has_reader_error:
        status = CommandStatus.ERROR
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
        reader_error=has_reader_error,
    )

    if check:
        result.raise_for_status()

    return result
