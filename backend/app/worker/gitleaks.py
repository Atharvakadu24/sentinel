"""Gitleaks secret detection scanner adapter and output normalizer.

Implements Blueprint Section 10.4 (Deterministic static analysis - Gitleaks CLI),
Section 10.5 (Canonical Finding Schema), Section 10.6 (Fingerprint Generation),
and Threat Mitigations T2 (Subprocess isolation), T3 (Zero-secret disclosure),
and T8 (Path safety).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import re
import stat
import tempfile
import tomllib
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.core.config import get_settings
from app.domain.findings import (
    _FORBIDDEN_RAW_KEYS,
    _SECRET_VALUE_PATTERNS,
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingReference,
    FindingSeverity,
    FindingSource,
    VerificationStatus,
    _validate_raw_node,
)
from app.domain.fingerprint import (
    assign_occurrence_indices,
    compute_code_anchor,
    compute_finding_fingerprint,
    compute_secret_anchor,
    validate_fingerprint_key,
)
from app.worker.scanner import (
    ScanExecutionResult,
    ScanJobPayload,
    ScannedFile,
    ScannerInterface,
    ScanStatus,
)
from app.worker.staging import (
    StagedWorkspace,
    StagingCleanupError,
    StagingPathMappingError,
)
from app.worker.subprocess_runner import (
    CommandResult,
    CommandStatus,
    run_command_bounded,
)

logger = logging.getLogger("sentinel.worker.gitleaks")

_NETWORK_CONFIG_PREFIXES: tuple[str, ...] = (
    "http://",
    "https://",
    "ftp://",
    "ftps://",
    "s3://",
    "gs://",
    "az://",
    "git://",
    "ssh://",
    "scp://",
    "file://",
)
_URI_SCHEME_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]+:")
_MAX_CONFIG_FILE_BYTES: int = 1 * 1024 * 1024
_DEFAULT_GITLEAKS_CONFIG_REL_PATHS: frozenset[str] = frozenset(
    {"./rules/gitleaks/default.toml", "rules/gitleaks/default.toml"}
)
_UNTRUSTED_REPO_CONTROL_FILENAMES: frozenset[str] = frozenset({".gitleaks.toml", ".gitleaksignore"})
_FORBIDDEN_TOML_KEYS: frozenset[str] = frozenset(
    {
        "url",
        "urls",
        "uri",
        "uris",
        "remote",
        "endpoint",
        "endpoints",
        "fetch",
        "webhook",
        "webhooks",
        "include",
        "includes",
        "import",
        "imports",
        "plugin",
        "plugins",
    }
)
_EXTEND_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "url",
        "urls",
        "uri",
        "uris",
        "path",
        "paths",
        "file",
        "files",
        "source",
        "src",
        "config",
        "configs",
    }
)
_TOML_PATTERN_SAFE_KEYS: frozenset[str] = frozenset(
    {
        "regex",
        "regexes",
        "description",
        "title",
        "tags",
        "keywords",
        "stopwords",
        "commits",
        "paths",
        "path",
        "id",
        "secretgroup",
        "entropy",
    }
)
_CONTROL_CHAR_INLINE_PATTERN: re.Pattern[str] = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CONTROL_CHAR_SINGLELINE_PATTERN: re.Pattern[str] = re.compile(r"[\x00-\x1f\x7f]")
_PEM_HEADER_FOOTER_LINE_PATTERN: re.Pattern[str] = re.compile(
    r"^-----+(?:BEGIN|END)\s+[A-Z0-9 _\-]+-----+$"
)
_SAFE_FRAGMENT_WORDS: frozenset[str] = frozenset(
    {
        "secret",
        "secrets",
        "token",
        "tokens",
        "password",
        "passwd",
        "passphrase",
        "credential",
        "credentials",
        "private",
        "public",
        "personal",
        "access",
        "apikey",
        "api_key",
        "secret_key",
        "private_key",
        "public_key",
        "access_key",
        "access_token",
        "auth_token",
        "api_token",
        "signing_key",
        "github",
        "gitlab",
        "stripe",
        "twilio",
        "google",
        "slack",
        "openai",
        "anthropic",
        "heroku",
        "azure",
        "bearer",
        "oauth",
        "oauth2",
        "detected",
        "hardcoded",
        "generic",
        "header",
        "config",
        "default",
        "sentinel",
        "example",
        "sample",
        "placeholder",
        "redact",
        "redacted",
    }
)
_DEFAULT_REMEDIATION: str = (
    "Revoke and rotate the exposed secret immediately, remove it from git history, "
    "and use an external secrets manager."
)
_DEFAULT_REFERENCE: FindingReference = FindingReference(
    type="cwe",
    id="CWE-798",
    url="https://cwe.mitre.org/data/definitions/798.html",
)

# Conservative allowlisted identifier format for RuleID (letters, numbers, hyphens, underscores, dots; max 128 chars)
_RULE_ID_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")

# Conservative allowlisted tag identifier format (max 64 chars)
_TAG_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")

# Maximum permitted report file size (10 MB cap)
_MAX_REPORT_FILE_BYTES: int = 10 * 1024 * 1024

# Maximum allowed description length
_MAX_DESCRIPTION_LENGTH: int = 1000

# Recognizable redaction placeholder prefixes
_REDACTION_PLACEHOLDER_PREFIXES: tuple[str, ...] = ("REDACTED", "[REDACTED", "***")


class GitleaksError(Exception):
    """Base exception for Gitleaks adapter operations."""


class GitleaksExecutionError(GitleaksError):
    """Raised when Gitleaks process execution fails."""


class GitleaksNormalizationError(GitleaksError):
    """Raised when Gitleaks output normalization fails."""


def _is_posix_platform() -> bool:
    """Return True on POSIX hosts where Unix mode bits are enforced."""
    return os.name != "nt"


def _is_safe_directory_chain(directory: Path, *, allow_symlink: bool = False) -> bool:
    """Check directory and all ancestor components for symlinks and unsafe world-writable bits."""
    abs_dir = Path(os.path.abspath(str(directory)))
    raw_dir_link = directory.is_symlink()
    try:
        dir_is_link = raw_dir_link or abs_dir.is_symlink()
        dir_st = os.lstat(abs_dir)
    except OSError:
        return False

    if (not allow_symlink) and (dir_is_link or stat.S_ISLNK(dir_st.st_mode)):
        return False
    if not stat.S_ISDIR(dir_st.st_mode):
        return False
    if _is_posix_platform() and (dir_st.st_mode & stat.S_IWOTH):
        return False

    for ancestor in abs_dir.parents:
        try:
            anc_is_link = ancestor.is_symlink()
            anc_st = os.lstat(ancestor)
        except OSError:
            return False

        if (not allow_symlink) and (anc_is_link or stat.S_ISLNK(anc_st.st_mode)):
            return False
        if not stat.S_ISDIR(anc_st.st_mode):
            return False
        # Permit sticky-bit system temp dirs like Linux /tmp (0o1777), reject non-sticky S_IWOTH (0o777)
        if (
            _is_posix_platform()
            and (anc_st.st_mode & stat.S_IWOTH)
            and not (anc_st.st_mode & stat.S_ISVTX)
        ):
            return False

    return True


def _is_executable_file(path: Path, *, allow_symlink: bool = False) -> bool:
    """Check if path is a regular, non-symlink (by policy), executable file in safe directories."""
    try:
        is_link = path.is_symlink()
        st = os.lstat(path)
        if is_link or stat.S_ISLNK(st.st_mode):
            if not allow_symlink:
                return False
            st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return False
        if not os.access(path, os.X_OK):
            return False
        if _is_posix_platform() and (st.st_mode & stat.S_IWOTH):
            return False
        return _is_safe_directory_chain(path.parent, allow_symlink=allow_symlink)
    except OSError:
        return False


def _candidate_executable_names(entry_dir: Path, name: str) -> list[Path]:
    """Build candidate executable paths inside a validated PATH directory."""
    if os.name == "nt" and not Path(name).suffix:
        raw_pathext = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        allowed_exts = [
            ext.strip().lower()
            for ext in raw_pathext.split(";")
            if ext.strip().lower() in {".com", ".exe", ".bat", ".cmd"}
        ]
        if not allowed_exts:
            allowed_exts = [".com", ".exe", ".bat", ".cmd"]
        return [entry_dir / f"{name}{ext}" for ext in allowed_exts]
    return [entry_dir / name]


def _resolve_executable(
    executable: str | Path,
    *,
    allow_path_lookup: bool | None = None,
    allow_symlink: bool = False,
) -> str | None:
    """Resolve an executable path safely with strict symlink and production PATH policy.

    Policy:
    - In production (``APP_ENV == "production"`` unless overridden via ``allow_path_lookup``),
      ambient ``PATH`` lookups and relative executable paths are rejected; an explicit configured
      absolute path is required.
    - Symlinked executables are rejected by default (``allow_symlink=False``).
    - When ambient ``PATH`` lookup is permitted in development/test, empty/relative/UNC
      ``PATH`` entries, Windows implicit CWD lookup, and POSIX world-writable directories are
      skipped.

    Args:
        executable: Configured executable name or path.
        allow_path_lookup: Optional explicit override controlling ambient PATH/relative lookup.
        allow_symlink: Whether symlinked executable targets are permitted (default False).

    Returns:
        Absolute filesystem path to the executable, or None if invalid, untrusted, or not found.
    """
    p_str = str(executable).strip()
    if not p_str or "\x00" in p_str:
        return None

    if p_str.startswith(("\\\\", "//")) or "://" in p_str or _URI_SCHEME_PATTERN.match(p_str):
        return None

    if allow_path_lookup is None:
        try:
            path_lookup_allowed = get_settings().APP_ENV != "production"
        except Exception:  # noqa: BLE001 - fail closed if settings cannot be inspected
            path_lookup_allowed = False
    else:
        path_lookup_allowed = allow_path_lookup

    p = Path(p_str)
    if p.is_absolute() or "/" in p_str or "\\" in p_str:
        if not path_lookup_allowed and not p.is_absolute():
            logger.warning("Relative Gitleaks executable path is disabled in production")
            return None
        if _is_executable_file(p, allow_symlink=allow_symlink):
            return str(p.resolve()) if allow_symlink else os.path.abspath(p)
        return None

    if not path_lookup_allowed:
        logger.warning("Ambient PATH resolution for Gitleaks executable is disabled in production")
        return None

    raw_path = os.environ.get("PATH", "")
    for raw_entry in raw_path.split(os.pathsep):
        entry = raw_entry.strip().strip('"')
        if not entry or "\x00" in entry or entry.startswith(("\\\\", "//")):
            continue
        entry_dir = Path(entry)
        if not entry_dir.is_absolute():
            continue
        if not _is_safe_directory_chain(entry_dir, allow_symlink=allow_symlink):
            continue

        for candidate in _candidate_executable_names(entry_dir, p_str):
            if _is_executable_file(candidate, allow_symlink=allow_symlink):
                return str(candidate.resolve()) if allow_symlink else os.path.abspath(candidate)

    return None


def _is_network_config_path(config_path: str | Path) -> bool:
    """Check whether a config path attempts network fetching or uses remote schemes."""
    clean = str(config_path).strip().lower()
    if not clean:
        return False
    if clean.startswith(("\\\\", "//")) or "://" in clean:
        return True
    if any(clean.startswith(prefix) for prefix in _NETWORK_CONFIG_PREFIXES):
        return True
    return bool(_URI_SCHEME_PATTERN.match(clean))


def _is_broad_trusted_config_dir(root_abs: Path) -> bool:
    """Reject filesystem roots, system-wide dirs, temp roots, and CWD as trusted config roots."""
    if root_abs.parent == root_abs or len(root_abs.parts) <= 1:
        return True

    norm_candidate = os.path.normcase(os.path.abspath(str(root_abs)))
    broad_candidates: list[str] = [
        tempfile.gettempdir(),
        os.getcwd(),
        "/tmp",
        "/var",
        "/var/tmp",
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/home",
        "/root",
    ]
    if os.name == "nt":
        for env_key in ("WINDIR", "SystemRoot", "TEMP", "TMP"):
            val = os.environ.get(env_key)
            if val:
                broad_candidates.append(val)

    broad_norms = {os.path.normcase(os.path.abspath(p)) for p in broad_candidates if p}
    return norm_candidate in broad_norms


def _validate_trusted_config_root(root: Path) -> bool:
    """Validate a candidate trusted Gitleaks config directory against broad/symlink/perm risks."""
    root_abs = Path(os.path.abspath(str(root)))
    if _is_broad_trusted_config_dir(root_abs):
        return False
    return _is_safe_directory_chain(root_abs, allow_symlink=False)


def _relative_parts_under(root_abs: Path, target_abs: Path) -> tuple[str, ...] | None:
    """Return relative parts if target_abs is strictly beneath root_abs without resolving symlinks."""
    root_parts = root_abs.parts
    target_parts = target_abs.parts
    if len(target_parts) <= len(root_parts):
        return None
    if os.name == "nt":
        if [os.path.normcase(p) for p in target_parts[: len(root_parts)]] != [
            os.path.normcase(p) for p in root_parts
        ]:
            return None
    elif target_parts[: len(root_parts)] != root_parts:
        return None
    return target_parts[len(root_parts) :]


def _default_trusted_config_dirs() -> list[Path]:
    """Return dedicated trusted local directories for Gitleaks configurations."""
    candidates: list[Path] = []
    module_parents = Path(__file__).resolve().parents
    if len(module_parents) > 3:
        candidates.append(module_parents[3] / "rules" / "gitleaks")

    try:
        settings = get_settings()
        explicit_trusted_dir = getattr(settings, "GITLEAKS_TRUSTED_CONFIG_DIR", None)
        if isinstance(explicit_trusted_dir, str) and explicit_trusted_dir.strip():
            candidates.append(Path(os.path.abspath(explicit_trusted_dir.strip())))
    except Exception as exc:  # noqa: BLE001 - fail safely to default repo directory
        logger.debug("Using default Gitleaks config directory (%s)", type(exc).__name__)

    deduped: list[Path] = []
    seen: set[str] = set()
    for d in candidates:
        norm = os.path.normcase(os.path.abspath(d))
        if norm not in seen:
            seen.add(norm)
            deduped.append(Path(os.path.abspath(d)))
    return deduped


def _has_symlink_between(root_dir: Path, target_path: Path) -> bool:
    """Return True if root_dir or any component down to target_path is a symlink or unsafe dir."""
    abs_root = Path(os.path.abspath(str(root_dir)))
    abs_target = Path(os.path.abspath(str(target_path)))

    if not _is_safe_directory_chain(abs_root, allow_symlink=False):
        return True

    rel_parts = _relative_parts_under(abs_root, abs_target)
    if rel_parts is None:
        return True

    curr = abs_root
    for idx, part in enumerate(rel_parts):
        curr = curr / part
        is_leaf = idx == len(rel_parts) - 1
        try:
            if curr.is_symlink():
                return True
            st = os.lstat(curr)
            if stat.S_ISLNK(st.st_mode):
                return True
            if not is_leaf:
                if not stat.S_ISDIR(st.st_mode):
                    return True
                if _is_posix_platform() and (st.st_mode & stat.S_IWOTH):
                    return True
        except FileNotFoundError:
            # Missing leaf will produce GITLEAKS_CONFIG_NOT_FOUND unless it was a symlink
            if curr.is_symlink():
                return True
            continue
        except OSError:
            return True
    return False


def _validate_gitleaks_toml_config(parsed: dict[str, Any]) -> bool:
    """Inspect parsed Gitleaks TOML structure to reject external/network dependencies."""
    node_count = 0

    def _walk(node: Any, *, key_name: str = "", in_extend: bool = False, depth: int = 0) -> bool:
        nonlocal node_count
        if depth > 12:
            return False
        node_count += 1
        if node_count > 5000:
            return False

        if isinstance(node, dict):
            for raw_k, raw_v in node.items():
                if not isinstance(raw_k, str):
                    return False
                k_lower = raw_k.strip().lower()
                if k_lower in _FORBIDDEN_TOML_KEYS:
                    return False
                if in_extend and k_lower in _EXTEND_FORBIDDEN_KEYS:
                    return False
                child_in_extend = in_extend or (k_lower == "extend")
                if k_lower == "extend" and not isinstance(raw_v, dict):
                    return False
                if not _walk(
                    raw_v,
                    key_name=k_lower,
                    in_extend=child_in_extend,
                    depth=depth + 1,
                ):
                    return False
            return True

        if isinstance(node, list):
            return all(
                _walk(item, key_name=key_name, in_extend=in_extend, depth=depth + 1)
                for item in node
            )

        if isinstance(node, str):
            val_clean = node.strip()
            if (
                in_extend
                and val_clean
                and (_is_network_config_path(val_clean) or "/" in val_clean or "\\" in val_clean)
            ):
                # Reject string settings inside [extend] that look like paths/URLs
                return False
            return not (
                key_name not in _TOML_PATTERN_SAFE_KEYS and _is_network_config_path(val_clean)
            )

        return True

    return _walk(parsed)


def _validate_and_load_config(
    config_path: str | Path,
    *,
    trusted_config_dirs: Iterable[str | Path] | None = None,
    max_bytes: int | None = None,
) -> tuple[Path | None, bytes | None, str | None, str | None]:
    """Validate Gitleaks TOML config safely and return verified raw TOML bytes against TOCTOU."""
    size_limit = _MAX_CONFIG_FILE_BYTES if max_bytes is None else max_bytes
    raw_str = str(config_path).strip()
    if not raw_str or "\x00" in raw_str or _is_network_config_path(raw_str):
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Network-dependent or invalid Gitleaks configuration path is prohibited",
        )

    candidate = Path(os.path.abspath(raw_str))
    if candidate.suffix.lower() != ".toml":
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration file must use the .toml format",
        )

    trusted_roots = (
        [Path(os.path.abspath(str(d))) for d in trusted_config_dirs]
        if trusted_config_dirs is not None
        else _default_trusted_config_dirs()
    )
    if not trusted_roots:
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "No trusted directories configured for Gitleaks configuration files",
        )

    matched_root: Path | None = None
    for root in trusted_roots:
        root_abs = Path(os.path.abspath(str(root)))
        if not _validate_trusted_config_root(root_abs):
            continue
        if _relative_parts_under(root_abs, candidate) is not None:
            matched_root = root_abs
            break

    if matched_root is None or _has_symlink_between(matched_root, candidate):
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration path is outside trusted directories or uses symlinks",
        )

    try:
        is_link = candidate.is_symlink()
        lst = os.lstat(candidate)
    except FileNotFoundError:
        if candidate.is_symlink():
            return (
                None,
                None,
                "GITLEAKS_INVALID_CONFIG_PATH",
                "Symlink Gitleaks configuration paths are prohibited",
            )
        return (
            None,
            None,
            "GITLEAKS_CONFIG_NOT_FOUND",
            "Gitleaks configuration file not found",
        )
    except OSError:
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration file cannot be accessed safely",
        )

    if is_link or stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration path must be a non-symlink regular file",
        )

    if _is_posix_platform() and (lst.st_mode & stat.S_IWOTH):
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration file must not be world-writable",
        )

    if lst.st_size > size_limit:
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration file exceeds maximum allowed size",
        )

    open_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = -1
    try:
        fd = os.open(candidate, open_flags)
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            return (
                None,
                None,
                "GITLEAKS_INVALID_CONFIG_PATH",
                "Gitleaks configuration path must be a regular file",
            )
        if _is_posix_platform() and (fst.st_mode & stat.S_IWOTH):
            return (
                None,
                None,
                "GITLEAKS_INVALID_CONFIG_PATH",
                "Gitleaks configuration file must not be world-writable",
            )
        if (
            lst.st_ino != 0
            and fst.st_ino != 0
            and (fst.st_dev != lst.st_dev or fst.st_ino != lst.st_ino)
        ):
            return (
                None,
                None,
                "GITLEAKS_INVALID_CONFIG_PATH",
                "Gitleaks configuration file changed during validation",
            )
        if fst.st_size > size_limit:
            return (
                None,
                None,
                "GITLEAKS_INVALID_CONFIG_PATH",
                "Gitleaks configuration file exceeds maximum allowed size",
            )
        with os.fdopen(fd, "rb") as f:
            fd = -1
            raw_bytes = f.read(size_limit + 1)
    except OSError:
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration file cannot be opened safely",
        )
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    if len(raw_bytes) > size_limit:
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration file exceeds maximum allowed size",
        )

    try:
        config_text = raw_bytes.decode("utf-8")
        parsed = tomllib.loads(config_text)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration file is not valid UTF-8 TOML",
        )

    if not isinstance(parsed, dict) or not _validate_gitleaks_toml_config(parsed):
        return (
            None,
            None,
            "GITLEAKS_INVALID_CONFIG_PATH",
            "Gitleaks configuration contains prohibited external or network directives",
        )

    return (candidate, raw_bytes, None, None)


def _map_severity(tags: Any) -> FindingSeverity:
    """Map Gitleaks rule tags or metadata to canonical FindingSeverity."""
    if isinstance(tags, list):
        tags_lower = [str(t).strip().lower() for t in tags if isinstance(t, str)]
        if any(t in ("critical", "crit") for t in tags_lower):
            return FindingSeverity.CRITICAL
        if "medium" in tags_lower:
            return FindingSeverity.MEDIUM
        if "low" in tags_lower:
            return FindingSeverity.LOW
        if "info" in tags_lower:
            return FindingSeverity.INFO
    return FindingSeverity.HIGH


def _strip_control_chars(text: str, *, allow_newlines: bool = False) -> str:
    """Remove ASCII control characters safely."""
    pattern = _CONTROL_CHAR_INLINE_PATTERN if allow_newlines else _CONTROL_CHAR_SINGLELINE_PATTERN
    return pattern.sub("", text)


def _is_placeholder_secret(secret_value: str | None) -> bool:
    """Return True if the extracted secret string is already a redaction placeholder."""
    if not secret_value:
        return False
    stripped = secret_value.strip()
    return any(stripped.startswith(ph) for ph in _REDACTION_PLACEHOLDER_PREFIXES)


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and merge overlapping or directly adjacent text intervals."""
    if not spans:
        return []
    ordered = sorted(spans)
    merged: list[tuple[int, int]] = [ordered[0]]
    for start, end in ordered[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def _is_sensitive_fragment(fragment: str, *, secret_len: int) -> bool:
    """Return True when a shared substring represents secret material rather than generic prose."""
    core = fragment.strip()
    if len(core) < 6:
        return False

    lowered = core.lower()
    if lowered in _SAFE_FRAGMENT_WORDS:
        return False

    if len(core) >= 8:
        tokens = [tok for tok in re.split(r"[\s_\-]+", lowered) if tok]
        is_benign_phrase = (
            bool(tokens)
            and len(core) <= 16
            and all(tok in _SAFE_FRAGMENT_WORDS for tok in tokens)
            and not any(ch.isdigit() for ch in core)
            and not (any(ch.isupper() for ch in core) and any(ch.islower() for ch in core))
        )
        return not is_benign_phrase

    # Length 6..7 fragments: require strong share of short secret or non-plain-word entropy cues
    if secret_len <= 10:
        return True
    has_digit_or_symbol = any(not ch.isalnum() or ch.isdigit() for ch in core)
    has_mixed_case = any(ch.isupper() for ch in core) and any(ch.islower() for ch in core)
    return has_digit_or_symbol or has_mixed_case


def _extract_secret_sources(secret_value: str) -> list[str]:
    """Collect candidate secret strings (including multi-line body fragments without PEM headers)."""
    trimmed = secret_value.strip()
    if not trimmed:
        return []

    sources: list[str] = [trimmed]
    if "\n" in trimmed or "\r" in trimmed:
        non_header_lines: list[str] = []
        for raw_line in trimmed.splitlines():
            line = raw_line.strip()
            if not line or _PEM_HEADER_FOOTER_LINE_PATTERN.match(line):
                continue
            non_header_lines.append(line)
            if len(line) >= 6 and line not in sources:
                sources.append(line)
        joined_body = "".join(non_header_lines)
        if len(joined_body) >= 6 and joined_body not in sources:
            sources.append(joined_body)
    return sources


def _find_secret_fragment_spans(text: str, secret_value: str | None) -> list[tuple[int, int]]:
    """Find spans in ``text`` matching exact ``secret_value`` or partial secret fragments."""
    if not text or not secret_value or _is_placeholder_secret(secret_value):
        return []

    spans: list[tuple[int, int]] = []
    exact_variants = [secret_value]
    trimmed = secret_value.strip()
    if trimmed and trimmed != secret_value:
        exact_variants.append(trimmed)

    for variant in exact_variants:
        if not variant:
            continue
        start_idx = 0
        while True:
            pos = text.find(variant, start_idx)
            if pos == -1:
                break
            spans.append((pos, pos + len(variant)))
            start_idx = pos + len(variant)

    for src in _extract_secret_sources(trimmed):
        bounded_src = src[:2048]
        if len(bounded_src) < 6:
            continue
        text_lower = text.lower()
        src_lower = bounded_src.lower()
        # Only use case-folded comparison if character lengths match 1-to-1
        if len(text_lower) == len(text) and len(src_lower) == len(bounded_src):
            text_cmp, src_cmp = text_lower, src_lower
        else:
            text_cmp, src_cmp = text, bounded_src

        gram_positions: dict[str, list[int]] = {}
        for i in range(len(src_cmp) - 5):
            gram = src_cmp[i : i + 6]
            pos_list = gram_positions.setdefault(gram, [])
            if len(pos_list) < 32:
                pos_list.append(i)

        j = 0
        text_len = len(text_cmp)
        src_len = len(src_cmp)
        while j <= text_len - 6:
            gram = text_cmp[j : j + 6]
            candidates = gram_positions.get(gram)
            if not candidates:
                j += 1
                continue
            best_len = 0
            for i in candidates:
                k = 6
                while j + k < text_len and i + k < src_len and text_cmp[j + k] == src_cmp[i + k]:
                    k += 1
                best_len = max(best_len, k)
            if best_len >= 6 and _is_sensitive_fragment(text[j : j + best_len], secret_len=src_len):
                spans.append((j, j + best_len))
                j = max(j + 1, j + best_len - 5)
            else:
                j += 1

    return _merge_spans(spans)


def _normalize_secret_inputs(secret_value: str | Iterable[str] | None) -> list[str]:
    """Deduplicate and sort non-placeholder secret strings longest-first for determinism."""
    if secret_value is None:
        return []
    candidates = [secret_value] if isinstance(secret_value, str) else list(secret_value)
    unique = {
        s for s in candidates if isinstance(s, str) and s.strip() and not _is_placeholder_secret(s)
    }
    return sorted(unique, key=lambda s: (-len(s), s))


def _find_all_sensitive_spans(
    text: str, secret_value: str | Iterable[str] | None = None
) -> list[tuple[int, int]]:
    """Collect all pattern-based and secret-fragment spans in ``text``."""
    if not text:
        return []
    spans: list[tuple[int, int]] = []
    for sec in _normalize_secret_inputs(secret_value):
        spans.extend(_find_secret_fragment_spans(text, sec))
    for pattern in _SECRET_VALUE_PATTERNS:
        for match in pattern.finditer(text):
            if match.end() > match.start():
                spans.append((match.start(), match.end()))
    return _merge_spans(spans)


def _scrub_secret_text(
    text: str,
    secret_value: str | Iterable[str] | None = None,
    *,
    replacement: str = "[REDACTED]",
) -> str:
    """Replace full secrets, partial secret fragments, and known secret patterns in one pass."""
    if not text:
        return text
    merged = _find_all_sensitive_spans(text, secret_value)
    if not merged:
        return text

    parts: list[str] = []
    cursor = 0
    for start, end in merged:
        parts.append(text[cursor:start])
        parts.append(replacement)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def _scrub_snippet_text(
    snippet: str,
    *,
    primary_secret: str | None,
    file_secrets: Sequence[str],
    primary_replacement: str,
    secondary_replacement: str = "[REDACTED]",
) -> str:
    """Redact primary and co-located file secrets safely in one deterministic pass."""
    if not snippet:
        return snippet

    ordered_secrets = _normalize_secret_inputs(
        [*(file_secrets or ()), *([primary_secret] if primary_secret else ())]
    )
    primary_spans: list[tuple[int, int]] = (
        _merge_spans(_find_secret_fragment_spans(snippet, primary_secret))
        if primary_secret and not _is_placeholder_secret(primary_secret)
        else []
    )
    secondary_spans: list[tuple[int, int]] = []
    for sec in ordered_secrets:
        if primary_secret and sec == primary_secret:
            continue
        secondary_spans.extend(_find_secret_fragment_spans(snippet, sec))
    merged_secondary = _merge_spans(secondary_spans)

    pattern_spans: list[tuple[int, int]] = []
    for pattern in _SECRET_VALUE_PATTERNS:
        for match in pattern.finditer(snippet):
            if match.end() > match.start():
                pattern_spans.append((match.start(), match.end()))
    merged_patterns = _merge_spans(pattern_spans)

    all_merged = _merge_spans([*primary_spans, *merged_secondary, *merged_patterns])
    if not all_merged:
        return snippet

    def _overlaps(span: tuple[int, int], pool: list[tuple[int, int]]) -> bool:
        s, e = span
        return any(ps < e and s < pe for ps, pe in pool)

    parts: list[str] = []
    cursor = 0
    for span in all_merged:
        start, end = span
        parts.append(snippet[cursor:start])
        use_primary = _overlaps(span, primary_spans) or (
            not primary_spans
            and _overlaps(span, merged_patterns)
            and not _overlaps(span, merged_secondary)
        )
        parts.append(primary_replacement if use_primary else secondary_replacement)
        cursor = end
    parts.append(snippet[cursor:])
    return "".join(parts)


def _contains_secret_or_fragment(text: str, secret_value: str | Iterable[str] | None) -> bool:
    """Return True if any non-placeholder secret or sensitive fragment appears in ``text``."""
    return any(
        _find_secret_fragment_spans(text, sec) for sec in _normalize_secret_inputs(secret_value)
    )


def _sanitize_rule_id(
    rule_id: str,
    secret_value: str | Iterable[str] | None,
    *,
    key_bytes: bytes,
) -> tuple[str, bool]:
    """Sanitize a scanner-supplied RuleID against full/partial secret material.

    Preserves safe rule identifiers unchanged. When full/partial secret material or a
    recognized secret token pattern is detected inside RuleID, replaces only the
    sensitive spans and appends a deterministic domain-separated HMAC tag so
    fingerprinting remains deterministic without disclosing any secret bytes.
    """
    merged = _find_all_sensitive_spans(rule_id, secret_value)
    if not merged:
        return (rule_id, False)

    parts: list[str] = []
    cursor = 0
    for start, end in merged:
        parts.append(rule_id[cursor:start])
        parts.append("redacted")
        cursor = end
    parts.append(rule_id[cursor:])
    replaced = "".join(parts)

    # Collapse repeated 'redacted' tokens or separator chains while keeping safe rule context
    replaced = re.sub(r"(?:redacted(?:[-_\.]+redacted)+)", "redacted", replaced)
    replaced = re.sub(r"[^a-zA-Z0-9_\-\.]", "-", replaced)
    replaced = re.sub(r"[-_\.]{2,}", "-", replaced).strip("-_.")

    tag = hmac.new(
        key_bytes,
        b"rule-id-v1|" + rule_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:8]

    if not replaced or replaced.lower() == "redacted":
        return (f"redacted-rule-{tag}", True)

    prefix_cap = 128 - len(tag) - 1
    safe_id = f"{replaced[:prefix_cap].rstrip('-_.')}-{tag}"
    return (safe_id, True)


def _sanitize_metadata_node(
    data: Any,
    secret_to_scrub: str | Iterable[str] | None = None,
    depth: int = 0,
) -> Any:
    """Recursively scrub forbidden keys, secret fragments, secret patterns, and oversized metadata.

    Threat Mitigation T3: Never copy Match, Secret, or Line fields from Gitleaks
    into any persistent or exposed structure. Also scrubs exact secrets and partial fragments.
    """
    if depth > 8:
        return None

    if isinstance(data, dict):
        cleaned: dict[str, Any] = {}
        for k, v in data.items():
            if not isinstance(k, str):
                continue
            k_clean = _strip_control_chars(k.strip())
            k_lower = k_clean.lower()
            if k_lower in _FORBIDDEN_RAW_KEYS or k_lower in ("lines", "match"):
                continue
            if any(
                bad in k_lower
                for bad in (
                    "secret",
                    "token",
                    "password",
                    "passwd",
                    "credential",
                    "api_key",
                )
            ):
                continue
            k_clean = _scrub_secret_text(k_clean, secret_to_scrub)
            k_final = k_clean[:100].strip()
            if not k_final:
                continue

            cleaned_val = _sanitize_metadata_node(v, secret_to_scrub, depth + 1)
            if cleaned_val is not None:
                cleaned[k_final] = cleaned_val
        return cleaned

    if isinstance(data, list):
        scrubbed_list = [
            _sanitize_metadata_node(item, secret_to_scrub, depth + 1) for item in data[:50]
        ]
        return [item for item in scrubbed_list if item is not None]

    if isinstance(data, str):
        val = _strip_control_chars(data, allow_newlines=False)
        val = _scrub_secret_text(val, secret_to_scrub)
        return val[:500]

    if isinstance(data, bool):
        return data

    if isinstance(data, int):
        return data

    if isinstance(data, float):
        if not math.isfinite(data):
            return None
        return data

    return None


def _sanitize_metadata(
    metadata: dict[str, Any], secret_to_scrub: str | Iterable[str] | None = None
) -> dict[str, Any]:
    """Sanitize and validate raw metadata for canonical findings."""
    cleaned = _sanitize_metadata_node(metadata, secret_to_scrub=secret_to_scrub)
    if not isinstance(cleaned, dict):
        return {}

    try:
        serialized = json.dumps(cleaned, ensure_ascii=False)
        if len(serialized.encode("utf-8")) > 8192:
            cleaned = {"truncated": True}
        _validate_raw_node(cleaned)
    except (ValueError, TypeError):
        return {}

    return cleaned


def _extract_snippet(content: str, start_line: int, end_line: int) -> tuple[str, int]:
    """Extract authoritative code snippet from file content within line bounds.

    Blueprint Section 10.5:
    - Slices up to 12 lines
    - Caps snippet length to 2000 characters
    - Returns tuple of (snippet, snippet_start_line)
    """
    lines = content.splitlines()
    total_lines = len(lines)

    if total_lines == 0 or start_line > total_lines or start_line < 1:
        return ("", start_line)

    clamped_end = max(start_line, min(end_line, total_lines))
    selected_lines = lines[start_line - 1 : clamped_end]
    if len(selected_lines) > 12:
        selected_lines = selected_lines[:12]

    snippet = "\n".join(selected_lines)
    if len(snippet) > 2000:
        snippet = snippet[:1997] + "..."

    return (snippet, start_line)


def _cleanup_report_file(report_file: Path) -> bool:
    """Remove an ephemeral Gitleaks report file and verify absence without leaking paths/secrets."""
    try:
        report_file.unlink()
    except FileNotFoundError:
        return True
    except OSError as err:
        logger.error(
            "Failed to remove ephemeral Gitleaks report file: %s",
            type(err).__name__,
        )
        return False

    try:
        os.lstat(report_file)
    except FileNotFoundError:
        return True
    except OSError as err:
        logger.error(
            "Failed to verify ephemeral Gitleaks report file removal: %s",
            type(err).__name__,
        )
        return False

    logger.error("Ephemeral Gitleaks report file still present after unlink")
    return False


def _read_and_cleanup_report_file(
    report_file: Path, max_bytes: int = _MAX_REPORT_FILE_BYTES
) -> tuple[str | None, str | None]:
    """Read a Gitleaks JSON report file safely using descriptor validation and guarantee unlinking.

    Guarantees:
    - Uses descriptor-based opening with ``O_NOFOLLOW`` where supported and ``os.fstat()``
      regular-file/inode verification to prevent symlink-following and TOCTOU swaps.
    - Requires a regular file type (rejects symlinks, directories, devices, sockets, FIFOs).
    - Checks file size via ``os.fstat()`` before reading and enforces bounded read (`max_bytes + 1`).
    - Rejects oversized reports and invalid UTF-8 encodings with stable error codes.
    - Attempts unlink on all exit paths and fails closed if report cleanup fails.
    - Never includes report content, secrets, or filesystem paths in logs or error values.

    Returns:
        Tuple of (report_text, error_code). At most one of the two is meaningful,
        or (None, None) if the file did not exist and cleanup succeeded.
    """
    result_text: str | None = None
    result_err: str | None = None
    fd = -1

    try:
        try:
            is_link = report_file.is_symlink()
        except OSError:
            is_link = False

        if is_link:
            logger.warning("Gitleaks report file is a symlink; rejecting for safety")
            result_err = "GITLEAKS_UNSAFE_REPORT_FILE"
            lst = None
        else:
            try:
                lst = os.lstat(report_file)
            except FileNotFoundError:
                lst = None
            except OSError as err:
                logger.warning("Failed to stat Gitleaks report file: %s", type(err).__name__)
                result_err = "GITLEAKS_UNSAFE_REPORT_FILE"
                lst = None

        if result_err is None and lst is not None:
            if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
                logger.warning("Gitleaks report file is a symlink or non-regular file; rejecting")
                result_err = "GITLEAKS_UNSAFE_REPORT_FILE"
            elif lst.st_size > max_bytes:
                logger.warning(
                    "Gitleaks report file exceeds size cap (%d > %d)", lst.st_size, max_bytes
                )
                result_err = "GITLEAKS_REPORT_TOO_LARGE"
            else:
                open_flags = (
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_BINARY", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                )
                try:
                    fd = os.open(report_file, open_flags)
                except FileNotFoundError:
                    # Distinguish clean disappearance from a Windows dangling-symlink swap
                    try:
                        post_lst = os.lstat(report_file)
                        if stat.S_ISLNK(post_lst.st_mode):
                            result_err = "GITLEAKS_UNSAFE_REPORT_FILE"
                    except FileNotFoundError:
                        pass
                    except OSError:
                        result_err = "GITLEAKS_UNSAFE_REPORT_FILE"
                except OSError as err:
                    logger.warning("Failed to open Gitleaks report file: %s", type(err).__name__)
                    result_err = "GITLEAKS_UNSAFE_REPORT_FILE"

                if result_err is None and fd >= 0:
                    try:
                        fst = os.fstat(fd)
                        if not stat.S_ISREG(fst.st_mode):
                            logger.warning(
                                "Opened Gitleaks report descriptor is not a regular file"
                            )
                            result_err = "GITLEAKS_UNSAFE_REPORT_FILE"
                        elif (
                            lst.st_ino != 0
                            and fst.st_ino != 0
                            and (fst.st_dev != lst.st_dev or fst.st_ino != lst.st_ino)
                        ):
                            logger.warning(
                                "Gitleaks report file inode changed between stat and open"
                            )
                            result_err = "GITLEAKS_UNSAFE_REPORT_FILE"
                        elif fst.st_size > max_bytes:
                            logger.warning(
                                "Gitleaks report descriptor exceeds size cap (%d > %d)",
                                fst.st_size,
                                max_bytes,
                            )
                            result_err = "GITLEAKS_REPORT_TOO_LARGE"
                        else:
                            with os.fdopen(fd, "rb") as f:
                                fd = -1
                                raw_bytes = f.read(max_bytes + 1)

                            if len(raw_bytes) > max_bytes:
                                logger.warning("Gitleaks report file exceeds size cap during read")
                                result_err = "GITLEAKS_REPORT_TOO_LARGE"
                            else:
                                try:
                                    result_text = raw_bytes.decode("utf-8").strip()
                                except UnicodeDecodeError:
                                    logger.warning(
                                        "Gitleaks report file contains invalid character encoding"
                                    )
                                    result_err = "GITLEAKS_INVALID_REPORT_ENCODING"
                    except OSError as err:
                        logger.warning(
                            "Failed to read Gitleaks report descriptor: %s", type(err).__name__
                        )
                        result_err = "GITLEAKS_UNSAFE_REPORT_FILE"
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        cleanup_ok = _cleanup_report_file(report_file)

    if not cleanup_ok:
        return (None, result_err or "GITLEAKS_CLEANUP_FAILED")

    return (result_text, result_err)


def _resolve_configured_config_path(explicit_config_path: str | Path | None) -> str:
    """Resolve explicit or default Gitleaks config path deterministically regardless of CWD."""
    if explicit_config_path is not None:
        return str(explicit_config_path)

    settings = get_settings()
    raw_cfg = str(getattr(settings, "GITLEAKS_CONFIG_PATH", "./rules/gitleaks/default.toml"))
    stripped = raw_cfg.strip()
    if stripped in _DEFAULT_GITLEAKS_CONFIG_REL_PATHS:
        module_parents = Path(__file__).resolve().parents
        if len(module_parents) > 3:
            return str(module_parents[3] / "rules" / "gitleaks" / "default.toml")
    return raw_cfg


def _write_materialized_config_file(config_path: Path, config_bytes: bytes) -> None:
    """Materialize pre-validated TOML bytes into an isolated regular file with O_NOFOLLOW."""
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    o_binary = getattr(os, "O_BINARY", 0)
    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow | o_binary
    fd = os.open(config_path, open_flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise GitleaksError("Materialized config target is not a regular file")
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            except (OSError, NotImplementedError):
                pass
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(config_bytes)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


class GitleaksScannerAdapter(ScannerInterface):
    """Production Gitleaks CLI adapter conforming to ScannerInterface.

    Stages files via StagedWorkspace, executes Gitleaks bounded via run_command_bounded(),
    parses Gitleaks JSON results, reconstructs authoritative code snippets from ScannedFile,
    computes HMAC secret anchors from raw detected secrets before unlinking the ephemeral
    report file, redacts detected secret values, and normalizes findings to CanonicalFinding.
    """

    def __init__(
        self,
        *,
        executable_path: str | Path | None = None,
        config_path: str | Path | None = None,
        trusted_config_dirs: Iterable[str | Path] | None = None,
        timeout_sec: int | None = None,
        max_output_bytes: int = 10 * 1024 * 1024,
        fingerprint_key: str | bytes | None = None,
        runner: Callable[..., CommandResult] = run_command_bounded,
        workspace_base_dir: str | Path | None = None,
    ) -> None:
        """Initialize the Gitleaks adapter.

        Args:
            executable_path: Gitleaks binary path or command name.
            config_path: Path to Sentinel-trusted Gitleaks TOML config (defaults to GITLEAKS_CONFIG_PATH).
            trusted_config_dirs: Optional allowlisted directories for custom configs.
            timeout_sec: Subprocess execution timeout in seconds.
            max_output_bytes: Maximum output bytes allowed before termination.
            fingerprint_key: Server-side HMAC key for secret anchor calculation.
            runner: Callable executing subprocess commands (defaults to run_command_bounded).
            workspace_base_dir: Optional base directory for staging workspaces.
        """
        settings = get_settings()
        self.executable_path = str(executable_path or settings.GITLEAKS_PATH)
        self.config_path = _resolve_configured_config_path(config_path)
        self.trusted_config_dirs = (
            tuple(trusted_config_dirs) if trusted_config_dirs is not None else None
        )
        self.timeout_sec = timeout_sec if timeout_sec is not None else settings.GITLEAKS_TIMEOUT_SEC
        self.max_output_bytes = max_output_bytes
        self.runner = runner
        self.workspace_base_dir = workspace_base_dir

        if fingerprint_key is not None:
            self.fingerprint_key: str | bytes = fingerprint_key
        else:
            try:
                self.fingerprint_key = settings.validate_runtime_fingerprint_key()
            except ValueError:
                self.fingerprint_key = settings.FINGERPRINT_KEY.get_secret_value()

    def scan(
        self,
        payload: ScanJobPayload,
        *,
        workspace: StagedWorkspace | None = None,
    ) -> ScanExecutionResult:
        """Execute Gitleaks analysis over submitted files and return structured results."""
        # 1. Check for scannable files
        scannable_files = [f for f in payload.files if f.scanned]
        if not scannable_files:
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                components={"gitleaks": "passed"},
                counts={
                    "findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                findings=[],
            )

        # 2. Always validate Sentinel-controlled TOML configuration before launching scanner
        validated_config_path, validated_config_bytes, cfg_err_code, cfg_err_msg = (
            _validate_and_load_config(
                self.config_path,
                trusted_config_dirs=self.trusted_config_dirs,
            )
        )
        if (
            cfg_err_code is not None
            or validated_config_path is None
            or validated_config_bytes is None
        ):
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code=cfg_err_code or "GITLEAKS_INVALID_CONFIG_PATH",
                error_message=cfg_err_msg or "Invalid Gitleaks configuration",
                retryable=False,
                components={"gitleaks": "failed"},
            )

        # 3. Validate runtime FINGERPRINT_KEY for secret anchor computation
        try:
            validated_key = validate_fingerprint_key(self.fingerprint_key)
        except (ValueError, TypeError) as err:
            logger.error(
                "Gitleaks adapter: invalid or unconfigured FINGERPRINT_KEY: %s",
                type(err).__name__,
            )
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_INVALID_FINGERPRINT_KEY",
                error_message="FINGERPRINT_KEY is invalid, unconfigured, or an insecure placeholder",
                retryable=False,
                components={"gitleaks": "failed"},
            )

        # 4. Resolve executable path
        resolved_exec = _resolve_executable(self.executable_path)
        if resolved_exec is None:
            if self.runner is run_command_bounded:
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="GITLEAKS_BINARY_NOT_FOUND",
                    error_message="Gitleaks executable not found",
                    retryable=False,
                    components={"gitleaks": "failed"},
                )
            resolved_exec = self.executable_path

        # 5. Execute analysis using validated shared workspace or ephemeral StagedWorkspace
        if workspace is not None:
            if (
                not isinstance(workspace, StagedWorkspace)
                or workspace._cleaned_up
                or not _UNTRUSTED_REPO_CONTROL_FILENAMES.issubset(workspace._excluded_filenames)
            ):
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="GITLEAKS_EXECUTION_ERROR",
                    error_message=(
                        "Shared staged workspace must be active and exclude untrusted Gitleaks control files"
                    ),
                    retryable=False,
                    components={"gitleaks": "failed"},
                )
            try:
                if not workspace.staged_files:
                    return ScanExecutionResult(
                        status=ScanStatus.SUCCEEDED,
                        components={"gitleaks": "passed"},
                        counts={
                            "findings": 0,
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0,
                            "info": 0,
                        },
                        findings=[],
                    )
                return self._execute_and_normalize(
                    workspace=workspace,
                    payload=payload,
                    executable=resolved_exec,
                    key_bytes=validated_key,
                    config_bytes=validated_config_bytes,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Gitleaks scan execution failed unexpectedly: %s",
                    type(exc).__name__,
                )
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="GITLEAKS_EXECUTION_ERROR",
                    error_message="Gitleaks staging or execution failure",
                    retryable=False,
                    components={"gitleaks": "failed"},
                )

        try:
            with StagedWorkspace(
                payload.files,
                base_dir=self.workspace_base_dir,
                exclude_filenames=_UNTRUSTED_REPO_CONTROL_FILENAMES,
            ) as owned_workspace:
                if not owned_workspace.staged_files:
                    return ScanExecutionResult(
                        status=ScanStatus.SUCCEEDED,
                        components={"gitleaks": "passed"},
                        counts={
                            "findings": 0,
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0,
                            "info": 0,
                        },
                        findings=[],
                    )
                return self._execute_and_normalize(
                    workspace=owned_workspace,
                    payload=payload,
                    executable=resolved_exec,
                    key_bytes=validated_key,
                    config_bytes=validated_config_bytes,
                )
        except StagingCleanupError as exc:
            logger.error(
                "Gitleaks staging workspace cleanup failed: %s",
                type(exc).__name__,
            )
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_CLEANUP_FAILED",
                error_message="Gitleaks workspace cleanup failed",
                retryable=False,
                components={"gitleaks": "failed"},
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Gitleaks scan execution failed unexpectedly: %s",
                type(exc).__name__,
            )
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_EXECUTION_ERROR",
                error_message="Gitleaks staging or execution failure",
                retryable=False,
                components={"gitleaks": "failed"},
            )

    def _execute_and_normalize(
        self,
        *,
        workspace: StagedWorkspace,
        payload: ScanJobPayload,
        executable: str,
        key_bytes: bytes,
        config_bytes: bytes,
    ) -> ScanExecutionResult:
        """Run Gitleaks bounded subprocess with isolated materialized config and normalize output."""
        report_file = workspace.path / "gitleaks-report.json"
        materialized_config_file = workspace.path / "gitleaks-config.toml"
        _write_materialized_config_file(materialized_config_file, config_bytes)

        # Assumption (unverified locally without a pinned Gitleaks binary): explicit
        # '--config <materialized_config_file>' together with '[extend] useDefault = true'
        # loads built-in Gitleaks rules while staged '.gitleaks.toml'/'.gitleaksignore' are excluded.
        cmd = [
            executable,
            "detect",
            "--source",
            str(workspace.source_dir),
            "--report-format",
            "json",
            "--report-path",
            str(report_file),
            "--config",
            str(materialized_config_file),
            "--no-git",
            "--exit-code",
            "1",
        ]

        try:
            cmd_result = self.runner(
                args=cmd,
                cwd=workspace.path,
                timeout_sec=self.timeout_sec,
                max_output_bytes=self.max_output_bytes,
                check=False,
            )

            return self._interpret_command_result(
                cmd_result=cmd_result,
                workspace=workspace,
                payload=payload,
                report_file=report_file,
                key_bytes=key_bytes,
            )
        finally:
            if not _cleanup_report_file(materialized_config_file):
                logger.warning("Ephemeral Gitleaks config cleanup incomplete in execution finally")
            if not _cleanup_report_file(report_file):
                logger.warning("Ephemeral Gitleaks report cleanup incomplete in execution finally")

    def _interpret_command_result(
        self,
        *,
        cmd_result: CommandResult,
        workspace: StagedWorkspace,
        payload: ScanJobPayload,
        report_file: Path,
        key_bytes: bytes,
    ) -> ScanExecutionResult:
        """Interpret bounded CommandResult and map to ScanExecutionResult."""
        if cmd_result.status == CommandStatus.EXECUTABLE_NOT_FOUND:
            cleanup_ok = _cleanup_report_file(report_file)
            msg = "Gitleaks executable not found"
            if not cleanup_ok:
                msg = f"{msg}; ephemeral report cleanup failed"
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_BINARY_NOT_FOUND",
                error_message=msg,
                retryable=False,
                components={"gitleaks": "failed"},
            )

        if cmd_result.status == CommandStatus.TIMEOUT:
            cleanup_ok = _cleanup_report_file(report_file)
            msg = "Gitleaks execution timed out"
            if not cleanup_ok:
                msg = f"{msg}; ephemeral report cleanup failed"
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_TIMEOUT",
                error_message=msg,
                retryable=False,
                components={"gitleaks": "failed"},
            )

        if cmd_result.status == CommandStatus.OUTPUT_LIMIT_EXCEEDED:
            cleanup_ok = _cleanup_report_file(report_file)
            msg = "Gitleaks output limit exceeded"
            if not cleanup_ok:
                msg = f"{msg}; ephemeral report cleanup failed"
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_OUTPUT_LIMIT_EXCEEDED",
                error_message=msg,
                retryable=False,
                components={"gitleaks": "failed"},
            )

        if cmd_result.status == CommandStatus.ERROR:
            cleanup_ok = _cleanup_report_file(report_file)
            msg = "Unexpected error during Gitleaks execution"
            if not cleanup_ok:
                msg = f"{msg}; ephemeral report cleanup failed"
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_EXECUTION_ERROR",
                error_message=msg,
                retryable=False,
                components={"gitleaks": "failed"},
            )

        # Fatal exit codes (> 1) indicate CLI syntax error or configuration failure
        if cmd_result.exit_code is not None and cmd_result.exit_code not in (0, 1):
            cleanup_ok = _cleanup_report_file(report_file)
            msg = "Gitleaks execution failed with non-zero exit code"
            if not cleanup_ok:
                msg = f"{msg}; ephemeral report cleanup failed"
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_EXECUTION_FAILED",
                error_message=msg,
                retryable=False,
                components={"gitleaks": "failed"},
            )

        # Retrieve report JSON: read safely with descriptor checks, size caps, and guaranteed unlinking
        report_text, report_err = _read_and_cleanup_report_file(
            report_file, max_bytes=min(self.max_output_bytes, _MAX_REPORT_FILE_BYTES)
        )
        if report_err:
            error_msgs = {
                "GITLEAKS_REPORT_TOO_LARGE": "Gitleaks report file exceeds maximum allowed size",
                "GITLEAKS_UNSAFE_REPORT_FILE": "Gitleaks report file is invalid or unsafe",
                "GITLEAKS_INVALID_REPORT_ENCODING": "Gitleaks report file contains invalid character encoding",
                "GITLEAKS_CLEANUP_FAILED": "Failed to clean up ephemeral Gitleaks report file",
            }
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code=report_err,
                error_message=error_msgs.get(report_err, "Gitleaks report file error"),
                retryable=False,
                components={"gitleaks": "failed"},
            )

        if not report_text:
            try:
                report_text = cmd_result.stdout.decode("utf-8").strip()
            except UnicodeDecodeError:
                logger.warning("Gitleaks stdout output contains invalid character encoding")
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="GITLEAKS_INVALID_REPORT_ENCODING",
                    error_message="Gitleaks output contains invalid character encoding",
                    retryable=False,
                    components={"gitleaks": "failed"},
                )

        if not report_text:
            if cmd_result.exit_code == 0:
                # Normal Gitleaks exit 0 with no leaks found
                return ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    components={"gitleaks": "passed"},
                    counts={
                        "findings": 0,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                    },
                    findings=[],
                )
            # Non-zero exit code with no findings output represents an execution failure
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_EXECUTION_FAILED",
                error_message="Gitleaks produced no report output",
                retryable=False,
                components={"gitleaks": "failed"},
            )

        # Parse JSON report
        try:
            raw_data = json.loads(report_text)
        except json.JSONDecodeError:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_INVALID_JSON",
                error_message="Failed to parse Gitleaks output as JSON",
                retryable=False,
                components={"gitleaks": "failed"},
            )

        if raw_data is None:
            raw_results: list[Any] = []
        elif isinstance(raw_data, list):
            raw_results = raw_data
        elif (
            isinstance(raw_data, dict)
            and "findings" in raw_data
            and isinstance(raw_data["findings"], list)
        ):
            raw_results = raw_data["findings"]
        else:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_MALFORMED_OUTPUT",
                error_message="Gitleaks output JSON root must be a list of finding objects",
                retryable=False,
                components={"gitleaks": "failed"},
            )

        # Check non-zero exit code when no findings were produced
        if cmd_result.exit_code not in (0, None) and not raw_results:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_EXECUTION_FAILED",
                error_message="Gitleaks exited with non-zero status without findings",
                retryable=False,
                components={"gitleaks": "failed"},
            )

        if not raw_results:
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                components={"gitleaks": "passed"},
                counts={
                    "findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                findings=[],
            )

        # Normalize raw results
        return self._normalize_results(
            raw_results=raw_results,
            workspace=workspace,
            payload=payload,
            key_bytes=key_bytes,
        )

    def _normalize_results(
        self,
        *,
        raw_results: list[Any],
        workspace: StagedWorkspace,
        payload: ScanJobPayload,
        key_bytes: bytes,
    ) -> ScanExecutionResult:
        """Parse raw Gitleaks findings and construct CanonicalFinding models.

        Threat Mitigation T3: Raw secret values and matched lines must never
        leak into snippets, titles, descriptions, raw metadata, or logging.
        """
        files_by_path: dict[str, ScannedFile] = {f.path: f for f in payload.files}
        # Pass 1: Collect all non-placeholder secrets per file across the entire batch so
        # co-located secrets on the same line or snippet window cannot leak across findings.
        file_secrets_by_path: dict[str, set[str]] = {}
        for batch_item in raw_results:
            if not isinstance(batch_item, dict):
                continue
            batch_file_raw = batch_item.get("File") or batch_item.get("file")
            if not isinstance(batch_file_raw, str) or not batch_file_raw.strip():
                continue
            try:
                mapped_original_path = workspace.get_original_path(batch_file_raw)
            except StagingPathMappingError:
                continue
            mapped_scanned = files_by_path.get(mapped_original_path)
            if mapped_scanned is None or not mapped_scanned.scanned:
                continue
            batch_secret_raw = batch_item.get("Secret") or batch_item.get("secret")
            if (
                isinstance(batch_secret_raw, str)
                and batch_secret_raw.strip()
                and not _is_placeholder_secret(batch_secret_raw)
            ):
                file_secrets_by_path.setdefault(mapped_original_path, set()).add(batch_secret_raw)

        intermediate_items: list[dict[str, Any]] = []
        rejected_count = 0

        for idx, item in enumerate(raw_results):
            if not isinstance(item, dict):
                logger.warning("Skipping raw Gitleaks finding at index %d: not a dictionary", idx)
                rejected_count += 1
                continue

            rule_id_raw = item.get("RuleID") or item.get("rule_id") or item.get("RuleId")
            if not isinstance(rule_id_raw, str):
                logger.warning(
                    "Skipping raw Gitleaks finding at index %d: missing RuleID",
                    idx,
                )
                rejected_count += 1
                continue
            raw_rule_id = _strip_control_chars(rule_id_raw.strip())
            if not _RULE_ID_PATTERN.match(raw_rule_id):
                logger.warning(
                    "Skipping raw Gitleaks finding at index %d: invalid RuleID format",
                    idx,
                )
                rejected_count += 1
                continue

            staged_path_raw = item.get("File") or item.get("file")
            if not isinstance(staged_path_raw, str) or not staged_path_raw.strip():
                logger.warning(
                    "Skipping raw Gitleaks finding at index %d: missing File",
                    idx,
                )
                rejected_count += 1
                continue

            try:
                original_path = workspace.get_original_path(staged_path_raw)
            except StagingPathMappingError:
                logger.warning(
                    "Skipping finding at index %d: staged path cannot be mapped to workspace",
                    idx,
                )
                rejected_count += 1
                continue

            scanned_file = files_by_path.get(original_path)
            if scanned_file is None or not scanned_file.scanned:
                logger.warning(
                    "Skipping finding at index %d: path references an unscanned or unknown file",
                    idx,
                )
                rejected_count += 1
                continue

            # Strict line coordinate validation: reject booleans explicitly
            start_line = item.get("StartLine") if "StartLine" in item else item.get("start_line")
            end_line = item.get("EndLine") if "EndLine" in item else item.get("end_line")
            if (
                type(start_line) is not int
                or type(end_line) is not int
                or start_line < 1
                or end_line < start_line
            ):
                logger.warning(
                    "Skipping finding at index %d: invalid line coordinates",
                    idx,
                )
                rejected_count += 1
                continue

            file_lines = scanned_file.content.splitlines()
            file_line_count = len(file_lines)
            if file_line_count == 0 or start_line > file_line_count or end_line > file_line_count:
                logger.warning(
                    "Skipping finding at index %d: coordinates exceed file line count",
                    idx,
                )
                rejected_count += 1
                continue

            # Strict column coordinate validation: reject booleans and out-of-range positions.
            # Note: No pinned Gitleaks binary is present in the environment/repo to empirically verify
            # inclusive vs exclusive EndColumn semantics; [1, line_len + 1] supports both consistently.
            start_col = (
                item.get("StartColumn") if "StartColumn" in item else item.get("start_column")
            )
            end_col = item.get("EndColumn") if "EndColumn" in item else item.get("end_column")

            validated_start_col: int | None = None
            validated_end_col: int | None = None

            if start_col is not None:
                if type(start_col) is not int or start_col < 1:
                    logger.warning("Skipping finding at index %d: invalid StartColumn", idx)
                    rejected_count += 1
                    continue
                line_len = len(file_lines[start_line - 1])
                if start_col > line_len + 1:
                    logger.warning(
                        "Skipping finding at index %d: StartColumn exceeds line length", idx
                    )
                    rejected_count += 1
                    continue
                validated_start_col = start_col

            if end_col is not None:
                if type(end_col) is not int or end_col < 1:
                    logger.warning("Skipping finding at index %d: invalid EndColumn", idx)
                    rejected_count += 1
                    continue
                end_line_len = len(file_lines[end_line - 1])
                if end_col > end_line_len + 1:
                    logger.warning(
                        "Skipping finding at index %d: EndColumn exceeds line length", idx
                    )
                    rejected_count += 1
                    continue
                validated_end_col = end_col

            if (
                start_line == end_line
                and validated_start_col is not None
                and validated_end_col is not None
                and validated_start_col > validated_end_col
            ):
                logger.warning(
                    "Skipping finding at index %d: inconsistent column coordinates on single line",
                    idx,
                )
                rejected_count += 1
                continue

            snippet, snippet_start_line = _extract_snippet(
                scanned_file.content, start_line, end_line
            )
            if not snippet or not snippet.strip():
                logger.warning(
                    "Skipping finding at index %d: empty code snippet extracted",
                    idx,
                )
                rejected_count += 1
                continue

            # Extract raw secret in memory for HMAC anchor computation and redaction
            secret_value_raw = item.get("Secret") or item.get("secret")
            secret_value = (
                secret_value_raw
                if isinstance(secret_value_raw, str) and secret_value_raw.strip()
                else None
            )

            # Check if secret value is already a redaction placeholder
            is_placeholder = _is_placeholder_secret(secret_value)
            scrub_secret = None if is_placeholder else secret_value
            applicable_file_secrets = _normalize_secret_inputs(
                [
                    *file_secrets_by_path.get(original_path, set()),
                    *([scrub_secret] if scrub_secret else ()),
                ]
            )

            # Sanitize untrusted RuleID against all applicable file secrets without discarding finding
            rule_id, rule_was_redacted = _sanitize_rule_id(
                raw_rule_id, applicable_file_secrets, key_bytes=key_bytes
            )
            if rule_was_redacted:
                logger.warning("Sanitized secret-bearing RuleID for finding at index %d", idx)

            # Compute anchor (HMAC-SHA256 for real secrets keyed by FINGERPRINT_KEY)
            try:
                if secret_value and not is_placeholder:
                    anchor = compute_secret_anchor(secret_value, key_bytes)
                else:
                    anchor = compute_code_anchor(snippet)
            except (ValueError, TypeError) as err:
                logger.warning(
                    "Skipping finding at index %d: failed to compute anchor: %s",
                    idx,
                    type(err).__name__,
                )
                rejected_count += 1
                continue

            # Redact raw secret, co-located file secrets, fragments, and known token patterns from snippet
            redaction_token = f"[REDACTED:{rule_id}]"
            snippet = _scrub_snippet_text(
                snippet,
                primary_secret=scrub_secret,
                file_secrets=applicable_file_secrets,
                primary_replacement=redaction_token,
            )
            # Re-enforce CanonicalFinding 2000-char limit if redaction tokens expanded a near-cap line
            if len(snippet) > 2000:
                snippet = snippet[:1997] + "..."

            if applicable_file_secrets and _contains_secret_or_fragment(
                snippet, applicable_file_secrets
            ):
                logger.warning(
                    "Skipping finding at index %d: secret could not be fully redacted from snippet",
                    idx,
                )
                rejected_count += 1
                continue

            # Construct sanitized title and description
            desc_field = item.get("Description") or item.get("description")
            desc_clean = ""
            if isinstance(desc_field, str):
                desc_clean = _strip_control_chars(desc_field.strip(), allow_newlines=False)[
                    :_MAX_DESCRIPTION_LENGTH
                ]
                desc_clean = _scrub_secret_text(desc_clean, applicable_file_secrets)

            if desc_clean:
                title = f"Hardcoded secret: {desc_clean}"[:120]
                description = f"Hardcoded secret detected matching rule '{rule_id}': {desc_clean}"[
                    :1000
                ]
            else:
                title = f"Hardcoded {rule_id} secret detected"[:120]
                description = f"Hardcoded secret detected matching rule '{rule_id}'."[:1000]

            # Final safety scrub of title and description against all applicable file secrets & patterns
            title = _strip_control_chars(_scrub_secret_text(title, applicable_file_secrets))[:120]
            description = _strip_control_chars(
                _scrub_secret_text(description, applicable_file_secrets)
            )[:1000]

            # Sanitize and validate tags (drop tags carrying any file secret or secret fragment)
            tags_raw = item.get("Tags") or item.get("tags")
            cleaned_tags: list[str] = []
            if isinstance(tags_raw, list):
                for t in tags_raw:
                    if isinstance(t, str):
                        t_clean = _strip_control_chars(t.strip())
                        if _find_all_sensitive_spans(t_clean, applicable_file_secrets):
                            continue
                        if _TAG_PATTERN.match(t_clean):
                            cleaned_tags.append(t_clean)
                        if len(cleaned_tags) >= 10:
                            break

            severity = _map_severity(cleaned_tags)

            # Construct sanitized raw metadata (Strictly exclude Secret, Match, Line)
            raw_candidate: dict[str, Any] = {
                "rule_id": rule_id,
            }
            if desc_clean:
                raw_candidate["description"] = desc_clean[:200]
            entropy = item.get("Entropy") if "Entropy" in item else item.get("entropy")
            if (
                isinstance(entropy, (int, float))
                and not isinstance(entropy, bool)
                and math.isfinite(entropy)
            ):
                raw_candidate["entropy"] = round(float(entropy), 2)
            if validated_start_col is not None:
                raw_candidate["start_column"] = validated_start_col
            if validated_end_col is not None:
                raw_candidate["end_column"] = validated_end_col
            if cleaned_tags:
                raw_candidate["tags"] = cleaned_tags

            raw_metadata = _sanitize_metadata(
                raw_candidate, secret_to_scrub=applicable_file_secrets
            )
            if applicable_file_secrets and _contains_secret_or_fragment(
                json.dumps(raw_metadata, ensure_ascii=False), applicable_file_secrets
            ):
                raw_metadata = {"rule_id": rule_id}

            intermediate_items.append(
                {
                    "rule_id": rule_id,
                    "source": FindingSource.GITLEAKS,
                    "category": FindingCategory.HARDCODED_SECRET,
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "confidence": FindingConfidence.HIGH,
                    "verification_status": VerificationStatus.SCANNER_DETECTED,
                    "file_path": original_path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "snippet": snippet,
                    "snippet_start_line": snippet_start_line,
                    "remediation": _DEFAULT_REMEDIATION,
                    "references": [_DEFAULT_REFERENCE],
                    "anchor": anchor,
                    "raw": raw_metadata,
                    "secret_value": secret_value,
                    "scrub_secret": scrub_secret,
                    "file_secrets": applicable_file_secrets,
                }
            )

        # Deduplicate exact duplicate scanner records before occurrence indexing
        # Identity: (rule_id, file_path, anchor, start_line, end_line, start_col, end_col)
        deduped_items: list[dict[str, Any]] = []
        seen_identities: set[tuple[Any, ...]] = set()

        for item_dict in intermediate_items:
            identity = (
                item_dict["rule_id"],
                item_dict["file_path"],
                item_dict["anchor"],
                item_dict["start_line"],
                item_dict["end_line"],
                item_dict["raw"].get("start_column"),
                item_dict["raw"].get("end_column"),
            )
            if identity in seen_identities:
                logger.debug("Discarding exact duplicate finding record")
                continue
            seen_identities.add(identity)
            deduped_items.append(item_dict)

        # Assign occurrence indices and construct CanonicalFinding instances
        assigned = assign_occurrence_indices(
            deduped_items,
            key_func=lambda d: (d["rule_id"], d["file_path"], d["anchor"]),
            line_func=lambda d: d["start_line"],
        )

        canonical_findings: list[CanonicalFinding] = []
        for finding_dict, occ in assigned:
            fp = compute_finding_fingerprint(
                rule_id=finding_dict["rule_id"],
                source=finding_dict["source"].value,
                file_path=finding_dict["file_path"],
                anchor=finding_dict["anchor"],
                occ=occ,
                category=finding_dict["category"].value,
            )
            try:
                canonical = CanonicalFinding(
                    rule_id=finding_dict["rule_id"],
                    source=finding_dict["source"],
                    category=finding_dict["category"],
                    title=finding_dict["title"],
                    description=finding_dict["description"],
                    severity=finding_dict["severity"],
                    confidence=finding_dict["confidence"],
                    verification_status=finding_dict["verification_status"],
                    file_path=finding_dict["file_path"],
                    start_line=finding_dict["start_line"],
                    end_line=finding_dict["end_line"],
                    snippet=finding_dict["snippet"],
                    snippet_start_line=finding_dict["snippet_start_line"],
                    remediation=finding_dict["remediation"],
                    references=finding_dict["references"],
                    in_diff=None,
                    fingerprint=fp,
                    raw=finding_dict["raw"],
                )

                # Ensure exact detected secrets and sensitive fragments for this file are absent
                secret_val = finding_dict.get("secret_value")
                file_secrets: list[str] = list(finding_dict.get("file_secrets") or ())
                serialized_finding = canonical.model_dump_json()
                raw_checks = [
                    *file_secrets,
                    *(
                        [secret_val]
                        if isinstance(secret_val, str)
                        and secret_val
                        and not _is_placeholder_secret(secret_val)
                        else []
                    ),
                ]
                leaked = any(sec in serialized_finding for sec in raw_checks)
                if not leaked and raw_checks:
                    fields_to_verify = [
                        canonical.rule_id,
                        *(s.rule_id for s in canonical.sources),
                        canonical.title,
                        canonical.description,
                        canonical.snippet,
                        canonical.remediation,
                        json.dumps(canonical.raw, ensure_ascii=False),
                        canonical.fingerprint,
                    ]
                    leaked = any(
                        _contains_secret_or_fragment(val, raw_checks) for val in fields_to_verify
                    )
                if leaked:
                    logger.warning(
                        "Skipping finding: secret or fragment detected in canonical finding serialization"
                    )
                    rejected_count += 1
                    continue

                canonical_findings.append(canonical)
            except (ValidationError, ValueError) as err:
                logger.warning(
                    "Skipping finding during normalization: validation failed: %s",
                    type(err).__name__,
                )
                rejected_count += 1

        total_raw = len(raw_results)
        if total_raw > 0 and not canonical_findings:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="GITLEAKS_NORMALIZATION_FAILED",
                error_message="Failed to normalize Gitleaks findings",
                retryable=False,
                components={"gitleaks": "failed"},
            )

        status = ScanStatus.PARTIAL if rejected_count > 0 else ScanStatus.SUCCEEDED
        component_status = "partial" if status == ScanStatus.PARTIAL else "passed"

        severity_counts = {
            "critical": sum(
                1 for f in canonical_findings if f.severity == FindingSeverity.CRITICAL
            ),
            "high": sum(1 for f in canonical_findings if f.severity == FindingSeverity.HIGH),
            "medium": sum(1 for f in canonical_findings if f.severity == FindingSeverity.MEDIUM),
            "low": sum(1 for f in canonical_findings if f.severity == FindingSeverity.LOW),
            "info": sum(1 for f in canonical_findings if f.severity == FindingSeverity.INFO),
        }
        counts = {"findings": len(canonical_findings), **severity_counts}

        return ScanExecutionResult(
            status=status,
            components={"gitleaks": component_status},
            counts=counts,
            findings=canonical_findings,
        )
