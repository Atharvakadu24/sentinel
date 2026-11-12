"""Job payload validation and deserialization for worker processing.

Enforces schema contracts and untrusted input safety checks before any
scanner engine or analysis step receives files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.domain.paths import normalize_and_validate_path
from app.services.scan_service import MAX_FILE_BYTES, MAX_FILES_COUNT, MAX_TOTAL_BYTES
from app.worker.scanner import ScanJobPayload, ScannedFile

_RE_GIT_SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_RE_GITHUB_FULL_NAME = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_FORBIDDEN_PAYLOAD_SECRET_KEYS = frozenset(
    {"token", "access_token", "installation_token", "private_key", "secret", "password", "jwt"}
)


@dataclass(frozen=True, slots=True)
class GitHubPRScanJobPayload:
    """Validated immutable payload for a queued GitHub pull-request scan job."""

    installation_id: int
    github_repo_id: int
    full_name: str
    pr_number: int
    head_sha: str
    base_sha: str | None = None
    run_ai: bool = True


class PayloadValidationError(Exception):
    """Raised when job payload structure or data fails validation."""


def validate_scan_payload(raw: Any) -> ScanJobPayload:
    """Validate and normalize a raw Job.payload dictionary into ScanJobPayload.

    Args:
        raw: Raw JSON-compatible object stored in Job.payload.

    Returns:
        Validated, immutable ScanJobPayload instance.

    Raises:
        PayloadValidationError: If payload structure, file paths, or content are invalid.
    """
    if not isinstance(raw, dict):
        raise PayloadValidationError(
            f"Job payload must be a JSON object dictionary, got '{type(raw).__name__}'"
        )

    if "files" not in raw:
        raise PayloadValidationError("Job payload is missing required 'files' key")

    raw_files = raw["files"]
    if not isinstance(raw_files, list):
        raise PayloadValidationError(
            f"Job payload 'files' must be a list, got '{type(raw_files).__name__}'"
        )

    if len(raw_files) == 0:
        raise PayloadValidationError("Job payload 'files' list cannot be empty")

    if len(raw_files) > MAX_FILES_COUNT:
        raise PayloadValidationError(
            f"Job payload 'files' list exceeds maximum of {MAX_FILES_COUNT} files, got {len(raw_files)}"
        )

    validated_files: list[ScannedFile] = []
    seen_casefold_paths: set[str] = set()
    total_bytes = 0

    for idx, item in enumerate(raw_files):
        if not isinstance(item, dict):
            raise PayloadValidationError(
                f"File at index {idx} must be a dictionary, got '{type(item).__name__}'"
            )

        if "path" not in item:
            raise PayloadValidationError(f"File at index {idx} is missing required 'path'")
        if "content" not in item:
            raise PayloadValidationError(f"File at index {idx} is missing required 'content'")

        raw_path = item["path"]
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise PayloadValidationError(
                f"File at index {idx} has invalid or empty path: {raw_path!r}"
            )

        try:
            normalized_path = normalize_and_validate_path(raw_path)
        except (ValueError, TypeError) as exc:
            raise PayloadValidationError(
                f"File at index {idx} has invalid path '{raw_path}': {exc}"
            ) from exc

        # Case-folded path uniqueness
        casefolded = normalized_path.casefold()
        if casefolded in seen_casefold_paths:
            raise PayloadValidationError(
                f"Duplicate file path '{normalized_path}' after case-folding normalization"
            )
        seen_casefold_paths.add(casefolded)

        raw_content = item["content"]
        if not isinstance(raw_content, str):
            raise PayloadValidationError(
                f"File content for '{normalized_path}' must be a string, got '{type(raw_content).__name__}'"
            )

        if "\x00" in raw_content:
            raise PayloadValidationError(
                f"File content for '{normalized_path}' contains invalid NUL bytes"
            )

        content_bytes = len(raw_content.encode("utf-8"))
        if content_bytes > MAX_FILE_BYTES:
            raise PayloadValidationError(
                f"File content for '{normalized_path}' exceeds maximum size of {MAX_FILE_BYTES} bytes ({content_bytes} bytes)"
            )

        total_bytes += content_bytes
        if total_bytes > MAX_TOTAL_BYTES:
            raise PayloadValidationError(
                f"Total file content size exceeds maximum allowed size of {MAX_TOTAL_BYTES} bytes ({total_bytes} bytes)"
            )

        raw_scanned = item.get("scanned", True)
        if not isinstance(raw_scanned, bool):
            raise PayloadValidationError(
                f"'scanned' for '{normalized_path}' must be a boolean, got '{type(raw_scanned).__name__}'"
            )

        raw_skip_reason = item.get("skip_reason")
        if raw_skip_reason is not None and not isinstance(raw_skip_reason, str):
            raise PayloadValidationError(
                f"'skip_reason' for '{normalized_path}' must be a string or None, got '{type(raw_skip_reason).__name__}'"
            )

        validated_files.append(
            ScannedFile(
                path=normalized_path,
                content=raw_content,
                scanned=raw_scanned,
                skip_reason=raw_skip_reason,
            )
        )

    raw_run_ai = raw.get("run_ai", True)
    if not isinstance(raw_run_ai, bool):
        raise PayloadValidationError(
            f"Job payload 'run_ai' must be a boolean, got '{type(raw_run_ai).__name__}'"
        )

    return ScanJobPayload(files=validated_files, run_ai=raw_run_ai)


def validate_github_pr_scan_payload(raw: Any) -> GitHubPRScanJobPayload:
    """Validate and normalize a raw GitHub PR scan Job.payload dictionary."""
    if not isinstance(raw, dict):
        raise PayloadValidationError(
            f"Job payload must be a JSON object dictionary, got '{type(raw).__name__}'"
        )

    for forbidden in _FORBIDDEN_PAYLOAD_SECRET_KEYS:
        if forbidden in raw:
            raise PayloadValidationError(
                f"Job payload must not contain credential field '{forbidden}'"
            )

    def _req_pos_int(key: str) -> int:
        val = raw.get(key)
        if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
            raise PayloadValidationError(f"Job payload '{key}' must be a positive integer")
        return val

    installation_id = _req_pos_int("installation_id")
    github_repo_id = _req_pos_int("github_repo_id")
    pr_number = _req_pos_int("pr_number")

    full_name = raw.get("full_name")
    if not isinstance(full_name, str) or not _RE_GITHUB_FULL_NAME.match(full_name.strip()):
        raise PayloadValidationError("Job payload 'full_name' must be a valid 'owner/repo' string")
    owner, repo = full_name.strip().split("/", 1)
    if owner in (".", "..") or repo in (".", ".."):
        raise PayloadValidationError("Job payload 'full_name' contains invalid path segments")

    head_sha = raw.get("head_sha")
    if not isinstance(head_sha, str) or not _RE_GIT_SHA.match(head_sha.strip()):
        raise PayloadValidationError("Job payload 'head_sha' must be a valid commit SHA")

    base_sha = raw.get("base_sha")
    cleaned_base: str | None = None
    if base_sha is not None:
        if not isinstance(base_sha, str) or not _RE_GIT_SHA.match(base_sha.strip()):
            raise PayloadValidationError(
                "Job payload 'base_sha' must be a valid commit SHA or None"
            )
        cleaned_base = base_sha.strip().lower()

    raw_run_ai = raw.get("run_ai", True)
    if not isinstance(raw_run_ai, bool):
        raise PayloadValidationError(
            f"Job payload 'run_ai' must be a boolean, got '{type(raw_run_ai).__name__}'"
        )

    return GitHubPRScanJobPayload(
        installation_id=installation_id,
        github_repo_id=github_repo_id,
        full_name=full_name.strip(),
        pr_number=pr_number,
        head_sha=head_sha.strip().lower(),
        base_sha=cleaned_base,
        run_ai=raw_run_ai,
    )
