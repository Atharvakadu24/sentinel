"""Deterministic, versioned finding fingerprint generation.

Implements Blueprint Section 10.4 and Section 10.6:
    norm        = collapse all whitespace in lines[start_line..end_line] of the actual file
    anchor      = hex(sha256(norm))[:16]
                  (secrets: hex(hmac_sha256(FINGERPRINT_KEY, secret_value))[:16])
    rule_key    = rule_id (AI findings: "ai:" + category)
    occ         = zero-based index among findings in the same scan sharing (rule_key, file, anchor),
                  ordered by start_line
    fingerprint = sha256("v1|" + rule_key + "|" + normalized_path + "|" + anchor + "|" + occ)

Properties:
- Deterministic: identical inputs always produce the identical 64-character hex digest.
- Line-number independent: shifting lines above a finding does not alter its fingerprint.
- Path-safe: host absolute paths are rejected and paths are NFC-normalized with forward slashes.
- Secret-safe: raw secret values are HMAC-keyed with FINGERPRINT_KEY into a 16-char anchor and
  never appear in the fingerprint string or stored models.
- Versioned: explicit "v1" scheme prefix allows future evolution without silent identity drift.
"""

import hashlib
import hmac
import re
from collections.abc import Callable, Sequence

from app.domain.paths import normalize_and_validate_path

FINGERPRINT_VERSION = "v1"

_HEX_ANCHOR_PATTERN = re.compile(r"^[0-9a-fA-F]{16}$")
_WHITESPACE_PATTERN = re.compile(r"\s+")


def collapse_whitespace(text: str) -> str:
    """Collapse all whitespace characters (spaces, tabs, newlines) completely.

    Stripping all whitespace ensures the resulting anchor is immune to indentation shifts,
    CRLF vs LF line endings, and trailing whitespace.
    """
    return _WHITESPACE_PATTERN.sub("", text)


def compute_code_anchor(code_text: str) -> str:
    """Compute the 16-character hex anchor for code snippet lines.

    Args:
        code_text: The source code lines spanning start_line to end_line.

    Returns:
        A 16-character lowercase hex string representing the normalized code anchor.

    Raises:
        ValueError: If code_text is empty or contains only whitespace.
    """
    if not code_text or not code_text.strip():
        raise ValueError("Code text cannot be empty or purely whitespace for anchor calculation")

    normalized = collapse_whitespace(code_text)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def validate_fingerprint_key(fingerprint_key: str | bytes) -> bytes:
    """Validate server-side FINGERPRINT_KEY material without mutating it.

    Blueprint Section 10.4:
    "The fingerprint anchor for a secret is an HMAC-SHA256 of the secret value keyed by
    a server-side FINGERPRINT_KEY (so the stored identity cannot be reversed or compared
    offline without the key)."

    Ensures the key is non-empty, non-whitespace, at least 16 bytes, and
    rejects known default template placeholders.

    SECURITY INVARIANTS:
    - Never silently trim leading/trailing whitespace: valid key bytes are preserved verbatim.
    - Check both string and bytes representations for empty or whitespace-only inputs.
    - Never echo or log key material in error messages.
    - Meeting the minimum length does not imply high entropy; production keys must be
      generated using a CSPRNG (e.g. `openssl rand -hex 32` or `secrets.token_hex(32)`).

    Args:
        fingerprint_key: The secret key material as string or bytes.

    Returns:
        The exact, unmodified key bytes.

    Raises:
        TypeError: If fingerprint_key is not str or bytes.
        ValueError: If fingerprint_key is empty, whitespace-only, shorter than 16 bytes,
                    or matches a known template placeholder.
    """
    if not isinstance(fingerprint_key, (str, bytes)):
        raise TypeError(
            f"FINGERPRINT_KEY must be str or bytes, got {type(fingerprint_key).__name__}"
        )

    if isinstance(fingerprint_key, str):
        if not fingerprint_key:
            raise ValueError("FINGERPRINT_KEY must be provided")
        if not fingerprint_key.strip():
            raise ValueError("FINGERPRINT_KEY must not be whitespace-only")
        key_bytes = fingerprint_key.encode("utf-8")
    else:
        if not fingerprint_key:
            raise ValueError("FINGERPRINT_KEY must be provided")
        if not fingerprint_key.strip():
            raise ValueError("FINGERPRINT_KEY must not be whitespace-only")
        key_bytes = fingerprint_key

    if len(key_bytes) < 16:
        raise ValueError(
            "FINGERPRINT_KEY must be at least 16 bytes to ensure cryptographic security"
        )

    # Check for known template placeholders without echoing key material
    lowered = (
        fingerprint_key.lower()
        if isinstance(fingerprint_key, str)
        else fingerprint_key.lower().decode("utf-8", errors="ignore")
    )
    if "replace-with" in lowered or "placeholder" in lowered:
        raise ValueError("FINGERPRINT_KEY cannot be an unconfigured template placeholder")

    return key_bytes


def compute_secret_anchor(secret_value: str, fingerprint_key: str | bytes) -> str:
    """Compute the 16-character HMAC-SHA256 anchor for a detected secret.

    Blueprint Section 10.4:
    "The fingerprint anchor for a secret is an HMAC-SHA256 of the secret value keyed by
    a server-side FINGERPRINT_KEY (so the stored identity cannot be reversed or compared
    offline without the key)."

    Args:
        secret_value: The raw secret value detected by the scanner.
        fingerprint_key: The server-side secret key (FINGERPRINT_KEY).

    Returns:
        A 16-character lowercase hex HMAC anchor. The raw secret is never stored.

    Raises:
        TypeError: If secret_value or fingerprint_key has an invalid type.
        ValueError: If secret_value is empty, or fingerprint_key is invalid.
    """
    if not isinstance(secret_value, str):
        raise TypeError(f"Secret value must be a string, got {type(secret_value).__name__}")
    if not secret_value:
        raise ValueError("Secret value cannot be empty")

    key_bytes = validate_fingerprint_key(fingerprint_key)
    secret_bytes = secret_value.encode("utf-8")
    return hmac.new(key_bytes, secret_bytes, hashlib.sha256).hexdigest()[:16]


def compute_rule_key(source: str, rule_id: str, category: str | None = None) -> str:
    """Compute the canonical rule key for fingerprinting.

    Per Blueprint Section 10.6:
    rule_key = rule_id (AI findings: "ai:" + category)
    """
    source_lower = source.strip().lower()
    if source_lower == "ai":
        if not category or not category.strip():
            raise ValueError("Category is required to compute AI rule key ('ai:<category>')")
        cat_clean = category.strip().lower()
        if "|" in cat_clean:
            raise ValueError("Category must not contain pipe ('|') character")
        return f"ai:{cat_clean}"
    if not rule_id or not rule_id.strip():
        raise ValueError("rule_id cannot be empty")
    clean_rule = rule_id.strip()
    if "|" in clean_rule:
        raise ValueError("rule_id must not contain pipe ('|') character")
    return clean_rule


def compute_finding_fingerprint(
    *,
    rule_id: str,
    source: str,
    file_path: str,
    anchor: str,
    occ: int = 0,
    category: str | None = None,
    version: str = FINGERPRINT_VERSION,
) -> str:
    """Compute the canonical 64-character SHA-256 fingerprint for a finding.

    Format:
        sha256("{version}|{rule_key}|{normalized_path}|{anchor}|{occ}")

    Fields that contribute to the fingerprint:
        - version: Schema version ('v1')
        - rule_key: Scanner rule ID or 'ai:{category}'
        - normalized_path: NFC-normalized relative path with forward slashes
        - anchor: 16-character hex digest of normalized code or HMAC of secret
        - occ: Zero-based occurrence index among findings sharing (rule_key, file, anchor)

    Fields that DO NOT contribute to the fingerprint:
        - Line numbers (start_line, end_line)
        - Finding severity and confidence
        - Finding title, description, and remediation text
        - Project ID, scan ID, timestamps, and commit SHAs

    Returns:
        A 64-character lowercase hex SHA-256 digest.
    """
    if not _HEX_ANCHOR_PATTERN.match(anchor):
        raise ValueError(f"Anchor must be a 16-character hexadecimal string, got '{anchor}'")

    if occ < 0:
        raise ValueError(f"Occurrence index (occ) must be non-negative, got {occ}")

    normalized_path = normalize_and_validate_path(file_path)
    rule_key = compute_rule_key(source=source, rule_id=rule_id, category=category)

    payload = f"{version}|{rule_key}|{normalized_path}|{anchor.lower()}|{occ}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def assign_occurrence_indices[T](
    items: Sequence[T],
    *,
    key_func: Callable[[T], tuple[str, str, str]],
    line_func: Callable[[T], int],
) -> list[tuple[T, int]]:
    """Assign 0-based occurrence indices (`occ`) for findings sharing (rule_key, file, anchor).

    Blueprint Section 10.6:
    "occ = zero-based index among findings in the same scan sharing (rule_key, file, anchor),
    ordered by start_line"

    Args:
        items: Sequence of finding objects or dictionaries.
        key_func: Function returning (rule_key, normalized_file_path, anchor) tuple for an item.
        line_func: Function returning the integer start_line for an item.

    Returns:
        List of (item, occ) tuples maintaining original items with their assigned index.
    """
    # Sort items by line number within their identity group
    indexed_items = list(enumerate(items))
    indexed_items.sort(key=lambda pair: (key_func(pair[1]), line_func(pair[1]), pair[0]))

    counts: dict[tuple[str, str, str], int] = {}
    assignments: list[tuple[int, T, int]] = []

    for orig_idx, item in indexed_items:
        group_key = key_func(item)
        current_occ = counts.get(group_key, 0)
        counts[group_key] = current_occ + 1
        assignments.append((orig_idx, item, current_occ))

    # Restore original input order
    assignments.sort(key=lambda t: t[0])
    return [(item, occ) for _, item, occ in assignments]
