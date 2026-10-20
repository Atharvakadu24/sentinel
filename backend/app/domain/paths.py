"""Path normalization and validation rules for Sentinel findings and source files.

Strictly implements Blueprint Workflow A and Threat T8 specifications:
- NFC Unicode normalization
- Forward slashes only (backslashes rejected)
- Relative paths only (no leading slashes, no drive letters)
- No path traversal segments ('.' or '..')
- No empty segments ('//')
- No NUL bytes or control characters
- Maximum 255 characters total
- Maximum 10 segments
"""

from __future__ import annotations

import re
import unicodedata

_DRIVE_LETTER_PATTERN = re.compile(r"^[a-zA-Z]:")
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def normalize_and_validate_path(path: str) -> str:
    """Normalize and validate a relative file path according to Sentinel safety rules.

    Args:
        path: The file path string to validate.

    Returns:
        The NFC-normalized, validated relative path with forward slashes.

    Raises:
        ValueError: If the path violates any safety or format constraints.
    """
    if not isinstance(path, str):
        raise TypeError(f"Path must be a string, got {type(path).__name__}")

    if not path or not path.strip():
        raise ValueError("Path must not be empty or whitespace-only")

    # 1. Reject NUL bytes and control characters
    if _CONTROL_CHAR_PATTERN.search(path):
        raise ValueError("Path contains invalid control characters or NUL bytes")

    # 2. Reject backslashes explicitly (T8: backslashes rejected, forward slashes only)
    if "\\" in path:
        raise ValueError("Path must use forward slashes only; backslashes are forbidden")

    # 3. Reject pipe character (fingerprint delimiter collision defense)
    if "|" in path:
        raise ValueError("Path must not contain pipe ('|') characters")

    # 4. Reject Windows drive letters
    if _DRIVE_LETTER_PATTERN.match(path):
        raise ValueError("Path must be relative; drive letters are forbidden")

    # 5. Reject absolute paths (leading forward slash)
    if path.startswith("/"):
        raise ValueError("Path must be relative; leading slashes are forbidden")

    # 6. Reject trailing slash (findings point to files, not directories)
    if path.endswith("/"):
        raise ValueError("File path must not end with a trailing slash")

    # 7. Unicode NFC normalization
    normalized = unicodedata.normalize("NFC", path)

    # 8. Check length
    if len(normalized) > 255:
        raise ValueError(f"Path exceeds maximum length of 255 characters (got {len(normalized)})")

    # 9. Segment-level inspection
    segments = normalized.split("/")

    if len(segments) > 10:
        raise ValueError(f"Path exceeds maximum limit of 10 segments (got {len(segments)})")

    for segment in segments:
        if not segment:
            raise ValueError("Path must not contain empty segments ('//')")
        if segment in (".", ".."):
            raise ValueError("Path traversal segments ('.' or '..') are forbidden")
        if segment.endswith(" "):
            raise ValueError(f"Path segment '{segment}' must not end with a space")
        if segment.endswith("."):
            raise ValueError(f"Path segment '{segment}' must not end with a space or dot")
        if segment != segment.strip():
            raise ValueError(
                f"Path segment '{segment}' must not contain leading or trailing whitespace"
            )

    return normalized
