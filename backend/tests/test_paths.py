"""Unit tests for file path normalization and security validation (Workflow A / T8)."""

from __future__ import annotations

import unicodedata

import pytest

from app.domain.paths import normalize_and_validate_path


class TestPathNormalization:
    """Tests for path safety constraints and NFC normalization."""

    def test_valid_simple_path(self) -> None:
        assert normalize_and_validate_path("main.py") == "main.py"
        assert normalize_and_validate_path("app/core/config.py") == "app/core/config.py"
        assert normalize_and_validate_path("src/components/Button.tsx") == "src/components/Button.tsx"

    def test_unicode_nfc_normalization(self) -> None:
        # e + acute accent (NFD) normalized to single character é (NFC)
        decomposed = "src/caf\u0065\u0301.py"
        composed = "src/caf\u00e9.py"
        assert unicodedata.is_normalized("NFD", decomposed)
        normalized = normalize_and_validate_path(decomposed)
        assert normalized == composed
        assert unicodedata.is_normalized("NFC", normalized)

    @pytest.mark.parametrize(
        "invalid_path,expected_err",
        [
            ("", "must not be empty"),
            ("   ", "must not be empty"),
            ("/etc/passwd", "leading slashes are forbidden"),
            ("/src/main.py", "leading slashes are forbidden"),
            ("C:/Windows/System32", "drive letters are forbidden"),
            ("d:/sentinel/app.py", "drive letters are forbidden"),
            ("app\\main.py", "backslashes are forbidden"),
            ("foo/../bar.py", "Path traversal segments"),
            ("../bar.py", "Path traversal segments"),
            ("foo/./bar.py", "Path traversal segments"),
            ("./bar.py", "Path traversal segments"),
            ("foo//bar.py", "empty segments"),
            ("src/main.py/", "trailing slash"),
            ("src/main\x00.py", "control characters or NUL bytes"),
            ("src/main\r.py", "control characters or NUL bytes"),
            ("src/main\n.py", "control characters or NUL bytes"),
            ("src/main.py ", "must not end with a space"),
            ("src/main.py.", "must not end with a space or dot"),
            ("app/foo|bar.py", "must not contain pipe"),
            ("src/ main.py", "must not contain leading or trailing whitespace"),
            ("src /main.py", "must not end with a space"),
        ],
    )
    def test_rejected_unsafe_paths(self, invalid_path: str, expected_err: str) -> None:
        with pytest.raises(ValueError, match=expected_err):
            normalize_and_validate_path(invalid_path)

    def test_max_segments_limit(self) -> None:
        # 10 segments is allowed
        ten_segments = "/".join(f"d{i}" for i in range(9)) + "/file.py"
        assert normalize_and_validate_path(ten_segments) == ten_segments

        # 11 segments is rejected
        eleven_segments = "/".join(f"d{i}" for i in range(10)) + "/file.py"
        with pytest.raises(ValueError, match="exceeds maximum limit of 10 segments"):
            normalize_and_validate_path(eleven_segments)

    def test_max_length_limit(self) -> None:
        # Path longer than 255 chars
        long_name = "a" * 250 + ".py"
        with pytest.raises(ValueError, match="exceeds maximum length of 255"):
            normalize_and_validate_path(f"src/{long_name}")

    def test_invalid_type_raises(self) -> None:
        with pytest.raises(TypeError, match="Path must be a string"):
            normalize_and_validate_path(None)  # type: ignore[arg-type]
