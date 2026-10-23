"""Unit tests for Sentinel application settings and security invariants (Threat T1, T3, T13)."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings


class TestSettings:
    """Tests for environment settings loading, validation, and secret masking."""

    def test_default_development_settings(self) -> None:
        settings = Settings()
        assert settings.APP_ENV == "development"
        assert settings.APP_NAME == "Sentinel"
        assert settings.PORT == 8000
        assert settings.AI_DEBUG_LOG is False

    def test_secret_masking(self) -> None:
        """Secrets must never be exposed via str() or repr() representations."""
        settings = Settings(
            SECRET_KEY=SecretStr("super_secret_master_key_1234567890123456"),
            FINGERPRINT_KEY=SecretStr("0123456789abcdef0123456789abcdef"),
        )
        assert "super_secret_master_key" not in str(settings.SECRET_KEY)
        assert "super_secret_master_key" not in repr(settings.SECRET_KEY)
        assert "0123456789abcdef" not in str(settings.FINGERPRINT_KEY)
        assert "0123456789abcdef" not in repr(settings.FINGERPRINT_KEY)

    def test_valid_custom_fingerprint_key(self) -> None:
        valid_key = "0123456789abcdef0123456789abcdef"
        settings = Settings(FINGERPRINT_KEY=SecretStr(valid_key))
        assert settings.FINGERPRINT_KEY.get_secret_value() == valid_key
        assert settings.validate_runtime_fingerprint_key() == valid_key.encode("utf-8")

    def test_fingerprint_key_whitespace_only_rejected(self) -> None:
        with pytest.raises(ValidationError, match="whitespace-only"):
            Settings(FINGERPRINT_KEY=SecretStr("               "))

    def test_fingerprint_key_too_short_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 16 bytes"):
            Settings(FINGERPRINT_KEY=SecretStr("short_key_8b"))

    def test_runtime_validation_rejects_unconfigured_placeholder(self) -> None:
        """Default placeholder is accepted at startup in dev, but fails strict runtime check."""
        settings = Settings(
            FINGERPRINT_KEY=SecretStr("replace-with-a-secure-random-hex-key-for-fingerprinting")
        )
        with pytest.raises(ValueError, match="template placeholder"):
            settings.validate_runtime_fingerprint_key()

    def test_production_fails_if_ai_debug_log_enabled(self) -> None:
        """Blueprint Section 11.8: Startup MUST fail if AI_DEBUG_LOG is true in production."""
        valid_key = SecretStr("0123456789abcdef0123456789abcdef")
        with pytest.raises(ValidationError, match="AI_DEBUG_LOG must not be true in production"):
            Settings(
                APP_ENV="production",
                AI_DEBUG_LOG=True,
                SECRET_KEY=valid_key,
                SESSION_SECRET=valid_key,
                FINGERPRINT_KEY=valid_key,
            )

    def test_production_fails_if_fingerprint_key_is_placeholder(self) -> None:
        valid_key = SecretStr("0123456789abcdef0123456789abcdef")
        with pytest.raises(ValidationError, match="FINGERPRINT_KEY is invalid"):
            Settings(
                APP_ENV="production",
                AI_DEBUG_LOG=False,
                SECRET_KEY=valid_key,
                SESSION_SECRET=valid_key,
                FINGERPRINT_KEY=SecretStr(
                    "replace-with-a-secure-random-hex-key-for-fingerprinting"
                ),
            )

    def test_production_fails_if_secret_key_too_short(self) -> None:
        valid_key = SecretStr("0123456789abcdef0123456789abcdef")
        with pytest.raises(ValidationError, match="minimum length of 32 characters"):
            Settings(
                APP_ENV="production",
                AI_DEBUG_LOG=False,
                SECRET_KEY=SecretStr("too_short_key_under_32"),
                SESSION_SECRET=valid_key,
                FINGERPRINT_KEY=valid_key,
            )

    def test_production_fails_if_secret_key_relies_on_whitespace_padding(self) -> None:
        valid_key = SecretStr("0123456789abcdef0123456789abcdef")
        with pytest.raises(ValidationError, match="must not rely on whitespace padding"):
            Settings(
                APP_ENV="production",
                AI_DEBUG_LOG=False,
                SECRET_KEY=SecretStr("short_key" + " " * 25),
                SESSION_SECRET=valid_key,
                FINGERPRINT_KEY=valid_key,
            )

    def test_production_fails_if_secret_key_contains_known_placeholder(self) -> None:
        valid_key = SecretStr("0123456789abcdef0123456789abcdef")
        with pytest.raises(
            ValidationError, match="contains known placeholder pattern 'replace-with'"
        ):
            Settings(
                APP_ENV="production",
                AI_DEBUG_LOG=False,
                SECRET_KEY=SecretStr("replace-with-a-random-32-byte-hex-string-for-dev-only"),
                SESSION_SECRET=valid_key,
                FINGERPRINT_KEY=valid_key,
            )

    def test_production_fails_if_secret_key_exhibits_trivial_repetition(self) -> None:
        valid_key = SecretStr("0123456789abcdef0123456789abcdef")
        with pytest.raises(
            ValidationError, match="trivial repetition or insufficient character diversity"
        ):
            Settings(
                APP_ENV="production",
                AI_DEBUG_LOG=False,
                SECRET_KEY=SecretStr("a" * 32),
                SESSION_SECRET=valid_key,
                FINGERPRINT_KEY=valid_key,
            )

    def test_production_fails_if_session_secret_weak_or_placeholder(self) -> None:
        valid_key = SecretStr("0123456789abcdef0123456789abcdef")
        with pytest.raises(ValidationError, match="contains known placeholder pattern 'changeme'"):
            Settings(
                APP_ENV="production",
                AI_DEBUG_LOG=False,
                SECRET_KEY=valid_key,
                SESSION_SECRET=SecretStr("changeme_session_secret_key_1234567"),
                FINGERPRINT_KEY=valid_key,
            )

    def test_production_succeeds_with_strong_configuration(self) -> None:
        settings = Settings(
            APP_ENV="production",
            AI_DEBUG_LOG=False,
            SECRET_KEY=SecretStr("12345678901234567890123456789012"),
            SESSION_SECRET=SecretStr("abcdef0123456789abcdef0123456789"),
            FINGERPRINT_KEY=SecretStr("fedcba9876543210fedcba9876543210"),
        )
        assert settings.APP_ENV == "production"
        assert settings.validate_runtime_fingerprint_key() == b"fedcba9876543210fedcba9876543210"
        assert settings.ENABLE_DEV_UNAUTHENTICATED_SCANS is False

    def test_default_enable_dev_unauthenticated_scans_is_false(self) -> None:
        settings = Settings()
        assert settings.ENABLE_DEV_UNAUTHENTICATED_SCANS is False

    def test_production_fails_if_enable_dev_unauthenticated_scans_true(self) -> None:
        valid_key = SecretStr("0123456789abcdef0123456789abcdef")
        with pytest.raises(
            ValidationError,
            match="ENABLE_DEV_UNAUTHENTICATED_SCANS must not be true in production",
        ):
            Settings(
                APP_ENV="production",
                AI_DEBUG_LOG=False,
                ENABLE_DEV_UNAUTHENTICATED_SCANS=True,
                SECRET_KEY=valid_key,
                SESSION_SECRET=valid_key,
                FINGERPRINT_KEY=valid_key,
            )

    def test_invalid_app_env_rejected(self) -> None:
        """Non-standard or mis-cased environment names are rejected by Literal validation."""
        for invalid_env in ["staging", "PRODUCTION", "prod", "DEV", ""]:
            with pytest.raises(ValidationError):
                Settings(APP_ENV=invalid_env)

    def test_enable_dev_unauthenticated_scans_boolean_parsing(self) -> None:
        """Verify strict boolean parsing for dev unauthenticated scans."""
        assert (
            Settings(ENABLE_DEV_UNAUTHENTICATED_SCANS=False).ENABLE_DEV_UNAUTHENTICATED_SCANS
            is False
        )
        assert (
            Settings(ENABLE_DEV_UNAUTHENTICATED_SCANS=True).ENABLE_DEV_UNAUTHENTICATED_SCANS is True
        )
