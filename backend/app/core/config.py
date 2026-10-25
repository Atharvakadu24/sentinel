"""Application configuration and environment settings.

Implements Blueprint Section 4 (Technology Stack) and Section 12 (Security Threat Model)
using type-safe Pydantic Settings with strict secret masking and production guards.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.domain.fingerprint import validate_fingerprint_key


class Settings(BaseSettings):
    """Sentinel system configuration loaded from environment variables and .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    # Application & Server
    APP_ENV: Literal["development", "test", "production"] = "development"
    APP_NAME: str = "Sentinel"
    API_HOST: str = "0.0.0.0"
    PORT: int = 8000
    FRONTEND_ORIGIN: str = "http://localhost:5173"
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # Secrets (minimum 32 chars in production)
    SECRET_KEY: SecretStr = Field(
        default_factory=lambda: SecretStr("replace-with-a-random-32-byte-hex-string-for-dev-only")
    )
    SESSION_SECRET: SecretStr = Field(
        default_factory=lambda: SecretStr(
            "replace-with-a-random-32-byte-hex-string-for-session-cookies"
        )
    )

    # Database (PostgreSQL 16)
    DATABASE_URL: str = (
        "postgresql://sentinel_user:sentinel_dev_password@localhost:5432/sentinel_db"
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_ECHO: bool = False

    # Security & Fingerprint Key (Server-side HMAC anchor key)
    FINGERPRINT_KEY: SecretStr = Field(
        default_factory=lambda: SecretStr("replace-with-a-secure-random-hex-key-for-fingerprinting")
    )

    # GitHub App Integration
    GITHUB_APP_ID: int | None = None
    GITHUB_CLIENT_ID: str | None = None
    GITHUB_CLIENT_SECRET: SecretStr | None = None
    GITHUB_WEBHOOK_SECRET: SecretStr | None = None
    GITHUB_APP_PRIVATE_KEY_PATH: str | None = "./secrets/github-app.private-key.pem"

    # AI Review & LLM
    LLM_PROVIDER: Literal["anthropic", "gemini"] = "anthropic"
    LLM_MODEL: str = "claude-3-5-haiku-20241022"
    ANTHROPIC_API_KEY: SecretStr | None = None
    GEMINI_API_KEY: SecretStr | None = None
    AI_ENABLED: bool = False
    AI_DAILY_TOKEN_LIMIT_PER_USER: int = 100000
    AI_DAILY_TOKEN_CAP: int = 500000
    AI_SCAN_MAX_FILES: int = 6
    AI_SCAN_MAX_INPUT_TOKENS: int = 40000
    AI_PER_CALL_TIMEOUT_SEC: int = 30
    AI_TOTAL_BUDGET_SEC: int = 90
    AI_DEBUG_LOG: bool = False

    # Static Analysis Scanners & Paths
    SEMGREP_PATH: str = "semgrep"
    GITLEAKS_PATH: str = "gitleaks"
    SEMGREP_RULES_PATH: str = "./rules/semgrep"
    SCANNER_TEMP_DIR: str = "/tmp/sentinel"
    SEMGREP_TIMEOUT_SEC: int = 120
    GITLEAKS_TIMEOUT_SEC: int = 60

    # Background Worker & Job Queue
    WORKER_POLL_INTERVAL_SEC: float = 1.5
    WORKER_JOB_LEASE_SEC: int = 60
    WORKER_HEARTBEAT_SEC: int = 15
    WORKER_MAX_CONCURRENCY: int = 2
    WORKER_REAPER_INTERVAL_SEC: float = 30.0

    # Observability
    SENTRY_DSN: str | None = None

    # Development-only opt-in guards (Threat T4 / Tenant Isolation)
    # Scan creation requires authenticated sessions; unauthenticated access fails closed
    # by default and can only be enabled explicitly in non-production environments.
    ENABLE_DEV_UNAUTHENTICATED_SCANS: bool = False

    @field_validator("FINGERPRINT_KEY")
    @classmethod
    def validate_fingerprint_key_setting(cls, v: SecretStr) -> SecretStr:
        """Validate FINGERPRINT_KEY using domain rules.

        Note: In development and test environments, the default placeholder is permitted
        if not yet configured, but whenever a non-default key is set, or when validate_key()
        is called explicitly, it must satisfy all cryptographic constraints.
        """
        raw_key = v.get_secret_value()
        # In development/test, allow unconfigured default placeholder during initial setup,
        # but enforce validation if a custom key is provided.
        if raw_key == "replace-with-a-secure-random-hex-key-for-fingerprinting":
            return v
        try:
            validate_fingerprint_key(raw_key)
        except (ValueError, TypeError) as err:
            raise ValueError(f"Invalid FINGERPRINT_KEY configuration: {err}") from None
        return v

    def validate_runtime_fingerprint_key(self) -> bytes:
        """Strict runtime extraction and verification of FINGERPRINT_KEY bytes.

        MUST be invoked before scanner processing or secret anchor computation begins.
        Raises ValueError if an unconfigured placeholder or weak key is active.
        """
        return validate_fingerprint_key(self.FINGERPRINT_KEY.get_secret_value())

    @model_validator(mode="after")
    def validate_production_invariants(self) -> Settings:
        """Enforce production security invariants (Threat T1, T3, T13)."""
        if self.APP_ENV == "production":
            # 1. Blueprint 11.8: Startup MUST fail if AI_DEBUG_LOG is true in production
            if self.AI_DEBUG_LOG:
                raise ValueError("Startup failure: AI_DEBUG_LOG must not be true in production")

            # 2. Strict FINGERPRINT_KEY verification
            try:
                self.validate_runtime_fingerprint_key()
            except ValueError as err:
                raise ValueError(
                    f"Production startup failure: FINGERPRINT_KEY is invalid: {err}"
                ) from None

            # 3. Production secret hygiene (minimum length, non-placeholder, character diversity)
            _validate_production_secret("SECRET_KEY", self.SECRET_KEY)
            _validate_production_secret("SESSION_SECRET", self.SESSION_SECRET)

            # 4. Fail-closed: unauthenticated scan submissions MUST NOT be enabled in production
            if self.ENABLE_DEV_UNAUTHENTICATED_SCANS:
                raise ValueError(
                    "Production startup failure: ENABLE_DEV_UNAUTHENTICATED_SCANS must not be true in production"
                )

        return self


_KNOWN_SECRET_PLACEHOLDERS: tuple[str, ...] = (
    "replace-with",
    "placeholder",
    "changeme",
    "example",
    "default-secret",
)


def _validate_production_secret(name: str, secret: SecretStr) -> None:
    """Validate that a production secret satisfies length, non-placeholder, and structural checks.

    Enforces minimum length of 32 characters, rejects whitespace-only or padded values,
    disallows known template/placeholder strings, and rejects trivially repetitive characters.
    Note: Static checks verify structural hygiene and known bad values; they do not claim
    to mathematically prove cryptographic randomness.
    """
    raw_val = secret.get_secret_value()
    if len(raw_val) < 32:
        raise ValueError(
            f"Production startup failure: {name} must have a minimum length of 32 characters"
        )
    if len(raw_val.strip()) < 32:
        raise ValueError(
            f"Production startup failure: {name} must not rely on whitespace padding to satisfy length"
        )

    lowered = raw_val.lower()
    for placeholder in _KNOWN_SECRET_PLACEHOLDERS:
        if placeholder in lowered:
            raise ValueError(
                f"Production startup failure: {name} contains known placeholder "
                f"pattern '{placeholder}' and must be explicitly configured"
            )

    if len(set(raw_val.strip())) < 8:
        raise ValueError(
            f"Production startup failure: {name} exhibits trivial repetition or "
            "insufficient character diversity"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retrieve cached application settings instance."""
    return Settings()
