"""Application configuration and environment settings.

Implements Blueprint Section 4 (Technology Stack) and Section 12 (Security Threat Model)
using type-safe Pydantic Settings with strict secret masking and production guards.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

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
    GITHUB_APP_PRIVATE_KEY: SecretStr | None = None
    GITHUB_APP_SLUG: str | None = None
    GITHUB_APP_INSTALL_CALLBACK_URL: str | None = None
    GITHUB_API_BASE_URL: str = "https://api.github.com"
    GITHUB_OAUTH_BASE_URL: str = "https://github.com"
    GITHUB_STATE_TTL_SEC: int = 600
    GITHUB_CLIENT_TIMEOUT_SEC: float = 15.0

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
    GITLEAKS_CONFIG_PATH: str = "./rules/gitleaks/default.toml"
    GITLEAKS_TRUSTED_CONFIG_DIR: str | None = None
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
    def validate_worker_heartbeat_settings(self) -> Settings:
        """Validate background worker queue lease and heartbeat settings."""
        if self.WORKER_JOB_LEASE_SEC <= 0:
            raise ValueError("WORKER_JOB_LEASE_SEC must be a positive integer")
        if self.WORKER_HEARTBEAT_SEC <= 0:
            raise ValueError("WORKER_HEARTBEAT_SEC must be a positive integer")
        if self.WORKER_HEARTBEAT_SEC >= self.WORKER_JOB_LEASE_SEC:
            raise ValueError(
                f"WORKER_HEARTBEAT_SEC ({self.WORKER_HEARTBEAT_SEC}) must be strictly less "
                f"than WORKER_JOB_LEASE_SEC ({self.WORKER_JOB_LEASE_SEC})"
            )
        return self

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

            # 5. Production must pin GITLEAKS_PATH to an explicit absolute executable path
            gitleaks_path = self.GITLEAKS_PATH.strip()
            if (
                not gitleaks_path
                or "\x00" in gitleaks_path
                or "://" in gitleaks_path
                or gitleaks_path.startswith(("//", "\\\\"))
                or not Path(gitleaks_path).is_absolute()
            ):
                raise ValueError(
                    "Production startup failure: GITLEAKS_PATH must be an explicit absolute path in production"
                )

            # 6. Validate configured GitHub webhook/app/OAuth secrets in production
            if self.GITHUB_WEBHOOK_SECRET is not None:
                _validate_production_secret("GITHUB_WEBHOOK_SECRET", self.GITHUB_WEBHOOK_SECRET)
            if self.GITHUB_CLIENT_SECRET is not None:
                _validate_production_secret("GITHUB_CLIENT_SECRET", self.GITHUB_CLIENT_SECRET)

            has_explicit_key_path = (
                "GITHUB_APP_PRIVATE_KEY_PATH" in self.model_fields_set
                and self.GITHUB_APP_PRIVATE_KEY_PATH is not None
                and bool(self.GITHUB_APP_PRIVATE_KEY_PATH.strip())
            )
            has_any_github_config = (
                self.GITHUB_APP_ID is not None
                or self.GITHUB_CLIENT_ID is not None
                or self.GITHUB_CLIENT_SECRET is not None
                or self.GITHUB_APP_PRIVATE_KEY is not None
                or has_explicit_key_path
                or self.GITHUB_APP_SLUG is not None
                or self.GITHUB_WEBHOOK_SECRET is not None
            )
            if has_any_github_config:
                if self.GITHUB_APP_ID is None:
                    raise ValueError(
                        "Production startup failure: GITHUB_APP_ID is required when GitHub App private key or integration settings are configured"
                    )
                pem_text = self.get_github_private_key_pem()
                if pem_text is None:
                    raise ValueError(
                        "Production startup failure: A valid GitHub App private key (GITHUB_APP_PRIVATE_KEY or readable GITHUB_APP_PRIVATE_KEY_PATH) is required when GITHUB_APP_ID is set"
                    )
                try:
                    _parse_github_pem(pem_text)
                except ValueError as exc:
                    raise ValueError(
                        f"Production startup failure: Configured GitHub App private key is unusable: {exc}"
                    ) from exc
                if self.GITHUB_WEBHOOK_SECRET is None:
                    raise ValueError(
                        "Production startup failure: GITHUB_WEBHOOK_SECRET is required when GitHub App integration is enabled"
                    )
                if not self.GITHUB_APP_SLUG:
                    raise ValueError(
                        "Production startup failure: GITHUB_APP_SLUG is required when GitHub App integration is enabled"
                    )

        return self

    @model_validator(mode="after")
    def validate_github_settings(self) -> Settings:
        """Validate GitHub App configuration boundaries and secret hygiene."""
        if self.GITHUB_APP_ID is not None and self.GITHUB_APP_ID <= 0:
            raise ValueError("GITHUB_APP_ID must be a positive integer")

        if (
            isinstance(self.GITHUB_STATE_TTL_SEC, bool)
            or self.GITHUB_STATE_TTL_SEC <= 0
            or self.GITHUB_STATE_TTL_SEC > 3600
        ):
            raise ValueError("GITHUB_STATE_TTL_SEC must be between 1 and 3600 seconds")

        if isinstance(self.GITHUB_CLIENT_TIMEOUT_SEC, bool) or self.GITHUB_CLIENT_TIMEOUT_SEC <= 0:
            raise ValueError("GITHUB_CLIENT_TIMEOUT_SEC must be a positive number")

        for secret_name, secret_val in (
            ("GITHUB_WEBHOOK_SECRET", self.GITHUB_WEBHOOK_SECRET),
            ("GITHUB_CLIENT_SECRET", self.GITHUB_CLIENT_SECRET),
            ("GITHUB_APP_PRIVATE_KEY", self.GITHUB_APP_PRIVATE_KEY),
        ):
            if secret_val is not None and not secret_val.get_secret_value().strip():
                raise ValueError(f"{secret_name} cannot be empty or whitespace-only")

        if self.GITHUB_APP_PRIVATE_KEY is not None:
            raw_pem = self.GITHUB_APP_PRIVATE_KEY.get_secret_value().replace("\\n", "\n").strip()
            try:
                _parse_github_pem(raw_pem)
            except ValueError as exc:
                raise ValueError(f"GITHUB_APP_PRIVATE_KEY is invalid: {exc}") from exc

        if self.GITHUB_CLIENT_ID is not None:
            cleaned_client_id = self.GITHUB_CLIENT_ID.strip()
            if not cleaned_client_id or any(
                ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned_client_id
            ):
                raise ValueError("GITHUB_CLIENT_ID cannot be empty or contain whitespace")
            self.GITHUB_CLIENT_ID = cleaned_client_id

        if (self.GITHUB_CLIENT_ID is not None) != (self.GITHUB_CLIENT_SECRET is not None):
            raise ValueError(
                "GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must both be set when configuring GitHub OAuth"
            )

        if self.GITHUB_APP_SLUG is not None:
            slug = self.GITHUB_APP_SLUG.strip()
            if not slug or not _RE_GITHUB_SLUG.match(slug):
                raise ValueError(
                    "GITHUB_APP_SLUG must contain only alphanumeric characters and hyphens"
                )
            self.GITHUB_APP_SLUG = slug

        require_https = self.APP_ENV == "production"
        allowed_schemes = {"https"} if require_https else {"https", "http"}
        self.GITHUB_API_BASE_URL = validate_github_base_url(
            self.GITHUB_API_BASE_URL, name="GITHUB_API_BASE_URL", require_https=require_https
        )
        self.GITHUB_OAUTH_BASE_URL = validate_github_base_url(
            self.GITHUB_OAUTH_BASE_URL, name="GITHUB_OAUTH_BASE_URL", require_https=require_https
        )

        if self.GITHUB_APP_INSTALL_CALLBACK_URL is not None:
            callback_url = self.GITHUB_APP_INSTALL_CALLBACK_URL.strip()
            parsed_cb = urlparse(callback_url)
            if (
                not callback_url
                or parsed_cb.scheme not in allowed_schemes
                or not parsed_cb.netloc
                or parsed_cb.username is not None
                or parsed_cb.password is not None
                or parsed_cb.fragment
                or any(ch.isspace() for ch in callback_url)
            ):
                raise ValueError(
                    "GITHUB_APP_INSTALL_CALLBACK_URL must be a valid HTTP(S) URL without credentials or whitespace"
                )
            self.GITHUB_APP_INSTALL_CALLBACK_URL = callback_url

        return self

    def get_github_private_key_pem(self) -> str | None:
        """Resolve configured GitHub App PEM private key from inline secret or readable file path."""
        if self.GITHUB_APP_PRIVATE_KEY is not None:
            raw = self.GITHUB_APP_PRIVATE_KEY.get_secret_value().replace("\\n", "\n").strip()
            if raw:
                return raw

        if self.GITHUB_APP_PRIVATE_KEY_PATH is not None:
            cleaned_path = self.GITHUB_APP_PRIVATE_KEY_PATH.strip()
            if cleaned_path and "\x00" not in cleaned_path:
                key_file = Path(cleaned_path)
                try:
                    if key_file.is_file() and key_file.stat().st_size <= 65_536:
                        content = key_file.read_text(encoding="utf-8").strip()
                        if content:
                            return content
                except (OSError, UnicodeDecodeError):
                    return None

        return None

    def is_github_app_configured(self) -> bool:
        """Return True when GitHub App ID and a valid parseable RSA PEM key are configured."""
        if self.GITHUB_APP_ID is None:
            return False
        pem_text = self.get_github_private_key_pem()
        if not pem_text:
            return False
        try:
            _parse_github_pem(pem_text)
        except ValueError:
            return False
        return True

    def has_partial_github_config(self) -> bool:
        """Return True when any GitHub setting is explicitly supplied."""
        has_explicit_key_path = (
            "GITHUB_APP_PRIVATE_KEY_PATH" in self.model_fields_set
            and self.GITHUB_APP_PRIVATE_KEY_PATH is not None
            and bool(self.GITHUB_APP_PRIVATE_KEY_PATH.strip())
        )
        return (
            self.GITHUB_APP_ID is not None
            or self.GITHUB_CLIENT_ID is not None
            or self.GITHUB_CLIENT_SECRET is not None
            or self.GITHUB_APP_PRIVATE_KEY is not None
            or has_explicit_key_path
            or self.GITHUB_APP_SLUG is not None
            or self.GITHUB_WEBHOOK_SECRET is not None
        )

    def is_github_oauth_configured(self) -> bool:
        """Return True when GitHub App OAuth client ID and secret are both configured."""
        return (
            self.GITHUB_CLIENT_ID is not None
            and bool(self.GITHUB_CLIENT_ID.strip())
            and self.GITHUB_CLIENT_SECRET is not None
            and bool(self.GITHUB_CLIENT_SECRET.get_secret_value().strip())
        )

    def is_github_webhook_configured(self) -> bool:
        """Return True when a non-empty GitHub webhook secret is configured."""
        return self.GITHUB_WEBHOOK_SECRET is not None and bool(
            self.GITHUB_WEBHOOK_SECRET.get_secret_value().strip()
        )

    def is_github_configured(self) -> bool:
        """Return True when both GitHub App API authentication and webhook secret are configured."""
        return self.is_github_app_configured() and self.is_github_webhook_configured()

    def get_github_install_base_url(self) -> str | None:
        """Return GitHub App public installation URL when slug is configured."""
        if not self.GITHUB_APP_SLUG:
            return None
        return f"{self.GITHUB_OAUTH_BASE_URL}/apps/{self.GITHUB_APP_SLUG}/installations/new"


def validate_github_base_url(raw_url: str, *, name: str, require_https: bool = False) -> str:
    """Validate a GitHub API/OAuth base URL without credentials, query strings, fragments, or whitespace."""
    if not isinstance(raw_url, str):
        raise TypeError(f"{name} must be a URL string")

    cleaned = raw_url.strip()
    if (
        not cleaned
        or "\\" in cleaned
        or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned)
    ):
        raise ValueError(f"{name} must be a valid URL without whitespace or control characters")

    parsed = urlparse(cleaned)
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} contains an invalid port") from exc

    allowed_schemes = {"https"} if require_https else {"https", "http"}
    segments = [seg for seg in parsed.path.split("/") if seg]
    if (
        parsed.scheme.lower() not in allowed_schemes
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(seg in (".", "..") for seg in segments)
    ):
        scheme_label = "an HTTPS" if require_https else "a valid HTTP(S)"
        raise ValueError(
            f"{name} must be {scheme_label} URL without credentials, query parameters, or fragments"
        )
    return cleaned.rstrip("/")


_RE_GITHUB_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")


_KNOWN_SECRET_PLACEHOLDERS: tuple[str, ...] = (
    "replace-with",
    "placeholder",
    "changeme",
    "example",
    "default-secret",
)


def _parse_github_pem(pem_text: str) -> None:
    """Validate an RSA PEM key lazily to avoid a top-level import cycle with app.services."""
    from app.services.github_crypto import GitHubKeyError, parse_rsa_private_key_pem

    try:
        parse_rsa_private_key_pem(pem_text)
    except GitHubKeyError as exc:
        raise ValueError(str(exc)) from exc


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
