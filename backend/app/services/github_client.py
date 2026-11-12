"""Authenticated GitHub App REST API client with short-lived token caching and retries.

Implements:
- GitHub App RS256 JWT generation from PEM private key
- Thread-safe, memory-only short-lived installation access token caching and refresh
- Safe pagination (`Link` next URL validation preventing SSRF/cross-origin token leakage)
- Rate-limit, permission, not-found, and bounded transient retry/backoff classification
- Redaction of all tokens, JWTs, and private keys from logs and exceptions
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Self
from urllib.parse import quote, urlencode, urlparse

import httpx

from app.core.config import Settings, get_settings, validate_github_base_url
from app.domain.paths import normalize_and_validate_path
from app.services.github_crypto import (
    GitHubKeyError,
    RSAPrivateKey,
    create_github_app_jwt,
    parse_rsa_private_key_pem,
)

logger = logging.getLogger("sentinel.github.client")

DEFAULT_GITHUB_API_VERSION = "2022-11-28"
DEFAULT_PER_PAGE = 100
DEFAULT_MAX_PAGES = 100
DEFAULT_MAX_API_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_ERROR_RESPONSE_BYTES = 64 * 1024
TOKEN_REFRESH_MARGIN = timedelta(seconds=60)
DEFAULT_TOKEN_TTL = timedelta(minutes=55)

_RE_GITHUB_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_RE_GITHUB_REF = re.compile(r"^[^\x00-\x1f\x7f\s?#\\]+$")
_RE_LINK_NEXT = re.compile(
    r'<([^>]+)>\s*;\s*[^,]*\brel=(?:"[^"]*\bnext\b[^"]*"|next(?=[;\s,]|$))',
    re.IGNORECASE,
)
_RE_REDACT_SECRETS = re.compile(
    r"(?:"
    r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
    r"|\beyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\b"
    r"|\b(?:ghs|ghu|ghr|ghp|gho)_[A-Za-z0-9_]{10,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{10,}\b"
    r"|\b(?:client_secret|access_token|refresh_token)\s*[:=]\s*['\"]?[^\s'\",;&}]+"
    r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)"
    r")",
    re.IGNORECASE,
)


def redact_github_secrets(text: str | None) -> str:
    """Strip GitHub tokens, JWTs, and PEM material from error strings."""
    if not text:
        return ""
    return _RE_REDACT_SECRETS.sub("[REDACTED_GITHUB_SECRET]", text)


class GitHubClientError(Exception):
    """Base error for GitHub App API operations."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retryable: bool = False,
        error_code: str = "GITHUB_API_ERROR",
    ) -> None:
        super().__init__(redact_github_secrets(message))
        self.status_code = status_code
        self.retryable = retryable
        self.error_code = error_code


class GitHubConfigurationError(GitHubClientError):
    """Raised when GitHub App credentials or API base configuration are missing or invalid."""

    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            status_code=None,
            retryable=False,
            error_code="GITHUB_CONFIGURATION_ERROR",
        )


class GitHubAuthenticationError(GitHubClientError):
    """Raised on 401 authentication failures with GitHub App JWT or installation tokens."""

    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            status_code=401,
            retryable=False,
            error_code="GITHUB_AUTHENTICATION_ERROR",
        )


class GitHubPermissionError(GitHubClientError):
    """Raised on non-rate-limit 403 permission failures."""

    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            status_code=403,
            retryable=False,
            error_code="GITHUB_PERMISSION_ERROR",
        )


class GitHubNotFoundError(GitHubClientError):
    """Raised on 404/410 missing installation, repository, pull request, or file errors."""

    def __init__(self, message: str, *, status_code: int = 404) -> None:
        super().__init__(
            message,
            status_code=status_code,
            retryable=False,
            error_code="GITHUB_NOT_FOUND",
        )


class GitHubValidationError(GitHubClientError):
    """Raised on invalid local inputs or unexpected 4xx/malformed GitHub API responses."""

    def __init__(self, message: str, *, status_code: int | None = 422) -> None:
        super().__init__(
            message,
            status_code=status_code,
            retryable=False,
            error_code="GITHUB_VALIDATION_ERROR",
        )


class GitHubRateLimitError(GitHubClientError):
    """Raised when primary or secondary GitHub API rate limits are exhausted."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 429,
        retry_after_sec: int | None = None,
        reset_at: datetime | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            retryable=True,
            error_code="GITHUB_RATE_LIMIT",
        )
        self.retry_after_sec = retry_after_sec
        self.reset_at = reset_at


class GitHubTransientError(GitHubClientError):
    """Raised on 5xx responses, timeouts, or transient transport errors after bounded retries."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(
            message,
            status_code=status_code,
            retryable=True,
            error_code="GITHUB_TRANSIENT_ERROR",
        )


class _ResponseTooLargeError(GitHubValidationError):
    """Internal exception raised when streamed GitHub API response exceeds max_response_bytes."""


class GitHubOAuthError(GitHubClientError):
    """Raised when GitHub user OAuth code exchange is denied, expired, or rejected."""

    def __init__(self, message: str, *, status_code: int | None = 403) -> None:
        super().__init__(
            message,
            status_code=status_code,
            retryable=False,
            error_code="GITHUB_OAUTH_ERROR",
        )


@dataclass(frozen=True, slots=True)
class GitHubOAuthUser:
    """Verified GitHub user identity resolved via user-to-server OAuth token."""

    id: int
    login: str


@dataclass(frozen=True, slots=True)
class GitHubInstallationInfo:
    """Verified metadata returned by GET /app/installations/{installation_id}."""

    id: int
    account_login: str
    account_type: Literal["User", "Organization"]
    status: Literal["active", "suspended"]
    permissions: dict[str, str]
    repository_selection: str | None = None
    account_id: int | None = None


@dataclass(frozen=True, slots=True)
class GitHubRepositoryInfo:
    """Metadata for an accessible GitHub repository."""

    id: int
    name: str
    full_name: str
    default_branch: str
    private: bool
    archived: bool = False
    html_url: str | None = None


@dataclass(frozen=True, slots=True)
class GitHubPullRequestFile:
    """Changed file entry returned by GET /repos/{owner}/{repo}/pulls/{pr}/files."""

    filename: str
    status: str
    additions: int
    deletions: int
    changes: int
    sha: str | None = None
    previous_filename: str | None = None


@dataclass(frozen=True, slots=True)
class GitHubFileContent:
    """Result of fetching a single file blob from the GitHub Contents API."""

    path: str
    size: int
    sha: str | None
    content: bytes | None
    skip_reason: str | None = None


@dataclass(frozen=True, slots=True)
class _CachedInstallationToken:
    token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _BufferedResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes

    def json(self) -> Any:
        return json.loads(self.content.decode("utf-8"))


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _split_full_name(full_name: str) -> tuple[str, str]:
    cleaned = full_name.strip()
    parts = cleaned.split("/")
    if len(parts) != 2:
        raise GitHubValidationError(
            "Repository full_name must match 'owner/repo'", status_code=None
        )
    owner, repo = parts
    if (
        not owner
        or not repo
        or owner in (".", "..")
        or repo in (".", "..")
        or not _RE_GITHUB_NAME.match(owner)
        or not _RE_GITHUB_NAME.match(repo)
    ):
        raise GitHubValidationError("Invalid GitHub repository owner or name", status_code=None)
    return owner, repo


def _parse_iso_datetime(raw: str | None) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _extract_error_message(response: _BufferedResponse | httpx.Response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            msg = payload.get("message")
            if isinstance(msg, str) and msg.strip():
                return redact_github_secrets(msg.strip())
    except Exception:  # noqa: BLE001 - fall back to HTTP reason/status
        logger.debug("Non-JSON GitHub API error response (status=%s)", response.status_code)
    return f"HTTP {response.status_code}"


def _parse_retry_after(
    response: _BufferedResponse | httpx.Response, *, now: datetime
) -> tuple[int | None, datetime | None]:
    retry_after_raw = response.headers.get("Retry-After")
    retry_after_sec: int | None = None
    if retry_after_raw is not None:
        try:
            retry_after_sec = max(1, min(3600, int(float(retry_after_raw.strip()))))
        except ValueError:
            retry_after_sec = None

    reset_at: datetime | None = None
    reset_raw = response.headers.get("X-RateLimit-Reset")
    if reset_raw is not None:
        try:
            reset_ts = int(reset_raw.strip())
            reset_at = datetime.fromtimestamp(reset_ts, tz=UTC)
            if retry_after_sec is None:
                delta = int((reset_at - now).total_seconds())
                if delta > 0:
                    retry_after_sec = min(3600, delta)
        except (ValueError, OverflowError):
            reset_at = None

    return retry_after_sec, reset_at


def _parse_next_link(
    link_header: str | None,
    *,
    base_scheme: str,
    base_netloc: str,
    base_path_prefix: str,
    expected_rel_path: str | None = None,
) -> str | None:
    """Extract and SSRF-validate the RFC 8288 rel='next' URL from a Link header."""
    if not link_header:
        return None
    for part in link_header.split(","):
        match = _RE_LINK_NEXT.search(part.strip())
        if not match:
            continue
        candidate = match.group(1).strip()
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate) or "\\" in candidate:
            raise GitHubValidationError(
                "Pagination link contains invalid characters", status_code=None
            )
        parsed = urlparse(candidate)
        if parsed.scheme.lower() != base_scheme.lower():
            raise GitHubValidationError("Pagination link scheme mismatch", status_code=None)
        if parsed.netloc.lower() != base_netloc.lower():
            raise GitHubValidationError("Pagination link host mismatch", status_code=None)
        if parsed.username is not None or parsed.password is not None:
            raise GitHubValidationError(
                "Pagination link must not contain credentials", status_code=None
            )
        if parsed.fragment:
            raise GitHubValidationError(
                "Pagination link must not contain fragment", status_code=None
            )
        if base_path_prefix and not parsed.path.startswith(base_path_prefix):
            raise GitHubValidationError("Pagination link path prefix mismatch", status_code=None)
        rel_path = parsed.path[len(base_path_prefix) :] if base_path_prefix else parsed.path
        if not rel_path.startswith("/"):
            rel_path = "/" + rel_path
        segments = rel_path.split("/")
        if any(seg in (".", "..") for seg in segments):
            raise GitHubValidationError(
                "Pagination link must not contain path traversal segments", status_code=None
            )
        if expected_rel_path is not None and rel_path != expected_rel_path:
            raise GitHubValidationError("Pagination link target path mismatch", status_code=None)
        return f"{rel_path}?{parsed.query}" if parsed.query else rel_path
    return None


class GitHubAppClient:
    """Synchronous GitHub App REST API client for backend services and worker jobs."""

    def __init__(
        self,
        *,
        app_id: int,
        private_key: RSAPrivateKey,
        base_url: str = "https://api.github.com",
        oauth_base_url: str = "https://github.com",
        client_id: str | None = None,
        client_secret: str | None = None,
        oauth_redirect_uri: str | None = None,
        require_https: bool | None = None,
        timeout_sec: float = 15.0,
        max_retries: int = 2,
        max_pages: int = DEFAULT_MAX_PAGES,
        transport: httpx.BaseTransport | None = None,
        now_fn: Callable[[], datetime] = _utc_now,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if app_id <= 0:
            raise GitHubConfigurationError("GitHub App ID must be a positive integer")

        if require_https is None:
            env_app_env = os.environ.get("APP_ENV")
            if env_app_env is not None:
                enforce_https = env_app_env.strip().lower() == "production"
            else:
                try:
                    enforce_https = get_settings().APP_ENV == "production"
                except Exception:  # noqa: BLE001 - avoid masking unrelated settings errors
                    enforce_https = False
        else:
            enforce_https = require_https

        try:
            normalized_base = validate_github_base_url(
                base_url,
                name="GitHub API base URL",
                require_https=enforce_https,
            )
            normalized_oauth_base = validate_github_base_url(
                oauth_base_url,
                name="GitHub OAuth base URL",
                require_https=enforce_https,
            )
        except (ValueError, TypeError) as exc:
            raise GitHubConfigurationError(str(exc)) from exc

        parsed_base = urlparse(normalized_base)

        self.app_id = app_id
        self._private_key = private_key
        self.base_url = normalized_base
        self._oauth_base_url = normalized_oauth_base
        self._client_id = client_id.strip() if client_id and client_id.strip() else None
        self._client_secret = (
            client_secret.strip() if client_secret and client_secret.strip() else None
        )
        self._oauth_redirect_uri = (
            oauth_redirect_uri.strip()
            if oauth_redirect_uri and oauth_redirect_uri.strip()
            else None
        )
        self._base_scheme = parsed_base.scheme
        self._base_netloc = parsed_base.netloc
        self._base_path_prefix = parsed_base.path.rstrip("/")
        self.max_retries = max(0, max_retries)
        self.max_pages = max(1, max_pages)
        self._now_fn = now_fn
        self._sleep_fn = sleep_fn

        self._token_lock = threading.Lock()
        self._token_cache: dict[int, _CachedInstallationToken] = {}
        self._refresh_locks: dict[int, threading.Lock] = {}

        client_kwargs: dict[str, Any] = {
            "base_url": normalized_base,
            "timeout": httpx.Timeout(timeout_sec),
            "follow_redirects": False,
            "headers": {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": DEFAULT_GITHUB_API_VERSION,
                "User-Agent": "Sentinel-GitHubApp/1.0",
            },
        }
        if transport is not None:
            client_kwargs["transport"] = transport
        self._client = httpx.Client(**client_kwargs)

    def __repr__(self) -> str:
        return f"GitHubAppClient(app_id={self.app_id!r}, base_url={self.base_url!r})"

    __str__ = __repr__

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
        now_fn: Callable[[], datetime] = _utc_now,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> GitHubAppClient:
        """Construct a configured GitHubAppClient from validated application Settings."""
        if settings.GITHUB_APP_ID is None:
            raise GitHubConfigurationError("GITHUB_APP_ID is not configured")

        pem_text = settings.get_github_private_key_pem()
        if not pem_text:
            raise GitHubConfigurationError("GitHub App private key is not configured or unreadable")

        try:
            private_key = parse_rsa_private_key_pem(pem_text)
        except GitHubKeyError as exc:
            raise GitHubConfigurationError(f"Invalid GitHub App private key: {exc}") from exc

        return cls(
            app_id=settings.GITHUB_APP_ID,
            private_key=private_key,
            base_url=settings.GITHUB_API_BASE_URL,
            oauth_base_url=settings.GITHUB_OAUTH_BASE_URL,
            client_id=settings.GITHUB_CLIENT_ID,
            client_secret=(
                settings.GITHUB_CLIENT_SECRET.get_secret_value()
                if settings.GITHUB_CLIENT_SECRET is not None
                else None
            ),
            oauth_redirect_uri=settings.GITHUB_APP_INSTALL_CALLBACK_URL,
            require_https=(settings.APP_ENV == "production"),
            timeout_sec=settings.GITHUB_CLIENT_TIMEOUT_SEC,
            transport=transport,
            now_fn=now_fn,
            sleep_fn=sleep_fn,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def clear_token_cache(self, installation_id: int | None = None) -> None:
        """Clear cached in-memory installation token(s)."""
        with self._token_lock:
            if installation_id is None:
                self._token_cache.clear()
            else:
                self._token_cache.pop(installation_id, None)

    def _get_refresh_lock(self, installation_id: int) -> threading.Lock:
        with self._token_lock:
            lock = self._refresh_locks.get(installation_id)
            if lock is None:
                lock = threading.Lock()
                self._refresh_locks[installation_id] = lock
            return lock

    def _invalidate_installation_token(self, installation_id: int, failed_token: str) -> None:
        """Evict cached token only if it matches the exact token rejected with 401."""
        with self._token_lock:
            cached = self._token_cache.get(installation_id)
            if cached is not None and cached.token == failed_token:
                self._token_cache.pop(installation_id, None)

    def _create_app_jwt(self) -> str:
        now_ts = int(self._now_fn().timestamp())
        return create_github_app_jwt(self.app_id, self._private_key, now=now_ts)

    def _read_bounded_response(
        self,
        response: httpx.Response,
        *,
        max_bytes: int,
    ) -> _BufferedResponse:
        effective_limit = (
            min(max_bytes, MAX_ERROR_RESPONSE_BYTES) if response.status_code >= 400 else max_bytes
        )
        content_len_raw = response.headers.get("Content-Length")
        if content_len_raw is not None:
            try:
                if int(content_len_raw.strip()) > effective_limit:
                    raise _ResponseTooLargeError(
                        "GitHub API response Content-Length exceeds safety limit",
                        status_code=response.status_code,
                    )
            except ValueError:
                pass

        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            if not chunk:
                continue
            total += len(chunk)
            if total > effective_limit:
                raise _ResponseTooLargeError(
                    "GitHub API response body exceeds safety limit",
                    status_code=response.status_code,
                )
            chunks.append(chunk)

        return _BufferedResponse(
            status_code=response.status_code,
            headers=response.headers,
            content=b"".join(chunks),
        )

    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        token_provider: Callable[[], str],
        on_unauthorized: Callable[[str], None] | None = None,
        allow_404_return_none: bool = False,
        max_response_bytes: int = DEFAULT_MAX_API_RESPONSE_BYTES,
    ) -> _BufferedResponse | None:
        """Execute HTTP request with bounded streaming, transient retry, and single-shot 401 refresh."""
        refreshed_on_401 = False
        attempt = 0

        while True:
            bearer = token_provider()
            headers = {"Authorization": f"Bearer {bearer}"}

            try:
                with self._client.stream(method, url, headers=headers) as stream_resp:
                    response = self._read_bounded_response(
                        stream_resp, max_bytes=max_response_bytes
                    )
            except _ResponseTooLargeError:
                raise
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt < self.max_retries:
                    backoff = min(2.0, 0.5 * (2**attempt))
                    attempt += 1
                    self._sleep_fn(backoff)
                    continue
                raise GitHubTransientError(
                    f"GitHub API transport error during {method} {url}: {exc}"
                ) from exc

            code = response.status_code
            if 200 <= code < 300:
                return response

            if allow_404_return_none and code in (404, 410):
                return None

            if code == 401:
                if on_unauthorized is not None and not refreshed_on_401:
                    refreshed_on_401 = True
                    on_unauthorized(bearer)
                    continue
                raise GitHubAuthenticationError(
                    f"GitHub API authentication failed ({code}): {_extract_error_message(response)}"
                )

            if code == 403 or code == 429:
                msg = _extract_error_message(response)
                remaining = response.headers.get("X-RateLimit-Remaining")
                has_retry_after = "Retry-After" in response.headers
                is_rate_limit = (
                    code == 429
                    or remaining == "0"
                    or has_retry_after
                    or "rate limit" in msg.lower()
                    or "secondary rate limit" in msg.lower()
                )
                if is_rate_limit:
                    retry_after_sec, reset_at = _parse_retry_after(response, now=self._now_fn())
                    if (
                        retry_after_sec is not None
                        and retry_after_sec <= 2
                        and attempt < self.max_retries
                    ):
                        attempt += 1
                        self._sleep_fn(float(retry_after_sec))
                        continue
                    raise GitHubRateLimitError(
                        f"GitHub API rate limit exceeded: {msg}",
                        status_code=code,
                        retry_after_sec=retry_after_sec,
                        reset_at=reset_at,
                    )
                raise GitHubPermissionError(f"GitHub API permission denied: {msg}")

            if code in (404, 410):
                raise GitHubNotFoundError(
                    f"GitHub resource not found: {_extract_error_message(response)}",
                    status_code=code,
                )

            if code == 422:
                raise GitHubValidationError(
                    f"GitHub API rejected request: {_extract_error_message(response)}",
                    status_code=422,
                )

            if code in (500, 502, 503, 504):
                if attempt < self.max_retries:
                    backoff = min(2.0, 0.5 * (2**attempt))
                    attempt += 1
                    self._sleep_fn(backoff)
                    continue
                raise GitHubTransientError(
                    f"GitHub API server error ({code}): {_extract_error_message(response)}",
                    status_code=code,
                )

            if 300 <= code < 400:
                raise GitHubClientError(
                    f"Unexpected redirect ({code}) returned by GitHub API",
                    status_code=code,
                    retryable=False,
                )

            raise GitHubClientError(
                f"GitHub API error ({code}): {_extract_error_message(response)}",
                status_code=code,
                retryable=False,
            )

    def get_installation_token(self, installation_id: int, *, force_refresh: bool = False) -> str:
        """Obtain a short-lived installation token, serialized per installation on refresh."""
        if isinstance(installation_id, bool) or installation_id <= 0:
            raise GitHubValidationError("installation_id must be positive", status_code=None)

        now = self._now_fn()
        if not force_refresh:
            with self._token_lock:
                cached = self._token_cache.get(installation_id)
                if cached is not None and cached.expires_at - now > TOKEN_REFRESH_MARGIN:
                    return cached.token

        refresh_lock = self._get_refresh_lock(installation_id)
        with refresh_lock:
            now = self._now_fn()
            if not force_refresh:
                with self._token_lock:
                    cached = self._token_cache.get(installation_id)
                    if cached is not None and cached.expires_at - now > TOKEN_REFRESH_MARGIN:
                        return cached.token

            response = self._request_with_retry(
                "POST",
                f"/app/installations/{installation_id}/access_tokens",
                token_provider=self._create_app_jwt,
                max_response_bytes=MAX_ERROR_RESPONSE_BYTES,
            )
            assert response is not None
            try:
                data = response.json()
            except Exception as exc:
                raise GitHubClientError("Malformed JSON in installation token response") from exc

            if not isinstance(data, dict):
                raise GitHubClientError("Unexpected installation token response structure")

            token = data.get("token")
            if not isinstance(token, str) or not token.strip():
                raise GitHubClientError(
                    "GitHub access token response did not contain a valid token"
                )

            expires_at = _parse_iso_datetime(data.get("expires_at"))
            if expires_at is None:
                expires_at = now + DEFAULT_TOKEN_TTL

            with self._token_lock:
                self._token_cache[installation_id] = _CachedInstallationToken(
                    token=token.strip(),
                    expires_at=expires_at,
                )
                return self._token_cache[installation_id].token

    def _installation_get(self, installation_id: int, url: str) -> _BufferedResponse:
        resp = self._request_with_retry(
            "GET",
            url,
            token_provider=lambda: self.get_installation_token(installation_id),
            on_unauthorized=lambda used_tok: self._invalidate_installation_token(
                installation_id, used_tok
            ),
        )
        assert resp is not None
        return resp

    def _parse_installation_dict(self, data: Any) -> GitHubInstallationInfo:
        if not isinstance(data, dict):
            raise GitHubClientError("Unexpected installation metadata response structure")

        raw_id = data.get("id")
        if isinstance(raw_id, bool) or not isinstance(raw_id, int) or raw_id <= 0:
            raise GitHubClientError("Installation metadata missing valid numeric 'id'")

        account = data.get("account")
        if not isinstance(account, dict):
            raise GitHubClientError("Installation metadata missing 'account' object")

        login = account.get("login")
        account_type = account.get("type")
        raw_acct_id = account.get("id")
        account_id = (
            raw_acct_id
            if isinstance(raw_acct_id, int)
            and not isinstance(raw_acct_id, bool)
            and raw_acct_id > 0
            else None
        )
        if not isinstance(login, str) or not login.strip():
            raise GitHubClientError("Installation metadata missing 'account.login'")
        if account_type not in ("User", "Organization"):
            raise GitHubClientError(f"Unsupported installation account type: {account_type!r}")

        raw_perms = data.get("permissions")
        permissions: dict[str, str] = {}
        if isinstance(raw_perms, dict):
            for k, v in raw_perms.items():
                if isinstance(k, str) and isinstance(v, str):
                    permissions[k] = v

        suspended_at = data.get("suspended_at")
        status_val: Literal["active", "suspended"] = (
            "suspended" if suspended_at is not None else "active"
        )

        repo_selection = data.get("repository_selection")
        return GitHubInstallationInfo(
            id=raw_id,
            account_login=login.strip(),
            account_type=account_type,
            status=status_val,
            permissions=permissions,
            repository_selection=repo_selection if isinstance(repo_selection, str) else None,
            account_id=account_id,
        )

    def get_installation(self, installation_id: int) -> GitHubInstallationInfo:
        """Fetch verified installation metadata using GitHub App JWT authentication."""
        if installation_id <= 0:
            raise GitHubValidationError("installation_id must be positive", status_code=None)

        response = self._request_with_retry(
            "GET",
            f"/app/installations/{installation_id}",
            token_provider=self._create_app_jwt,
        )
        assert response is not None
        try:
            data = response.json()
        except Exception as exc:
            raise GitHubClientError("Malformed JSON in installation metadata response") from exc

        return self._parse_installation_dict(data)

    def exchange_oauth_code(self, code: str) -> str:
        """Exchange a single-use GitHub OAuth authorization code for a user access token."""
        if not self._client_id or not self._client_secret:
            raise GitHubConfigurationError(
                "GitHub OAuth client credentials (GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET) are not configured"
            )

        cleaned_code = code.strip()
        if (
            not cleaned_code
            or len(cleaned_code) > 512
            or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned_code)
        ):
            raise GitHubOAuthError("Invalid GitHub OAuth authorization code", status_code=403)

        form_fields: dict[str, str] = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": cleaned_code,
        }
        if self._oauth_redirect_uri:
            form_fields["redirect_uri"] = self._oauth_redirect_uri

        body_bytes = urlencode(form_fields).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        token_url = f"{self._oauth_base_url}/login/oauth/access_token"

        try:
            with self._client.stream(
                "POST", token_url, content=body_bytes, headers=headers
            ) as resp:
                response = self._read_bounded_response(resp, max_bytes=MAX_ERROR_RESPONSE_BYTES)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise GitHubTransientError(
                f"GitHub OAuth token exchange transport error: {exc}"
            ) from exc

        if response.status_code == 429:
            retry_after_sec, reset_at = _parse_retry_after(response, now=self._now_fn())
            raise GitHubRateLimitError(
                "GitHub OAuth token exchange rate limit exceeded",
                status_code=429,
                retry_after_sec=retry_after_sec,
                reset_at=reset_at,
            )
        if response.status_code >= 500:
            raise GitHubTransientError(
                f"GitHub OAuth token exchange upstream error ({response.status_code})",
                status_code=response.status_code,
            )
        if response.status_code in (401, 403):
            raise GitHubOAuthError("GitHub OAuth token exchange was rejected", status_code=403)
        if not (200 <= response.status_code < 300):
            raise GitHubOAuthError(
                f"GitHub OAuth token exchange failed ({response.status_code})",
                status_code=403,
            )

        try:
            data = response.json()
        except Exception as exc:
            raise GitHubClientError("Malformed JSON in GitHub OAuth token response") from exc

        if not isinstance(data, dict):
            raise GitHubClientError("Unexpected GitHub OAuth token response structure")

        oauth_error = data.get("error")
        if isinstance(oauth_error, str) and oauth_error.strip():
            err_slug = oauth_error.strip().lower()
            if err_slug in ("incorrect_client_credentials", "application_suspended"):
                raise GitHubConfigurationError("GitHub OAuth client credentials were rejected")
            if err_slug == "redirect_uri_mismatch":
                raise GitHubOAuthError(
                    "GitHub OAuth callback redirect URI mismatch",
                    status_code=403,
                )
            raise GitHubOAuthError(
                "GitHub OAuth authorization code is invalid, expired, or denied",
                status_code=403,
            )

        access_token = data.get("access_token")
        if (
            not isinstance(access_token, str)
            or not access_token.strip()
            or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in access_token.strip())
        ):
            raise GitHubOAuthError("GitHub OAuth response did not include a valid access token")

        token_type = data.get("token_type")
        if token_type is not None and (
            not isinstance(token_type, str) or token_type.strip().lower() != "bearer"
        ):
            raise GitHubOAuthError("Unsupported token_type in GitHub OAuth response")

        return access_token.strip()

    def get_oauth_user(self, user_access_token: str) -> GitHubOAuthUser:
        """Fetch authenticated GitHub user identity using a user-to-server OAuth token."""
        cleaned_token = user_access_token.strip()
        if not cleaned_token or any(ch.isspace() for ch in cleaned_token):
            raise GitHubOAuthError("Invalid user access token", status_code=403)

        response = self._request_with_retry(
            "GET",
            "/user",
            token_provider=lambda: cleaned_token,
            max_response_bytes=1024 * 1024,
        )
        assert response is not None
        try:
            data = response.json()
        except Exception as exc:
            raise GitHubClientError("Malformed JSON in GitHub user response") from exc

        if not isinstance(data, dict):
            raise GitHubClientError("Unexpected GitHub user response structure")

        user_id = data.get("id")
        login = data.get("login")
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
            raise GitHubClientError("GitHub user response missing valid numeric 'id'")
        if not isinstance(login, str) or not login.strip():
            raise GitHubClientError("GitHub user response missing 'login'")

        return GitHubOAuthUser(id=user_id, login=login.strip())

    def list_user_installations(self, user_access_token: str) -> list[GitHubInstallationInfo]:
        """List GitHub App installations accessible to the authenticated OAuth user."""
        cleaned_token = user_access_token.strip()
        if not cleaned_token or any(ch.isspace() for ch in cleaned_token):
            raise GitHubOAuthError("Invalid user access token", status_code=403)

        installations: list[GitHubInstallationInfo] = []
        next_url: str | None = f"/user/installations?per_page={DEFAULT_PER_PAGE}"

        for _ in range(self.max_pages):
            if next_url is None:
                break
            response = self._request_with_retry(
                "GET",
                next_url,
                token_provider=lambda: cleaned_token,
            )
            assert response is not None
            try:
                data = response.json()
            except Exception as exc:
                raise GitHubClientError("Malformed JSON in user installations response") from exc

            if not isinstance(data, dict) or not isinstance(data.get("installations"), list):
                raise GitHubClientError("Unexpected user installations response structure")

            for item in data["installations"]:
                installations.append(self._parse_installation_dict(item))

            next_url = _parse_next_link(
                response.headers.get("Link"),
                base_scheme=self._base_scheme,
                base_netloc=self._base_netloc,
                base_path_prefix=self._base_path_prefix,
                expected_rel_path="/user/installations",
            )
        else:
            if next_url is not None:
                raise GitHubClientError(
                    "GitHub user installations pagination exceeded maximum page limit"
                )

        return installations

    def _parse_repository(self, item: Any) -> GitHubRepositoryInfo:
        if not isinstance(item, dict):
            raise GitHubClientError("Malformed repository object in GitHub API response")

        repo_id = item.get("id")
        name = item.get("name")
        full_name = item.get("full_name")
        default_branch = item.get("default_branch") or "main"
        private = item.get("private", False)
        archived = item.get("archived", False)
        html_url = item.get("html_url")

        if isinstance(repo_id, bool) or not isinstance(repo_id, int) or repo_id <= 0:
            raise GitHubClientError("Repository payload missing valid numeric 'id'")
        if not isinstance(name, str) or not name.strip():
            raise GitHubClientError("Repository payload missing 'name'")
        if not isinstance(full_name, str) or "/" not in full_name:
            raise GitHubClientError("Repository payload missing valid 'full_name'")
        if not isinstance(default_branch, str) or not default_branch.strip():
            default_branch = "main"

        return GitHubRepositoryInfo(
            id=repo_id,
            name=name.strip(),
            full_name=full_name.strip(),
            default_branch=default_branch.strip(),
            private=bool(private),
            archived=bool(archived),
            html_url=html_url.strip() if isinstance(html_url, str) and html_url.strip() else None,
        )

    def list_installation_repositories(self, installation_id: int) -> list[GitHubRepositoryInfo]:
        """List all repositories accessible to the installation across paginated responses."""
        repositories: list[GitHubRepositoryInfo] = []
        next_url: str | None = f"/installation/repositories?per_page={DEFAULT_PER_PAGE}"

        for _ in range(self.max_pages):
            if next_url is None:
                break
            response = self._installation_get(installation_id, next_url)
            try:
                data = response.json()
            except Exception as exc:
                raise GitHubClientError(
                    "Malformed JSON in installation repositories response"
                ) from exc

            if not isinstance(data, dict) or not isinstance(data.get("repositories"), list):
                raise GitHubClientError("Unexpected installation repositories response structure")

            for raw_repo in data["repositories"]:
                repositories.append(self._parse_repository(raw_repo))

            next_url = _parse_next_link(
                response.headers.get("Link"),
                base_scheme=self._base_scheme,
                base_netloc=self._base_netloc,
                base_path_prefix=self._base_path_prefix,
                expected_rel_path="/installation/repositories",
            )
        else:
            if next_url is not None:
                raise GitHubClientError("GitHub repository pagination exceeded maximum page limit")

        return repositories

    def list_pull_request_files(
        self,
        installation_id: int,
        full_name: str,
        pr_number: int,
    ) -> list[GitHubPullRequestFile]:
        """List changed files in a pull request across paginated GitHub API responses."""
        if isinstance(pr_number, bool) or pr_number <= 0:
            raise GitHubValidationError("pr_number must be a positive integer", status_code=None)
        owner, repo = _split_full_name(full_name)
        pr_files_path = (
            f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/pulls/{pr_number}/files"
        )

        files: list[GitHubPullRequestFile] = []
        next_url: str | None = f"{pr_files_path}?per_page={DEFAULT_PER_PAGE}"

        for _ in range(self.max_pages):
            if next_url is None:
                break
            response = self._installation_get(installation_id, next_url)
            try:
                data = response.json()
            except Exception as exc:
                raise GitHubClientError("Malformed JSON in pull request files response") from exc

            if not isinstance(data, list):
                raise GitHubClientError("Unexpected pull request files response structure")

            for item in data:
                if not isinstance(item, dict):
                    raise GitHubClientError("Malformed file entry in pull request files response")
                filename = item.get("filename")
                file_status = item.get("status")
                if not isinstance(filename, str) or not filename.strip():
                    raise GitHubClientError("Pull request file entry missing 'filename'")
                if not isinstance(file_status, str) or not file_status.strip():
                    raise GitHubClientError("Pull request file entry missing 'status'")
                prev = item.get("previous_filename")
                sha = item.get("sha")
                files.append(
                    GitHubPullRequestFile(
                        filename=filename.strip(),
                        status=file_status.strip(),
                        additions=int(item.get("additions") or 0),
                        deletions=int(item.get("deletions") or 0),
                        changes=int(item.get("changes") or 0),
                        sha=sha if isinstance(sha, str) else None,
                        previous_filename=prev if isinstance(prev, str) else None,
                    )
                )

            next_url = _parse_next_link(
                response.headers.get("Link"),
                base_scheme=self._base_scheme,
                base_netloc=self._base_netloc,
                base_path_prefix=self._base_path_prefix,
                expected_rel_path=pr_files_path,
            )
        else:
            if next_url is not None:
                raise GitHubClientError("Pull request file pagination exceeded maximum page limit")

        return files

    def get_file_content(
        self,
        installation_id: int,
        full_name: str,
        path: str,
        ref: str,
        *,
        max_bytes: int,
    ) -> GitHubFileContent:
        """Fetch bounded file content from GitHub Contents API at `ref`."""
        owner, repo = _split_full_name(full_name)
        normalized_path = normalize_and_validate_path(path)
        cleaned_ref = ref.strip()
        if not cleaned_ref or not _RE_GITHUB_REF.match(cleaned_ref):
            raise GitHubValidationError("Invalid Git ref parameter", status_code=None)

        encoded_path = "/".join(quote(part, safe="") for part in normalized_path.split("/"))
        url = (
            f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/contents/{encoded_path}"
            f"?ref={quote(cleaned_ref, safe='')}"
        )
        max_resp_bytes = min(
            DEFAULT_MAX_API_RESPONSE_BYTES,
            max(256 * 1024, ((max_bytes * 4) // 3) + 128 * 1024),
        )

        try:
            response = self._request_with_retry(
                "GET",
                url,
                token_provider=lambda: self.get_installation_token(installation_id),
                on_unauthorized=lambda used_tok: self._invalidate_installation_token(
                    installation_id, used_tok
                ),
                allow_404_return_none=True,
                max_response_bytes=max_resp_bytes,
            )
        except _ResponseTooLargeError:
            return GitHubFileContent(
                path=normalized_path,
                size=max_bytes + 1,
                sha=None,
                content=None,
                skip_reason="file_too_large",
            )
        if response is None:
            return GitHubFileContent(
                path=normalized_path,
                size=0,
                sha=None,
                content=None,
                skip_reason="not_found_at_ref",
            )

        try:
            data = response.json()
        except Exception as exc:
            raise GitHubClientError("Malformed JSON in repository file content response") from exc

        if isinstance(data, list) or not isinstance(data, dict):
            return GitHubFileContent(
                path=normalized_path,
                size=0,
                sha=None,
                content=None,
                skip_reason="non_file_entry",
            )

        entry_type = data.get("type")
        sha = data.get("sha") if isinstance(data.get("sha"), str) else None
        raw_size = data.get("size")
        size = int(raw_size) if isinstance(raw_size, int) and not isinstance(raw_size, bool) else 0

        if entry_type != "file":
            return GitHubFileContent(
                path=normalized_path,
                size=size,
                sha=sha,
                content=None,
                skip_reason=f"unsupported_entry_type_{entry_type}"
                if entry_type
                else "non_file_entry",
            )

        if size > max_bytes:
            return GitHubFileContent(
                path=normalized_path,
                size=size,
                sha=sha,
                content=None,
                skip_reason="file_too_large",
            )

        encoding = data.get("encoding")
        raw_content = data.get("content")
        if encoding != "base64" or not isinstance(raw_content, str):
            return GitHubFileContent(
                path=normalized_path,
                size=size,
                sha=sha,
                content=None,
                skip_reason="unsupported_content_encoding",
            )

        # Bound encoded payload length prior to allocating decoded bytes
        compact_b64 = "".join(raw_content.split())
        if len(compact_b64) > ((max_bytes + 2) // 3) * 4 + 4:
            return GitHubFileContent(
                path=normalized_path,
                size=max_bytes + 1,
                sha=sha,
                content=None,
                skip_reason="file_too_large",
            )

        try:
            decoded = base64.b64decode(compact_b64.encode("ascii"), validate=True)
        except Exception as exc:
            raise GitHubClientError("Invalid base64 content in GitHub file response") from exc

        if len(decoded) > max_bytes:
            return GitHubFileContent(
                path=normalized_path,
                size=len(decoded),
                sha=sha,
                content=None,
                skip_reason="file_too_large",
            )

        return GitHubFileContent(
            path=normalized_path,
            size=len(decoded),
            sha=sha,
            content=decoded,
            skip_reason=None,
        )
