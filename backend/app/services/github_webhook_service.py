"""GitHub webhook verification, idempotency, lifecycle sync, and PR scan enqueueing."""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import GitHubInstallation, Project, WebhookEvent
from app.services.job_service import _normalize_datetime, sanitize_failure_message
from app.services.scan_service import ScanConflictError, create_github_pr_scan

logger = logging.getLogger("sentinel.services.github_webhook")

_RE_SHA256_SIG = re.compile(r"^sha256=([0-9a-f]{64})$", re.IGNORECASE)
_RE_EVENT_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_RE_DELIVERY_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_RE_GIT_SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_RE_GITHUB_FULL_NAME = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

SUPPORTED_PR_ACTIONS: frozenset[str] = frozenset(
    {"opened", "synchronize", "reopened", "ready_for_review"}
)


class WebhookValidationError(ValueError):
    """Raised when incoming webhook headers or payload violate contract."""


@dataclass(frozen=True, slots=True)
class WebhookProcessResult:
    """Sanitized processing result returned to webhook HTTP handler."""

    duplicate: bool
    delivery_id: str
    event_type: str
    outcome: str
    scan_id: uuid.UUID | None = None


def verify_github_webhook_signature(
    secret: str,
    raw_body: bytes,
    signature_header: str | None,
) -> bool:
    """Verify X-Hub-Signature-256 HMAC SHA-256 signature in constant time."""
    if not secret or not signature_header:
        return False

    match = _RE_SHA256_SIG.match(signature_header.strip())
    if not match:
        return False

    provided_hex = match.group(1).lower()
    expected_hex = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest().lower()
    return hmac.compare_digest(expected_hex, provided_hex)


def validate_webhook_headers(
    *,
    event_type: str | None,
    delivery_id: str | None,
) -> tuple[str, str]:
    """Validate required X-GitHub-Event and X-GitHub-Delivery headers."""
    clean_event = (event_type or "").strip()
    if not clean_event or not _RE_EVENT_NAME.match(clean_event):
        raise WebhookValidationError("Missing or invalid X-GitHub-Event header")

    clean_delivery = (delivery_id or "").strip()
    if not clean_delivery or not _RE_DELIVERY_ID.match(clean_delivery):
        raise WebhookValidationError("Missing or invalid X-GitHub-Delivery header")

    return clean_event, clean_delivery


def _extract_positive_int(obj: Any, key: str) -> int | None:
    if not isinstance(obj, dict):
        return None
    val = obj.get(key)
    if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
        return None
    return val


def _handle_installation_event(
    session: Session,
    *,
    action: str | None,
    installation_id: int | None,
    payload: dict[str, Any],
    now: datetime,
) -> str:
    if installation_id is None:
        return "ignored_event"

    inst = session.scalar(
        select(GitHubInstallation).where(GitHubInstallation.installation_id == installation_id)
    )
    if inst is None:
        return "no_project"

    projects = list(
        session.scalars(
            select(Project).where(
                Project.installation_id == inst.id,
                Project.kind == "github",
                Project.deleted_at.is_(None),
            )
        ).all()
    )

    if action == "deleted":
        inst.status = "deleted"
        inst.updated_at = now
        for proj in projects:
            if proj.status == "active":
                proj.status = "access_lost"
                proj.updated_at = now
        return "accepted"

    if action == "suspend":
        inst.status = "suspended"
        inst.updated_at = now
        for proj in projects:
            if proj.status == "active":
                proj.status = "access_lost"
                proj.updated_at = now
        return "accepted"

    if action == "unsuspend":
        if inst.status == "suspended":
            inst.status = "active"
            inst.updated_at = now
            for proj in projects:
                if proj.status == "access_lost":
                    proj.status = "active"
                    proj.updated_at = now
        return "accepted"

    if action == "created":
        raw_inst = payload.get("installation")
        if isinstance(raw_inst, dict):
            account = raw_inst.get("account")
            if isinstance(account, dict):
                login = account.get("login")
                acct_type = account.get("type")
                if isinstance(login, str) and login.strip():
                    inst.account_login = login.strip()
                if acct_type in ("User", "Organization"):
                    inst.account_type = acct_type
            inst.status = "suspended" if raw_inst.get("suspended_at") is not None else "active"
            inst.updated_at = now
        return "accepted"

    return "ignored_event"


def _handle_installation_repositories_event(
    session: Session,
    *,
    action: str | None,
    installation_id: int | None,
    payload: dict[str, Any],
    now: datetime,
) -> str:
    if installation_id is None:
        return "ignored_event"

    inst = session.scalar(
        select(GitHubInstallation).where(GitHubInstallation.installation_id == installation_id)
    )
    if inst is None:
        return "no_project"

    if action == "removed":
        raw_removed = payload.get("repositories_removed")
        if not isinstance(raw_removed, list):
            return "ignored_event"
        removed_ids = {
            rid for item in raw_removed if (rid := _extract_positive_int(item, "id")) is not None
        }
        if not removed_ids:
            return "ignored_event"
        projects = list(
            session.scalars(
                select(Project).where(
                    Project.installation_id == inst.id,
                    Project.kind == "github",
                    Project.github_repo_id.in_(removed_ids),
                    Project.deleted_at.is_(None),
                )
            ).all()
        )
        if not projects:
            return "no_project"
        for proj in projects:
            if proj.status == "active":
                proj.status = "access_lost"
                proj.updated_at = now
        return "accepted"

    if action == "added":
        raw_added = payload.get("repositories_added")
        if not isinstance(raw_added, list):
            return "ignored_event"
        added_map: dict[int, str] = {}
        for item in raw_added:
            rid = _extract_positive_int(item, "id")
            full_name = item.get("full_name") if isinstance(item, dict) else None
            if rid is not None and isinstance(full_name, str) and full_name.strip():
                added_map[rid] = full_name.strip()
        if not added_map:
            return "ignored_event"
        projects = list(
            session.scalars(
                select(Project).where(
                    Project.installation_id == inst.id,
                    Project.kind == "github",
                    Project.github_repo_id.in_(set(added_map)),
                    Project.deleted_at.is_(None),
                )
            ).all()
        )
        if not projects:
            return "no_project"
        for proj in projects:
            if proj.github_repo_id in added_map:
                proj.full_name = added_map[proj.github_repo_id]
            if inst.status == "active" and proj.status == "access_lost":
                proj.status = "active"
            proj.updated_at = now
        return "accepted"

    return "ignored_event"


def _handle_pull_request_event(
    session: Session,
    *,
    action: str | None,
    installation_id: int | None,
    repo_id: int | None,
    pr_number: int | None,
    head_sha: str | None,
    payload: dict[str, Any],
    now: datetime,
) -> tuple[str, uuid.UUID | None]:
    if action not in SUPPORTED_PR_ACTIONS:
        return "ignored_event", None

    pr_obj = payload.get("pull_request")
    if not isinstance(pr_obj, dict):
        return "error", None

    if bool(pr_obj.get("draft", False)):
        return "ignored_draft", None

    repo_obj = payload.get("repository")
    full_name = repo_obj.get("full_name") if isinstance(repo_obj, dict) else None
    cleaned_full_name = full_name.strip() if isinstance(full_name, str) else ""
    if (
        installation_id is None
        or repo_id is None
        or pr_number is None
        or not head_sha
        or not _RE_GIT_SHA.match(head_sha)
        or not _RE_GITHUB_FULL_NAME.match(cleaned_full_name)
    ):
        return "error", None
    owner_seg, repo_seg = cleaned_full_name.split("/", 1)
    if owner_seg in (".", "..") or repo_seg in (".", ".."):
        return "error", None

    inst = session.scalar(
        select(GitHubInstallation).where(
            GitHubInstallation.installation_id == installation_id,
            GitHubInstallation.status == "active",
        )
    )
    if inst is None:
        return "no_project", None

    project = session.scalar(
        select(Project).where(
            Project.installation_id == inst.id,
            Project.github_repo_id == repo_id,
            Project.kind == "github",
            Project.deleted_at.is_(None),
            Project.status == "active",
        )
    )
    if project is None:
        return "no_project", None

    base_obj = pr_obj.get("base")
    base_sha_raw = base_obj.get("sha") if isinstance(base_obj, dict) else None
    base_sha = (
        base_sha_raw.strip()
        if isinstance(base_sha_raw, str) and _RE_GIT_SHA.match(base_sha_raw.strip())
        else None
    )

    title_raw = pr_obj.get("title")
    pr_title = (
        "".join(ch if ch not in "\r\n\t\x00" else " " for ch in title_raw).strip()[:200]
        if isinstance(title_raw, str)
        else None
    )

    trigger_key = f"pr:{pr_number}:sha:{head_sha.lower()}"
    try:
        scan, _job = create_github_pr_scan(
            session,
            project_id=project.id,
            installation_id=installation_id,
            github_repo_id=repo_id,
            full_name=cleaned_full_name,
            pr_number=pr_number,
            head_sha=head_sha.lower(),
            base_sha=base_sha.lower() if base_sha else None,
            pr_title=pr_title,
            trigger_key=trigger_key,
            now=now,
            auto_commit=False,
        )
    except ScanConflictError:
        # Duplicate delivery / reopen on same already-enqueued PR commit SHA
        return "ignored_event", None

    return "accepted", scan.id


def process_github_webhook(
    session: Session,
    *,
    delivery_id: str,
    event_type: str,
    payload: dict[str, Any],
    now: datetime | None = None,
    auto_commit: bool = False,
) -> WebhookProcessResult:
    """Process a verified GitHub webhook idempotently inside a database transaction."""
    existing = session.scalar(select(WebhookEvent).where(WebhookEvent.delivery_id == delivery_id))
    if existing is not None:
        return WebhookProcessResult(
            duplicate=True,
            delivery_id=delivery_id,
            event_type=existing.event_type,
            outcome=existing.outcome,
            scan_id=existing.scan_id,
        )

    current_time = _normalize_datetime(now) or utc_now()
    action_raw = payload.get("action")
    action = action_raw.strip() if isinstance(action_raw, str) and action_raw.strip() else None

    installation_id = _extract_positive_int(payload.get("installation"), "id")
    repo_id = _extract_positive_int(payload.get("repository"), "id")

    pr_obj = payload.get("pull_request")
    pr_number = _extract_positive_int(pr_obj, "number")
    head_obj = pr_obj.get("head") if isinstance(pr_obj, dict) else None
    head_sha_raw = head_obj.get("sha") if isinstance(head_obj, dict) else None
    head_sha = (
        head_sha_raw.strip() if isinstance(head_sha_raw, str) and head_sha_raw.strip() else None
    )

    outcome = "ignored_event"
    scan_id: uuid.UUID | None = None

    try:
        with session.begin_nested():
            if event_type == "ping":
                outcome = "accepted"
            elif event_type == "installation":
                outcome = _handle_installation_event(
                    session,
                    action=action,
                    installation_id=installation_id,
                    payload=payload,
                    now=current_time,
                )
            elif event_type == "installation_repositories":
                outcome = _handle_installation_repositories_event(
                    session,
                    action=action,
                    installation_id=installation_id,
                    payload=payload,
                    now=current_time,
                )
            elif event_type == "pull_request":
                outcome, scan_id = _handle_pull_request_event(
                    session,
                    action=action,
                    installation_id=installation_id,
                    repo_id=repo_id,
                    pr_number=pr_number,
                    head_sha=head_sha,
                    payload=payload,
                    now=current_time,
                )
            else:
                outcome = "ignored_event"
    except Exception as exc:  # noqa: BLE001 - sanitize unexpected processing failures cleanly
        logger.error(
            "Error processing GitHub webhook delivery=%s event=%s: %s",
            delivery_id,
            event_type,
            sanitize_failure_message(str(exc)),
        )
        outcome = "error"
        scan_id = None

    event_row = WebhookEvent(
        delivery_id=delivery_id,
        event_type=event_type,
        action=action,
        github_installation_id=installation_id,
        github_repo_id=repo_id,
        pr_number=pr_number,
        head_sha=head_sha.lower() if head_sha and _RE_GIT_SHA.match(head_sha) else None,
        outcome=outcome,
        scan_id=scan_id,
        received_at=current_time,
    )
    session.add(event_row)

    try:
        session.flush()
        if auto_commit:
            session.commit()
    except IntegrityError:
        session.rollback()
        raced = session.scalar(select(WebhookEvent).where(WebhookEvent.delivery_id == delivery_id))
        if raced is not None:
            return WebhookProcessResult(
                duplicate=True,
                delivery_id=delivery_id,
                event_type=raced.event_type,
                outcome=raced.outcome,
                scan_id=raced.scan_id,
            )
        raise

    return WebhookProcessResult(
        duplicate=False,
        delivery_id=delivery_id,
        event_type=event_type,
        outcome=outcome,
        scan_id=scan_id,
    )
