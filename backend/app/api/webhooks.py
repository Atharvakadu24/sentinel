"""API route for GitHub App webhook ingestion."""

from __future__ import annotations

import json

from fastapi import APIRouter, Header, HTTPException, Request, status

from app.api.deps import AppSettings, DbSession
from app.schemas.github import GitHubWebhookResponse
from app.services.github_webhook_service import (
    WebhookValidationError,
    process_github_webhook,
    validate_webhook_headers,
    verify_github_webhook_signature,
)

router = APIRouter(tags=["webhooks"])

MAX_WEBHOOK_BODY_BYTES: int = 5 * 1024 * 1024


@router.post(
    "/webhooks/github",
    response_model=GitHubWebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest GitHub App webhook delivery",
    description="Authenticates raw request HMAC SHA-256 signatures, enforces delivery idempotency, synchronizes installation state, and enqueues async pull request scan jobs.",
)
async def github_webhook_endpoint(
    request: Request,
    session: DbSession,
    settings: AppSettings,
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
) -> GitHubWebhookResponse:
    """Authenticate and ingest GitHub webhook deliveries without blocking synchronously on scans."""
    if not settings.is_github_webhook_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub webhook integration is not configured.",
        )

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            parsed_len = int(content_length.strip())
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Content-Length header.",
            ) from exc
        if parsed_len < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Content-Length header.",
            )
        if parsed_len > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="Webhook payload exceeds maximum allowed size.",
            )

    assert settings.GITHUB_WEBHOOK_SECRET is not None
    chunks: list[bytes] = []
    total_bytes = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        total_bytes += len(chunk)
        if total_bytes > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="Webhook payload exceeds maximum allowed size.",
            )
        chunks.append(chunk)
    raw_body = b"".join(chunks)

    secret = settings.GITHUB_WEBHOOK_SECRET.get_secret_value()
    if not verify_github_webhook_signature(secret, raw_body, x_hub_signature_256):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature.",
        )

    try:
        event_type, delivery_id = validate_webhook_headers(
            event_type=x_github_event,
            delivery_id=x_github_delivery,
        )
    except WebhookValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    try:
        parsed_payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed JSON webhook payload.",
        ) from exc

    if not isinstance(parsed_payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook payload must be a JSON object.",
        )

    result = process_github_webhook(
        session,
        delivery_id=delivery_id,
        event_type=event_type,
        payload=parsed_payload,
    )

    return GitHubWebhookResponse(
        status="duplicate" if result.duplicate else "processed",
        delivery_id=result.delivery_id,
        event_type=result.event_type,
        outcome=result.outcome,
        scan_id=result.scan_id,
    )
