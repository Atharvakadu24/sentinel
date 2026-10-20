"""Canonical security finding data models and verification rules.

Implements Blueprint Section 10.5 (Canonical Finding Schema), Section 10.7
(Verification Status Semantics), and Section 10.8 (Severity vs Confidence).
"""

from __future__ import annotations

import json
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.domain.fingerprint import (
    compute_code_anchor,
    compute_finding_fingerprint,
    compute_secret_anchor,
)
from app.domain.paths import normalize_and_validate_path

_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_RAW_KEYS = frozenset(
    {
        "secret",
        "match",
        "line",
        "raw_secret",
        "plaintext_secret",
        "secret_value",
        "credential",
        "password",
        "private_key",
    }
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA|AROA)[0-9A-Z]{16}\b"),
    re.compile(r"\bglpat-[0-9a-zA-Z_-]{20,}\b"),
    re.compile(r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]",
        re.IGNORECASE,
    ),
)


def _validate_raw_node(node: Any, depth: int = 0) -> None:
    """Recursively validate raw metadata fields and values for safety.

    Blueprint Section 10.4:
    "Never copy Match, Secret or Line fields from Gitleaks output into any Sentinel structure."
    "A global redactor runs over every string before it is stored, logged..."

    Blueprint Section 10.5:
    "raw: object, sanitized, <= 8 KB, internal only"
    """
    if depth > 10:
        raise ValueError("raw metadata nesting exceeds maximum depth limit of 10")

    if isinstance(node, dict):
        for k, val in node.items():
            if not isinstance(k, str):
                raise TypeError("raw metadata dictionary keys must be strings")
            lowered_k = k.strip().lower()
            if lowered_k in _FORBIDDEN_RAW_KEYS:
                raise ValueError(
                    f"raw metadata contains forbidden key '{k}'; "
                    "scanner Match, Secret, Line and credential fields must never be retained"
                )
            _validate_raw_node(val, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _validate_raw_node(item, depth + 1)
    elif isinstance(node, str):
        for pattern in _SECRET_VALUE_PATTERNS:
            if pattern.search(node):
                raise ValueError(
                    "raw metadata contains apparent secret material matching prohibited pattern; "
                    "values must be sanitized before retention"
                )
    elif isinstance(node, (int, float, bool)) or node is None:
        pass
    else:
        raise TypeError(
            f"raw metadata contains unsupported non-JSON primitive of type '{type(node).__name__}'"
        )


class FindingSource(str, Enum):
    """Originating source of a finding."""

    SEMGREP = "semgrep"
    GITLEAKS = "gitleaks"
    AI = "ai"


class FindingCategory(str, Enum):
    """Standardized finding vulnerability categories."""

    INJECTION = "injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    HARDCODED_SECRET = "hardcoded_secret"
    CRYPTO = "crypto"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    AUTHN_AUTHZ = "authn_authz"
    INSECURE_CONFIG = "insecure_config"
    DATA_EXPOSURE = "data_exposure"
    LOGIC_BUG = "logic_bug"
    ERROR_HANDLING = "error_handling"
    OTHER = "other"


class FindingSeverity(str, Enum):
    """Impact if the issue is real (Section 10.8)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingConfidence(str, Enum):
    """Likelihood that the finding is a true positive (Section 10.8)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VerificationStatus(str, Enum):
    """Verification state of a finding (Section 10.7).

    - scanner_detected: A deterministic rule matched. Exploitability is not proven.
    - ai_corroborated: Scanner match plus an AI claim grounded at the same location.
    - ai_grounded: AI claim whose quoted evidence was relocated at the cited lines.
    - ai_unverified: Reserved; never stored in MVP.
    """

    SCANNER_DETECTED = "scanner_detected"
    AI_CORROBORATED = "ai_corroborated"
    AI_GROUNDED = "ai_grounded"
    AI_UNVERIFIED = "ai_unverified"


class FindingStatus(str, Enum):
    """Persistent lifecycle status of a finding across scans (Section 7 Workflow C)."""

    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    DISMISSED = "dismissed"
    FALSE_POSITIVE = "false_positive"


class AITriageVerdict(str, Enum):
    """Triage verdict produced by the AI reviewer on scanner findings (Section 11.4)."""

    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    UNCERTAIN = "uncertain"


class FindingSourceRef(BaseModel):
    """Reference to a contributing detector source and rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: FindingSource
    rule_id: str = Field(min_length=1, max_length=255)


class FindingReference(BaseModel):
    """Security reference link (CWE, OWASP, etc.)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: str = Field(min_length=1, max_length=50)
    id: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=500)


class AIAssessment(BaseModel):
    """AI assessment metadata for triage and corroboration."""

    model_config = ConfigDict(extra="forbid")

    verdict: AITriageVerdict | None = None
    rationale: str | None = Field(default=None, max_length=300)
    explanation: str | None = Field(default=None, max_length=1000)
    relocated: bool = False
    capped_from: dict[str, str] | None = None


class CanonicalFinding(BaseModel):
    """Canonical, normalized security finding schema.

    Strictly matches Blueprint Section 10.5 specifications.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
        hide_input_in_errors=True,
    )

    rule_id: str = Field(min_length=1, max_length=255)
    source: FindingSource
    sources: list[FindingSourceRef] = Field(default_factory=list)
    category: FindingCategory
    title: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=1000)
    severity: FindingSeverity
    confidence: FindingConfidence
    verification_status: VerificationStatus
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet: str = Field(max_length=2000)
    snippet_start_line: int | None = Field(default=None, ge=1)
    remediation: str = Field(min_length=1, max_length=1000)
    references: list[FindingReference] = Field(default_factory=list)
    in_diff: bool | None = None
    fingerprint: str = Field(min_length=64, max_length=64)
    ai_assessment: AIAssessment | None = None
    raw: dict[str, Any] | None = None

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        """Ensure file path conforms to Sentinel normalization and safety rules."""
        return normalize_and_validate_path(v)

    @field_validator("fingerprint")
    @classmethod
    def validate_fingerprint_format(cls, v: str) -> str:
        """Ensure fingerprint is a 64-character lowercase hex string."""
        if not _HEX_64_PATTERN.match(v):
            raise ValueError(f"Fingerprint must be a 64-character lowercase hex string, got '{v}'")
        return v

    @field_validator("snippet")
    @classmethod
    def validate_snippet_bounds(cls, v: str) -> str:
        """Ensure snippet does not exceed the 12-line maximum (Section 10.5)."""
        lines = v.splitlines()
        if len(lines) > 12:
            raise ValueError(f"Snippet cannot exceed 12 lines (got {len(lines)})")
        return v

    @field_validator("raw")
    @classmethod
    def validate_raw_metadata(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        """Validate raw metadata conforms to Section 10.4 and 10.5: sanitized, <= 8 KB."""
        if v is None:
            return None

        # Recursively inspect all keys, nested structures, and string values
        _validate_raw_node(v)

        try:
            serialized = json.dumps(v, ensure_ascii=False)
        except (TypeError, ValueError) as err:
            raise ValueError(f"raw metadata must be JSON-serializable: {err}") from err

        byte_len = len(serialized.encode("utf-8"))
        if byte_len > 8192:
            raise ValueError(
                f"raw metadata exceeds maximum size of 8 KB (8192 bytes, got {byte_len} bytes)"
            )

        return v

    @model_validator(mode="before")
    @classmethod
    def populate_default_sources(cls, data: Any) -> Any:
        """Default `sources` to contain primary `source` and `rule_id` if omitted."""
        if isinstance(data, dict) and ("sources" not in data or not data["sources"]):
            src = data.get("source")
            r_id = data.get("rule_id")
            if src and r_id:
                data["sources"] = [{"source": src, "rule_id": r_id}]
        return data

    @model_validator(mode="after")
    def validate_cross_field_constraints(self) -> CanonicalFinding:
        """Enforce blueprint integrity rules across multiple fields."""
        # 1. Line range integrity
        if self.end_line < self.start_line:
            raise ValueError(
                f"end_line ({self.end_line}) cannot be less than start_line ({self.start_line})"
            )

        # 2. ai_unverified is reserved and not allowed for stored findings (Section 10.5)
        if self.verification_status == VerificationStatus.AI_UNVERIFIED:
            raise ValueError(
                "ai_unverified status is reserved and cannot be assigned to canonical findings"
            )

        # 3. Verification status consistency per detector type (Section 10.7)
        if self.source in (FindingSource.SEMGREP, FindingSource.GITLEAKS):
            if self.verification_status not in (
                VerificationStatus.SCANNER_DETECTED,
                VerificationStatus.AI_CORROBORATED,
            ):
                raise ValueError(
                    f"Scanner findings ({self.source.value}) must have verification status "
                    f"scanner_detected or ai_corroborated, got {self.verification_status.value}"
                )
        elif self.source == FindingSource.AI:
            if self.verification_status != VerificationStatus.AI_GROUNDED:
                raise ValueError(
                    f"AI-only finding cannot have {self.verification_status.value} verification status; "
                    "must be ai_grounded"
                )

            # AI-only severity and confidence caps (Section 10.8)
            if self.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                raise ValueError(
                    f"AI-only findings are capped at medium severity; got {self.severity.value}"
                )
            if self.confidence == FindingConfidence.HIGH:
                raise ValueError(
                    f"AI-only findings are capped at medium confidence; got {self.confidence.value}"
                )

            # AI reviewer cannot author hardcoded_secret findings (Section 11.5)
            if self.category == FindingCategory.HARDCODED_SECRET:
                raise ValueError(
                    "AI reviewer cannot author hardcoded_secret findings; Gitleaks owns secrets"
                )

        # 4. Gitleaks findings must belong to hardcoded_secret category
        if (
            self.source == FindingSource.GITLEAKS
            and self.category != FindingCategory.HARDCODED_SECRET
        ):
            raise ValueError(
                f"Gitleaks findings must have category hardcoded_secret, got {self.category.value}"
            )

        return self

    @classmethod
    def create_canonical(
        cls,
        *,
        rule_id: str,
        source: FindingSource,
        category: FindingCategory,
        title: str,
        description: str,
        severity: FindingSeverity,
        confidence: FindingConfidence,
        verification_status: VerificationStatus,
        file_path: str,
        start_line: int,
        end_line: int,
        snippet: str,
        remediation: str,
        code_anchor: str | None = None,
        secret_value: str | None = None,
        fingerprint_key: str | bytes | None = None,
        occ: int = 0,
        snippet_start_line: int | None = None,
        references: list[FindingReference] | None = None,
        in_diff: bool | None = None,
        ai_assessment: AIAssessment | None = None,
        raw: dict[str, Any] | None = None,
    ) -> CanonicalFinding:
        """Convenience factory that deterministically computes anchor and fingerprint."""
        norm_path = normalize_and_validate_path(file_path)

        # Compute anchor
        if category == FindingCategory.HARDCODED_SECRET or source == FindingSource.GITLEAKS:
            if secret_value is not None:
                if not fingerprint_key:
                    raise ValueError(
                        "fingerprint_key is required to compute secret anchor from secret_value"
                    )
                if secret_value in snippet:
                    raise ValueError(
                        "Raw secret value cannot appear unredacted in finding snippet (must use [REDACTED:{rule_id}])"
                    )
                if raw is not None:
                    raw_dump = json.dumps(raw, ensure_ascii=False)
                    if secret_value in raw_dump:
                        raise ValueError("Raw secret value cannot appear in raw metadata")
                anchor = compute_secret_anchor(secret_value, fingerprint_key)
            elif code_anchor is not None:
                anchor = code_anchor
            else:
                raise ValueError("Either secret_value or code_anchor is required for secret finding")
        else:
            if code_anchor is not None:
                anchor = code_anchor
            else:
                anchor = compute_code_anchor(snippet)

        fp = compute_finding_fingerprint(
            rule_id=rule_id,
            source=source.value,
            file_path=norm_path,
            anchor=anchor,
            occ=occ,
            category=category.value,
        )

        return cls(
            rule_id=rule_id,
            source=source,
            category=category,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            verification_status=verification_status,
            file_path=norm_path,
            start_line=start_line,
            end_line=end_line,
            snippet=snippet,
            snippet_start_line=snippet_start_line or start_line,
            remediation=remediation,
            references=references or [],
            in_diff=in_diff,
            fingerprint=fp,
            ai_assessment=ai_assessment,
            raw=raw,
        )
