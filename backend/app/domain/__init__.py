"""Domain logic package: canonical models, schemas, and fingerprinting."""

from app.domain.findings import (
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingReference,
    FindingSeverity,
    FindingSource,
    FindingSourceRef,
    FindingStatus,
    VerificationStatus,
)
from app.domain.fingerprint import (
    FINGERPRINT_VERSION,
    compute_code_anchor,
    compute_finding_fingerprint,
    compute_secret_anchor,
)
from app.domain.paths import normalize_and_validate_path

__all__ = [
    "FINGERPRINT_VERSION",
    "CanonicalFinding",
    "FindingCategory",
    "FindingConfidence",
    "FindingReference",
    "FindingSeverity",
    "FindingSource",
    "FindingSourceRef",
    "FindingStatus",
    "VerificationStatus",
    "compute_code_anchor",
    "compute_finding_fingerprint",
    "compute_secret_anchor",
    "normalize_and_validate_path",
]
