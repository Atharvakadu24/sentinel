"""Unit tests for CanonicalFinding schema validation and constraints (Blueprint 10.5 / 10.7 / 10.8)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.domain.findings import (
    AIAssessment,
    AITriageVerdict,
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingReference,
    FindingSeverity,
    FindingSource,
    VerificationStatus,
)


class TestCanonicalFindingModel:
    """Tests for CanonicalFinding schema validation and security invariants."""

    def test_valid_deterministic_finding(self) -> None:
        finding = CanonicalFinding(
            rule_id="python.security.injection.sql",
            source=FindingSource.SEMGREP,
            category=FindingCategory.INJECTION,
            title="SQL Injection via string formatting",
            description="User input is concatenated directly into SQL execute call.",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            verification_status=VerificationStatus.SCANNER_DETECTED,
            file_path="app/db/users.py",
            start_line=45,
            end_line=47,
            snippet="query = f'SELECT * FROM users WHERE id = {user_id}'\ncursor.execute(query)",
            remediation="Use parameterized queries instead of string interpolation.",
            references=[
                FindingReference(
                    type="cwe",
                    id="CWE-89",
                    url="https://cwe.mitre.org/data/definitions/89.html",
                )
            ],
            in_diff=True,
            fingerprint="a" * 64,
        )

        assert finding.rule_id == "python.security.injection.sql"
        assert len(finding.sources) == 1
        assert finding.sources[0].source == FindingSource.SEMGREP
        assert finding.sources[0].rule_id == "python.security.injection.sql"
        assert finding.file_path == "app/db/users.py"

    def test_create_canonical_factory_for_code(self) -> None:
        snippet = "eval(user_payload)"
        finding = CanonicalFinding.create_canonical(
            rule_id="python.lang.security.audit.eval",
            source=FindingSource.SEMGREP,
            category=FindingCategory.INJECTION,
            title="Use of dangerous eval function",
            description="Dynamic code evaluation using untrusted input.",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.HIGH,
            verification_status=VerificationStatus.SCANNER_DETECTED,
            file_path="src/parser.py",
            start_line=12,
            end_line=12,
            snippet=snippet,
            remediation="Avoid eval; use safe AST parsing or JSON decoders.",
        )

        assert len(finding.fingerprint) == 64
        assert finding.file_path == "src/parser.py"
        assert finding.snippet == snippet

    def test_create_canonical_factory_for_secret(
        self, sample_secret_value: str, sample_fingerprint_key: str
    ) -> None:
        redacted_snippet = "API_KEY = '[REDACTED:generic-api-key]'"
        finding = CanonicalFinding.create_canonical(
            rule_id="generic-api-key",
            source=FindingSource.GITLEAKS,
            category=FindingCategory.HARDCODED_SECRET,
            title="Hardcoded API Secret Detected",
            description="A sensitive API credential was detected in plaintext.",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            verification_status=VerificationStatus.SCANNER_DETECTED,
            file_path="config/credentials.py",
            start_line=5,
            end_line=5,
            snippet=redacted_snippet,
            remediation="Rotate this credential immediately and store in environment secrets.",
            secret_value=sample_secret_value,
            fingerprint_key=sample_fingerprint_key,
        )

        # Raw secret must NEVER be present in the finding object or fingerprint
        assert sample_secret_value not in finding.fingerprint
        assert sample_secret_value not in finding.snippet
        assert len(finding.fingerprint) == 64

    def test_end_line_before_start_line_rejected(self) -> None:
        with pytest.raises(ValidationError, match="end_line .* cannot be less than start_line"):
            CanonicalFinding(
                rule_id="rule1",
                source=FindingSource.SEMGREP,
                category=FindingCategory.INJECTION,
                title="Invalid line order",
                description="Test description",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.LOW,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="app.py",
                start_line=50,
                end_line=40,  # Invalid
                snippet="code()",
                remediation="Fix line",
                fingerprint="b" * 64,
            )

    def test_start_line_zero_or_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CanonicalFinding(
                rule_id="rule1",
                source=FindingSource.SEMGREP,
                category=FindingCategory.INJECTION,
                title="Invalid start line",
                description="Test description",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.LOW,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="app.py",
                start_line=0,  # Must be >= 1
                end_line=1,
                snippet="code()",
                remediation="Fix line",
                fingerprint="c" * 64,
            )

    def test_snippet_exceeding_twelve_lines_rejected(self) -> None:
        thirteen_lines = "\n".join(f"line_{i}" for i in range(13))
        with pytest.raises(ValidationError, match="Snippet cannot exceed 12 lines"):
            CanonicalFinding(
                rule_id="rule1",
                source=FindingSource.SEMGREP,
                category=FindingCategory.INJECTION,
                title="Long snippet",
                description="Test description",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.LOW,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="app.py",
                start_line=1,
                end_line=13,
                snippet=thirteen_lines,
                remediation="Fix snippet",
                fingerprint="d" * 64,
            )

    def test_ai_unverified_status_rejected_in_mvp(self) -> None:
        with pytest.raises(ValidationError, match="ai_unverified status is reserved"):
            CanonicalFinding(
                rule_id="ai.test",
                source=FindingSource.AI,
                category=FindingCategory.LOGIC_BUG,
                title="Unverified AI claim",
                description="Test description",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.MEDIUM,
                verification_status=VerificationStatus.AI_UNVERIFIED,
                file_path="app.py",
                start_line=1,
                end_line=2,
                snippet="test()",
                remediation="Fix",
                fingerprint="e" * 64,
            )

    def test_ai_only_finding_cannot_claim_scanner_detected(self) -> None:
        with pytest.raises(ValidationError, match="AI-only finding cannot have scanner_detected"):
            CanonicalFinding(
                rule_id="ai.injection",
                source=FindingSource.AI,
                category=FindingCategory.INJECTION,
                title="AI finding claiming rule detection",
                description="Test description",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.MEDIUM,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="app.py",
                start_line=1,
                end_line=2,
                snippet="test()",
                remediation="Fix",
                fingerprint="f" * 64,
            )

    def test_ai_severity_and_confidence_capped_at_medium(self) -> None:
        # AI finding with critical severity must be rejected
        with pytest.raises(ValidationError, match="AI-only findings are capped at medium severity"):
            CanonicalFinding(
                rule_id="ai.injection",
                source=FindingSource.AI,
                category=FindingCategory.INJECTION,
                title="AI finding with critical severity",
                description="Test description",
                severity=FindingSeverity.CRITICAL,  # Capped at medium
                confidence=FindingConfidence.MEDIUM,
                verification_status=VerificationStatus.AI_GROUNDED,
                file_path="app.py",
                start_line=1,
                end_line=2,
                snippet="test()",
                remediation="Fix",
                fingerprint="0" * 64,
            )

        # AI finding with high confidence must be rejected
        with pytest.raises(ValidationError, match="AI-only findings are capped at medium confidence"):
            CanonicalFinding(
                rule_id="ai.injection",
                source=FindingSource.AI,
                category=FindingCategory.INJECTION,
                title="AI finding with high confidence",
                description="Test description",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,  # Capped at medium
                verification_status=VerificationStatus.AI_GROUNDED,
                file_path="app.py",
                start_line=1,
                end_line=2,
                snippet="test()",
                remediation="Fix",
                fingerprint="1" * 64,
            )

    def test_ai_cannot_author_hardcoded_secret_category(self) -> None:
        with pytest.raises(ValidationError, match="AI reviewer cannot author hardcoded_secret"):
            CanonicalFinding(
                rule_id="ai.secret",
                source=FindingSource.AI,
                category=FindingCategory.HARDCODED_SECRET,  # Gitleaks owns secrets
                title="AI claimed secret",
                description="Test description",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.MEDIUM,
                verification_status=VerificationStatus.AI_GROUNDED,
                file_path="app.py",
                start_line=1,
                end_line=2,
                snippet="key = '123'",
                remediation="Fix",
                fingerprint="2" * 64,
            )

    def test_gitleaks_finding_must_be_hardcoded_secret_category(self) -> None:
        with pytest.raises(ValidationError, match="Gitleaks findings must have category hardcoded_secret"):
            CanonicalFinding(
                rule_id="gitleaks.token",
                source=FindingSource.GITLEAKS,
                category=FindingCategory.INJECTION,  # Invalid for Gitleaks
                title="Gitleaks injection",
                description="Test description",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="app.py",
                start_line=1,
                end_line=2,
                snippet="key = '123'",
                remediation="Fix",
                fingerprint="3" * 64,
            )

    def test_unsafe_path_rejected_in_finding(self) -> None:
        with pytest.raises(ValidationError, match="Path traversal segments"):
            CanonicalFinding(
                rule_id="rule1",
                source=FindingSource.SEMGREP,
                category=FindingCategory.INJECTION,
                title="Path traversal",
                description="Test description",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.LOW,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="../outside/app.py",
                start_line=1,
                end_line=2,
                snippet="code()",
                remediation="Fix",
                fingerprint="4" * 64,
            )

    def test_finding_with_ai_assessment(self) -> None:
        assessment = AIAssessment(
            verdict=AITriageVerdict.LIKELY_TRUE_POSITIVE,
            rationale="Query is dynamically concatenated with unsanitized user variable.",
            explanation="Detailed explanation of the attack vector.",
            relocated=False,
            capped_from={"severity": "critical", "confidence": "high"},
        )
        finding = CanonicalFinding(
            rule_id="ai.sqli",
            source=FindingSource.AI,
            category=FindingCategory.INJECTION,
            title="SQL Injection vulnerability",
            description="Dynamic SQL query detected",
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.MEDIUM,
            verification_status=VerificationStatus.AI_GROUNDED,
            file_path="app/query.py",
            start_line=10,
            end_line=12,
            snippet="query = 'SELECT * FROM users'",
            remediation="Use parameterized queries",
            fingerprint="5" * 64,
            ai_assessment=assessment,
        )
        assert finding.ai_assessment is not None
        assert finding.ai_assessment.verdict == AITriageVerdict.LIKELY_TRUE_POSITIVE
        assert finding.ai_assessment.capped_from == {"severity": "critical", "confidence": "high"}

    def test_scanner_cannot_claim_ai_grounded_status(self) -> None:
        with pytest.raises(
            ValidationError, match="Scanner findings .* must have verification status"
        ):
            CanonicalFinding(
                rule_id="semgrep.sqli",
                source=FindingSource.SEMGREP,
                category=FindingCategory.INJECTION,
                title="SQLi",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.AI_GROUNDED,  # Invalid for scanner
                file_path="app/db.py",
                start_line=1,
                end_line=2,
                snippet="query()",
                remediation="Fix",
                fingerprint="6" * 64,
            )

    def test_scanner_with_ai_corroborated_allowed(self) -> None:
        finding = CanonicalFinding(
            rule_id="semgrep.sqli",
            source=FindingSource.SEMGREP,
            category=FindingCategory.INJECTION,
            title="SQLi",
            description="Test",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            verification_status=VerificationStatus.AI_CORROBORATED,
            file_path="app/db.py",
            start_line=1,
            end_line=2,
            snippet="query()",
            remediation="Fix",
            fingerprint="7" * 64,
        )
        assert finding.verification_status == VerificationStatus.AI_CORROBORATED

    def test_raw_metadata_size_bounds(self) -> None:
        valid_raw = {"details": "a" * 100}
        finding = CanonicalFinding(
            rule_id="semgrep.sqli",
            source=FindingSource.SEMGREP,
            category=FindingCategory.INJECTION,
            title="SQLi",
            description="Test",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            verification_status=VerificationStatus.SCANNER_DETECTED,
            file_path="app/db.py",
            start_line=1,
            end_line=2,
            snippet="query()",
            remediation="Fix",
            fingerprint="8" * 64,
            raw=valid_raw,
        )
        assert finding.raw == valid_raw

        oversized_raw = {"huge_data": "x" * 9000}
        with pytest.raises(ValidationError, match="exceeds maximum size of 8 KB"):
            CanonicalFinding(
                rule_id="semgrep.sqli",
                source=FindingSource.SEMGREP,
                category=FindingCategory.INJECTION,
                title="SQLi",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="app/db.py",
                start_line=1,
                end_line=2,
                snippet="query()",
                remediation="Fix",
                fingerprint="9" * 64,
                raw=oversized_raw,
            )

    def test_raw_metadata_forbids_unredacted_secret_keys(self) -> None:
        # Top-level 'Secret' rejected
        with pytest.raises(ValidationError, match="contains forbidden key 'Secret'"):
            CanonicalFinding(
                rule_id="gitleaks.token",
                source=FindingSource.GITLEAKS,
                category=FindingCategory.HARDCODED_SECRET,
                title="Token leak",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="config.py",
                start_line=1,
                end_line=1,
                snippet="API_KEY = '[REDACTED:token]'",
                remediation="Fix",
                fingerprint="a" * 64,
                raw={"Secret": "redacted_placeholder_val", "RuleID": "token"},
            )

        # Top-level 'Line' rejected (Section 10.4: Never copy Match, Secret or Line)
        with pytest.raises(ValidationError, match="contains forbidden key 'Line'"):
            CanonicalFinding(
                rule_id="gitleaks.token",
                source=FindingSource.GITLEAKS,
                category=FindingCategory.HARDCODED_SECRET,
                title="Token leak",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="config.py",
                start_line=1,
                end_line=1,
                snippet="API_KEY = '[REDACTED:token]'",
                remediation="Fix",
                fingerprint="a" * 64,
                raw={"Line": 42, "RuleID": "token"},
            )

        # Nested forbidden key 'Match' inside sub-dictionary
        with pytest.raises(ValidationError, match="contains forbidden key 'Match'"):
            CanonicalFinding(
                rule_id="gitleaks.token",
                source=FindingSource.GITLEAKS,
                category=FindingCategory.HARDCODED_SECRET,
                title="Token leak",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="config.py",
                start_line=1,
                end_line=1,
                snippet="API_KEY = '[REDACTED:token]'",
                remediation="Fix",
                fingerprint="a" * 64,
                raw={"scanner_output": {"nested_details": {"Match": "candidate"}}},
            )

        # Nested forbidden key inside list of dictionaries
        with pytest.raises(ValidationError, match="contains forbidden key 'line'"):
            CanonicalFinding(
                rule_id="gitleaks.token",
                source=FindingSource.GITLEAKS,
                category=FindingCategory.HARDCODED_SECRET,
                title="Token leak",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="config.py",
                start_line=1,
                end_line=1,
                snippet="API_KEY = '[REDACTED:token]'",
                remediation="Fix",
                fingerprint="a" * 64,
                raw={"occurrences": [{"file": "a.py", "line": 10}]},
            )

    def test_raw_metadata_rejects_secret_bearing_values_under_misleading_keys(self) -> None:
        """Denylisting keys alone is insufficient; values under benign keys must be inspected."""
        # Apparent GitHub PAT under harmless key 'notes'
        with pytest.raises(
            ValidationError, match="apparent secret material matching prohibited pattern"
        ) as exc_info_pat:
            CanonicalFinding(
                rule_id="semgrep.test",
                source=FindingSource.SEMGREP,
                category=FindingCategory.INJECTION,
                title="Test",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="app.py",
                start_line=1,
                end_line=1,
                snippet="test()",
                remediation="Fix",
                fingerprint="b" * 64,
                raw={"notes": "ghp_123456789012345678901234567890123456"},
            )
        # CRITICAL: Secret value must never be echoed in exception message
        assert "ghp_" not in str(exc_info_pat.value)

        # Private key block under benign key 'description'
        fake_private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEfakekeycontent\n-----END RSA PRIVATE KEY-----"
        with pytest.raises(
            ValidationError, match="apparent secret material matching prohibited pattern"
        ) as exc_info_pk:
            CanonicalFinding(
                rule_id="semgrep.test",
                source=FindingSource.SEMGREP,
                category=FindingCategory.INJECTION,
                title="Test",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="app.py",
                start_line=1,
                end_line=1,
                snippet="test()",
                remediation="Fix",
                fingerprint="c" * 64,
                raw={"info": {"context": fake_private_key}},
            )
        assert "MIIEfakekeycontent" not in str(exc_info_pk.value)

    def test_create_canonical_rejects_secret_value_in_raw_metadata(
        self, sample_secret_value: str, sample_fingerprint_key: str
    ) -> None:
        """create_canonical must reject raw metadata containing the secret value even under an innocent key."""
        with pytest.raises(ValueError, match="Raw secret value cannot appear in raw metadata") as exc_info:
            CanonicalFinding.create_canonical(
                rule_id="token-rule",
                source=FindingSource.GITLEAKS,
                category=FindingCategory.HARDCODED_SECRET,
                title="Secret leak",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="config.py",
                start_line=1,
                end_line=1,
                snippet="API_KEY = '[REDACTED:token-rule]'",
                remediation="Rotate",
                secret_value=sample_secret_value,
                fingerprint_key=sample_fingerprint_key,
                raw={"innocent_label": sample_secret_value},  # Secret placed in harmless key!
            )
        # Secret value must NEVER be echoed in error message
        assert sample_secret_value not in str(exc_info.value)

    def test_create_canonical_rejects_unredacted_secret_in_snippet(
        self, sample_secret_value: str, sample_fingerprint_key: str
    ) -> None:
        unredacted_snippet = f"API_KEY = '{sample_secret_value}'"
        with pytest.raises(ValueError, match="cannot appear unredacted in finding snippet") as exc_info:
            CanonicalFinding.create_canonical(
                rule_id="token-rule",
                source=FindingSource.GITLEAKS,
                category=FindingCategory.HARDCODED_SECRET,
                title="Unredacted Secret Leak",
                description="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                verification_status=VerificationStatus.SCANNER_DETECTED,
                file_path="config.py",
                start_line=1,
                end_line=1,
                snippet=unredacted_snippet,  # Plaintext secret leak!
                remediation="Rotate",
                secret_value=sample_secret_value,
                fingerprint_key=sample_fingerprint_key,
            )
        assert sample_secret_value not in str(exc_info.value)

    def test_canonical_finding_is_frozen_immutable(self) -> None:
        finding = CanonicalFinding(
            rule_id="ai.eval",
            source=FindingSource.AI,
            category=FindingCategory.INJECTION,
            title="Eval usage",
            description="Test",
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.MEDIUM,
            verification_status=VerificationStatus.AI_GROUNDED,
            file_path="app.py",
            start_line=1,
            end_line=2,
            snippet="eval()",
            remediation="Fix",
            fingerprint="b" * 64,
        )
        with pytest.raises(ValidationError):
            finding.severity = FindingSeverity.CRITICAL  # type: ignore[misc]
