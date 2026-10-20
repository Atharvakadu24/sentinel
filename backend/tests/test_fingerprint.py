"""Unit tests for deterministic, versioned finding fingerprints (Blueprint 10.4 / 10.6)."""

from __future__ import annotations

import pytest

from app.domain.fingerprint import (
    FINGERPRINT_VERSION,
    assign_occurrence_indices,
    collapse_whitespace,
    compute_code_anchor,
    compute_finding_fingerprint,
    compute_rule_key,
    compute_secret_anchor,
    validate_fingerprint_key,
)


class TestFingerprintGeneration:
    """Tests for deterministic fingerprinting, immutability, and safety."""

    def test_default_version_constant(self) -> None:
        assert FINGERPRINT_VERSION == "v1"

    def test_collapse_whitespace(self) -> None:
        assert collapse_whitespace("  hello \t\r\n world  ") == "helloworld"

    def test_deterministic_output(self, sample_sql_injection_code: str) -> None:
        anchor = compute_code_anchor(sample_sql_injection_code)
        fp1 = compute_finding_fingerprint(
            rule_id="python.lang.security.audit.sqli",
            source="semgrep",
            file_path="app/db/user_repo.py",
            anchor=anchor,
            occ=0,
        )
        for _ in range(100):
            fp2 = compute_finding_fingerprint(
                rule_id="python.lang.security.audit.sqli",
                source="semgrep",
                file_path="app/db/user_repo.py",
                anchor=anchor,
                occ=0,
            )
            assert fp1 == fp2
        assert len(fp1) == 64

    def test_line_number_independence(self) -> None:
        """Moving code lines up or down in a file MUST NOT change the finding fingerprint."""
        code = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
        anchor = compute_code_anchor(code)

        # Finding at line 10
        fp_line_10 = compute_finding_fingerprint(
            rule_id="sqli-rule",
            source="semgrep",
            file_path="services/user.py",
            anchor=anchor,
            occ=0,
        )

        # Same finding at line 250 due to edits above it
        fp_line_250 = compute_finding_fingerprint(
            rule_id="sqli-rule",
            source="semgrep",
            file_path="services/user.py",
            anchor=anchor,
            occ=0,
        )

        assert fp_line_10 == fp_line_250

    def test_whitespace_and_indent_immunity(self) -> None:
        """Indentation or CRLF changes to the code lines MUST NOT change the code anchor."""
        code_2_spaces = "  def run():\n    eval(x)\n"
        code_4_spaces = "    def run():\r\n        eval(x)\r\n"
        code_tabs = "\tdef run():\n\teval(x)\n"

        anchor_2 = compute_code_anchor(code_2_spaces)
        anchor_4 = compute_code_anchor(code_4_spaces)
        anchor_tabs = compute_code_anchor(code_tabs)

        assert anchor_2 == anchor_4 == anchor_tabs
        assert len(anchor_2) == 16

    def test_code_modification_changes_anchor_and_fingerprint(self) -> None:
        """Modifying the actual flagged code MUST generate a new fingerprint (requires re-review)."""
        code_v1 = "db.execute(f'SELECT * FROM users WHERE name = {name}')"
        code_v2 = "db.execute(f'SELECT id, name FROM users WHERE name = {name}')"

        anchor_v1 = compute_code_anchor(code_v1)
        anchor_v2 = compute_code_anchor(code_v2)
        assert anchor_v1 != anchor_v2

        fp_v1 = compute_finding_fingerprint(
            rule_id="sqli", source="semgrep", file_path="app.py", anchor=anchor_v1
        )
        fp_v2 = compute_finding_fingerprint(
            rule_id="sqli", source="semgrep", file_path="app.py", anchor=anchor_v2
        )
        assert fp_v1 != fp_v2

    def test_secret_safe_anchor_handling(
        self, sample_secret_value: str, sample_fingerprint_key: str
    ) -> None:
        """Raw secret values are HMAC-hashed and never exposed in the anchor or fingerprint."""
        anchor = compute_secret_anchor(sample_secret_value, sample_fingerprint_key)
        assert len(anchor) == 16
        # Raw secret string must NOT be present in the hex anchor
        assert sample_secret_value not in anchor

        fp = compute_finding_fingerprint(
            rule_id="generic-api-key",
            source="gitleaks",
            file_path="config/settings.py",
            anchor=anchor,
            category="hardcoded_secret",
        )
        assert sample_secret_value not in fp
        assert len(fp) == 64

    def test_secret_anchor_requires_key_and_secret(self) -> None:
        with pytest.raises(ValueError, match="Secret value cannot be empty"):
            compute_secret_anchor("", "a_valid_length_key_16_bytes")
        with pytest.raises(TypeError, match="Secret value must be a string"):
            compute_secret_anchor(None, "a_valid_length_key_16_bytes")  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="FINGERPRINT_KEY must be provided"):
            compute_secret_anchor("secret_token", "")
        with pytest.raises(ValueError, match="FINGERPRINT_KEY must be provided"):
            compute_secret_anchor("secret_token", b"")
        with pytest.raises(ValueError, match="FINGERPRINT_KEY must not be whitespace-only"):
            compute_secret_anchor("secret_token", "                ")
        with pytest.raises(ValueError, match="FINGERPRINT_KEY must not be whitespace-only"):
            compute_secret_anchor("secret_token", b"                ")
        with pytest.raises(ValueError, match="at least 16 bytes"):
            compute_secret_anchor("secret_token", "short_weak_key")
        with pytest.raises(ValueError, match="at least 16 bytes"):
            compute_secret_anchor("secret_token", b"short_weak_key")
        with pytest.raises(ValueError, match="cannot be an unconfigured template placeholder"):
            compute_secret_anchor(
                "secret_token", "replace-with-a-secure-random-hex-key-for-fingerprinting"
            )
        with pytest.raises(TypeError, match="FINGERPRINT_KEY must be str or bytes"):
            compute_secret_anchor("secret_token", 1234567890123456)  # type: ignore[arg-type]

    def test_secret_anchor_preserves_valid_key_whitespace_without_mutating(
        self, sample_secret_value: str
    ) -> None:
        """Valid key whitespace must never be silently trimmed before HMAC calculation."""
        padded_key = "  0123456789abcdef0123456789abcdef  "
        unpadded_key = "0123456789abcdef0123456789abcdef"

        assert validate_fingerprint_key(padded_key) == padded_key.encode("utf-8")

        anchor_padded = compute_secret_anchor(sample_secret_value, padded_key)
        anchor_unpadded = compute_secret_anchor(sample_secret_value, unpadded_key)

        # Different key bytes produce different HMAC anchors
        assert anchor_padded != anchor_unpadded

        # Bytes key produces identical anchor to UTF-8 encoded string key
        anchor_bytes = compute_secret_anchor(sample_secret_value, unpadded_key.encode("utf-8"))
        assert anchor_bytes == anchor_unpadded

    def test_different_keys_produce_different_secret_anchors(
        self, sample_secret_value: str
    ) -> None:
        anchor_k1 = compute_secret_anchor(sample_secret_value, "key_one_32_bytes_long_secret_1")
        anchor_k2 = compute_secret_anchor(sample_secret_value, "key_two_32_bytes_long_secret_2")
        assert anchor_k1 != anchor_k2

    def test_rule_key_derivation(self) -> None:
        # Scanners use rule_id
        assert compute_rule_key("semgrep", "python.sql.injection") == "python.sql.injection"
        assert compute_rule_key("gitleaks", "github-pat") == "github-pat"

        # AI findings use 'ai:<category>'
        assert compute_rule_key("ai", "ignored_id", category="injection") == "ai:injection"
        assert compute_rule_key("ai", "ignored_id", category="XSS") == "ai:xss"

        # AI requires category
        with pytest.raises(ValueError, match="Category is required to compute AI rule key"):
            compute_rule_key("ai", "some_rule", category=None)

        # Pipe delimiter rejection prevents collision in fingerprint payloads
        with pytest.raises(ValueError, match="rule_id must not contain pipe"):
            compute_rule_key("semgrep", "rule|injection")
        with pytest.raises(ValueError, match="Category must not contain pipe"):
            compute_rule_key("ai", "some_rule", category="inj|ection")

    def test_versioning_isolation(self, sample_sql_injection_code: str) -> None:
        anchor = compute_code_anchor(sample_sql_injection_code)
        fp_v1 = compute_finding_fingerprint(
            rule_id="sqli",
            source="semgrep",
            file_path="app.py",
            anchor=anchor,
            version="v1",
        )
        fp_v2 = compute_finding_fingerprint(
            rule_id="sqli",
            source="semgrep",
            file_path="app.py",
            anchor=anchor,
            version="v2",
        )
        assert fp_v1 != fp_v2

    def test_occurrence_indexing(self) -> None:
        """Duplicate identical findings in the same file get distinct fingerprints via occ."""
        anchor = "0123456789abcdef"
        fp_occ0 = compute_finding_fingerprint(
            rule_id="r1", source="semgrep", file_path="app.py", anchor=anchor, occ=0
        )
        fp_occ1 = compute_finding_fingerprint(
            rule_id="r1", source="semgrep", file_path="app.py", anchor=anchor, occ=1
        )
        assert fp_occ0 != fp_occ1

    def test_distinct_canonical_fields_produce_distinct_fingerprints(self) -> None:
        anchor = "0123456789abcdef"
        base_fp = compute_finding_fingerprint(
            rule_id="ruleA", source="semgrep", file_path="app/main.py", anchor=anchor, occ=0
        )

        diff_rule = compute_finding_fingerprint(
            rule_id="ruleB", source="semgrep", file_path="app/main.py", anchor=anchor, occ=0
        )
        diff_path = compute_finding_fingerprint(
            rule_id="ruleA", source="semgrep", file_path="app/other.py", anchor=anchor, occ=0
        )
        diff_anchor = compute_finding_fingerprint(
            rule_id="ruleA", source="semgrep", file_path="app/main.py", anchor="fedcba9876543210", occ=0
        )
        diff_occ = compute_finding_fingerprint(
            rule_id="ruleA", source="semgrep", file_path="app/main.py", anchor=anchor, occ=1
        )

        assert len({base_fp, diff_rule, diff_path, diff_anchor, diff_occ}) == 5

    def test_assign_occurrence_indices_ordering(self) -> None:
        items = [
            {"id": "f1", "rule": "r1", "path": "a.py", "anchor": "1111222233334444", "line": 50},
            {"id": "f2", "rule": "r1", "path": "a.py", "anchor": "1111222233334444", "line": 10},
            {"id": "f3", "rule": "r2", "path": "a.py", "anchor": "1111222233334444", "line": 20},
            {"id": "f4", "rule": "r1", "path": "a.py", "anchor": "1111222233334444", "line": 80},
        ]
        assigned = assign_occurrence_indices(
            items,
            key_func=lambda x: (str(x["rule"]), str(x["path"]), str(x["anchor"])),
            line_func=lambda x: int(str(x["line"])),
        )

        # Output preserves original item order with assigned occ
        res_by_id = {item["id"]: occ for item, occ in assigned}
        assert res_by_id["f2"] == 0  # lowest line (10) gets occ=0
        assert res_by_id["f1"] == 1  # line 50 gets occ=1
        assert res_by_id["f4"] == 2  # line 80 gets occ=2
        assert res_by_id["f3"] == 0  # different rule (r2), so occ=0

    def test_occurrence_indices_permutation_invariance(self) -> None:
        """Scan input ordering permutations produce identical occurrence index assignments."""
        items = [
            {"id": "a", "rule": "r1", "path": "p.py", "anchor": "aaaa111122223333", "line": 100},
            {"id": "b", "rule": "r1", "path": "p.py", "anchor": "aaaa111122223333", "line": 20},
        ]
        items_reversed = list(reversed(items))

        key_fn = lambda x: (str(x["rule"]), str(x["path"]), str(x["anchor"]))
        line_fn = lambda x: int(str(x["line"]))

        assigned_orig = {
            item["id"]: occ
            for item, occ in assign_occurrence_indices(items, key_func=key_fn, line_func=line_fn)
        }
        assigned_rev = {
            item["id"]: occ
            for item, occ in assign_occurrence_indices(
                items_reversed, key_func=key_fn, line_func=line_fn
            )
        }

        assert assigned_orig == assigned_rev == {"a": 1, "b": 0}

    def test_occurrence_indices_upstream_insertion_limitation(self) -> None:
        """Documented blueprint trade-off: inserting an earlier duplicate identical finding shifts occ.

        Section 10.6 specifies occ ordered by start_line. If an identical finding (same rule, file,
        anchor) is added earlier in the file, subsequent identical findings intentionally shift occ.
        """
        key_fn = lambda x: (str(x["rule"]), str(x["path"]), str(x["anchor"]))
        line_fn = lambda x: int(str(x["line"]))

        # Scan 1: Single finding at line 50
        scan_1 = [{"id": "inst_1", "rule": "r", "path": "a.py", "anchor": "1234567890abcdef", "line": 50}]
        assigned_1 = assign_occurrence_indices(scan_1, key_func=key_fn, line_func=line_fn)
        assert assigned_1[0][1] == 0

        # Scan 2: Developer adds an earlier identical finding at line 10
        scan_2 = [
            {"id": "inst_0", "rule": "r", "path": "a.py", "anchor": "1234567890abcdef", "line": 10},
            {"id": "inst_1", "rule": "r", "path": "a.py", "anchor": "1234567890abcdef", "line": 50},
        ]
        assigned_2 = {
            item["id"]: occ
            for item, occ in assign_occurrence_indices(scan_2, key_func=key_fn, line_func=line_fn)
        }
        assert assigned_2["inst_0"] == 0
        assert assigned_2["inst_1"] == 1  # Shifted from 0 to 1 due to earlier insertion
