"""Tests for intel_derive — pure functions, no I/O."""

from datetime import UTC, datetime

from src.rubricai.intel_derive import (
    _infer_utility_from_cvss,
    _infer_utility_from_description,
    _parse_cvss_vector,
    derive_finding_context,
)
from src.rubricai.schemas.intel import CvssInfo, IntelResult


def _make_intel(
    description: str | None = None,
    cvss_vector: str | None = None,
    cvss_base: float = 8.8,
) -> IntelResult:
    return IntelResult(
        cve_or_id="CVE-2024-TEST",
        retrieved_at=datetime.now(tz=UTC),
        sources=["NVD"],
        description=description,
        cvss=(
            CvssInfo(base=cvss_base, vector=cvss_vector, version="3.1")
            if cvss_vector
            else None
        ),
    )


# ---------------------------------------------------------------------------
# _parse_cvss_vector
# ---------------------------------------------------------------------------


class TestParseCvssVector:
    def test_parses_v31_vector(self):
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        parts = _parse_cvss_vector(vec)
        assert parts["AV"] == "N"
        assert parts["AC"] == "L"
        assert parts["PR"] == "N"
        assert parts["C"] == "H"
        assert parts["I"] == "H"
        assert parts["A"] == "H"

    def test_parses_physical_access_vector(self):
        vec = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        parts = _parse_cvss_vector(vec)
        assert parts["AV"] == "P"
        assert parts["PR"] == "H"

    def test_empty_string_returns_empty(self):
        assert _parse_cvss_vector("") == {}

    def test_no_colons_returns_empty(self):
        # Junk input — no k:v pairs
        assert _parse_cvss_vector("notavector") == {}

    def test_partial_vector_still_parsed(self):
        parts = _parse_cvss_vector("AV:N/AC:L")
        assert parts["AV"] == "N"
        assert parts["AC"] == "L"


# ---------------------------------------------------------------------------
# _infer_utility_from_description
# ---------------------------------------------------------------------------


class TestInferUtilityFromDescription:
    def test_rce_keywords(self):
        assert "rce" in _infer_utility_from_description(
            "allows remote code execution via crafted packet"
        )

    def test_auth_bypass_keywords(self):
        assert "auth_bypass" in _infer_utility_from_description(
            "authentication bypass allows unauthenticated access"
        )

    def test_privilege_escalation(self):
        assert "priv_esc" in _infer_utility_from_description(
            "local privilege escalation to root"
        )

    def test_data_exfiltration(self):
        assert "data_access" in _infer_utility_from_description(
            "allows exfiltration of sensitive data via crafted request"
        )

    def test_denial_of_service(self):
        assert "dos" in _infer_utility_from_description(
            "denial of service via resource exhaustion"
        )

    def test_tampering(self):
        assert "tampering" in _infer_utility_from_description(
            "allows attacker to modify configuration files"
        )

    def test_multiple_matches_returned(self):
        result = _infer_utility_from_description(
            "remote code execution with privilege escalation possible"
        )
        assert "rce" in result
        assert "priv_esc" in result

    def test_no_match_returns_other(self):
        result = _infer_utility_from_description(
            "this vulnerability affects a logging component"
        )
        assert result == ["other"]

    def test_case_insensitive(self):
        assert "rce" in _infer_utility_from_description("REMOTE CODE EXECUTION")


# ---------------------------------------------------------------------------
# _infer_utility_from_cvss
# ---------------------------------------------------------------------------


class TestInferUtilityFromCvss:
    def test_high_confidentiality_maps_to_data_access(self):
        assert "data_access" in _infer_utility_from_cvss({"C": "H"})

    def test_high_integrity_maps_to_tampering(self):
        assert "tampering" in _infer_utility_from_cvss({"I": "H"})

    def test_high_availability_maps_to_dos(self):
        assert "dos" in _infer_utility_from_cvss({"A": "H"})

    def test_all_high_returns_all_three(self):
        result = _infer_utility_from_cvss({"C": "H", "I": "H", "A": "H"})
        assert set(result) == {"data_access", "tampering", "dos"}

    def test_all_none_returns_other(self):
        result = _infer_utility_from_cvss({"C": "N", "I": "N", "A": "N"})
        assert result == ["other"]

    def test_empty_dict_returns_other(self):
        assert _infer_utility_from_cvss({}) == ["other"]


# ---------------------------------------------------------------------------
# derive_finding_context
# ---------------------------------------------------------------------------


class TestDeriveFindingContext:
    def test_confidence_cvss_plus_description(self):
        intel = _make_intel(
            description="Remote code execution via network",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        ctx = derive_finding_context(intel)
        assert ctx["confidence"] == "cvss+description"

    def test_confidence_cvss_only(self):
        intel = _make_intel(
            description=None,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        ctx = derive_finding_context(intel)
        assert ctx["confidence"] == "cvss_only"

    def test_confidence_description_only(self):
        intel = _make_intel(description="Remote code execution")
        # no CVSS vector
        ctx = derive_finding_context(intel)
        assert ctx["confidence"] == "description_only"

    def test_confidence_none(self):
        intel = IntelResult(
            cve_or_id="CVE-2024-TEST",
            retrieved_at=datetime.now(tz=UTC),
            sources=["NVD"],
        )
        ctx = derive_finding_context(intel)
        assert ctx["confidence"] == "none"
        assert ctx["attacker_utility"] == ["other"]

    def test_entry_point_network_av(self):
        intel = _make_intel(
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        ctx = derive_finding_context(intel)
        # cvss_av is top-level — NOT nested in entry_point so that entry_point
        # is safe to pass directly to Finding.entry_point (extra="forbid")
        assert "cvss_av" not in ctx["entry_point"]
        assert ctx["cvss_av"] == "N"
        assert "Network" in ctx["entry_point"]["description"]

    def test_entry_point_physical_av(self):
        intel = _make_intel(
            cvss_vector="CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        )
        ctx = derive_finding_context(intel)
        assert "cvss_av" not in ctx["entry_point"]
        assert ctx["cvss_av"] == "P"
        assert "Physical" in ctx["entry_point"]["description"]

    def test_entry_point_unknown_when_no_cvss(self):
        intel = _make_intel(description="Some vulnerability")
        ctx = derive_finding_context(intel)
        assert ctx["cvss_av"] is None
        assert "Unknown" in ctx["entry_point"]["description"]

    def test_preconditions_from_cvss(self):
        intel = _make_intel(
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
        )
        ctx = derive_finding_context(intel)
        assert ctx["preconditions"]["privileges_required"] == "low"
        assert ctx["preconditions"]["attack_complexity"] == "low"
        assert ctx["preconditions"]["user_interaction"] is True

    def test_preconditions_none_privileges_required(self):
        intel = _make_intel(
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        ctx = derive_finding_context(intel)
        assert ctx["preconditions"]["privileges_required"] == "none"
        assert ctx["preconditions"]["user_interaction"] is False

    def test_preconditions_use_unknown_when_no_cvss(self):
        """No CVSS vector → preconditions fall back to model defaults, not None."""
        intel = IntelResult(
            cve_or_id="CVE-2024-TEST",
            retrieved_at=datetime.now(tz=UTC),
            sources=["NVD"],
        )
        ctx = derive_finding_context(intel)
        # Values must be Preconditions-compatible (no None) so the dict can be
        # passed directly to Finding.preconditions without a validation error.
        from src.rubricai.schemas.finding import Preconditions

        p = Preconditions.model_validate(ctx["preconditions"])
        assert p.privileges_required == "unknown"
        assert p.attack_complexity == "unknown"
        assert p.user_interaction is False

    def test_attacker_utility_from_description_preferred(self):
        # Description says RCE but CVSS impacts alone would give data_access/tampering
        intel = _make_intel(
            description="allows remote code execution via buffer overflow",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        ctx = derive_finding_context(intel)
        assert "rce" in ctx["attacker_utility"]

    def test_description_returned_in_context(self):
        intel = _make_intel(description="Remote code execution via buffer overflow")
        ctx = derive_finding_context(intel)
        assert ctx["description"] == "Remote code execution via buffer overflow"

    def test_description_none_when_not_provided(self):
        intel = IntelResult(
            cve_or_id="CVE-2024-TEST",
            retrieved_at=datetime.now(tz=UTC),
            sources=["NVD"],
        )
        ctx = derive_finding_context(intel)
        assert ctx["description"] is None
