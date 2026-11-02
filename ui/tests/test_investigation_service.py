"""Unit tests for the DB-backed Investigation Centre read model.

These tests exercise the pure logic only (status vocabulary, filter
normalisation, row mapping) so they run without a database.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.repositories.investigation_repository import (  # noqa: E402
    InvestigationRepository,
    domain_label,
    normalize_status,
    status_label,
)
from services.investigation_service import (  # noqa: E402
    FINDINGS_VIEW_DOMAINS,
    STATUS_VOCABULARY,
    _clean_filters,
    get_evidence,
    resolve_findings_view,
)


class StatusVocabularyTests(unittest.TestCase):
    def test_network_security_statuses(self):
        self.assertEqual(normalize_status("passed"), "compliant")
        self.assertEqual(normalize_status("failed"), "not_compliant")
        self.assertEqual(normalize_status("not_assessed"), "not_assessed")
        self.assertEqual(normalize_status("compliant"), "compliant")
        self.assertEqual(normalize_status("non_compliant"), "not_compliant")

    def test_zero_trust_statuses(self):
        self.assertEqual(normalize_status("passed", "zero_trust"), "pass")
        self.assertEqual(normalize_status("failed", "zero_trust"), "fail")
        self.assertEqual(normalize_status("error", "zero_trust"), "investigation")
        self.assertEqual(normalize_status("investigate", "zero_trust"), "investigation")

    def test_unknown_status_degrades(self):
        self.assertEqual(normalize_status(None), "not_assessed")
        self.assertEqual(normalize_status("something-else"), "not_assessed")

    def test_labels_follow_domain(self):
        self.assertEqual(status_label("fail", "zero_trust"), "Fail")
        self.assertEqual(status_label("not_compliant"), "Not Compliant")
        self.assertEqual(status_label("investigation"), "Investigation")

    def test_vocabulary_differs_by_domain(self):
        network = [o["value"] for o in STATUS_VOCABULARY["network_security"]]
        zt = [o["value"] for o in STATUS_VOCABULARY["zero_trust"]]
        self.assertEqual(network, ["compliant", "not_compliant", "not_assessed"])
        self.assertEqual(zt, ["pass", "fail", "investigation"])
        self.assertNotEqual(network, zt)

    def test_domain_labels(self):
        self.assertEqual(domain_label("network_security"), "Network Security")
        self.assertEqual(domain_label("zero_trust"), "Zero Trust")

    def test_findings_tabs_map_to_domains(self):
        self.assertEqual(resolve_findings_view(), "firewall_audit")
        self.assertEqual(resolve_findings_view("firewall-audit"), "firewall_audit")
        self.assertEqual(resolve_findings_view("zero_trust"), "zero_trust")
        self.assertEqual(resolve_findings_view(domain="zero_trust"), "zero_trust")
        self.assertEqual(resolve_findings_view("unknown", domain="network_security"), "firewall_audit")
        self.assertEqual(FINDINGS_VIEW_DOMAINS["firewall_audit"], "network_security")
        self.assertEqual(FINDINGS_VIEW_DOMAINS["zero_trust"], "zero_trust")


class FilterNormalisationTests(unittest.TestCase):
    def test_defaults_sort_and_blank_values(self):
        filters = _clean_filters({})
        self.assertEqual(filters["sort"], "severity")
        for key in ("domain", "assessment", "pillar", "category", "status", "severity", "risk", "date"):
            self.assertEqual(filters[key], "all")

    def test_all_aliases_collapse(self):
        filters = _clean_filters({"domain": "any", "status": "All", "pillar": ""})
        self.assertEqual(filters["domain"], "all")
        self.assertEqual(filters["status"], "all")
        self.assertEqual(filters["pillar"], "all")

    def test_alias_keys(self):
        filters = _clean_filters({"risk_range": "high", "assessment_id": "abc", "q": "mfa"})
        self.assertEqual(filters["risk"], "high")
        self.assertEqual(filters["assessment"], "abc")
        self.assertEqual(filters["search"], "mfa")

    def test_values_are_preserved(self):
        filters = _clean_filters(
            {"domain": "zero_trust", "pillar": "Identity", "status": "fail", "sort": "risk"}
        )
        self.assertEqual(filters["domain"], "zero_trust")
        self.assertEqual(filters["pillar"], "Identity")
        self.assertEqual(filters["status"], "fail")
        self.assertEqual(filters["sort"], "risk")


class StatusCandidatesTests(unittest.TestCase):
    def test_zero_trust_fail_excludes_network_error(self):
        candidates = InvestigationRepository._status_candidates("fail")
        self.assertIn("failed", candidates)
        self.assertNotIn("not_assessed", candidates)

    def test_investigation_maps_to_error(self):
        candidates = InvestigationRepository._status_candidates("investigation")
        self.assertIn("error", candidates)

    def test_compliant_includes_passed(self):
        candidates = InvestigationRepository._status_candidates("compliant")
        self.assertIn("passed", candidates)


class RowMappingTests(unittest.TestCase):
    def _row(self, **overrides):
        base = {
            "id": "1",
            "assessment_id": "A1",
            "security_domain": "network_security",
            "assessment_type": "firewall_audit",
            "firewall_id": "vmpafw01",
            "pillar": None,
            "category": "critical_cves",
            "control_id": "PA-02",
            "control_name": "PA-02",
            "status": "failed",
            "severity": "critical",
            "risk_score": 95,
            "title": "PA-02 - critical_cves",
            "finding": "outdated",
            "detail": "outdated detail",
            "observed_value": None,
            "expected_value": "0",
            "remediation": "patch",
            "completed_at": None,
            "started_at": None,
            "created_at": None,
        }
        base.update(overrides)
        return base

    def test_network_row_maps_status_label(self):
        repo = InvestigationRepository(session=None)
        mapped = repo._finding_row(self._row())
        self.assertEqual(mapped["status"], "not_compliant")
        self.assertEqual(mapped["status_label"], "Not Compliant")
        self.assertEqual(mapped["domain_label"], "Network Security")
        self.assertEqual(mapped["risk_score"], 95.0)

    def test_zero_trust_row_uses_pass_fail(self):
        repo = InvestigationRepository(session=None)
        mapped = repo._finding_row(
            self._row(security_domain="zero_trust", status="error", pillar="Identity")
        )
        self.assertEqual(mapped["status"], "investigation")
        self.assertEqual(mapped["status_label"], "Investigation")
        self.assertEqual(mapped["pillar"], "Identity")

    def test_dict_values_become_text(self):
        repo = InvestigationRepository(session=None)
        mapped = repo._finding_row(self._row(finding={"a": 1}))
        self.assertIn('"a": 1', mapped["finding"])


class EvidenceValidationTests(unittest.TestCase):
    def test_missing_assessment_id_rejected(self):
        body, status = get_evidence("")
        self.assertEqual(status, 400)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main()
