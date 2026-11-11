import os
import sys
import unittest
from types import SimpleNamespace

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from services import zero_trust_store


def _row(**overrides):
    base = dict(
        assessment_id="zt-1",
        status="completed",
        scope="tenant",
        tenant_id="tenant-1",
        subscription_id="sub-1",
        started_at=None,
        updated_at=None,
        completed_at=None,
        progress=100,
        message="Assessment completed.",
        score=49,
        summary={
            "checks": 2,
            "passed": 1,
            "failed": 1,
            "errors": 0,
            "pillars": {"Identity": {"score": 50, "checks": 2}},
        },
        evidence={
            "tenant_id": "tenant-1",
            "subscription_id": "sub-1",
            "tenant_profile": {
                "available": True,
                "tenant_name": "Contoso",
                "primary_domain": "contoso.com",
                "users": 10,
                "guests": 2,
                "groups": 5,
                "applications": 7,
                "service_principals": 9,
            },
            "managed_devices": {"available": True, "count": 4, "devices": []},
        },
        report={
            "score": 49,
            "findings": [
                {
                    "id": "ZT-ID-1",
                    "title": "Identity inventory available",
                    "pillar": "Identity",
                    "status": "Pass",
                    "severity": "Medium",
                    "detail": "ok",
                },
                {
                    "id": "ZT-ID-2",
                    "title": "MFA enforced",
                    "pillar": "Identity",
                    "status": "Fail",
                    "severity": "High",
                    "detail": "missing",
                },
            ],
            "pillars": {"Identity": {"score": 50}},
        },
        error=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _canonical_payload(**overrides):
    payload = {
        "assessment_id": "zt-1",
        "status": "completed",
        "scope": "tenant",
        "progress": 100,
        "message": "Assessment completed.",
        "score": 49,
        "started_at": None,
        "updated_at": None,
        "completed_at": None,
        "tenant_id": "tenant-1",
        "subscription_id": "sub-1",
        "summary": {
            "checks": 2,
            "passed": 1,
            "failed": 1,
            "errors": 0,
            "pillars": {"Identity": {"score": 50, "checks": 2}},
        },
        "findings": [
            {
                "id": "ZT-ID-1",
                "title": "Identity inventory available",
                "pillar": "Identity",
                "status": "Pass",
                "severity": "Medium",
                "detail": "ok",
            },
            {
                "id": "ZT-ID-2",
                "title": "MFA enforced",
                "pillar": "Identity",
                "status": "Fail",
                "severity": "High",
                "detail": "missing",
            },
        ],
        "pillars": {"Identity": {"score": 50}},
        "evidence": {
            "tenant_profile": {
                "available": True,
                "tenant_name": "Contoso",
                "primary_domain": "contoso.com",
                "users": 10,
                "guests": 2,
                "groups": 5,
                "applications": 7,
                "service_principals": 9,
            },
            "managed_devices": {"available": True, "count": 4, "devices": []},
        },
    }
    payload.update(overrides)
    return payload


class FakeCanonical:
    def __init__(self, payload=None, rows=None):
        self.payload = payload
        self.rows = rows or {}
        self.saved = []

    def load_run(self, assessment_id):
        if self.payload is None or self.payload["assessment_id"] != assessment_id:
            return None
        return self.payload

    def latest_run(self):
        return self.payload

    def list_runs(self, limit=200):
        if self.payload is None:
            return []
        return [self.payload]

    def get_row(self, assessment_id):
        return SimpleNamespace(assessment_id=assessment_id) if assessment_id in self.rows else None

    def count(self):
        if self.payload is not None:
            return 1
        return len(self.rows)

    def latest_completed_at(self):
        if self.payload is not None:
            return self.payload.get("completed_at")
        return None

    def save_run(self, payload, user_id="anonymous"):
        self.saved.append((payload, user_id))
        self.payload = payload
        self.rows[payload["assessment_id"]] = payload
        return payload["assessment_id"]


class FakeLegacy:
    def __init__(self, row=None):
        self.row = row

    def get_assessment(self, assessment_id):
        if self.row is None or self.row.assessment_id != assessment_id:
            return None
        return self.row

    def list_assessments(self, limit=50):
        return [self.row] if self.row else []

    def count(self):
        return 1 if self.row else 0


class ZeroTrustStoreTests(unittest.TestCase):
    def setUp(self):
        self._canonical = zero_trust_store._canonical
        self._legacy = zero_trust_store._legacy
        self.canonical = FakeCanonical(payload=_canonical_payload())
        self.legacy = FakeLegacy(row=_row())
        zero_trust_store._canonical = lambda: self.canonical
        zero_trust_store._legacy = lambda: self.legacy

    def tearDown(self):
        zero_trust_store._canonical = self._canonical
        zero_trust_store._legacy = self._legacy

    def test_results_rebuild_from_canonical_payload(self):
        payload = zero_trust_store.get_results("zt-1")
        self.assertEqual(payload["status"], "completed")
        assessment = payload["assessment"]
        self.assertEqual(assessment["score"], 49)
        self.assertEqual(assessment["tenant"]["tenantName"], "Contoso")
        self.assertEqual(assessment["tenant"]["users"], 10)
        self.assertEqual(len(assessment["identity"]["tests"]), 2)

    def test_status_includes_full_assessment_only_when_requested(self):
        summary = zero_trust_store.get_status("zt-1")
        self.assertNotIn("assessment", summary)
        self.assertEqual(summary["progress"], 100)
        full = zero_trust_store.get_status("zt-1", full=True)
        self.assertIn("assessment", full)
        self.assertEqual(full["assessment"]["assessmentId"], "zt-1")

    def test_missing_assessment_raises_not_found(self):
        self.canonical = FakeCanonical(payload=None)
        self.legacy = FakeLegacy(row=None)
        with self.assertRaises(zero_trust_store.ZeroTrustStoreError) as ctx:
            zero_trust_store.get_results("missing")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_running_assessment_returns_no_data(self):
        self.canonical = FakeCanonical(
            payload=_canonical_payload(status="running", progress=10, findings=[])
        )
        payload = zero_trust_store.get_results("zt-1")
        self.assertEqual(payload["status"], "running")
        self.assertEqual(payload["progress"], 10)
        self.assertIsNone(payload["assessment"])

    def test_latest_summary_reads_canonical_row(self):
        summary = zero_trust_store.latest_summary()
        self.assertEqual(summary["assessmentId"], "zt-1")
        self.assertEqual(summary["score"], 49)

    def test_empty_store_reports_no_data(self):
        self.canonical = FakeCanonical(payload=None)
        self.legacy = FakeLegacy(row=None)
        self.assertIsNone(zero_trust_store.latest_summary())
        self.assertFalse(zero_trust_store.available())

    def test_results_do_not_read_legacy_table(self):
        self.canonical = FakeCanonical(payload=None)
        with self.assertRaises(zero_trust_store.ZeroTrustStoreError) as ctx:
            zero_trust_store.get_results("zt-1")
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(self.canonical.saved, [])

    def test_sync_legacy_mirrors_into_canonical_storage(self):
        self.canonical = FakeCanonical(payload=None)
        payload = zero_trust_store.sync_legacy("zt-1")
        self.assertEqual(payload["assessment_id"], "zt-1")
        self.assertEqual(len(self.canonical.saved), 1)
        mirrored, user_id = self.canonical.saved[0]
        self.assertEqual(mirrored["assessment_id"], "zt-1")
        self.assertEqual(user_id, "zero-trust-function")

    def test_sync_missing_skips_rows_already_canonical(self):
        self.canonical = FakeCanonical(payload=None, rows={"zt-1": {}})
        mirrored = zero_trust_store.sync_missing()
        self.assertEqual(mirrored, [])

    def test_latest_summary_ignores_legacy_row(self):
        self.canonical = FakeCanonical(payload=None)
        self.assertIsNone(zero_trust_store.latest_summary())
        self.assertFalse(zero_trust_store.available())


if __name__ == "__main__":
    unittest.main()
