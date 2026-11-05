import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from services.zero_trust_baseline_catalog import CONTROLS, PILLARS, PROFILES, payload
from services.zero_trust_control_copy import CONTROL_COPY


class ZeroTrustBaselineCatalogTests(unittest.TestCase):
    def test_payload_shape(self):
        data = payload()
        self.assertEqual([item["id"] for item in data["profiles"]], ["balanced", "recommended", "strict", "custom"])
        self.assertEqual(data["pillars"], list(PILLARS))
        self.assertEqual(len(data["controls"]), len(CONTROLS))
        self.assertTrue(data["storageKey"])
        self.assertIn("assessment-engine", data["disclaimer"])

    def test_every_control_copy_has_a_baseline_row(self):
        catalog_ids = {item["id"] for item in CONTROLS}
        self.assertEqual(catalog_ids, set(CONTROL_COPY.keys()))

    def test_mixed_control_kinds(self):
        kinds = {item["kind"] for item in CONTROLS}
        self.assertEqual(kinds, {"percent", "count", "toggle", "select"})

    def test_percent_and_count_have_explicit_pass_direction(self):
        for item in CONTROLS:
            if item["kind"] in ("percent", "count"):
                self.assertIn(item["pass"], ("gte", "lte"))
                self.assertIn("balanced", item["profiles"])
                self.assertIn("recommended", item["profiles"])
                self.assertIn("strict", item["profiles"])

    def test_mfa_threshold_is_assessment_engine_not_microsoft_product(self):
        mfa = next(item for item in CONTROLS if item["id"] == "ZT-ID-ID02-MFA")
        self.assertEqual(mfa["kind"], "percent")
        self.assertEqual(mfa["pass"], "gte")
        self.assertEqual(mfa["profiles"]["balanced"], 80)
        self.assertIn("assessment-engine", mfa["help"])
        self.assertIn("not a Microsoft Zero Trust product threshold", mfa["help"])

    def test_binary_controls_use_toggles(self):
        legacy = next(item for item in CONTROLS if item["id"] == "ZT-ID-ID04-LEGACY-AUTH")
        self.assertEqual(legacy["kind"], "toggle")
        self.assertTrue(legacy["profiles"]["balanced"])

    def test_inventory_controls_use_selectors(self):
        identity = next(item for item in CONTROLS if item["id"] == "ZT-ID-ID01-INVENTORY")
        self.assertEqual(identity["kind"], "select")
        self.assertEqual(identity["options"], ["Users", "Guests", "Groups", "Applications", "Service principals"])

    def test_profile_strictness_does_not_relax_balanced(self):
        for item in CONTROLS:
            balanced = item["profiles"]["balanced"]
            recommended = item["profiles"]["recommended"]
            strict = item["profiles"]["strict"]
            if item["kind"] == "percent" and item["pass"] == "gte":
                self.assertGreaterEqual(recommended, balanced)
                self.assertGreaterEqual(strict, recommended)
            elif item["kind"] == "count" and item["pass"] == "lte":
                self.assertLessEqual(recommended, balanced)
                self.assertLessEqual(strict, recommended)
            elif item["kind"] == "toggle":
                self.assertTrue(recommended)
                self.assertTrue(strict)


if __name__ == "__main__":
    unittest.main()
