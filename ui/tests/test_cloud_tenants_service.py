"""Unit tests for cloud tenant inventory helpers.

These tests exercise validation and normalisation only so they run without
a database.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import cloud_tenants_service  # noqa: E402
from services import tenant_bulk_service  # noqa: E402


class CloudTenantValidationTests(unittest.TestCase):
    def test_normalize_provider_defaults_azure(self):
        self.assertEqual(cloud_tenants_service._normalize_provider(""), "Azure")
        self.assertEqual(cloud_tenants_service._normalize_provider("azure"), "Azure")
        self.assertEqual(cloud_tenants_service._normalize_provider("AWS"), "AWS")

    def test_normalize_provider_rejects_unknown(self):
        with self.assertRaises(ValueError):
            cloud_tenants_service._normalize_provider("Oracle")

    def test_normalize_status(self):
        self.assertEqual(cloud_tenants_service._normalize_status(None), "active")
        self.assertEqual(cloud_tenants_service._normalize_status("live"), "active")
        self.assertEqual(cloud_tenants_service._normalize_status("Down"), "inactive")
        with self.assertRaises(ValueError):
            cloud_tenants_service._normalize_status("pending")


class TenantBulkTemplateTests(unittest.TestCase):
    def test_template_headers(self):
        self.assertIn("Tenant Name", tenant_bulk_service.TEMPLATE_HEADERS)
        self.assertIn("Tenant ID", tenant_bulk_service.TEMPLATE_HEADERS)
        self.assertIn("Cloud Provider", tenant_bulk_service.TEMPLATE_HEADERS)
        self.assertIn("Primary Domain", tenant_bulk_service.TEMPLATE_HEADERS)
        self.assertIn("Action", tenant_bulk_service.TEMPLATE_HEADERS)

    def test_template_bytes(self):
        buffer = tenant_bulk_service.build_template_bytes()
        self.assertTrue(buffer.getvalue().startswith(b"PK"))


if __name__ == "__main__":
    unittest.main()
