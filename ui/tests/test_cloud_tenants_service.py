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

    def test_tenant_fields_from_assessment(self):
        fields = cloud_tenants_service.tenant_fields_from_assessment({
            "tenant_id": "28f91c7c-d50f-4c19-9a26-0504aca35c52",
            "evidence": {
                "tenant_profile": {
                    "tenant_name": "LTIM SecCOE",
                    "primary_domain": "ltimsec.com",
                }
            },
        })
        self.assertEqual(fields["tenant_id"], "28f91c7c-d50f-4c19-9a26-0504aca35c52")
        self.assertEqual(fields["tenant_name"], "LTIM SecCOE")
        self.assertEqual(fields["primary_domain"], "ltimsec.com")
        self.assertEqual(fields["cloud_provider"], "Azure")

    def test_tenant_fields_from_assessment_profile_only(self):
        fields = cloud_tenants_service.tenant_fields_from_assessment({
            "evidence": {
                "tenant_id": "tenant-1",
                "tenant_profile": {
                    "tenant_name": "Contoso",
                    "tenant_id": "tenant-1",
                    "primary_domain": "contoso.com",
                },
            }
        })
        self.assertEqual(fields["tenant_id"], "tenant-1")
        self.assertEqual(fields["tenant_name"], "Contoso")
        self.assertEqual(fields["primary_domain"], "contoso.com")

    def test_fallback_domain(self):
        self.assertEqual(
            cloud_tenants_service._fallback_domain("tenant-1"),
            "tenant-1.onmicrosoft.com",
        )


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
