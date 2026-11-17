import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


CLONES = [
    {
        "firewall_id": "11",
        "id": "11",
        "target_asset_id": "11",
        "firewall_name": "vmpafw01",
        "device_name": "vmpafw01",
        "host_name": "20.44.53.215",
        "host_ip": "20.44.53.215",
        "firewall_host": "20.44.53.215",
        "status": "live",
        "vendor": "Palo Alto",
        "source": "managed_firewalls",
    },
    {
        "firewall_id": "12",
        "id": "12",
        "target_asset_id": "12",
        "firewall_name": "vmpafw01-clone",
        "device_name": "vmpafw01-clone",
        "host_name": "20.44.53.215",
        "host_ip": "20.44.53.215",
        "firewall_host": "20.44.53.215",
        "status": "live",
        "vendor": "Palo Alto",
        "source": "managed_firewalls",
    },
]


class ResolveWriteTargetTests(unittest.TestCase):
    def test_missing_target_returns_inventory_and_pending_write(self):
        from services.managed_targets import MissingFirewallError, resolve_write_target

        payload = {
            "operation": "apply_change",
            "conversation_id": "conv-1",
            "changes": [
                {
                    "category": "service",
                    "action": "delete",
                    "name": "HTTPS-8443",
                    "fields": {"Name": "HTTPS-8443"},
                }
            ],
        }
        with mock.patch(
            "services.managed_targets.list_managed_firewalls",
            return_value=CLONES,
        ):
            with self.assertRaises(MissingFirewallError) as raised:
                resolve_write_target(payload)
        exc = raised.exception
        self.assertEqual(exc.code, "MISSING_FIREWALL")
        self.assertEqual(len(exc.firewalls), 2)
        self.assertEqual(exc.pending_write["category"], "service")
        self.assertEqual(exc.pending_write["action"], "delete")
        self.assertEqual(exc.pending_write["name"], "HTTPS-8443")
        self.assertEqual(exc.pending_write["conversation_id"], "conv-1")
        self.assertFalse(exc.pending_write["bulk"])

    def test_host_alone_is_rejected(self):
        from services.managed_targets import MissingFirewallError, resolve_write_target

        with mock.patch(
            "services.managed_targets.list_managed_firewalls",
            return_value=CLONES,
        ):
            with self.assertRaises(MissingFirewallError):
                resolve_write_target({"firewall_host": "20.44.53.215"})

    def test_name_vmpafw01_is_validated(self):
        from services.managed_targets import resolve_write_target

        with mock.patch(
            "services.managed_targets.list_managed_firewalls",
            return_value=CLONES,
        ):
            target = resolve_write_target({"firewall_name": "vmpafw01"})
        self.assertEqual(target["firewall_id"], "11")
        self.assertEqual(target["firewall_name"], "vmpafw01")

    def test_live_firewall_host_name_and_id(self):
        from services.managed_targets import resolve_write_target

        live = [
            {
                "firewall_id": "2",
                "id": "2",
                "target_asset_id": "2",
                "firewall_name": "vmpafw01",
                "device_name": "vmpafw01",
                "name": "vmpafw01",
                "host_name": "20.44.53.215",
                "host_ip": "20.44.53.215",
                "firewall_host": "20.44.53.215",
                "status": "live",
            },
            {
                "firewall_id": "4",
                "id": "4",
                "target_asset_id": "4",
                "firewall_name": "vmpafw03",
                "device_name": "vmpafw03",
                "name": "vmpafw03",
                "host_name": "20.44.53.215",
                "host_ip": "20.44.53.215",
                "firewall_host": "20.44.53.215",
                "status": "live",
            },
            {
                "firewall_id": "5",
                "id": "5",
                "target_asset_id": "5",
                "firewall_name": "vmpafw04",
                "device_name": "vmpafw04",
                "name": "vmpafw04",
                "host_name": "20.44.53.215",
                "host_ip": "20.44.53.215",
                "firewall_host": "20.44.53.215",
                "status": "live",
            },
        ]
        with mock.patch(
            "services.managed_targets.list_managed_firewalls",
            return_value=live,
        ):
            by_host_name = resolve_write_target({"firewall_host": "vmpafw01"})
            by_asset = resolve_write_target({"target_asset_id": "2"})
            by_host_id = resolve_write_target({"firewall_host": "2"})
        self.assertEqual(by_host_name["firewall_id"], "2")
        self.assertEqual(by_asset["firewall_name"], "vmpafw01")
        self.assertEqual(by_host_id["firewall_name"], "vmpafw01")

    def test_unknown_name_is_invalid(self):
        from services.managed_targets import InvalidFirewallError, resolve_write_target

        with mock.patch(
            "services.managed_targets.list_managed_firewalls",
            return_value=CLONES,
        ):
            with self.assertRaises(InvalidFirewallError) as raised:
                resolve_write_target({"firewall_name": "not-a-firewall"})
        self.assertEqual(raised.exception.code, "INVALID_FIREWALL")

    def test_create_job_does_not_fall_back_to_default_host(self):
        from services import firewall_jobs

        with mock.patch(
            "services.managed_targets.list_managed_firewalls",
            return_value=CLONES,
        ):
            with self.assertRaises(firewall_jobs.JobValidationError):
                firewall_jobs.create_job(
                    "user-1",
                    {
                        "operation": "apply_change",
                        "changes": [
                            {
                                "category": "address",
                                "action": "create",
                                "name": "webserver12",
                                "fields": {
                                    "Name": "webserver12",
                                    "Address Type": "ip-netmask",
                                    "Address Value": "10.20.30.12/32",
                                },
                            }
                        ],
                    },
                )


class JobIdentityTests(unittest.TestCase):
    def test_identity_requires_id_or_name_and_host(self):
        from services.managed_targets import job_identity

        body = job_identity(CLONES[0])
        self.assertEqual(body["target_asset_id"], "11")
        self.assertEqual(body["firewall_host"], "20.44.53.215")
        self.assertEqual(body["firewall_name"], "vmpafw01")


if __name__ == "__main__":
    unittest.main()
