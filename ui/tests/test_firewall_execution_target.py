import sys
import types
import unittest
from unittest import mock


def _install_stubs():
    if "requests" not in sys.modules:
        sys.modules["requests"] = types.ModuleType("requests")
    if "sqlalchemy" not in sys.modules:
        sqlalchemy = types.ModuleType("sqlalchemy")
        sqlalchemy.create_engine = lambda *_args, **_kwargs: None
        sqlalchemy.text = lambda value: value
        sys.modules["sqlalchemy"] = sqlalchemy
        orm = types.ModuleType("sqlalchemy.orm")
        orm.sessionmaker = lambda *_args, **_kwargs: None
        orm.declarative_base = lambda *_args, **_kwargs: object
        orm.relationship = lambda *_args, **_kwargs: None
        sys.modules["sqlalchemy.orm"] = orm
        sql_exc = types.ModuleType("sqlalchemy.exc")
        sql_exc.SQLAlchemyError = Exception
        sys.modules["sqlalchemy.exc"] = sql_exc
    if "database" not in sys.modules:
        database = types.ModuleType("database")
        database.db = types.ModuleType("database.db")
        database.db.get_session = lambda: None
        database.repositories = types.ModuleType("database.repositories")
        database.repositories.ManagedFirewallsRepository = object
        sys.modules["database"] = database
        sys.modules["database.db"] = database.db
        sys.modules["database.repositories"] = database.repositories
    if "services.managed_firewalls_service" not in sys.modules:
        managed = types.ModuleType("services.managed_firewalls_service")
        managed.list_firewalls = lambda: []
        managed.display_label = lambda value: value
        sys.modules["services.managed_firewalls_service"] = managed
    if "services.firewall_jobs_service" not in sys.modules:
        jobs = types.ModuleType("services.firewall_jobs_service")

        class FirewallJobsError(RuntimeError):
            def __init__(self, message, status_code=502):
                super().__init__(message)
                self.status_code = status_code

        jobs.FirewallJobsError = FirewallJobsError
        jobs.preflight = lambda *_args, **_kwargs: {"live": True, "host": "20.44.53.215"}
        jobs.create_and_dispatch_job = lambda *_args, **_kwargs: None
        sys.modules["services.firewall_jobs_service"] = jobs


_install_stubs()


CLONES = [
    {
        "id": 11,
        "device_name": "vmpafw01",
        "host_name": "20.44.53.215",
        "host_ip": "20.44.53.215",
        "host": "20.44.53.215",
        "status": "live",
        "label": "vmpafw01 (20.44.53.215)",
    },
    {
        "id": 12,
        "device_name": "vmpafw01-clone",
        "host_name": "20.44.53.215",
        "host_ip": "20.44.53.215",
        "host": "20.44.53.215",
        "status": "live",
        "label": "vmpafw01-clone (20.44.53.215)",
    },
]


class JobTargetFieldsTests(unittest.TestCase):
    def test_unique_identity_prefers_id_and_name(self):
        from services import netsec_service

        body = netsec_service.job_target_fields(CLONES[0])
        self.assertEqual(body["firewall_id"], "11")
        self.assertEqual(body["firewall_name"], "vmpafw01")
        self.assertEqual(body["device_name"], "vmpafw01")
        self.assertEqual(body["target_asset_id"], "11")
        self.assertEqual(body["firewall_host"], "vmpafw01")

    def test_missing_identity_raises(self):
        from services import netsec_service

        with self.assertRaises(ValueError):
            netsec_service.job_target_fields({"host": "20.44.53.215"})


class ResolveTargetTests(unittest.TestCase):
    def test_host_alone_is_ambiguous(self):
        from services import netsec_service

        with mock.patch.object(netsec_service, "list_target_firewalls", return_value=CLONES):
            with self.assertRaisesRegex(ValueError, "firewall_id or firewall_name"):
                netsec_service.resolve_target(firewall_host="20.44.53.215")

    def test_unique_id_wins_among_clones(self):
        from services import netsec_service

        with mock.patch.object(netsec_service, "list_target_firewalls", return_value=CLONES):
            target = netsec_service.resolve_target(firewall_id="12")
        self.assertEqual(target["device_name"], "vmpafw01-clone")
        self.assertEqual(target["id"], 12)

    def test_unique_name_wins_among_clones(self):
        from services import netsec_service

        with mock.patch.object(netsec_service, "list_target_firewalls", return_value=CLONES):
            target = netsec_service.resolve_target(firewall_name="vmpafw01")
        self.assertEqual(target["id"], 11)

    def test_name_as_firewall_id_still_resolves(self):
        from services import netsec_service

        with mock.patch.object(netsec_service, "list_target_firewalls", return_value=CLONES):
            target = netsec_service.resolve_target(firewall_id="vmpafw01")
        self.assertEqual(target["id"], 11)

    def test_live_name_as_firewall_host(self):
        from services import netsec_service

        live = [
            {
                "id": 2,
                "device_name": "vmpafw01",
                "host_name": "20.44.53.215",
                "host_ip": "20.44.53.215",
                "host": "20.44.53.215",
                "status": "live",
            },
            {
                "id": 4,
                "device_name": "vmpafw03",
                "host_name": "20.44.53.215",
                "host_ip": "20.44.53.215",
                "host": "20.44.53.215",
                "status": "live",
            },
            {
                "id": 5,
                "device_name": "vmpafw04",
                "host_name": "20.44.53.215",
                "host_ip": "20.44.53.215",
                "host": "20.44.53.215",
                "status": "live",
            },
        ]
        with mock.patch.object(netsec_service, "list_target_firewalls", return_value=live):
            by_name = netsec_service.resolve_target(firewall_host="vmpafw01")
            by_id = netsec_service.resolve_target(firewall_id="2")
            by_asset = netsec_service.resolve_target(firewall_host="2")
        self.assertEqual(by_name["id"], 2)
        self.assertEqual(by_id["device_name"], "vmpafw01")
        self.assertEqual(by_asset["device_name"], "vmpafw01")

    def test_missing_selection_raises(self):
        from services import netsec_service

        with mock.patch.object(netsec_service, "list_target_firewalls", return_value=CLONES):
            with self.assertRaisesRegex(ValueError, "firewall_id or firewall_name"):
                netsec_service.resolve_target()


class MaestroSelectionTests(unittest.TestCase):
    def test_extract_firewall_id_and_name(self):
        from services import maestro_firewall_jobs

        selection = maestro_firewall_jobs.extract_firewall_selection(
            "create object web-01 with ip 10.0.0.1 firewall_name=vmpafw01"
        )
        self.assertEqual(selection["firewall_name"], "vmpafw01")

        selection = maestro_firewall_jobs.extract_firewall_selection(
            "Approve",
            messages=[{"role": "user", "content": "Target vmpafw01"}],
        )
        self.assertEqual(selection["firewall_name"], "vmpafw01")

    def test_bulk_request_still_detected(self):
        from services import maestro_firewall_jobs

        self.assertTrue(maestro_firewall_jobs.is_bulk_upload_request("upload bulk changes"))
        self.assertTrue(maestro_firewall_jobs.is_bulk_upload_request("please upload an excel workbook"))
        self.assertFalse(maestro_firewall_jobs.is_bulk_upload_request("create object web-01 with ip 10.0.0.1"))

    def test_write_without_firewall_asks_for_selection(self):
        from services import maestro_firewall_jobs

        agent = {"id": "netsec-execution-agent", "name": "Firewall Execution Agent"}
        with mock.patch.object(
            maestro_firewall_jobs.netsec_service,
            "list_target_firewalls",
            return_value=CLONES,
        ):
            result = maestro_firewall_jobs.try_handle(
                agent,
                "user-1",
                "create object web-01 with ip 10.0.0.1",
            )
        self.assertIn("firewall_id or firewall_name", result["reply"])
        self.assertIn("Pending:", result["reply"])
        option_block = next(
            block for block in result["blocks"] if block.get("type") == "options"
        )
        self.assertEqual(option_block["title"], "Select firewall")
        self.assertTrue(any("vmpafw01" in opt["label"] for opt in option_block["options"]))

    def test_selection_continues_pending_write(self):
        from services import maestro_firewall_jobs

        agent = {"id": "netsec-execution-agent", "name": "Firewall Execution Agent"}
        history = [
            {"role": "user", "content": "Delete service HTTPS-8443"},
            {"role": "user", "content": "vmpafw01"},
        ]
        with mock.patch.object(
            maestro_firewall_jobs.netsec_service,
            "list_target_firewalls",
            return_value=CLONES,
        ):
            with mock.patch.object(
                maestro_firewall_jobs.firewall_jobs_service,
                "preflight",
                return_value={"live": True, "host": "20.44.53.215"},
            ):
                result = maestro_firewall_jobs.try_handle(
                    agent,
                    "user-1",
                    "vmpafw01",
                    messages=history,
                )
        self.assertIn("https-8443", result["reply"].lower())
        self.assertNotIn("What do you want to do", result["reply"])
        confirm = next(block for block in result["blocks"] if block.get("type") == "confirm")
        self.assertIn("HTTPS-8443", confirm["text"])

    def test_foundry_maestro_is_not_intercepted(self):
        from services import maestro_firewall_jobs

        agent = {
            "id": "master-orchestrator-agent",
            "name": "Maestro AI",
            "type": "Master Orchestrator",
            "agent_id": "test-agent",
        }
        result = maestro_firewall_jobs.try_handle(
            agent,
            "user-1",
            "create object web-01 with ip 10.0.0.1",
        )
        self.assertIsNone(result)

    def test_new_write_does_not_reuse_previous_job_firewall(self):
        from services import maestro_firewall_jobs

        agent = {"id": "netsec-execution-agent", "name": "Firewall Execution Agent"}
        history = [
            {
                "role": "user",
                "content": "create object web-01 with ip 10.0.0.1 firewall_name=vmpafw01",
            },
            {"role": "user", "content": "Delete service HTTPS-8443"},
        ]
        with mock.patch.object(
            maestro_firewall_jobs.netsec_service,
            "list_target_firewalls",
            return_value=CLONES,
        ):
            result = maestro_firewall_jobs.try_handle(
                agent,
                "user-1",
                "Delete service HTTPS-8443",
                messages=history,
            )
        self.assertIn("firewall_id or firewall_name", result["reply"])
        self.assertIn("HTTPS-8443", result["reply"])


if __name__ == "__main__":
    unittest.main()
