import unittest
from unittest import mock

from netsec_execution.connector.function_app import FunctionAppPanosClient

from services import agent_status_service
from services import feat_health_service
from services import netsec_service


def _status_row(status="live", detail="Reachable (HTTP 200)", latency_ms=120):
    return [
        {
            "id": "netsec-execution-agent",
            "name": "FEAT",
            "type": "Network Security Agent",
            "model": "gpt-5.1",
            "connected": True,
            "status": status,
            "detail": detail,
            "latency_ms": latency_ms,
            "checked_at": 1700000000,
        }
    ]


class FeatHealthTests(unittest.TestCase):
    def _client(self):
        client = FunctionAppPanosClient(
            base_url="https://feat.example/api",
            function_key="test-key",
        )
        client._get = mock.Mock(return_value={"status": "success"})
        return client

    def test_reports_each_component_and_keeps_unobservable_worker_unknown(self):
        client = self._client()
        with mock.patch.object(netsec_service, "_client", return_value=client), \
                mock.patch.object(
                    agent_status_service,
                    "get_agent_statuses",
                    return_value=_status_row(),
                ):
            data = feat_health_service._collect()

        by_id = {item["id"]: item for item in data["components"]}
        self.assertEqual(by_id["a2a"]["status"], "live")
        self.assertEqual(by_id["a2a"]["detail"], "Reachable (HTTP 200)")
        self.assertEqual(by_id["function_app"]["status"], "live")
        self.assertEqual(by_id["pan_os"]["status"], "live")
        self.assertEqual(by_id["job_worker"]["status"], "unknown")
        self.assertIn("job-worker health endpoint", by_id["job_worker"]["detail"])

    def test_probe_failure_is_reported_not_faked(self):
        client = self._client()
        client._get = mock.Mock(side_effect=RuntimeError("connection refused"))
        with mock.patch.object(netsec_service, "_client", return_value=client), \
                mock.patch.object(
                    agent_status_service,
                    "get_agent_statuses",
                    return_value=_status_row(status="down", detail="HTTP 500"),
                ):
            data = feat_health_service._collect()

        by_id = {item["id"]: item for item in data["components"]}
        self.assertEqual(by_id["a2a"]["status"], "down")
        self.assertEqual(by_id["function_app"]["status"], "down")
        self.assertIn("connection refused", by_id["function_app"]["detail"])
        self.assertEqual(by_id["pan_os"]["status"], "down")

    def test_health_never_contains_api_keys(self):
        client = self._client()
        with mock.patch.object(netsec_service, "_client", return_value=client), \
                mock.patch.object(
                    agent_status_service,
                    "get_agent_statuses",
                    return_value=_status_row(),
                ):
            data = feat_health_service._collect()

        self.assertNotIn("test-key", str(data))


if __name__ == "__main__":
    unittest.main()
