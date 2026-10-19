"""Bridge from the platform UI to the Firewall Execution Agent job ledger.

The execution agent owns the live gate, approval gate and job lifecycle.
This module only forwards requests (never talks to PAN-OS) so the browser
keeps using function-level auth rather than exposing the Function key.
"""

import logging
import os

import requests

logger = logging.getLogger("firewall.jobs.service")

DEFAULT_FUNCTION_URL = (
    "https://firewall-execution-agent-gahmfgfghubpa6gk"
    ".southindia-01.azurewebsites.net/api"
)
TIMEOUT = int(os.environ.get("NETSEC_FUNCTION_TIMEOUT", "60") or "60")


class FirewallJobsError(RuntimeError):
    def __init__(self, message, status_code=502):
        super().__init__(message)
        self.status_code = status_code


def _env(name, default=""):
    return (os.environ.get(name) or "").strip() or default


def _base_url():
    return _env("NETSEC_FUNCTION_URL", DEFAULT_FUNCTION_URL).rstrip("/")


def _function_key():
    return _env("NETSEC_FUNCTION_KEY")


def _configured():
    key = _function_key()
    return bool(_base_url()) and bool(key) and not key.startswith("PLACEHOLDER")


def _request(method, path, user_id, body=None, params=None):
    if not _configured():
        raise FirewallJobsError(
            "The Firewall Execution Agent is not configured "
            "(NETSEC_FUNCTION_URL / NETSEC_FUNCTION_KEY).",
            503,
        )
    headers = {
        "Content-Type": "application/json",
        "x-functions-key": _function_key(),
        "x-user-id": str(user_id or "anonymous"),
    }
    query = {"code": _function_key()}
    query.update(params or {})
    try:
        response = requests.request(
            method,
            "{0}/{1}".format(_base_url(), path.lstrip("/")),
            headers=headers,
            params=query,
            json=body,
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise FirewallJobsError(
            "Could not reach the Firewall Execution Agent: {0}".format(exc)
        )

    try:
        data = response.json()
    except ValueError:
        data = {}
    if response.status_code >= 400:
        raise FirewallJobsError(
            data.get("message")
            or data.get("error")
            or "Execution agent returned HTTP {0}".format(response.status_code),
            response.status_code,
        )
    return data


def preflight(user_id, firewall_host=None):
    params = {"firewall_host": firewall_host} if firewall_host else None
    return _request("GET", "firewall/preflight", user_id, params=params)


def list_jobs(user_id, status=None, limit=100):
    params = {"limit": limit}
    if status:
        params["status"] = status
    return _request("GET", "firewall/jobs", user_id, params=params).get(
        "jobs", []
    )


def create_job(user_id, payload):
    body = dict(payload or {})
    body["user_id"] = str(user_id or "anonymous")
    return _request("POST", "firewall/jobs", user_id, body).get("job")


def get_job(user_id, task_id):
    return _request(
        "GET", "firewall/jobs/{0}".format(task_id), user_id
    ).get("job")


def approve_job(user_id, task_id, approve=True):
    body = {"user_id": str(user_id or "anonymous"), "approve": bool(approve)}
    return _request(
        "POST", "firewall/jobs/{0}/approve".format(task_id), user_id, body
    ).get("job")
