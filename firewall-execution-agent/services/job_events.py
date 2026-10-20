"""Push firewall job transitions to Azure SignalR.

PostgreSQL remains the source of truth. This module only wakes the Jobs page.
The connection string is read from ``SIGNALR_CONNECTION`` and is never logged.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time

import requests

logger = logging.getLogger("firewall.jobs.events")

HUB = (os.environ.get("FIREWALL_JOBS_HUB") or "FirewallJobsHub").strip()
TARGET = "jobUpdated"
CLIENT_TTL = 3600
REST_TTL = 60
_PUBLISH_TIMEOUT = 5


def _connection_string():
    return (os.environ.get("SIGNALR_CONNECTION") or "").strip()


def _parse():
    parts = {}
    for item in _connection_string().split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        parts[key.strip()] = value.strip()
    endpoint = (parts.get("Endpoint") or "").rstrip("/")
    access_key = parts.get("AccessKey") or ""
    return endpoint, access_key


def is_configured():
    endpoint, access_key = _parse()
    return bool(endpoint) and bool(access_key) and bool(HUB)


def _b64url(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwt(audience, access_key, ttl, user_id=None):
    header = _b64url(json.dumps({"typ": "JWT", "alg": "HS256"}))
    now = int(time.time())
    payload = {
        "aud": audience,
        "exp": now + int(ttl),
        "iat": now,
        "nbf": now,
    }
    if user_id:
        payload["nameid"] = str(user_id)
    body = _b64url(json.dumps(payload, separators=(",", ":")))
    signing = "{0}.{1}".format(header, body).encode("ascii")
    signature = hmac.new(
        access_key.encode("utf-8"), signing, hashlib.sha256
    ).digest()
    return "{0}.{1}.{2}".format(header, body, _b64url(signature))


def negotiate(user_id=None):
    """Return a short-lived client URL + token for the Jobs page."""
    if not is_configured():
        raise RuntimeError("SIGNALR_CONNECTION is not configured.")
    endpoint, access_key = _parse()
    url = "{0}/client/?hub={1}".format(endpoint, HUB)
    return {
        "url": url,
        "accessToken": _jwt(url, access_key, CLIENT_TTL, user_id=user_id),
        "hub": HUB,
        "target": TARGET,
    }


def _summary(job):
    if not job:
        return None
    return {
        "task_id": job.get("task_id"),
        "status": job.get("status"),
        "user_id": job.get("user_id"),
        "operation": job.get("operation"),
        "firewall_host": job.get("firewall_host"),
        "device_group": job.get("device_group"),
        "panos_job_id": job.get("panos_job_id"),
        "updated_at": job.get("updated_at"),
    }


def publish(job):
    """Broadcast a job status change. Failures are logged, never raised."""
    payload = _summary(job)
    if not payload or not payload.get("task_id"):
        return False
    if not is_configured():
        return False
    endpoint, access_key = _parse()
    audience = "{0}/api/v1/hubs/{1}".format(endpoint, HUB)
    token = _jwt(audience, access_key, REST_TTL)
    try:
        response = requests.post(
            "{0}?api-version=2022-11-01".format(audience),
            headers={
                "Authorization": "Bearer {0}".format(token),
                "Content-Type": "application/json",
            },
            json={"target": TARGET, "arguments": [payload]},
            timeout=_PUBLISH_TIMEOUT,
        )
        if response.status_code >= 400:
            logger.warning(
                "SignalR publish HTTP %s for job %s",
                response.status_code,
                payload["task_id"],
            )
            return False
        return True
    except Exception:
        logger.warning(
            "SignalR publish failed for job %s", payload["task_id"], exc_info=True
        )
        return False
