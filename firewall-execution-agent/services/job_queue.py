"""Azure Service Bus delivery for approved firewall jobs.

Uses the Service Bus REST API so the Function App does not need the
``azure-servicebus`` SDK at runtime. The queue is session-enabled so every
job for a given firewall/device-group is worked in order. PostgreSQL remains
the source of truth; the message only carries the job id and routing scope.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse

import requests

logger = logging.getLogger("firewall.jobs.queue")

QUEUE_NAME = os.environ.get("FIREWALL_JOBS_QUEUE", "firewall-jobs")


def _parse_connection():
    parts = {}
    blob = (os.environ.get("SERVICEBUS_CONNECTION") or "").strip()
    for item in blob.split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        parts[key.strip()] = value.strip()
    endpoint = (parts.get("Endpoint") or "").rstrip("/")
    return {
        "endpoint": endpoint,
        "key_name": parts.get("SharedAccessKeyName") or "",
        "key": parts.get("SharedAccessKey") or "",
    }


def connection_string():
    return (os.environ.get("SERVICEBUS_CONNECTION") or "").strip()


def is_configured():
    parsed = _parse_connection()
    return bool(parsed["endpoint"] and parsed["key_name"] and parsed["key"])


def session_id_for(firewall_host, device_group):
    return "{0}/{1}".format(
        (firewall_host or "unknown").strip(),
        (device_group or "shared").strip(),
    )


def _https_endpoint(endpoint):
    if endpoint.startswith("sb://"):
        return "https://" + endpoint[len("sb://"):]
    return endpoint


def _sas_token(uri, key_name, key, ttl=120):
    expiry = int(time.time()) + int(ttl)
    encoded_uri = urllib.parse.quote_plus(uri)
    signing = "{0}\n{1}".format(encoded_uri, expiry).encode("utf-8")
    signature = base64.b64encode(
        hmac.new(key.encode("utf-8"), signing, hashlib.sha256).digest()
    )
    return (
        "SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}".format(
            encoded_uri,
            urllib.parse.quote_plus(signature),
            expiry,
            urllib.parse.quote_plus(key_name),
        )
    )


def publish(job):
    """Send one job message. Returns the Service Bus message id."""
    if not is_configured():
        raise RuntimeError("SERVICEBUS_CONNECTION is not configured.")

    parsed = _parse_connection()
    job_id = job.get("job_id") or job.get("task_id")
    payload = {
        "job_id": job_id,
        "task_id": job_id,
        "firewall_host": job.get("firewall_host") or "",
        "device_group": job.get("device_group") or "",
        "operation": job.get("operation") or "",
    }
    session_id = job.get("session_id") or session_id_for(
        job.get("firewall_host"), job.get("device_group")
    )
    https = _https_endpoint(parsed["endpoint"]).rstrip("/")
    resource = "{0}/{1}".format(https, QUEUE_NAME)
    url = "{0}/messages".format(resource)
    token = _sas_token(resource, parsed["key_name"], parsed["key"])
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "BrokerProperties": json.dumps(
            {
                "SessionId": session_id,
                "MessageId": str(job_id),
                "ContentType": "application/json",
            }
        ),
    }
    response = requests.post(
        url,
        headers=headers,
        data=json.dumps(payload),
        timeout=20,
    )
    if response.status_code >= 300:
        raise RuntimeError(
            "Service Bus publish failed with HTTP {0}.".format(response.status_code)
        )
    logger.info("Queued firewall job %s in session %s", job_id, session_id)
    return str(job_id)
