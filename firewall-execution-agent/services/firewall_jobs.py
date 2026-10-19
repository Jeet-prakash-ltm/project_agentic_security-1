"""Firewall job lifecycle: live gate, approval, queueing and execution.

Flow enforced here:

1. ``preflight`` / ``create`` check that the firewall answers on the XML API.
   If it is down the request fails with ``cannot proceed firewall is down``
   and no job is created or queued.
2. A created job waits in ``PENDING_APPROVAL``; nothing is applied until a
   user explicitly approves it.
3. ``approve`` re-checks the firewall, marks the job ``QUEUED`` and publishes
   it to the session-enabled Service Bus queue.
4. The queue worker applies staged configuration, commits, polls the PAN-OS
   job (PEND -> ACT -> FIN) and records every transition in PostgreSQL.
"""

import logging
import os
import re
import time
import uuid
from xml.etree import ElementTree

from connectors.panos_client import PanosClient

from services import job_queue
from services import job_store
from services.audit import audit
from services.firewall_job_lifecycle import (
    APPLYING_CONFIG,
    APPROVED_APPROVAL,
    CANCELLED,
    COMMITTING,
    FAILED,
    FIREWALL_DOWN_MESSAGE,
    PENDING,
    PENDING_APPROVAL,
    POST_VALIDATION,
    QUEUED,
    REJECTED,
    RUNNING,
    STARTING,
    SUCCEEDED,
    TIMEOUT,
)
from services.settings import Settings

logger = logging.getLogger("firewall.jobs")

ALLOWED_OPERATIONS = ("commit", "apply_change")

ALLOWED_ACTIONS = ("set", "edit", "delete")

POLL_INTERVAL = int(os.environ.get("FIREWALL_JOB_POLL_SECONDS") or "5")
JOB_TIMEOUT = int(os.environ.get("FIREWALL_JOB_TIMEOUT_SECONDS") or "900")

PANOS_FINISHED = ("FIN", "FINISHED", "COMPLETED", "DONE")
PANOS_FAILED = ("FAIL", "FAILED", "ERROR")


class FirewallDownError(RuntimeError):
    def __init__(self, message=FIREWALL_DOWN_MESSAGE):
        super().__init__(message)


class JobNotFound(LookupError):
    pass


class JobConflict(RuntimeError):
    pass


class JobValidationError(ValueError):
    pass


def _client(timeout=10):
    previous = Settings.TIMEOUT
    Settings.TIMEOUT = timeout
    try:
        client = PanosClient()
    finally:
        Settings.TIMEOUT = previous
    client.timeout = timeout
    return client


_SECRET_RE = re.compile(
    r"(password|passwd|key|api_key|token)=([^&\s'\"]+)", re.IGNORECASE
)


def _root(xml):
    if not xml:
        return None
    try:
        return ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return None


def _response_status(xml):
    root = _root(xml)
    return (root.get("status") or "").lower() if root is not None else None


def _response_message(xml):
    root = _root(xml)
    if root is None:
        return ""
    node = root.find(".//msg")
    if node is not None and node.text:
        return node.text.strip()
    node = root.find(".//result")
    if node is not None and node.text:
        return node.text.strip()
    return ""


def _safe_error(exc):
    return _SECRET_RE.sub(r"\1=***", str(exc))[:200]


def check_firewall_live(firewall_host=None):
    """Probe the firewall XML API. Returns ``(live, detail)``."""
    try:
        client = _client(timeout=8)
        xml = client.op("<show><system><info/></system></show>")
        if _response_status(xml) == "success":
            return True, "firewall reachable"
        return False, "firewall returned an error response"
    except Exception as exc:
        logger.warning("Firewall live check failed: %s", _safe_error(exc))
        return False, "{0}: firewall unreachable".format(type(exc).__name__)


def preflight(firewall_host=None):
    live, detail = check_firewall_live(firewall_host)
    return {
        "live": live,
        "message": None if live else FIREWALL_DOWN_MESSAGE,
        "detail": detail,
        "host": firewall_host or Settings.FW_HOST or "",
    }


def _require_live():
    live, detail = check_firewall_live()
    if not live:
        raise FirewallDownError()
    return detail


def _clean(value, limit=255):
    return str(value or "").strip()[:limit]


def _validate(payload):
    operation = _clean(payload.get("operation"), 64).lower()
    if operation not in ALLOWED_OPERATIONS:
        raise JobValidationError(
            "operation must be one of: {0}.".format(", ".join(ALLOWED_OPERATIONS))
        )
    device_group = _clean(payload.get("device_group"), 255)
    if not device_group:
        raise JobValidationError("device_group is required.")

    requested = payload.get("requested_payload") or {}
    if not isinstance(requested, dict):
        raise JobValidationError("requested_payload must be an object.")

    if operation == "apply_change":
        action = _clean(requested.get("action"), 16).lower()
        if action not in ALLOWED_ACTIONS:
            raise JobValidationError(
                "requested_payload.action must be one of: {0}.".format(
                    ", ".join(ALLOWED_ACTIONS)
                )
            )
        if not _clean(requested.get("xpath"), 2048):
            raise JobValidationError("requested_payload.xpath is required.")
        if action in ("set", "edit") and not requested.get("element"):
            raise JobValidationError(
                "requested_payload.element is required for {0}.".format(action)
            )

    return operation, device_group, requested


def create_job(user_id, payload):
    operation, device_group, requested = _validate(payload or {})
    firewall_host = _clean(payload.get("firewall_host"), 255) or (
        Settings.FW_HOST or ""
    )

    _require_live()

    task_id = str(uuid.uuid4())
    session_id = job_queue.session_id_for(firewall_host, device_group)
    job = job_store.create_job(
        {
            "task_id": task_id,
            "user_id": user_id,
            "session_id": session_id,
            "firewall_host": firewall_host,
            "device_group": device_group,
            "operation": operation,
            "status": PENDING_APPROVAL,
            "requested_payload": requested,
            "approval_status": PENDING,
        }
    )
    audit(
        operation="createFirewallJob",
        description="task_id={0} op={1}".format(task_id, operation),
        xpath=device_group,
        result=PENDING_APPROVAL,
    )
    return job


def get_job(task_id):
    job = job_store.get_job(task_id)
    if job is None:
        raise JobNotFound("Firewall job not found.")
    return job


def approve_job(task_id, user_id, approve=True):
    job = job_store.get_job(task_id)
    if job is None:
        raise JobNotFound("Firewall job not found.")
    if (job.get("user_id") or "anonymous") != (user_id or "anonymous"):
        raise JobNotFound("Firewall job not found.")

    if job.get("approval_status") != PENDING:
        raise JobConflict(
            "Job is already {0}.".format(job.get("approval_status"))
        )

    if not approve:
        job = job_store.update_job(
            task_id,
            approval_status=REJECTED,
            status=CANCELLED,
            completed_at="now()",
        )
        audit(
            operation="rejectFirewallJob",
            description="task_id={0}".format(task_id),
            result=CANCELLED,
        )
        return job

    _require_live()

    job = job_store.update_job(
        task_id,
        approval_status=APPROVED_APPROVAL,
        status=QUEUED,
    )

    if not job_queue.is_configured():
        job = job_store.update_job(
            task_id,
            status=FAILED,
            error_message="SERVICEBUS_CONNECTION is not configured.",
        )
        raise JobConflict("Queue is not configured; job was not dispatched.")

    try:
        job_queue.publish(job)
    except Exception as exc:
        logger.exception("Failed to publish firewall job %s", task_id)
        job_store.update_job(
            task_id,
            status=FAILED,
            error_message="Queue publish failed: {0}".format(str(exc)[:300]),
        )
        raise JobConflict("Job could not be queued: {0}".format(str(exc)[:200]))

    audit(
        operation="approveFirewallJob",
        description="task_id={0}".format(task_id),
        result=QUEUED,
    )
    return job_store.get_job(task_id)


def _parse_job_id(xml):
    root = _root(xml)
    if root is None:
        return None
    node = root.find(".//job")
    return (node.text or "").strip() if node is not None else None


def _require_success(xml, action):
    status = _response_status(xml)
    if status == "error":
        raise RuntimeError(
            "PAN-OS rejected {0}: {1}".format(
                action, _response_message(xml) or "unknown error"
            )
        )
    return xml


def _parse_job_status(xml):
    root = _root(xml)
    if root is None:
        return None, None
    node = root.find(".//job")
    if node is None:
        return None, None
    status = None
    details = None
    for child in node:
        tag = child.tag.lower()
        if tag == "status":
            status = (child.text or "").strip().upper()
        elif tag in ("result", "details"):
            details = (child.text or "").strip()
    return status, details


def _wait_for_panos_job(client, panos_job_id):
    deadline = time.time() + JOB_TIMEOUT
    last = None
    while time.time() < deadline:
        xml = client.op(
            "<show><jobs><id>{0}</id></jobs></show>".format(panos_job_id)
        )
        status, details = _parse_job_status(xml)
        last = status
        if status and status.startswith(PANOS_FAILED):
            raise RuntimeError(details or "PAN-OS job failed ({0}).".format(status))
        if status and status.startswith(PANOS_FINISHED):
            if (details or "").strip().upper() in PANOS_FAILED:
                raise RuntimeError(
                    "PAN-OS job reported failure ({0}).".format(details)
                )
            return details or "PAN-OS job finished."
        time.sleep(max(POLL_INTERVAL, 1))
    raise TimeoutError(
        "PAN-OS job {0} did not finish within {1}s (last state: {2}).".format(
            panos_job_id, JOB_TIMEOUT, last or "unknown"
        )
    )


def _apply_change(client, requested):
    action = _clean(requested.get("action"), 16).lower()
    xpath = requested.get("xpath")
    element = requested.get("element")
    if action == "set":
        return client.set(xpath, element)
    if action == "edit":
        return client.edit(xpath, element)
    return client.delete(xpath)


def execute_job(task_id):
    """Run one approved job. Called by the Service Bus queue trigger."""
    job = job_store.get_job(task_id)
    if job is None:
        logger.warning("Job %s no longer exists; dropping message.", task_id)
        return None
    if job.get("approval_status") != APPROVED_APPROVAL:
        logger.warning(
            "Job %s is not approved (%s); refusing to execute.",
            task_id,
            job.get("approval_status"),
        )
        return job

    try:
        job_store.update_job(task_id, status=STARTING, started_at="now()")
        client = _client(timeout=Settings.TIMEOUT)
        requested = job.get("requested_payload") or {}
        operation = job.get("operation")

        if operation == "apply_change":
            job_store.update_job(task_id, status=APPLYING_CONFIG)
            _require_success(_apply_change(client, requested), "configuration change")

        job_store.update_job(task_id, status=COMMITTING)
        commit_xml = _require_success(client.commit(), "commit")
        panos_job_id = _parse_job_id(commit_xml)
        if not panos_job_id:
            raise RuntimeError("PAN-OS did not return a commit job id.")
        job_store.update_job(
            task_id, status=RUNNING, panos_job_id=panos_job_id
        )
        panos_result = None
        if panos_job_id:
            panos_result = _wait_for_panos_job(client, panos_job_id)

        job_store.update_job(task_id, status=POST_VALIDATION)
        _require_success(client.test_connection(), "post-commit check")

        result = {
            "operation": operation,
            "panos_job_id": panos_job_id,
            "panos_result": panos_result,
            "device_group": job.get("device_group"),
        }
        job_store.update_job(
            task_id,
            status=SUCCEEDED,
            result=result,
            completed_at="now()",
            error_message=None,
        )
        audit(
            operation="executeFirewallJob",
            description="task_id={0}".format(task_id),
            result=SUCCEEDED,
        )
        return job_store.get_job(task_id)
    except TimeoutError as exc:
        job_store.update_job(
            task_id,
            status=TIMEOUT,
            error_message=str(exc)[:500],
            completed_at="now()",
        )
        logger.exception("Firewall job %s timed out", task_id)
        return job_store.get_job(task_id)
    except Exception as exc:
        job_store.update_job(
            task_id,
            status=FAILED,
            error_message=str(exc)[:500],
            completed_at="now()",
        )
        logger.exception("Firewall job %s failed", task_id)
        return job_store.get_job(task_id)
