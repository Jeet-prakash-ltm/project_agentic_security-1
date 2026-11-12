"""Firewall job lifecycle: live gate, approval, queueing and execution.

Flow enforced here:

1. ``preflight`` / ``create`` check that the firewall answers on the XML API.
   If it is down the request fails with ``cannot proceed firewall is down``
   and no job is created or queued.
2. Chat or Hub submit is the single approval. ``create`` stages the job then
   immediately queues it. The Jobs page is status-only (queued / running /
   successful / failed) and does not collect a second approve.
3. ``approve`` remains for leftover jobs; it re-checks the firewall, marks
   the job ``queued`` and publishes it to the session-enabled Service Bus
   queue.
4. The queue worker applies every ``security_job_operations`` row, commits
   once, polls the PAN-OS job and records every transition in PostgreSQL.
"""

import hashlib
import json
import logging
import os
import re
import time
import uuid
from xml.etree import ElementTree

from connectors.panos_client import PanosClient

from services import job_planner
from services import job_queue
from services import job_store
from services.audit import audit
from services.firewall_job_lifecycle import (
    APPROVED_APPROVAL,
    AWAITING_APPROVAL,
    CANCELLED,
    COMMITTING,
    COMPLETED,
    FAILED,
    FIREWALL_DOWN_MESSAGE,
    OP_FAILED,
    OP_PENDING,
    OP_RUNNING,
    OP_SKIPPED,
    OP_SUCCESS,
    PENDING,
    QUEUED,
    REJECTED,
    REJECTED_STATUS,
    RUNNING,
    TERMINAL_STATUSES,
    TIMEOUT,
)
from services.job_planner import JobValidationError
from services.settings import Settings

logger = logging.getLogger("firewall.jobs")

ALLOWED_OPERATIONS = ("commit", "apply_change", "apply_bulk")

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


def _hash_payload(value):
    blob = json.dumps(value or {}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _source_type(payload):
    value = _clean(payload.get("source_type"), 64).lower().replace(" ", "_")
    aliases = {
        "ai_workspace": "ai_workspace",
        "aiworkspace": "ai_workspace",
        "workspace": "ai_workspace",
        "conversation": "ai_workspace",
        "maestro": "ai_workspace",
        "automation_hub": "automation_hub",
        "automationhub": "automation_hub",
        "automation": "automation_hub",
        "workbook": "automation_hub",
    }
    mapped = aliases.get(value.replace("-", ""), aliases.get(value, value))
    if mapped in ("ai_workspace", "automation_hub"):
        return mapped
    if payload.get("source_file_id") or payload.get("conversation_id"):
        return "ai_workspace"
    if payload.get("operation") == "apply_bulk" or payload.get("workbook_base64"):
        return "automation_hub"
    return "ai_workspace"


def create_job(user_id, payload, workbook_bytes=None):
    payload = payload or {}
    device_group = _clean(payload.get("device_group"), 255) or "vsys1"
    firewall_host = _clean(payload.get("firewall_host"), 255) or (
        Settings.FW_HOST or ""
    )

    _require_live()

    from workbook.adapter import WorkbookPanosClient
    from workbook.dependencies import Inventory

    inventory = Inventory(client_factory=lambda: WorkbookPanosClient())
    plan = job_planner.build_plan(
        payload,
        workbook_bytes=workbook_bytes,
        inventory=inventory,
        auto_create=_truthy(payload.get("auto_create"), default=True),
    )
    operation = plan["operation"]
    operations = plan["operations"]
    if not operations and operation != "commit":
        raise JobValidationError("Job has no operations to execute.")

    job_id = str(uuid.uuid4())
    session_id = job_queue.session_id_for(firewall_host, device_group)
    source_type = _source_type(payload)
    requested_payload = payload.get("requested_payload")
    if not isinstance(requested_payload, dict):
        requested_payload = {
            "operation": operation,
            "changes": payload.get("changes") or [],
            "source_type": source_type,
        }
    job = job_store.create_job(
        {
            "job_id": job_id,
            "user_id": user_id,
            "agent_id": _clean(payload.get("agent_id"), 64) or "firewall-execution-agent",
            "conversation_id": _clean(payload.get("conversation_id"), 64) or None,
            "security_domain": _clean(payload.get("security_domain"), 64)
            or "network_security",
            "job_type": _clean(payload.get("job_type"), 64) or "firewall_change",
            "operation": operation,
            "source_type": source_type,
            "source_name": _clean(payload.get("source_name"), 255)
            or ("AI Workspace" if source_type == "ai_workspace" else "Automation Hub"),
            "source_file_id": _clean(payload.get("source_file_id"), 64) or None,
            "target_asset_id": _clean(payload.get("target_asset_id"), 64) or None,
            "firewall_host": firewall_host,
            "device_group": device_group,
            "status": AWAITING_APPROVAL,
            "approval_status": PENDING,
            "requested_payload": requested_payload,
            "normalized_payload": plan["normalized_payload"],
            "execution_plan": plan["execution_plan"],
            "payload_hash": _hash_payload(requested_payload),
            "plan_hash": _hash_payload(plan["execution_plan"]),
            "requested_by": user_id,
        },
        operations=operations,
    )
    job["session_id"] = session_id
    audit(
        operation="createFirewallJob",
        description="job_id={0} op={1} ops={2}".format(
            job_id, operation, len(operations)
        ),
        xpath=device_group,
        result=AWAITING_APPROVAL,
    )
    return approve_job(job_id, user_id, approve=True)


def _truthy(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def get_job(job_id, include_operations=True):
    job = job_store.get_job(job_id, include_operations=include_operations)
    if job is None:
        raise JobNotFound("Firewall job not found.")
    return job


def approve_job(job_id, user_id, approve=True):
    job = job_store.get_job(job_id)
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
            job_id,
            approval_status=REJECTED,
            status=REJECTED_STATUS,
            completed_at="now()",
        )
        audit(
            operation="rejectFirewallJob",
            description="job_id={0}".format(job_id),
            result=CANCELLED,
        )
        return job

    _require_live()

    job = job_store.update_job(
        job_id,
        approval_status=APPROVED_APPROVAL,
        status=QUEUED,
        approved_by=user_id,
        approved_at="now()",
    )

    if not job_queue.is_configured():
        job = job_store.update_job(
            job_id,
            status=FAILED,
            error_message="SERVICEBUS_CONNECTION is not configured.",
        )
        raise JobConflict("Queue is not configured; job was not dispatched.")

    try:
        job_queue.publish(job)
    except Exception as exc:
        logger.exception("Failed to publish firewall job %s", job_id)
        job_store.update_job(
            job_id,
            status=FAILED,
            error_message="Queue publish failed: {0}".format(str(exc)[:300]),
        )
        raise JobConflict("Job could not be queued: {0}".format(str(exc)[:200]))

    audit(
        operation="approveFirewallJob",
        description="job_id={0}".format(job_id),
        result=QUEUED,
    )
    return job_store.get_job(job_id, include_operations=True)


def _parse_job_id(xml):
    root = _root(xml)
    if root is None:
        return None
    node = root.find(".//job")
    return (node.text or "").strip() if node is not None else None


def _require_success(xml, action):
    if isinstance(xml, dict):
        return xml
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


def execute_job(job_id):
    """Run one approved job. Called by the Service Bus queue trigger."""
    job = job_store.get_job(job_id, include_operations=True)
    if job is None:
        logger.warning("Job %s no longer exists; dropping message.", job_id)
        return None
    if job.get("approval_status") != APPROVED_APPROVAL:
        logger.warning(
            "Job %s is not approved (%s); refusing to execute.",
            job_id,
            job.get("approval_status"),
        )
        return job

    status = (job.get("status") or "").lower()
    if status in TERMINAL_STATUSES:
        logger.info("Job %s already %s; dropping duplicate delivery.", job_id, status)
        return job
    if status in (RUNNING, COMMITTING):
        logger.warning(
            "Job %s is already %s; refusing duplicate execution.",
            job_id,
            status,
        )
        return job
    if status != QUEUED:
        logger.warning(
            "Job %s is %s; refusing to execute until it is queued.",
            job_id,
            status,
        )
        return job

    operations = job.get("operations") or job_store.list_operations(job_id)
    try:
        job_store.update_job(job_id, status=RUNNING, started_at="now()")
        from workbook.adapter import WorkbookPanosClient
        from workbook.dependencies import Inventory

        client = WorkbookPanosClient()
        inventory = Inventory(client_factory=lambda: client)
        succeeded = 0
        failed = 0
        results = []

        for item in operations:
            sequence = item.get("sequence")
            job_store.update_operation(
                job_id, sequence, status=OP_RUNNING, started_at="now()"
            )
            try:
                outcome = job_planner.apply_operation(
                    client, item, inventory=inventory, auto_create=True
                )
                job_store.update_operation(
                    job_id,
                    sequence,
                    status=OP_SUCCESS,
                    result=outcome if isinstance(outcome, dict) else {"raw": str(outcome)[:500]},
                    completed_at="now()",
                    error_message=None,
                )
                succeeded += 1
                results.append(
                    {
                        "sequence": sequence,
                        "status": OP_SUCCESS,
                        "object_name": item.get("object_name"),
                        "category": item.get("category"),
                        "action": item.get("action"),
                    }
                )
            except Exception as exc:
                failed += 1
                message = str(exc)[:500]
                job_store.update_operation(
                    job_id,
                    sequence,
                    status=OP_FAILED,
                    error_code="PANOS_OP_FAILED",
                    error_message=message,
                    completed_at="now()",
                )
                results.append(
                    {
                        "sequence": sequence,
                        "status": OP_FAILED,
                        "object_name": item.get("object_name"),
                        "error": message,
                    }
                )
                logger.exception(
                    "Firewall job %s operation %s failed", job_id, sequence
                )
                break

        if failed:
            for item in operations:
                if item.get("sequence") in {row.get("sequence") for row in results}:
                    continue
                job_store.update_operation(
                    job_id,
                    item.get("sequence"),
                    status=OP_SKIPPED,
                    error_code="SKIPPED",
                    error_message="Skipped because a prior operation failed.",
                    completed_at="now()",
                )
            job_store.update_job(
                job_id,
                status=FAILED,
                error_message="{0} operation(s) failed; commit was not attempted.".format(
                    failed
                ),
                result={"operations": results, "succeeded": succeeded, "failed": failed},
                completed_at="now()",
            )
            return job_store.get_job(job_id, include_operations=True)

        job_store.update_job(job_id, status=COMMITTING)
        panos_client = _client(timeout=Settings.TIMEOUT)
        commit_xml = _require_success(panos_client.commit(), "commit")
        panos_job_id = _parse_job_id(commit_xml)
        if not panos_job_id:
            raise RuntimeError("PAN-OS did not return a commit job id.")
        panos_result = _wait_for_panos_job(panos_client, panos_job_id)
        _require_success(panos_client.test_connection(), "post-commit check")

        result = {
            "operation": job.get("operation"),
            "panos_job_id": panos_job_id,
            "panos_result": panos_result,
            "device_group": job.get("device_group"),
            "succeeded": succeeded,
            "failed": failed,
            "operations": results,
        }
        job_store.update_job(
            job_id,
            status=COMPLETED,
            result=result,
            completed_at="now()",
            error_message=None,
        )
        audit(
            operation="executeFirewallJob",
            description="job_id={0}".format(job_id),
            result=COMPLETED,
        )
        return job_store.get_job(job_id, include_operations=True)
    except TimeoutError as exc:
        job_store.update_job(
            job_id,
            status=TIMEOUT,
            error_message=str(exc)[:500],
            completed_at="now()",
        )
        logger.exception("Firewall job %s timed out", job_id)
        return job_store.get_job(job_id, include_operations=True)
    except Exception as exc:
        job_store.update_job(
            job_id,
            status=FAILED,
            error_message=str(exc)[:500],
            completed_at="now()",
        )
        logger.exception("Firewall job %s failed", job_id)
        return job_store.get_job(job_id, include_operations=True)
