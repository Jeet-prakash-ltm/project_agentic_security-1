"""Firewall Execution Agent service: workspace bridge to the playbook engine.

Manual and bulk Excel playbooks reuse the existing workbook catalogue. Each
row is executed through the Function App that backs the Foundry
``Firewall-Excecution-Agent`` OpenAPI tool (``NETSEC_FUNCTION_*``). When that
Function App is not configured the engine falls back to the direct PAN-OS
XML client (``NETSEC_FW_*``).

The per-user workbook is stored on the app server under ``NETSEC_WORKBOOK_DIR``
(default ``/tmp/netsec_uploads``) so a user's playbook can be re-run.
"""

import io
import logging
import os
import re

from netsec_execution.connector.function_app import make_client
from netsec_execution.services import catalog
from netsec_execution.services import engine
from netsec_execution.services import workbook

logger = logging.getLogger("netsec.service")

UPLOAD_DIR = os.environ.get("NETSEC_WORKBOOK_DIR", "/tmp/netsec_uploads")
MAX_ROWS = int(os.environ.get("NETSEC_MAX_ROWS", "500") or "500")

_XLSX_MIME = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)


def _workbook_path(user_id):
    safe_id = re.sub(r"[^A-Za-z0-9._-]+", "-", str(user_id or "anon"))
    return os.path.join(UPLOAD_DIR, "{0}.xlsx".format(safe_id))


def _ensure_dir():
    try:
        os.makedirs(UPLOAD_DIR, exist_ok=True)
    except OSError as exc:
        logger.warning("NetSec upload dir unavailable: %s", exc)


def _client():
    """Function App adapter when configured, otherwise direct PAN-OS."""
    return make_client()


def info():
    """Public connection + catalogue payload for the workspace panel."""
    client = _client()
    return {
        "configured": bool(client.configured),
        "missing": client.missing_config(),
        "host": client.host or "",
        "dry_run": bool(client.dry_run),
        "max_rows": MAX_ROWS,
        "playbooks": catalog.list_playbooks(),
        "via": "function_app" if client.__class__.__name__ == "FunctionAppPanosClient" else "panos",
    }


def save_workbook(user_id, file_storage):
    """Persist an uploaded workbook for ``user_id`` and return its summary."""
    _ensure_dir()
    path = _workbook_path(user_id)
    file_storage.save(path)
    summary = workbook.summarize(path)
    logger.info("Workbook saved for user %s: %s", user_id, summary)
    return summary


def workbook_summary(user_id):
    """Return the summary of the user's stored workbook, or ``None``."""
    path = _workbook_path(user_id)
    if not os.path.exists(path):
        return None
    return workbook.summarize(path)


def build_template_bytes():
    """Build the fill-in playbook workbook and return it as a ``BytesIO``."""
    buffer = io.BytesIO()
    workbook.build_template(buffer, catalog.PLAYBOOKS)
    buffer.seek(0)
    return buffer


def run_playbook(user_id, playbook_id, commit=None):
    """Execute one playbook against the firewall for the user's workbook.

    When the platform runs in apply mode (``NETSEC_FW_DRY_RUN=0``) the run
    commits the changes to the running configuration afterwards; pass
    ``commit`` explicitly to override (e.g. preview-only staging).

    Raises ``ValueError`` with a user-friendly message when the firewall is
    not configured or no workbook has been uploaded.
    """
    client = _client()
    if not client.configured:
        raise ValueError(
            "The Firewall Execution Agent is not connected to a firewall. "
            "Missing environment configuration: {0}.".format(
                ", ".join(client.missing_config())
            )
        )
    path = _workbook_path(user_id)
    if not os.path.exists(path):
        raise ValueError(
            "No playbook workbook uploaded yet. Download the template, fill "
            "it in, then upload it in the panel before running a playbook."
        )
    summary = workbook.summarize(path)
    total = summary.get("total_rows", 0)
    row_limit = None
    if total > MAX_ROWS:
        row_limit = MAX_ROWS
    result = engine.run_playbook(
        client,
        playbook_id,
        workbook_path=path,
        row_limit=row_limit,
        commit=commit,
    )
    result["host"] = client.host
    return result


def run_row(playbook_id, row, commit=None):
    """Execute a single manual operation row against the firewall.

    Unlike ``run_playbook`` this does not require an uploaded workbook: the
    row is a plain dict keyed by the playbook's workbook columns (including an
    ``Action`` of create/update/delete) supplied by the chat manual flow.

    Raises ``ValueError`` when the firewall is unconfigured or the payload
    does not describe a valid single-row change.
    """
    playbook = catalog.find_playbook(playbook_id)
    if playbook is None:
        raise ValueError(
            "Unknown object type: {0}.".format(playbook_id or "none")
        )
    if not isinstance(row, dict) or not row:
        raise ValueError("A row with the object fields is required.")
    action = (row.get("Action") or "").strip().lower()
    if action not in ("create", "update", "delete"):
        raise ValueError(
            "Pick an Action of create, update or delete for the operation."
        )
    client = _client()
    if not client.configured:
        raise ValueError(
            "The Firewall Execution Agent is not connected to a firewall. "
            "Missing environment configuration: {0}.".format(
                ", ".join(client.missing_config())
            )
        )
    headers = list(playbook.get("columns") or [])
    clean = {}
    for header in headers:
        value = row.get(header)
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        clean[header] = "" if value is None else str(value)
    rows = {
        playbook["sheet"]: {
            "headers": headers,
            "rows": [clean],
            "row_count": 1,
        }
    }
    result = engine.run_playbook(
        client, playbook_id, rows=rows, row_limit=1, commit=commit
    )
    result["host"] = client.host
    return result
