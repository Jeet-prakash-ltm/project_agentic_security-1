import base64
import os
import re
import tempfile

import azure.functions as func

from connectors.panos_client import PanosClient

from services.settings import Settings
from services.response import (
    success,
    error,
    preview
)
from services.validation import (
    ValidationError,
    require_xpath,
    require_element,
    require_cmd
)
from services.audit import audit
from services.xml_json import (
    PanosXmlError,
    agent_payload,
    is_system_info_cmd
)
from workbook.adapter import WorkbookPanosClient
from workbook.dependencies import Inventory
from workbook.runner import analyze_workbook, run_workbook
from workbook.changes import apply_change, prepare_change
from workbook import sheets, workbook


app = func.FunctionApp(
    http_auth_level=func.AuthLevel.FUNCTION
)


def get_body(req):
    try:
        return req.get_json()
    except Exception:
        return {}


def client():
    return PanosClient()


_SECRET_RE = re.compile(
    r"(password|passwd|key|api_key|token)=([^&\s'\"]+)", re.IGNORECASE
)


def redact(text):
    return _SECRET_RE.sub(r"\1=***", str(text))


def fail(ex, status_code=502):
    message = redact(ex)
    if isinstance(ex, (ValidationError, PanosXmlError, ValueError)):
        return error(message, 400)
    return error(message, status_code)


def _truthy(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def live_block():
    """Return a 409 response when the firewall is not reachable."""
    from services.firewall_job_lifecycle import FIREWALL_DOWN_MESSAGE
    from services.firewall_jobs import check_firewall_live

    live, _detail = check_firewall_live()
    if not live:
        return error(FIREWALL_DOWN_MESSAGE, 409)
    return None


def workbook_bytes(req, body):
    encoded = (
        body.get("workbook_base64")
        or body.get("file_base64")
        or body.get("content")
    )
    if encoded:
        try:
            return base64.b64decode(encoded)
        except Exception:
            raise ValueError("workbook_base64 is not valid base64")
    try:
        uploaded = req.files.get("file") or req.files.get("workbook")
    except Exception:
        uploaded = None
    if uploaded is not None:
        return uploaded.read()
    raise ValueError("workbook_base64 is required")


def _row_limit(body):
    value = body.get("row_limit")
    if value in (None, ""):
        return None
    return int(value)


def _write_temp(payload):
    handle, path = tempfile.mkstemp(suffix=".xlsx")
    os.close(handle)
    with open(path, "wb") as handle:
        handle.write(payload)
    return path


@app.route(route="panos/info")
def panos_info(req: func.HttpRequest):
    return success({
        "host_configured": bool(Settings.FW_HOST),
        "port": Settings.FW_PORT,
        "dry_run": Settings.DRY_RUN,
        "verify_tls": Settings.VERIFY_TLS,
        "api_key_configured": bool(Settings.FW_API_KEY)
    })


@app.route(route="panos/categories")
def panos_categories(req: func.HttpRequest):
    return success({
        "categories": sheets.categories(),
        "actions": ["create", "update", "delete"],
    })


@app.route(route="panos/test_connection")
def test_connection(req):
    try:
        xml = client().test_connection()
        return success(agent_payload(xml, flatten_system=True))
    except Exception as ex:
        return fail(ex)


@app.route(route="panos/config/get")
def config_get(req):
    try:
        body = get_body(req)
        xpath = require_xpath(body)
        xml = client().get(xpath)
        audit(operation="get", xpath=xpath, result="success")
        return success(agent_payload(xml, extra={"action": "get", "xpath": xpath}))
    except Exception as ex:
        return fail(ex)


@app.route(route="panos/config/set")
def config_set(req):
    try:
        blocked = live_block()
        if blocked:
            return blocked
        body = get_body(req)
        xpath = require_xpath(body)
        element = require_element(body)
        if Settings.DRY_RUN:
            return preview("Dry run enabled", {
                "operation": "set",
                "xpath": xpath
            })
        xml = client().set(xpath, element)
        audit(operation="set", xpath=xpath, result="success")
        return success(agent_payload(xml, extra={"action": "set", "xpath": xpath}))
    except Exception as ex:
        return fail(ex)


@app.route(route="panos/config/edit")
def config_edit(req):
    try:
        blocked = live_block()
        if blocked:
            return blocked
        body = get_body(req)
        xpath = require_xpath(body)
        element = require_element(body)
        if Settings.DRY_RUN:
            return preview("Dry run enabled", {
                "operation": "edit",
                "xpath": xpath
            })
        xml = client().edit(xpath, element)
        return success(agent_payload(xml, extra={"action": "edit", "xpath": xpath}))
    except Exception as ex:
        return fail(ex)


@app.route(route="panos/config/delete")
def config_delete(req):
    try:
        blocked = live_block()
        if blocked:
            return blocked
        body = get_body(req)
        xpath = require_xpath(body)
        if Settings.DRY_RUN:
            return preview("Dry run enabled", {
                "operation": "delete",
                "xpath": xpath
            })
        xml = client().delete(xpath)
        return success(agent_payload(xml, extra={"action": "delete", "xpath": xpath}))
    except Exception as ex:
        return fail(ex)


@app.route(route="panos/change", methods=["POST"])
def panos_change(req: func.HttpRequest):
    """Apply one structured configuration change and commit it.

    Body::

        {
          "category": "security_rule",
          "action": "create",
          "name": "allow-web",
          "fields": {"from": "trust", "to": "untrust", "source": "any",
                     "destination": "web", "rule_action": "allow"},
          "commit": true
        }
    """
    try:
        blocked = live_block()
        if blocked:
            return blocked
        body = get_body(req)
        category = body.get("category") or body.get("type")
        if not category:
            raise ValueError("category is required")
        fields_map = (
            body.get("fields")
            or body.get("values")
            or body.get("attributes")
            or {}
        )
        if not isinstance(fields_map, dict):
            raise ValueError("fields must be an object")
        commit = body.get("commit")
        commit = _truthy(commit, default=not Settings.DRY_RUN) if commit is not None else None
        auto_create = _truthy(body.get("auto_create"), default=True)
        change = prepare_change(
            category,
            action=body.get("action") or "create",
            name=body.get("name"),
            fields_map=fields_map,
        )
        client = WorkbookPanosClient()
        inventory = Inventory(client_factory=lambda: client)
        result = apply_change(
            client,
            change,
            commit=commit,
            inventory=inventory,
            auto_create=auto_create,
        )
        audit(
            operation="change",
            xpath="{0}:{1}".format(category, body.get("name") or ""),
            result="success" if not result.get("commit_error") else "error",
        )
        return success(result)
    except Exception as ex:
        return fail(ex)


@app.route(route="panos/commit")
def commit(req):
    try:
        blocked = live_block()
        if blocked:
            return blocked
        if Settings.DRY_RUN:
            return preview("Commit blocked because dry-run is enabled")
        xml = client().commit()
        return success(agent_payload(xml, extra={"action": "commit"}))
    except Exception as ex:
        return fail(ex)


@app.route(route="panos/workbook/analyze", methods=["POST"])
def panos_analyze_workbook(req: func.HttpRequest):
    """Detect categories and list row actions in an uploaded workbook.

    Performs no firewall changes. Use this to show the user what a workbook will
    do before running it.
    """
    path = None
    try:
        body = get_body(req)
        payload = workbook_bytes(req, body)
        if not payload:
            raise ValueError("workbook_base64 is required")
        path = _write_temp(payload)
        parsed = workbook.read_workbook(path)
        result = analyze_workbook(parsed, row_limit=_row_limit(body))
        return success(result)
    except Exception as ex:
        return fail(ex)
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


@app.route(route="panos/workbook/run", methods=["POST"])
def panos_run_workbook(req: func.HttpRequest):
    """Parse a workbook of any layout, apply every detected row and commit."""
    path = None
    try:
        blocked = live_block()
        if blocked:
            return blocked
        body = get_body(req)
        payload = workbook_bytes(req, body)
        if not payload:
            raise ValueError("workbook_base64 is required")
        path = _write_temp(payload)
        commit = body.get("commit")
        commit = _truthy(commit, default=not Settings.DRY_RUN) if commit is not None else None
        auto_create = _truthy(body.get("auto_create"), default=True)
        client = WorkbookPanosClient()
        result = run_workbook(
            client,
            path,
            row_limit=_row_limit(body),
            commit=commit,
            inventory=Inventory(client_factory=lambda: client),
            auto_create=auto_create,
        )
        audit(
            operation="runWorkbook",
            xpath=body.get("workbook_name") or "workbook.xlsx",
            result=result.get("status") or "success",
        )
        return success(result)
    except Exception as ex:
        return fail(ex)
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


@app.route(route="panos/op")
def op(req):
    try:
        body = get_body(req)
        cmd = require_cmd(body)
        xml = client().op(cmd)
        return success(agent_payload(
            xml,
            extra={"action": "op", "cmd": cmd},
            flatten_system=is_system_info_cmd(cmd)
        ))
    except Exception as ex:
        return fail(ex)


def _user_id(req, body=None):
    value = (
        req.headers.get("x-user-id")
        or (body or {}).get("user_id")
        or req.params.get("user_id")
        or "anonymous"
    )
    return str(value).strip()[:64] or "anonymous"


def _job_response(ex):
    from services.firewall_jobs import (
        FirewallDownError,
        JobConflict,
        JobNotFound,
        JobValidationError,
    )

    message = redact(ex)
    if isinstance(ex, FirewallDownError):
        return error(message, 409)
    if isinstance(ex, JobNotFound):
        return error(message, 404)
    if isinstance(ex, JobConflict):
        return error(message, 409)
    if isinstance(ex, JobValidationError):
        return error(message, 400)
    return error(message, 502)


@app.route(route="firewall/preflight")
def firewall_preflight(req):
    from services.firewall_jobs import preflight

    try:
        return success(preflight(req.params.get("firewall_host")))
    except Exception as ex:
        return _job_response(ex)


@app.route(route="firewall/jobs", methods=["GET"])
def firewall_jobs_list(req):
    from services import job_store

    if not job_store.is_configured():
        return error("DATABASE_URL is not configured.", 503)
    try:
        limit = int(req.params.get("limit") or 100)
    except (TypeError, ValueError):
        limit = 100
    jobs = job_store.list_jobs(
        user_id=_user_id(req),
        status=req.params.get("status"),
        limit=limit,
    )
    return success({"jobs": jobs})


@app.route(route="firewall/jobs", methods=["POST"])
def firewall_jobs_create(req):
    from services.firewall_jobs import create_job

    body = get_body(req)
    try:
        job = create_job(_user_id(req, body), body)
        return success({"job": job})
    except Exception as ex:
        return _job_response(ex)


@app.route(route="firewall/jobs/{task_id}", methods=["GET"])
def firewall_jobs_get(req):
    from services.firewall_jobs import get_job

    try:
        return success({"job": get_job(req.route_params.get("task_id"))})
    except Exception as ex:
        return _job_response(ex)


@app.route(route="firewall/signalr/negotiate", methods=["POST"])
def firewall_jobs_negotiate(req):
    from services import job_events

    if not job_events.is_configured():
        return error("SIGNALR_CONNECTION is not configured.", 503)
    try:
        return success(job_events.negotiate(_user_id(req)))
    except Exception as ex:
        return _job_response(ex)


@app.route(route="firewall/jobs/{task_id}/approve", methods=["POST"])
def firewall_jobs_approve(req):
    from services.firewall_jobs import approve_job

    body = get_body(req)
    approve = _truthy(body.get("approve"), default=True)
    try:
        job = approve_job(
            req.route_params.get("task_id"),
            _user_id(req, body),
            approve=approve,
        )
        return success({"job": job})
    except Exception as ex:
        return _job_response(ex)


@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="firewall-jobs",
    connection="SERVICEBUS_CONNECTION",
    is_sessions_enabled=True,
)
def firewall_jobs_worker(msg: func.ServiceBusMessage):
    import json

    from services.firewall_jobs import execute_job

    try:
        body = json.loads(msg.get_body().decode("utf-8"))
    except Exception:
        raise ValueError("Firewall job message is not valid JSON.")
    task_id = body.get("task_id")
    if not task_id:
        raise ValueError("Firewall job message is missing task_id.")
    execute_job(task_id)
