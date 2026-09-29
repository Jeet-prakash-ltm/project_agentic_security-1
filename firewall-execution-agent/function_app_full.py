import base64
import os
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
from workbook.runner import run_workbook


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


def fail(ex, status_code=502):
    if isinstance(ex, (ValidationError, PanosXmlError, ValueError)):
        return error(str(ex), 400)
    return error(str(ex), status_code)


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


@app.route(route="panos/info")
def panos_info(req: func.HttpRequest):
    return success({
        "host_configured": bool(Settings.FW_HOST),
        "port": Settings.FW_PORT,
        "dry_run": Settings.DRY_RUN,
        "verify_tls": Settings.VERIFY_TLS,
        "api_key_configured": bool(Settings.FW_API_KEY)
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


@app.route(route="panos/commit")
def commit(req):
    try:
        if Settings.DRY_RUN:
            return preview("Commit blocked because dry-run is enabled")
        xml = client().commit()
        return success(agent_payload(xml, extra={"action": "commit"}))
    except Exception as ex:
        return fail(ex)


@app.route(route="panos/workbook/run", methods=["POST"])
def panos_run_workbook(req: func.HttpRequest):
    path = None
    try:
        body = get_body(req)
        payload = workbook_bytes(req, body)
        if not payload:
            raise ValueError("workbook_base64 is required")
        row_limit = body.get("row_limit")
        if row_limit not in (None, ""):
            row_limit = int(row_limit)
        else:
            row_limit = None
        handle, path = tempfile.mkstemp(suffix=".xlsx")
        os.close(handle)
        with open(path, "wb") as handle:
            handle.write(payload)
        result = run_workbook(WorkbookPanosClient(), path, row_limit=row_limit)
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
