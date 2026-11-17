import json
import os
import time

import azure.functions as func

from connectors.paloalto.paloalto_connector import (
    PaloAltoConnector
)

from compliance.compliance_engine import (
    ComplianceEngine
)

from compliance.findings_generator import (
    FindingsGenerator
)

from reports.executive_summary import (
    ExecutiveSummary
)

from reports.excel_report import (
    ExcelReport
)

from reports.risk_summary import (
    RiskSummary
)

app = func.FunctionApp()


def _persist_result(firewall_name, result, function_name, assessment_id=None, status=None):
    try:
        from dbwriter import persist_assessment

        saved_id = persist_assessment(
            firewall_name,
            result,
            function_name,
            assessment_id=assessment_id,
            status=status,
        )
        if saved_id and isinstance(result, dict):
            result["assessment_id"] = saved_id
        return saved_id
    except Exception as exc:
        try:
            with open("/home/site/wwwroot/persist.log", "a") as handle:
                handle.write("persist hook failed: {0}\n".format(exc))
        except Exception:
            pass
        return None


def _start_assessment_run(firewall_name, function_name):
    try:
        from dbwriter import start_assessment

        return start_assessment(firewall_name, function_name)
    except Exception:
        return None



FIREWALL_IP = "10.1.0.5"
USERNAME = "fwadmin"
PASSWORD = "Q1$uk256@rtnt9"

FIREWALL_SELECT_KEYS = (
    "firewall",
    "firewall_id",
    "firewall_name",
    "selected_firewall",
    "hostname",
    "device_name",
    "scope",
)

ALL_FIREWALL_SELECTORS = {
    "all",
    "all firewalls",
    "all_firewalls",
    "all-firewalls",
    "*",
    "every",
    "every firewall",
    "entire inventory",
    "fleet",
}


def get_connector(firewall=None):

    hostname = FIREWALL_IP
    username = USERNAME
    password = PASSWORD

    if isinstance(firewall, dict):
        inventory_ip = (
            firewall.get("management_ip")
            or firewall.get("ip")
            or ""
        ).strip()
        inventory_user = (firewall.get("username") or "").strip()
        if inventory_ip:
            hostname = inventory_ip
        if inventory_user:
            username = inventory_user

    return PaloAltoConnector(
        hostname=hostname,
        username=username,
        password=password
    )


def _request_payload(req):
    payload = {}
    try:
        body = req.get_json()
        if isinstance(body, dict):
            payload.update(body)
    except Exception:
        pass
    try:
        for key in req.params:
            payload[key] = req.params.get(key)
    except Exception:
        pass
    return payload


def _is_all_firewalls(value):
    text = str(value or "").strip().lower()
    text = " ".join(text.replace("_", " ").replace("-", " ").split())
    return text in ALL_FIREWALL_SELECTORS


def _selected_firewall_value(payload):
    for key in FIREWALL_SELECT_KEYS:
        value = payload.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _normalize_status(value):
    text = str(value or "").strip().lower()
    if text in ("live", "up", "online", "active", "reachable"):
        return "live"
    return "down"


def _is_firewall_live(firewall):
    if not isinstance(firewall, dict):
        return False
    return _normalize_status(firewall.get("status")) == "live"


def _live_firewalls(firewalls):
    return [item for item in (firewalls or []) if _is_firewall_live(item)]


def _severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings or []:
        risk = str(finding.get("risk") or "").strip().lower()
        if risk in counts:
            counts[risk] += 1
    return counts


def _posture_label(pct, severity):
    severity = severity or {}
    if severity.get("critical") or pct < 50:
        return "high_risk"
    if severity.get("high") or pct < 80:
        return "elevated"
    return "healthy"


def _business_impact_text(findings, severity=None):
    severity = severity or _severity_counts(findings)
    if severity.get("critical"):
        return (
            "Critical control failures expose the network to compromise, "
            "outage, or undetected attack."
        )
    if severity.get("high"):
        return (
            "High-risk gaps weaken inspection, availability, or access "
            "control and should be remediated promptly."
        )
    if findings:
        return (
            "Residual findings are present but do not indicate an "
            "immediate critical exposure."
        )
    return "No non-compliant controls were identified in this assessment."


def _device_information(result):
    inventory = result.get("inventory") or {}
    selected = result.get("_selected_firewall") or {}
    return {
        "name": (
            selected.get("name")
            or inventory.get("hostname")
            or result.get("_firewall_id")
        ),
        "hostname": inventory.get("hostname") or selected.get("hostname"),
        "vendor": (
            inventory.get("vendor")
            or selected.get("vendor")
            or "Palo Alto"
        ),
        "model": inventory.get("model") or selected.get("model"),
        "version": (
            inventory.get("version")
            or inventory.get("pan_os_version")
            or selected.get("pan_os_version")
        ),
        "ip": (
            selected.get("management_ip")
            or inventory.get("ip")
            or inventory.get("management_ip")
        ),
        "status": selected.get("status") or "live",
        "serial": inventory.get("serial") or inventory.get("serial_number"),
        "uptime": inventory.get("uptime"),
        "scope": result.get("scope") or "single",
        "firewall_count": inventory.get("firewall_count"),
        "assessed_count": inventory.get("assessed_count"),
    }


def _overall_posture(result):
    summary = result.get("summary") or {}
    findings = result.get("findings") or []
    total = int(summary.get("total_controls") or 0)
    compliant = int(summary.get("compliant") or 0)
    pct = _approved_compliance_score(summary, result.get("assessment"))
    summary["compliance_score"] = pct
    summary["compliance_pct"] = pct
    severity = _severity_counts(findings)
    return {
        "label": _posture_label(pct, severity),
        "compliance_score": pct,
        "compliance_pct": pct,
        "total_controls": total,
        "compliant": compliant,
        "non_compliant": int(summary.get("non_compliant") or 0),
        "not_assessed": int(summary.get("not_assessed") or 0),
        "severity": severity,
    }


def _decorate_ui_payload(payload, response_type):
    if not isinstance(payload, dict):
        return payload
    payload["response_type"] = response_type
    payload["ui_schema"] = {
        "version": 1,
        "sections": [
            "device_information",
            "overall_posture",
            "findings",
            "business_impact",
            "recommendations",
        ],
    }
    return payload


def _approved_compliance_score(summary, assessment=None):
    total = int((summary or {}).get("total_controls") or 0)
    compliant = int((summary or {}).get("compliant") or 0)
    if total <= 0 and assessment:
        total = len(assessment)
        compliant = len([
            item for item in assessment
            if str(item.get("status") or "").upper() == "COMPLIANT"
        ])
    if total <= 0:
        return 0
    return round(compliant / float(total) * 100, 1)


def _structured_summary(result):
    summary = dict(result.get("summary") or {})
    assessment = result.get("assessment") or []
    total = int(summary.get("total_controls") or len(assessment) or 0)
    compliant = int(summary.get("compliant") or 0)
    non_compliant = int(summary.get("non_compliant") or 0)
    insufficient = int(
        summary.get("insufficient_data")
        or summary.get("not_assessed")
        or 0
    )
    if assessment and (not total or (compliant + non_compliant + insufficient) == 0):
        total = len(assessment)
        compliant = len([
            item for item in assessment
            if str(item.get("status") or "").upper() == "COMPLIANT"
        ])
        non_compliant = len([
            item for item in assessment
            if str(item.get("status") or "").upper() == "NON_COMPLIANT"
        ])
        insufficient = len([
            item for item in assessment
            if str(item.get("status") or "").upper() in (
                "NOT_ASSESSED", "INSUFFICIENT_DATA", "ERROR"
            )
        ])
    score = _approved_compliance_score(
        {
            "total_controls": total,
            "compliant": compliant,
        },
        assessment,
    )
    overall_risk = summary.get("overall_risk")
    if not overall_risk:
        overall_risk = RiskSummary.calculate_overall_risk(assessment)
    structured = {
        "total_controls": total,
        "compliant": compliant,
        "gap_identified": int(summary.get("gap_identified") or 0),
        "non_compliant": non_compliant,
        "insufficient_data": insufficient,
        "not_assessed": insufficient,
        "compliance_score": score,
        "compliance_pct": score,
        "overall_risk": str(overall_risk or "LOW").upper(),
    }
    result["summary"] = structured
    return structured


def _structured_assessment_response(result, kind="compliance"):
    if not isinstance(result, dict):
        return result
    summary = _structured_summary(result)
    findings = result.get("findings") or []
    persist_status = str(result.get("persist_status") or "").upper()
    collection_status = str(result.get("collection_status") or "").upper()
    if persist_status == "FAILED" or collection_status == "FAILED":
        status = "FAILED"
    elif collection_status == "PARTIAL":
        status = "PARTIAL"
    else:
        status = "SUCCESS"
    result["status"] = status
    result["assessment_kind"] = kind
    result["firewall"] = (
        result.get("firewall")
        or result.get("_firewall_id")
        or ((result.get("_selected_firewall") or {}).get("name"))
    )
    result["device"] = _device_information(result)
    result["device_information"] = result["device"]
    result["overall_posture"] = _overall_posture(result)
    result["business_impact"] = _business_impact_text(
        findings, result["overall_posture"].get("severity")
    )
    result["recommendations"] = [
        item.get("remediation")
        for item in findings
        if item.get("remediation")
    ]
    result["summary"] = summary
    return _decorate_ui_payload(result, "firewall_assessment")


def _decorate_assessment_payload(result, kind="compliance"):
    return _structured_assessment_response(result, kind)


def _firewall_down_response(firewall=None, firewalls=None):
    option = _firewall_option(firewall) if isinstance(firewall, dict) else {}
    name = option.get("name") or "selected firewall"
    payload = {
        "status": "FIREWALL_DOWN",
        "action_required": "select_live_firewall",
        "message": "firewall down or stopped",
        "selected_firewall": option or None,
        "options": [
            _firewall_option(item) for item in (firewalls or [])
        ],
        "firewalls": [
            _firewall_option(item) for item in (firewalls or [])
        ],
    }
    if option:
        payload["prompt"] = (
            "Firewall {0} is down or stopped. Assessment cannot be run. "
            "Select a live firewall from inventory."
        ).format(name)
    return success_response(
        _decorate_ui_payload(payload, "firewall_down")
    )


def _firewall_option(item):
    name = item.get("name") or item.get("hostname") or "unknown"
    vendor = (item.get("vendor") or "").strip() or "Palo Alto"
    ip_addr = (
        item.get("ip")
        or item.get("management_ip")
        or item.get("hostname")
        or "unknown"
    )
    status = _normalize_status(item.get("status"))
    return {
        "id": item.get("id"),
        "name": name,
        "vendor": vendor,
        "ip": ip_addr,
        "management_ip": ip_addr,
        "status": status,
        "hostname": item.get("hostname") or name,
        "model": item.get("model"),
        "serial_number": item.get("serial_number"),
        "pan_os_version": item.get("pan_os_version"),
        "device_type": item.get("device_type"),
        "source": item.get("source"),
        "label": "{0} | {1} | {2} | {3}".format(name, vendor, ip_addr, status),
        "display": "Name: {0} | Vendor: {1} | IP: {2} | Status: {3}".format(
            name, vendor, ip_addr, status
        ),
    }


def _firewall_selection_response(firewalls, message=None, invalid_selection=None):
    choices = [_firewall_option(item) for item in (firewalls or [])]
    all_option = {
        "id": "all",
        "name": "ALL",
        "vendor": "All Vendors",
        "ip": "all",
        "management_ip": "all",
        "status": "live",
        "hostname": "ALL",
        "model": None,
        "serial_number": None,
        "pan_os_version": None,
        "device_type": None,
        "source": "all_firewalls",
        "label": "ALL | All Vendors | all | live",
        "display": "Name: ALL | Vendor: All Vendors | IP: all | Status: live",
        "description": (
            "Run audit/compliance assessment on all firewalls and generate "
            "a combined executive summary and report."
        ),
    }
    options = [all_option] + choices
    payload = {
        "status": "AWAITING_FIREWALL_SELECTION",
        "action_required": "select_firewall",
        "response_type": "firewall_selection",
        "always_select": True,
        "message": message or (
            "Every firewall audit or compliance assessment must start with "
            "firewall selection. Show the inventory and wait for the user to "
            "select one live firewall or ALL. Do not reuse a previous selection."
        ),
        "instructions": (
            "ALWAYS ask for firewall selection at the start of every new "
            "audit or compliance assessment. Do not reuse a firewall selected "
            "earlier in the conversation. Show name, vendor, IP, and live/down "
            "status. Assessment cannot be run if the selected firewall is down. "
            "If the user selects a down firewall, show: firewall down or stopped. "
            "After the user selects a live firewall or ALL, resubmit with "
            "firewall=<name or id> or firewall=ALL."
        ),
        "prompt": (
            "Which firewall should I assess this time? Options:\n"
            + "\n".join(
                "- {0}".format(item.get("display"))
                for item in options
            )
        ),
        "options": options,
        "firewalls": options,
        "count": len(options),
        "inventory_count": len(choices),
    }
    if invalid_selection:
        payload["invalid_selection"] = invalid_selection
        payload["message"] = (
            "Firewall '{0}' was not found in inventory. "
            "Please select one of the listed firewalls."
        ).format(invalid_selection)
    return success_response(
        _decorate_ui_payload(payload, "firewall_selection")
    )


def _require_selected_firewall(req):
    from dbwriter import get_firewall_by_selector, list_firewall_inventory

    payload = _request_payload(req)
    firewalls = list_firewall_inventory()
    selected_value = _selected_firewall_value(payload)

    if not firewalls:
        return None, error_response(
            "No firewalls found in firewall inventory. "
            "Add a firewall before running audit or compliance assessment.",
            status="NO_FIREWALLS",
            status_code=400,
        )

    if not selected_value:
        return None, error_response(
            "firewall is required. Call list_firewalls first, then POST "
            '{"firewall":"<name or ALL>"}.',
            status="MISSING_FIREWALL",
            status_code=400,
        )

    if _is_all_firewalls(selected_value):
        live = _live_firewalls(firewalls)
        if not live:
            return None, _firewall_down_response(firewalls=firewalls)
        return {
            "id": "all",
            "name": "ALL",
            "hostname": "ALL",
            "_all": True,
            "firewalls": live,
            "skipped_down": [
                _firewall_option(item)
                for item in firewalls
                if not _is_firewall_live(item)
            ],
            "source": "all_firewalls",
        }, None

    selected = get_firewall_by_selector(selected_value, firewalls)
    if not selected:
        return None, error_response(
            "Firewall '{0}' was not found in inventory.".format(selected_value),
            status="INVALID_FIREWALL",
            status_code=400,
            extra={
                "invalid_selection": selected_value,
                "firewalls": [_firewall_option(item) for item in firewalls],
            },
        )

    if not _is_firewall_live(selected):
        return None, _firewall_down_response(selected, firewalls)

    return selected, None


def load_baseline_rules():

    with open(
        "baseline/baseline_rules.json",
        "r"
    ) as f:

        return json.load(f)


def success_response(data):

    return func.HttpResponse(
        json.dumps(
            data,
            indent=2,
            default=str
        ),
        mimetype="application/json",
        status_code=200
    )


def error_response(error, status="ERROR", status_code=500, extra=None):

    payload = {
        "status": status,
        "message": str(error)
    }
    if extra:
        payload.update(extra)
    return func.HttpResponse(
        json.dumps(payload),
        mimetype="application/json",
        status_code=status_code
    )


def build_compliance_assessment(firewall=None):

    connector = get_connector(firewall)

    assessment_data = (
        connector.run_full_assessment()
    )

    baseline_rules = (
        load_baseline_rules()
    )

    compliance_engine = (
        ComplianceEngine(
            baseline_rules
        )
    )

    compliance_results = (
        compliance_engine.evaluate(
            assessment_data
        )
    )

    findings_generator = (
        FindingsGenerator()
    )

    findings = (
        findings_generator.generate(
            compliance_results
        )
    )

    summary = {

        "total_controls":
            len(
                compliance_results
            ),

        "compliant":
            len([
                r
                for r in compliance_results
                if r["status"]
                == "COMPLIANT"
            ]),

        "non_compliant":
            len([
                r
                for r in compliance_results
                if r["status"]
                == "NON_COMPLIANT"
            ]),

        "not_assessed":
            len([
                r
                for r in compliance_results
                if r["status"]
                == "NOT_ASSESSED"
            ])
    }

    collection_status = assessment_data.get("collection_status") or "SUCCESS"
    collection_errors = assessment_data.get("collection_errors") or {}

    result = {

        "collection_status":
            collection_status,

        "collection_errors":
            collection_errors,

        "collectors_ok":
            assessment_data.get("collectors_ok"),

        "collectors_failed":
            assessment_data.get("collectors_failed"),

        "collectors_total":
            assessment_data.get("collectors_total"),

        "collection_seconds":
            assessment_data.get("collection_seconds"),

        "inventory":
            assessment_data.get(
                "inventory",
                {}
            ),

        "health_status":
            assessment_data.get(
                "health_status",
                {}
            ),

        "ha_configuration":
            assessment_data.get(
                "ha_configuration",
                {}
            ),

        "policy_configuration":
            assessment_data.get(
                "policy_configuration",
                {}
            ),

        "security_services":
            assessment_data.get(
                "security_services",
                {}
            ),

        "routing_configuration":
            assessment_data.get(
                "routing_configuration",
                {}
            ),

        "vpn_configuration":
            assessment_data.get(
                "vpn_configuration",
                {}
            ),

        "logging_configuration":
            assessment_data.get(
                "logging_configuration",
                {}
            ),

        "administration_configuration":
            assessment_data.get(
                "administration_configuration",
                {}
            ),

        "zone_protection_configuration":
            assessment_data.get(
                "zone_protection_configuration",
                {}
            ),

        "backup_configuration":
            assessment_data.get(
                "backup_configuration",
                {}
            ),

        "summary":
            summary,

        "findings":
            findings,

        "assessment":
            compliance_results
    }

    if isinstance(firewall, dict):
        result["_firewall_id"] = (
            firewall.get("name")
            or firewall.get("hostname")
        )
        result["_selected_firewall"] = {
            "id": firewall.get("id"),
            "name": firewall.get("name"),
            "hostname": firewall.get("hostname"),
            "management_ip": firewall.get("management_ip"),
            "status": firewall.get("status"),
            "source": firewall.get("source"),
        }
        return result

    return result


def _firewall_display_name(firewall):
    if not isinstance(firewall, dict):
        return "unknown"
    return (
        firewall.get("name")
        or firewall.get("hostname")
        or firewall.get("management_ip")
        or "unknown"
    )


def _tag_firewall_result(result, firewall):
    if not isinstance(result, dict):
        result = {"result": result}
    name = _firewall_display_name(firewall)
    result["_firewall_id"] = name
    result["_selected_firewall"] = {
        "id": firewall.get("id"),
        "name": firewall.get("name"),
        "hostname": firewall.get("hostname"),
        "management_ip": firewall.get("management_ip"),
        "status": firewall.get("status"),
        "source": firewall.get("source"),
    }
    return result


def _empty_summary():
    return {
        "total_controls": 0,
        "compliant": 0,
        "non_compliant": 0,
        "not_assessed": 0,
        "compliance_score": 0,
        "compliance_pct": 0,
    }


def _combine_summaries(items):
    combined = _empty_summary()
    for item in items or []:
        summary = item.get("summary") or {}
        combined["total_controls"] += int(summary.get("total_controls") or 0)
        combined["compliant"] += int(summary.get("compliant") or 0)
        combined["non_compliant"] += int(summary.get("non_compliant") or 0)
        combined["not_assessed"] += int(summary.get("not_assessed") or 0)
    total = combined["total_controls"]
    if total:
        score = round(
            combined["compliant"] / float(total) * 100, 1
        )
    else:
        score = 0
    combined["compliance_score"] = score
    combined["compliance_pct"] = score
    return combined


def _annotate_findings(findings, firewall_name):
    annotated = []
    for finding in findings or []:
        item = dict(finding)
        item["firewall"] = firewall_name
        annotated.append(item)
    return annotated


def _annotate_assessment(assessment, firewall_name):
    annotated = []
    for item in assessment or []:
        row = dict(item)
        row["firewall"] = firewall_name
        annotated.append(row)
    return annotated


def _run_single_full_assessment(firewall):
    name = _firewall_display_name(firewall)
    assessment_id = _start_assessment_run(name, "run_full_assessment")
    connector = get_connector(firewall)
    result = connector.run_full_assessment()
    result = _tag_firewall_result(result, firewall)
    if assessment_id:
        result["assessment_id"] = assessment_id
    persist_status = (
        "FAILED" if result.get("collection_status") == "FAILED" else "COMPLETED"
    )
    _persist_result(
        name,
        result,
        "run_full_assessment",
        assessment_id=assessment_id,
        status=persist_status,
    )
    return result


def _run_single_compliance_assessment(firewall):
    name = _firewall_display_name(firewall)
    assessment_id = _start_assessment_run(name, "run_compliance_assessment")
    result = build_compliance_assessment(firewall)
    result = _tag_firewall_result(result, firewall)
    if assessment_id:
        result["assessment_id"] = assessment_id
    persist_status = "COMPLETED"
    if result.get("collection_status") == "FAILED":
        persist_status = "FAILED"
    elif not (result.get("summary") or {}).get("total_controls"):
        persist_status = "FAILED"
    _persist_result(
        name,
        result,
        "run_compliance_assessment",
        assessment_id=assessment_id,
        status=persist_status,
    )
    return result


def _generate_all_reports(combined):
    month = time.strftime("%b_%Y")
    firewall_id = combined.get("_firewall_id") or "ALL"
    executive = ExecutiveSummary().generate(combined)
    executive["assessment_id"] = combined.get("assessment_id")
    executive["scope"] = "ALL"
    executive["firewall_summaries"] = combined.get("firewall_summaries") or []
    executive["message"] = (
        "Combined executive summary generated for all firewalls. "
        "Check Report Centre."
    )
    report_name = "Executive_Summary_{0}_{1}".format(firewall_id, month)
    _persist_generated_report(
        "Executive Summary",
        combined,
        {
            "name": report_name,
            "download_url": "reports/{0}.pdf".format(report_name),
        },
    )

    workbook_name = "Assessment_Workbook_{0}_{1}".format(firewall_id, month)
    file_name = "{0}_Assessment_Workbook.xlsx".format(firewall_id)
    report_file = ExcelReport().generate(
        combined,
        output_file="/tmp/{0}".format(file_name)
    )
    from reports.blob_store import publish_workbook

    download_url = publish_workbook(report_file, file_name)
    _persist_generated_report(
        "Workbook",
        combined,
        {
            "name": workbook_name,
            "size": _file_size_label(report_file),
            "download_url": download_url,
            "storage_reference": report_file,
        },
    )
    combined["executive_summary"] = executive
    combined["report"] = {
        "status": "SUCCESS",
        "file_name": file_name,
        "download_available": bool(download_url),
        "download_url": download_url,
        "message": "Combined report generated for all firewalls, check Report Centre.",
    }
    return combined


def _build_all_firewalls_result(kind, firewalls):
    per_firewall = []
    failures = []
    skipped_down = []
    for firewall in firewalls or []:
        name = _firewall_display_name(firewall)
        if not _is_firewall_live(firewall):
            skipped_down.append(
                {
                    "firewall": name,
                    "status": "down",
                    "message": "firewall down or stopped",
                }
            )
            continue
        try:
            if kind == "compliance":
                result = _run_single_compliance_assessment(firewall)
            else:
                result = _run_single_full_assessment(firewall)
            per_firewall.append(result)
        except Exception as exc:
            failures.append(
                {
                    "firewall": name,
                    "status": "ERROR",
                    "message": str(exc),
                }
            )

    combined_findings = []
    combined_assessment = []
    firewall_summaries = []
    for result in per_firewall:
        name = result.get("_firewall_id") or "unknown"
        summary = result.get("summary") or _empty_summary()
        firewall_summaries.append(
            {
                "firewall": name,
                "status": "SUCCESS",
                "summary": summary,
                "assessment_id": result.get("assessment_id"),
                "selected_firewall": result.get("_selected_firewall"),
            }
        )
        combined_findings.extend(
            _annotate_findings(result.get("findings") or [], name)
        )
        combined_assessment.extend(
            _annotate_assessment(result.get("assessment") or [], name)
        )

    combined_summary = _combine_summaries(per_firewall)
    first = per_firewall[0] if per_firewall else {}
    combined = {
        "status": "SUCCESS" if per_firewall else "ERROR",
        "scope": "ALL",
        "_firewall_id": "ALL",
        "_selected_firewall": {
            "id": "all",
            "name": "ALL",
            "source": "all_firewalls",
        },
        "inventory": {
            "hostname": "ALL",
            "model": "All Firewalls",
            "version": None,
            "firewall_count": len(firewalls or []),
            "assessed_count": len(per_firewall),
            "failed_count": len(failures),
        },
        "summary": combined_summary,
        "findings": combined_findings,
        "assessment": combined_assessment,
        "firewall_summaries": firewall_summaries,
        "firewall_results": per_firewall,
        "failures": failures,
        "skipped_down": skipped_down,
        "health_status": first.get("health_status") or {},
        "ha_configuration": first.get("ha_configuration") or {},
        "policy_configuration": first.get("policy_configuration") or {},
        "security_services": first.get("security_services") or {},
        "routing_configuration": first.get("routing_configuration") or {},
        "vpn_configuration": first.get("vpn_configuration") or {},
        "logging_configuration": first.get("logging_configuration") or {},
        "administration_configuration": first.get("administration_configuration") or {},
        "zone_protection_configuration": first.get("zone_protection_configuration") or {},
        "backup_configuration": first.get("backup_configuration") or {},
        "message": (
            "Audit/compliance assessment completed for all selected firewalls. "
            "A combined executive summary and report were generated."
        ),
    }
    _persist_result("ALL", combined, "run_{0}_assessment_all".format(kind))
    return _generate_all_reports(combined)


@app.route(
    route="list_firewalls",
    auth_level=func.AuthLevel.FUNCTION
)
def list_firewalls(
    req: func.HttpRequest
):

    try:

        from dbwriter import list_firewall_inventory

        firewalls = list_firewall_inventory()
        choices = [_firewall_option(item) for item in (firewalls or [])]
        payload = {
            "status": "SUCCESS",
            "firewalls": choices,
            "count": len(choices),
            "inventory_count": len(choices),
        }
        return success_response(payload)

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_inventory",
    auth_level=func.AuthLevel.FUNCTION
)
def get_inventory(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_inventory()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_health_status",
    auth_level=func.AuthLevel.FUNCTION
)
def get_health_status(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_health_status()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_ha_configuration",
    auth_level=func.AuthLevel.FUNCTION
)
def get_ha_configuration(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_ha_configuration()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_policy_configuration",
    auth_level=func.AuthLevel.FUNCTION
)
def get_policy_configuration(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_policy_configuration()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_security_services",
    auth_level=func.AuthLevel.FUNCTION
)
def get_security_services(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_security_services()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_routing_configuration",
    auth_level=func.AuthLevel.FUNCTION
)
def get_routing_configuration(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_routing_configuration()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_vpn_configuration",
    auth_level=func.AuthLevel.FUNCTION
)
def get_vpn_configuration(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_vpn_configuration()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_logging_configuration",
    auth_level=func.AuthLevel.FUNCTION
)
def get_logging_configuration(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_logging_configuration()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_administration_configuration",
    auth_level=func.AuthLevel.FUNCTION
)
def get_administration_configuration(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_administration_configuration()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_zone_protection_configuration",
    auth_level=func.AuthLevel.FUNCTION
)
def get_zone_protection_configuration(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_zone_protection_configuration()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="get_backup_configuration",
    auth_level=func.AuthLevel.FUNCTION
)
def get_backup_configuration(
    req: func.HttpRequest
):

    try:

        return success_response(
            get_connector().get_backup_configuration()
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="run_full_assessment",
    auth_level=func.AuthLevel.FUNCTION
)
def run_full_assessment(
    req: func.HttpRequest
):

    try:

        selected, pending = _require_selected_firewall(req)
        if pending is not None:
            return pending

        if selected.get("_all"):
            return success_response(
                _decorate_assessment_payload(
                    _build_all_firewalls_result(
                        "full",
                        selected.get("firewalls") or []
                    ),
                    "full",
                )
            )

        result = _run_single_full_assessment(selected)

        return success_response(
            _decorate_assessment_payload(result, "full")
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="run_compliance_assessment",
    auth_level=func.AuthLevel.FUNCTION
)
def run_compliance_assessment(
    req: func.HttpRequest
):

    try:

        selected, pending = _require_selected_firewall(req)
        if pending is not None:
            return pending

        if selected.get("_all"):
            return success_response(
                _decorate_assessment_payload(
                    _build_all_firewalls_result(
                        "compliance",
                        selected.get("firewalls") or []
                    ),
                    "compliance",
                )
            )

        result = _run_single_compliance_assessment(selected)

        return success_response(
            _decorate_assessment_payload(result, "compliance")
        )

    except Exception as e:

        return error_response(e)


def _assessment_id_from_request(req):
    payload = _request_payload(req)
    for key in ("assessment_id", "run_id"):
        value = payload.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _load_assessment_for_report(req):
    from dbwriter import load_assessment_by_id

    assessment_id = _assessment_id_from_request(req)
    if not assessment_id:
        return None, error_response(
            "assessment_id is required.",
            status="MISSING_ASSESSMENT_ID",
            status_code=400,
        )
    stored = load_assessment_by_id(assessment_id)
    if not stored:
        return None, error_response(
            "Assessment '{0}' was not found.".format(assessment_id),
            status="ASSESSMENT_NOT_FOUND",
            status_code=404,
            extra={"assessment_id": assessment_id},
        )
    persist_status = str(stored.get("persist_status") or "").upper()
    if persist_status == "FAILED" or not (stored.get("summary") or {}).get("total_controls"):
        return None, error_response(
            "Assessment '{0}' did not complete with valid results.".format(
                assessment_id
            ),
            status="ASSESSMENT_FAILED",
            status_code=409,
            extra={"assessment_id": assessment_id},
        )
    return stored, None


def _file_size_label(path):
    try:
        size_bytes = os.path.getsize(path) if path and os.path.exists(path) else 0
    except Exception:
        return None
    if not size_bytes:
        return None
    if size_bytes >= 1024 * 1024:
        return "{0:.2f} MB".format(size_bytes / (1024 * 1024))
    return "{0:.0f} KB".format(size_bytes / 1024.0)


def _persist_generated_report(kind, assessment, extra=None):
    extra = extra or {}
    try:
        from dbwriter import persist_report

        inventory = assessment.get("inventory") or {}
        persist_report(
            {
                "name": extra.get("name"),
                "type": kind,
                "generated_by": "Firewall Audit Agent",
                "firewall": inventory.get("hostname") or assessment.get("_firewall_id"),
                "ts": time.time(),
                "status": "Completed",
                "size": extra.get("size"),
                "download_url": extra.get("download_url"),
                "assessment_id": assessment.get("assessment_id"),
                "security_domain": "network_security",
                "storage_reference": extra.get("storage_reference"),
            }
        )
    except Exception:
        pass


@app.route(
    route="executive_summary",
    auth_level=func.AuthLevel.FUNCTION
)
def executive_summary(
    req: func.HttpRequest
):

    try:

        assessment_result, missing = _load_assessment_for_report(req)
        if missing is not None:
            return missing

        summary = (
            ExecutiveSummary()
            .generate(
                assessment_result
            )
        )
        structured = _structured_summary(assessment_result)
        summary["status"] = "SUCCESS"
        summary["assessment_id"] = assessment_result.get("assessment_id")
        summary["firewall"] = (
            assessment_result.get("firewall")
            or assessment_result.get("_firewall_id")
        )
        summary["message"] = "Executive summary generated, check Report Centre."
        summary["_source"] = assessment_result.get("_source", "stored")
        summary["device"] = summary.get("device") or _device_information(assessment_result)
        summary["device_information"] = _device_information(assessment_result)
        summary["overall_posture"] = _overall_posture(assessment_result)
        summary["business_impact"] = _business_impact_text(
            assessment_result.get("findings") or []
        )
        summary["recommendations"] = summary.get("remediation_priorities") or []
        summary["findings"] = assessment_result.get("findings") or []
        if isinstance(summary.get("summary"), dict):
            summary["summary"].update(structured)
        summary = _decorate_ui_payload(summary, "executive_summary")

        month = time.strftime("%b_%Y")
        firewall_id = (
            (assessment_result.get("inventory") or {}).get("hostname")
            or assessment_result.get("_firewall_id")
            or "vmpafw01"
        )
        report_name = "Executive_Summary_{0}_{1}".format(firewall_id, month)
        _persist_generated_report(
            "Executive Summary",
            assessment_result,
            {
                "name": report_name,
                "download_url": "reports/{0}.pdf".format(report_name),
            },
        )

        return success_response(
            summary
        )

    except Exception as e:

        return error_response(e)


@app.route(
    route="generate_excel_report",
    auth_level=func.AuthLevel.FUNCTION
)
def generate_excel_report(
    req: func.HttpRequest
):

    try:

        assessment_result, missing = _load_assessment_for_report(req)
        if missing is not None:
            return missing

        report_generator = (
            ExcelReport()
        )

        firewall_id = (
            (assessment_result.get("inventory") or {}).get("hostname")
            or assessment_result.get("_firewall_id")
            or "vmpafw01"
        )
        month = time.strftime("%b_%Y")
        file_name = "{0}_Assessment_Workbook.xlsx".format(firewall_id)
        report_name = "Assessment_Workbook_{0}_{1}".format(firewall_id, month)
        report_file = (
            report_generator.generate(
                assessment_result,
                output_file="/tmp/{0}".format(file_name)
            )
        )
        from reports.blob_store import publish_workbook

        download_url = publish_workbook(report_file, file_name)
        download_available = bool(download_url)
        _persist_generated_report(
            "Workbook",
            assessment_result,
            {
                "name": report_name,
                "size": _file_size_label(report_file),
                "download_url": download_url,
                "storage_reference": report_file,
            },
        )

        return success_response({
            "status": "SUCCESS",
            "assessment_id": assessment_result.get("assessment_id"),
            "firewall": firewall_id,
            "file_name": file_name,
            "download_available": download_available,
            "download_url": download_url,
            "message": (
                "Report generated, check Report Centre."
                if download_available
                else "Report generated internally but no public download URL is available."
            ),
            "summary": assessment_result.get("summary", {}),
        })

    except Exception as e:

        return error_response(
            e
        )
