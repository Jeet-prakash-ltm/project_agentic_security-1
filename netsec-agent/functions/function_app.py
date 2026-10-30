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

app = func.FunctionApp()


def _db_log(run_id, activity, function_name, status, message=None):
    """Best-effort PostgreSQL audit logging (never raises)."""
    try:
        from dbwriter import log_activity

        log_activity(
            agent_id="firewall-audit-agent",
            run_id=run_id,
            activity=activity,
            function_name=function_name,
            status=status,
            message=message,
        )
    except Exception:
        pass


FIREWALL_IP = os.environ.get("PA_FIREWALL_HOST", "10.1.0.5")
USERNAME = os.environ.get("PA_USERNAME", "fwadmin")
PASSWORD = os.environ.get("PA_PASSWORD", "")


def get_connector():

    return PaloAltoConnector(
        hostname=FIREWALL_IP,
        username=USERNAME,
        password=PASSWORD
    )


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


def error_response(error):

    return func.HttpResponse(
        json.dumps(
            {
                "status": "ERROR",
                "message": str(error)
            }
        ),
        mimetype="application/json",
        status_code=500
    )


def build_compliance_assessment():

    connector = get_connector()

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

    return {

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

        connector = get_connector()

        result = (
            connector.run_full_assessment()
        )

        _db_log(
            "ns-full-" + str(int(time.time())),
            "assessment",
            "run_full_assessment",
            "Completed",
        )
        try:
            from dbwriter import persist_assessment

            assessment_id = persist_assessment(
                "vmpafw01", result, "run_full_assessment"
            )
            if assessment_id:
                result["assessment_id"] = assessment_id
        except Exception:
            pass

        return success_response(
            result
        )

    except Exception as e:

        _db_log(
            "ns-full-" + str(int(time.time())),
            "assessment",
            "run_full_assessment",
            "Failed",
            str(e),
        )
        return error_response(e)


@app.route(
    route="run_compliance_assessment",
    auth_level=func.AuthLevel.FUNCTION
)
def run_compliance_assessment(
    req: func.HttpRequest
):

    try:

        result = (
            build_compliance_assessment()
        )

        _db_log(
            "ns-compliance-" + str(int(time.time())),
            "assessment",
            "run_compliance_assessment",
            "Completed",
        )
        try:
            from dbwriter import persist_assessment

            assessment_id = persist_assessment(
                "vmpafw01", result, "run_compliance_assessment"
            )
            if assessment_id:
                result["assessment_id"] = assessment_id
        except Exception:
            pass

        return success_response(
            result
        )

    except Exception as e:

        _db_log(
            "ns-compliance-" + str(int(time.time())),
            "assessment",
            "run_compliance_assessment",
            "Failed",
            str(e),
        )
        return error_response(e)


def _stored_or_live_assessment():
    try:
        from dbwriter import load_latest_assessment

        stored = load_latest_assessment()
        if stored:
            return stored
    except Exception:
        pass
    return build_compliance_assessment()


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

        assessment_result = (
            _stored_or_live_assessment()
        )

        summary = (
            ExecutiveSummary()
            .generate(
                assessment_result
            )
        )
        summary["assessment_id"] = assessment_result.get("assessment_id")
        summary["message"] = "Executive summary generated, check Report Centre."
        summary["_source"] = assessment_result.get("_source", "live")

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

        _db_log(
            "ns-summary-" + str(int(time.time())),
            "report",
            "executive_summary",
            "Completed",
        )
        return success_response(
            summary
        )

    except Exception as e:

        _db_log(
            "ns-summary-" + str(int(time.time())),
            "report",
            "executive_summary",
            "Failed",
            str(e),
        )
        return error_response(e)


@app.route(
    route="generate_excel_report",
    auth_level=func.AuthLevel.FUNCTION
)
def generate_excel_report(
    req: func.HttpRequest
):

    try:

        assessment_result = (
            _stored_or_live_assessment()
        )

        report_generator = (
            ExcelReport()
        )

        firewall_id = (
            (assessment_result.get("inventory") or {}).get("hostname")
            or assessment_result.get("_firewall_id")
            or "vmpafw01"
        )
        month = time.strftime("%b_%Y")
        report_name = "Assessment_Workbook_{0}_{1}".format(firewall_id, month)
        download_url = "reports/{0}_Assessment_Workbook.xlsx".format(firewall_id)
        report_file = (
            report_generator.generate(
                assessment_result,
                output_file=
                "/tmp/{0}_Assessment_Workbook.xlsx".format(firewall_id)
            )
        )
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

        _db_log(
            "ns-excel-" + str(int(time.time())),
            "report",
            "generate_excel_report",
            "Completed",
        )
        return success_response({

            "status":
                "SUCCESS",

            "report_file":
                report_file,

            "message":
                "Report generated, check Report Centre.",

            "assessment_id":
                assessment_result.get("assessment_id"),

            "summary":
                assessment_result.get(
                    "summary",
                    {}
                )
        })

    except Exception as e:

        _db_log(
            "ns-excel-" + str(int(time.time())),
            "report",
            "generate_excel_report",
            "Failed",
            str(e),
        )
        return error_response(
            e
        )