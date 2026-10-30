"""PostgreSQL persistence for the network-security function app.

Writes every completed assessment into the canonical tables:

* ``assessments``
* ``assessment_findings``
* ``assessment_evidence``

Also writes an audit row to ``agent_activity_logs``. Failures are logged and
never break the HTTP function result.
"""

import logging
import os
import time
from datetime import datetime, timezone

log = logging.getLogger("netsec-dbwriter")

EVIDENCE_KEYS = (
    "inventory",
    "health_status",
    "ha_configuration",
    "policy_configuration",
    "security_services",
    "routing_configuration",
    "vpn_configuration",
    "logging_configuration",
    "administration_configuration",
    "zone_protection_configuration",
    "backup_configuration",
)

STATUS_MAP = {
    "COMPLIANT": "passed",
    "PASS": "passed",
    "PASSED": "passed",
    "NON_COMPLIANT": "failed",
    "FAIL": "failed",
    "FAILED": "failed",
    "NOT_ASSESSED": "not_assessed",
    "INSUFFICIENT_DATA": "not_assessed",
    "ERROR": "error",
}


def _database_url():
    return (os.environ.get("DATABASE_URL") or "").strip()


def _connect():
    import psycopg2

    return psycopg2.connect(_database_url(), sslmode="require", connect_timeout=10)


def _ensure_schema(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_activity_logs (
                id BIGSERIAL PRIMARY KEY,
                agent_id VARCHAR(64),
                run_id VARCHAR(64),
                activity VARCHAR(128),
                function_name VARCHAR(255),
                status VARCHAR(32) DEFAULT 'Completed',
                message TEXT,
                ts DOUBLE PRECISION,
                meta JSONB
            )
            """
        )
    conn.commit()


def _jsonb(value):
    from psycopg2.extras import Json

    if value is None:
        return None
    if isinstance(value, (dict, list, tuple)):
        return Json(value)
    return Json(value)


def _severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings or []:
        risk = (finding.get("risk") or finding.get("severity") or "").lower()
        if risk in counts:
            counts[risk] += 1
    return counts


def _map_status(raw):
    text = (raw or "").strip()
    mapped = STATUS_MAP.get(text.upper())
    if mapped:
        return mapped
    return text.lower() or "unknown"


def _risk_level(severity):
    if severity.get("critical"):
        return "critical"
    if severity.get("high"):
        return "high"
    if severity.get("medium"):
        return "medium"
    if severity.get("low"):
        return "low"
    return "low"


def _firewall_name(data, fallback="vmpafw01"):
    inventory = data.get("inventory") or {}
    name = (
        inventory.get("hostname")
        or data.get("_firewall_id")
        or fallback
        or "vmpafw01"
    )
    return str(name).strip() or "vmpafw01"


def _findings_rows(data):
    rows = data.get("findings") or []
    if rows:
        return rows
    return []


def _with_connection(fn):
    url = _database_url()
    if not url:
        log.info("DATABASE_URL not configured - skipping PostgreSQL write.")
        return None
    try:
        conn = _connect()
        try:
            _ensure_schema(conn)
            result = fn(conn)
            conn.commit()
            return result
        finally:
            conn.close()
    except Exception as exc:
        log.warning("PostgreSQL write failed (ignored): %s", exc)
        try:
            with open("/home/site/wwwroot/persist.log", "a") as handle:
                handle.write("persist failed: {0}\n".format(exc))
        except Exception:
            pass
        return None


def log_activity(agent_id, run_id, activity, function_name, status="Completed", message=None):
    """Insert one ``agent_activity_logs`` row."""

    def _run(conn):
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO agent_activity_logs
                    (agent_id, run_id, activity, function_name, status, message, ts)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    agent_id,
                    run_id,
                    activity,
                    function_name,
                    status,
                    str(message)[:2000] if message is not None else None,
                    time.time(),
                ),
            )

    return _with_connection(_run)


def persist_assessment(firewall_name, data, function_name="run_full_assessment"):
    """Persist one assessment run into canonical PostgreSQL tables."""
    if not isinstance(data, dict):
        return None

    firewall_name = _firewall_name(data, firewall_name)
    summary = data.get("summary") or {}
    findings = _findings_rows(data)
    severity = _severity_counts(findings)

    total_checks = int(summary.get("total_controls") or len(data.get("assessment") or []) or 0)
    passed_checks = int(summary.get("compliant") or 0)
    failed_checks = int(summary.get("non_compliant") or 0)
    error_checks = int(summary.get("not_assessed") or 0)
    if total_checks and passed_checks == 0 and failed_checks == 0 and data.get("assessment"):
        results = data.get("assessment") or []
        passed_checks = len([r for r in results if (r.get("status") or "").upper() == "COMPLIANT"])
        failed_checks = len([r for r in results if (r.get("status") or "").upper() == "NON_COMPLIANT"])
        error_checks = len([r for r in results if (r.get("status") or "").upper() == "NOT_ASSESSED"])
        total_checks = len(results)

    compliance_score = summary.get("compliance_pct")
    if compliance_score is None and total_checks:
        compliance_score = round(passed_checks / total_checks * 100, 1)
    security_score = data.get("security_score")
    overall_score = security_score if security_score is not None else compliance_score

    now = datetime.now(timezone.utc)
    run_id = "NS-{0}-{1}".format(firewall_name, int(time.time() * 1000))
    summary_payload = {
        "function_name": function_name,
        "firewall_name": firewall_name,
        "source": "network-security-firewall-agent",
        "total_controls": total_checks,
        "compliant": passed_checks,
        "non_compliant": failed_checks,
        "not_assessed": error_checks,
        "inventory": data.get("inventory") or {},
    }

    def _run(conn):
        from psycopg2.extras import execute_values

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assessments (
                    id, assessment_id, assessment_type, security_domain,
                    agent_id, asset_id, firewall_id, user_id, status,
                    overall_score, compliance_score, security_score, risk_level,
                    total_checks, passed_checks, failed_checks, error_checks,
                    critical_findings, high_findings, medium_findings, low_findings,
                    total_findings, summary, started_at, completed_at,
                    created_at, updated_at
                )
                VALUES (
                    gen_random_uuid(), %s, 'firewall_audit', 'network_security',
                    'firewall-audit-agent', %s, %s, 'anonymous', 'completed',
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s
                )
                """,
                (
                    run_id,
                    firewall_name,
                    firewall_name,
                    overall_score,
                    compliance_score,
                    security_score,
                    _risk_level(severity),
                    total_checks,
                    passed_checks,
                    failed_checks,
                    error_checks,
                    severity["critical"],
                    severity["high"],
                    severity["medium"],
                    severity["low"],
                    len(findings),
                    _jsonb(summary_payload),
                    now,
                    now,
                    now,
                    now,
                ),
            )

            finding_rows = []
            for item in findings:
                control = item.get("control")
                metric = item.get("metric")
                title = " — ".join(
                    [part for part in (control, metric) if part]
                ) or (item.get("finding") or control)
                finding_rows.append(
                    (
                        run_id,
                        None,
                        metric,
                        control,
                        control,
                        _map_status(item.get("status")),
                        (item.get("risk") or item.get("severity") or "").lower() or None,
                        item.get("risk_score"),
                        title,
                        item.get("finding"),
                        item.get("finding"),
                        _jsonb(item.get("observed")),
                        _jsonb(item.get("expected")),
                        item.get("remediation"),
                        now,
                    )
                )
            if finding_rows:
                execute_values(
                    cur,
                    """
                    INSERT INTO assessment_findings (
                        id, assessment_id, pillar, category, control_id, control_name,
                        status, severity, risk_score, title, finding, detail,
                        observed_value, expected_value, remediation, created_at
                    )
                    VALUES %s
                    """,
                    finding_rows,
                    template="(gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                )

            evidence_rows = []
            for key in EVIDENCE_KEYS:
                if key not in data:
                    continue
                payload = data.get(key)
                if payload is None:
                    continue
                evidence_rows.append(
                    (
                        run_id,
                        key,
                        key,
                        "collector_snapshot",
                        "paloalto",
                        _jsonb(payload),
                        now,
                    )
                )
            if data.get("assessment") is not None:
                evidence_rows.append(
                    (
                        run_id,
                        "assessment",
                        "compliance_engine",
                        "compliance_results",
                        "paloalto",
                        _jsonb(data.get("assessment")),
                        now,
                    )
                )
            if summary:
                evidence_rows.append(
                    (
                        run_id,
                        "summary",
                        function_name,
                        "assessment_summary",
                        "paloalto",
                        _jsonb(summary),
                        now,
                    )
                )
            if evidence_rows:
                execute_values(
                    cur,
                    """
                    INSERT INTO assessment_evidence (
                        id, assessment_id, pillar, collector, evidence_type,
                        source, payload, collected_at
                    )
                    VALUES %s
                    """,
                    evidence_rows,
                    template="(gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s)",
                )

        return run_id

    assessment_id = _with_connection(_run)
    if assessment_id:
        data["assessment_id"] = assessment_id
        log.info("Persisted canonical assessment %s", assessment_id)
        try:
            with open("/home/site/wwwroot/persist.log", "a") as handle:
                handle.write("persisted {0}\n".format(assessment_id))
        except Exception:
            pass
    return assessment_id


def load_latest_assessment(firewall_name=None):
    """Rebuild a Function App assessment payload from the latest canonical row."""

    def _run(conn):
        with conn.cursor() as cur:
            if firewall_name:
                cur.execute(
                    """
                    SELECT assessment_id, firewall_id, overall_score, compliance_score,
                           security_score, total_checks, passed_checks, failed_checks,
                           error_checks, summary, completed_at
                    FROM assessments
                    WHERE security_domain = 'network_security'
                      AND lower(coalesce(status, '')) = 'completed'
                      AND firewall_id = %s
                    ORDER BY completed_at DESC NULLS LAST, created_at DESC
                    LIMIT 1
                    """,
                    (firewall_name,),
                )
            else:
                cur.execute(
                    """
                    SELECT assessment_id, firewall_id, overall_score, compliance_score,
                           security_score, total_checks, passed_checks, failed_checks,
                           error_checks, summary, completed_at
                    FROM assessments
                    WHERE security_domain = 'network_security'
                      AND lower(coalesce(status, '')) = 'completed'
                    ORDER BY completed_at DESC NULLS LAST, created_at DESC
                    LIMIT 1
                    """
                )
            row = cur.fetchone()
            if not row:
                return None
            (
                assessment_id,
                firewall_id,
                overall_score,
                compliance_score,
                security_score,
                total_checks,
                passed_checks,
                failed_checks,
                error_checks,
                summary_blob,
                completed_at,
            ) = row

            cur.execute(
                """
                SELECT collector, evidence_type, payload
                FROM assessment_evidence
                WHERE assessment_id = %s
                """,
                (assessment_id,),
            )
            evidence = cur.fetchall()
            cur.execute(
                """
                SELECT control_id, category, status, severity, risk_score,
                       finding, observed_value, expected_value, remediation
                FROM assessment_findings
                WHERE assessment_id = %s
                ORDER BY created_at
                """,
                (assessment_id,),
            )
            finding_rows = cur.fetchall()

        def _as_json(value):
            if isinstance(value, (bytes, bytearray)):
                value = value.decode("utf-8")
            if isinstance(value, str):
                try:
                    import json as json_lib

                    return json_lib.loads(value)
                except Exception:
                    return value
            return value

        payload = {
            "assessment_id": assessment_id,
            "_firewall_id": firewall_id,
            "security_score": security_score or overall_score,
        }
        assessment = []
        summary = {}
        summary_blob = _as_json(summary_blob)
        for collector, evidence_type, body in evidence:
            body = _as_json(body)
            if evidence_type == "compliance_results" or collector == "assessment":
                if isinstance(body, list):
                    assessment = body
            elif evidence_type == "assessment_summary" or collector == "summary":
                if isinstance(body, dict):
                    summary = dict(body)
            elif collector in EVIDENCE_KEYS:
                payload[collector] = body

        if not summary:
            summary = {
                "total_controls": int(total_checks or 0),
                "compliant": int(passed_checks or 0),
                "non_compliant": int(failed_checks or 0),
                "not_assessed": int(error_checks or 0),
            }
        if isinstance(summary_blob, dict) and not payload.get("inventory"):
            inventory = summary_blob.get("inventory")
            if isinstance(inventory, dict):
                payload["inventory"] = inventory

        status_reverse = {
            "passed": "COMPLIANT",
            "failed": "NON_COMPLIANT",
            "not_assessed": "NOT_ASSESSED",
            "error": "NOT_ASSESSED",
        }
        findings = []
        for item in finding_rows:
            raw_status = (item[2] or "").lower()
            findings.append(
                {
                    "control": item[0],
                    "metric": item[1],
                    "status": status_reverse.get(raw_status, (item[2] or "").upper() or "NOT_ASSESSED"),
                    "risk": (item[3] or "MEDIUM").upper(),
                    "risk_score": item[4],
                    "finding": item[5],
                    "observed": item[6],
                    "expected": item[7],
                    "remediation": item[8],
                }
            )
        if not assessment:
            assessment = [
                {
                    "control": f["control"],
                    "status": f["status"],
                    "risk": f["risk"],
                    "metric": f.get("metric"),
                    "observed": f.get("observed"),
                    "expected": f.get("expected"),
                    "operator": None,
                }
                for f in findings
            ]
        payload["summary"] = summary
        payload["findings"] = findings
        payload["assessment"] = assessment
        if completed_at is not None:
            payload["_collected_at"] = str(completed_at)
        payload["_source"] = "stored"
        return payload

    return _with_connection(_run)


def persist_report(data):
    """Insert one ``reports_history`` row for a generated Excel/PDF report."""
    if not isinstance(data, dict):
        return None

    def _run(conn):
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reports_history (
                    user_id, name, type, generated_by, firewall, ts, status,
                    size, download_url, assessment_id, security_domain,
                    storage_reference
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    data.get("user_id") or "usr-admin",
                    data.get("name"),
                    data.get("type"),
                    data.get("generated_by") or "Firewall Audit Agent",
                    data.get("firewall"),
                    data.get("ts") or time.time(),
                    data.get("status") or "Completed",
                    data.get("size"),
                    data.get("download_url"),
                    data.get("assessment_id"),
                    data.get("security_domain") or "network_security",
                    data.get("storage_reference") or data.get("download_url"),
                ),
            )
            row = cur.fetchone()
            return row[0] if row else None

    return _with_connection(_run)
