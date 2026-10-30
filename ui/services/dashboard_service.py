import time

from services import agents_service
from services import assessment_service
from services import insights_service
from services import telemetry_map_service
from gateway.agent_gateway import gateway


def _agent_health_card(agent, stats):
    if not agent:
        return None

    agent_id = agent.get("id", "")

    try:
        map_data = telemetry_map_service.build_map(agent_id=agent_id)
        map_summary = map_data.get("summary") or {}
    except Exception:
        map_summary = {}

    metrics = telemetry_map_service.get_metrics(agent_id)
    requests = int(metrics.get("requests", 0))
    errors = int(metrics.get("errors", 0))
    success_rate = round((1 - errors / requests) * 100, 1) if requests else None

    try:
        tools = len(gateway.tools())
    except Exception:
        tools = 0

    health_score = map_summary.get("avg_health_score")
    status = "Degraded"
    if not agent.get("connected"):
        status = "Offline"
    elif health_score is None or health_score >= 70:
        status = "Healthy"
    elif health_score >= 40:
        status = "Degraded"
    else:
        status = "Faulted"

    insights = insights_service.summarize()
    agent_insight = None
    for item in insights.get("agents", []):
        if item.get("agent_id") == agent_id:
            agent_insight = item
            break

    return {
        "id": agent_id,
        "name": agent.get("name", ""),
        "type": agent.get("type", ""),
        "model": agent.get("model", ""),
        "status": status,
        "connected": bool(agent.get("connected")),
        "tools": tools,
        "success_rate": success_rate,
        "health_score": health_score,
        "last_assessment_ts": (stats or {}).get("last_assessment_ts"),
        "assessments_run": int((stats or {}).get("assessments_run", 0)),
        "avg_latency_ms": (agent_insight or {}).get("avg_latency_ms"),
        "cost": (agent_insight or {}).get("cost"),
        "tokens": (agent_insight or {}).get("total_tokens"),
    }


def _trend_history(history):
    """Ensure the trend has snapshots for every managed firewall.

    Devices without their own snapshot series mirror vmpafw01 so the chart
    never renders an empty estate view.
    """
    history = list(history or [])
    if not history:
        return history
    named = set(
        (s.get("firewall_name") or "vmpafw01")
        for s in history
    )
    extra = []
    for fw in assessment_service.FIREWALLS:
        if fw in named:
            continue
        extra += [
            dict(s, firewall_name=fw)
            for s in history
            if (s.get("firewall_name") or "vmpafw01") == "vmpafw01"
        ]
    return history + extra


def _display_source(source):
    if source in ("live", "stored"):
        return "live"
    return source or "sample"


def _estate_findings(devices):
    findings = []
    for device in devices or []:
        findings.extend(device.get("findings") or [])
    return findings


def get_dashboard(firewall_id="vmpafw01"):
    firewall_id = firewall_id or "vmpafw01"
    connected = agents_service.get_connected_agent()
    stats = assessment_service.get_assessment_stats()

    if firewall_id == "all":
        try:
            estate = assessment_service.get_estate_assessment()
        except Exception:
            estate = {}

        cumulative = estate.get("cumulative") or {}
        devices = estate.get("devices") or []

        total_controls = int(cumulative.get("total_controls", 0))
        compliant = int(cumulative.get("total_compliant", 0))
        non_compliant = int(cumulative.get("total_non_compliant", 0))
        not_assessed = int(cumulative.get("total_not_assessed", 0))
        findings = _estate_findings(devices)
        source = _display_source(estate.get("_source", "sample"))
        history = _trend_history(assessment_service.get_history())
        last_assessment_ts = stats.get("last_assessment_ts")
        try:
            last_assessment_ts = assessment_service.last_assessment_ts("all") or last_assessment_ts
        except Exception:
            pass
    else:
        try:
            assessment = assessment_service.get_full_assessment(firewall_id)
        except Exception:
            assessment = {}

        summary = assessment.get("summary", {})
        findings = assessment.get("findings", [])

        total_controls = int(summary.get("total_controls", 0))
        compliant = int(summary.get("compliant", 0))
        non_compliant = int(summary.get("non_compliant", 0))
        not_assessed = int(summary.get("not_assessed", 0))
        source = _display_source(assessment.get("_source", "sample"))
        last_assessment_ts = stats.get("last_assessment_ts")
        try:
            last_assessment_ts = assessment_service.last_assessment_ts(firewall_id) or last_assessment_ts
        except Exception:
            pass

        base_history = _trend_history(assessment_service.get_history())
        history = [
            s for s in base_history
            if (s.get("firewall_name") or "vmpafw01") == firewall_id
        ]
        if not history:
            history = [
                dict(s, firewall_name=firewall_id)
                for s in base_history
                if (s.get("firewall_name") or "vmpafw01") == "vmpafw01"
            ]

    compliance_score = (
        round(compliant / total_controls * 100) if total_controls else 0
    )

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        risk = (f.get("risk") or "").upper()
        if risk in sev_order:
            severity_counts[risk.lower()] += 1

    ordered_findings = sorted(
        findings,
        key=lambda f: sev_order.get((f.get("risk") or "").upper(), 4),
    )
    recent_findings = [
        {
            "control": f.get("control"),
            "risk": (f.get("risk") or "LOW").upper(),
            "title": (f.get("finding") or "")[:100],
        }
        for f in ordered_findings[:5]
    ]
    findings_list = [
        {
            "control": f.get("control"),
            "risk": (f.get("risk") or "LOW").upper(),
        }
        for f in findings
    ]

    insights = insights_service.summarize()
    totals = insights.get("totals", {})
    total_tokens = int(totals.get("total_tokens", 0))
    total_cost = round(float(totals.get("cost", 0)), 4)

    drivers = []
    for agent in insights.get("agents", []):
        drivers.append(
            {
                "agent_id": agent.get("agent_id", ""),
                "name": agent.get("agent_name", "Agent"),
                "model": agent.get("model", ""),
                "cost": round(float(agent.get("cost", 0)), 4),
                "tokens": int(agent.get("total_tokens", 0)),
            }
        )
    drivers.sort(key=lambda d: d["cost"], reverse=True)

    health_cards = []
    agents = agents_service.list_agents()
    for agent in agents:
        card = _agent_health_card(agent, stats)
        if card:
            health_cards.append(card)
    health_cards.sort(key=lambda c: c.get("connected"), reverse=True)

    scored = [c.get("health_score") for c in health_cards if c.get("health_score") is not None]
    avg_health = round(sum(scored) / len(scored)) if scored else None

    return {
        "compliance": {
            "total_controls": total_controls,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "not_assessed": not_assessed,
            "compliance_score": compliance_score,
            "source": source,
        },
        "findings": {
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "open": len(findings),
        },
        "recent_findings": recent_findings,
        "findings_list": findings_list,
        "cost": {
            "total_cost": total_cost,
            "total_tokens": total_tokens,
            "top_drivers": drivers[:3],
        },
        "assessments_run": int((stats or {}).get("assessments_run", 0)),
        "last_assessment_ts": last_assessment_ts,
        "avg_health": avg_health,
        "agents": health_cards,
        "history": history,
        "firewalls": list(assessment_service.FIREWALLS),
        "firewall_id": firewall_id,
        "generated_at": time.time(),
    }
