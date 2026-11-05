"""Deterministic Foundry routing for CloudSec incident / VM actions.

Every cloud action (incident counts, incident lists, investigation, VM
operations) is expressed as a single natural-language prompt sent to the
Cloud Incident Response prompt agent on Azure AI Foundry. That agent owns the
IncidentResponseTool (an OpenAPI tool backed by the CloudSec Azure Function),
so the UI never needs the live function key.

The prompts ask for terse, parseable replies where the UI needs structure
(e.g. the daily/weekly/monthly counts) and readable text elsewhere.
"""

import re

from gateway import foundry_client

CLOUD_AGENT_ID = "incident-response-agent-cloud-security"

# Operation names are written exactly as they appear in the Foundry agent's
# IncidentResponseTool / Azure Function surface.
_OPERATION = {
    "incident_counts": "GetSentinelIncidents",
    "incident_list": "GetSentinelIncidents",
    "investigate": "GetSentinelIncident",
    "incident_summary": "GenerateIncidentSummary",
    "isolate": "IsolateAzureVM",
    "start_vm": "StartVM",
    "stop_vm": "StopVM",
    "restart_vm": "RestartVM",
    "reconnect_vm": "RestoreVMConnectivity",
    "vm_context": "GetVMContext",
    "vm_instance_view": "GetVMInstanceView",
}


def _is_cloud_agent(agent):
    return foundry_client.is_cloud_agent(agent)


def _get_cloud_agent(agent_id=None):
    from services import agents_service

    if agent_id:
        agent = agents_service.get_agent(agent_id)
        if _is_cloud_agent(agent):
            return agent

    agent = agents_service.get_agent(CLOUD_AGENT_ID)
    if _is_cloud_agent(agent):
        return agent

    for candidate in agents_service.list_agents(include_key=True):
        if _is_cloud_agent(candidate):
            return candidate
    return None


def _vm_bits(params):
    params = params or {}
    return (
        str(params.get("vm_name") or "").strip(),
        str(params.get("resource_group") or "").strip(),
    )


def build_prompt(action, params=None):
    """Return the deterministic user prompt for a cloud action."""
    params = params or {}
    action = str(action or "").lower()
    operation = _OPERATION.get(action, action)

    if action == "incident_counts":
        return (
            "Use the IncidentResponseTool to retrieve Sentinel incidents for the "
            "daily, weekly, and monthly periods (call GetSentinelIncidents with "
            "period 'daily', then 'weekly', then 'monthly'). "
            "Then reply with ONLY three lines, nothing else:\n"
            "Daily: <count>\n"
            "Weekly: <count>\n"
            "Monthly: <count>\n"
            "Replace <count> with the number of incidents returned for each period."
        )

    if action == "incident_list":
        period = str(params.get("period") or "daily").strip()
        if period not in ("daily", "weekly", "monthly"):
            period = "daily"
        return (
            "Use the IncidentResponseTool to call GetSentinelIncidents with "
            "period '{period}'. List the {period} incidents you find, most recent "
            "first, up to five. For each include the incident ID, title, severity, "
            "status, and creation time. Use a concise bulleted list.".format(
                period=period
            )
        )

    if action == "investigate":
        incident_id = str(params.get("incident_id") or "").strip()
        return (
            "Use the IncidentResponseTool to call GetSentinelIncident with "
            "incident_id '{incident_id}'. Then investigate the returned incident: "
            "summarize what happened, the affected resources and entities, the "
            "current status and owner, and recommend concrete containment and "
            "remediation next steps. Format the response with clear headings.".format(
                incident_id=incident_id
            )
        )

    if action == "incident_summary":
        incident_id = str(params.get("incident_id") or "").strip()
        return (
            "Use the IncidentResponseTool to call GenerateIncidentSummary with "
            "incident_id '{incident_id}'. Then present the generated summary of "
            "the incident: what happened, key timeline events, affected resources "
            "and entities, and recommended containment and remediation next "
            "steps. Format the response with clear headings.".format(
                incident_id=incident_id
            )
        )

    vm_name, resource_group = _vm_bits(params)
    if action == "vm_context":
        return (
            "Use the IncidentResponseTool to call GetVMContext with "
            "vm_name '{vm_name}' and resource_group '{resource_group}'. "
            "Report the VM's configuration and context, including its size, "
            "operating system, location, resource group, attached network "
            "interfaces, and current power state.".format(
                vm_name=vm_name,
                resource_group=resource_group,
            )
        )

    if action == "vm_instance_view":
        return (
            "Use the IncidentResponseTool to call GetVMInstanceView with "
            "vm_name '{vm_name}' and resource_group '{resource_group}'. "
            "Report the VM's current runtime status and health from the "
            "instance view, including power state, provisioning state, and any "
            "platform, fault, or agent statuses.".format(
                vm_name=vm_name,
                resource_group=resource_group,
            )
        )

    if action == "isolate":
        return (
            "Use the IncidentResponseTool to call IsolateAzureVM with "
            "vm_name '{vm_name}' and resource_group '{resource_group}'. "
            "Report clearly whether the isolation succeeded or failed, and state "
            "the resulting network security posture of the VM.".format(
                vm_name=vm_name,
                resource_group=resource_group,
            )
        )

    if action in ("start_vm", "stop_vm", "restart_vm", "reconnect_vm"):
        return (
            "Use the IncidentResponseTool to call {operation} with "
            "vm_name '{vm_name}' and resource_group '{resource_group}'. "
            "Report clearly whether the operation succeeded or failed, and state "
            "the resulting power state of the VM.".format(
                operation=operation,
                vm_name=vm_name,
                resource_group=resource_group,
            )
        )

    raise ValueError("Unknown cloud action: {0}".format(action))


def parse_counts(reply):
    """Parse 'Daily: N / Weekly: N / Monthly: N' style lines from a reply."""
    counts = {}
    for key, label in (
        ("daily", "daily"),
        ("weekly", "weekly"),
        ("monthly", "monthly"),
    ):
        pattern = re.compile(
            r"{label}\s*[:=\-]?\s*(\d+)".format(label=label),
            re.IGNORECASE,
        )
        match = pattern.search(reply or "")
        if match:
            try:
                counts[key] = int(match.group(1))
            except (TypeError, ValueError):
                counts[key] = None
        else:
            counts[key] = None
    return counts


def _record(agent, prompt, result, conversation_id, user_id):
    try:
        from services import app_insights
        from services import insights_service
        from services import telemetry_map_service

        messages = [{"role": "user", "content": prompt}]
        insights_service.record_turn(
            agent=agent,
            messages=messages,
            usage=result.get("usage") or {},
            latency_ms=result.get("latency_ms"),
            reply=result.get("reply", ""),
            conversation_id=conversation_id,
            user_id=user_id,
        )
        app_insights.track_agent_chat(
            agent=agent,
            usage=result.get("usage"),
            latency_ms=result.get("latency_ms"),
            conversation_id=conversation_id,
        )
        telemetry_map_service.record_request(agent.get("id", ""), error=False)
    except Exception:
        pass


def run(action, params=None, agent_id=None, conversation_id=None, user_id="anonymous", record=True):
    """Execute one deterministic cloud action through the Foundry agent.

    Returns a dict with ``reply`` (agent text), ``usage``, ``agent`` and, for
    the incident-counts action, ``counts``. The KPI prefetch (``record=False``)
    still consumes tokens but is not stored as an insight conversation turn.
    """
    from services import agents_service

    agent = _get_cloud_agent(agent_id)
    if agent is None:
        raise ValueError("No connected Cloud Security Ops Agent is configured.")

    prompt = build_prompt(action, params)
    result = foundry_client.chat(
        agent,
        [{"role": "user", "content": prompt}],
    )

    if result.get("routed_via") == "ephemeral_model":
        status = result.get("fallback_status")
        suffix = (
            " The agent route returned HTTP {0}.".format(status)
            if status else ""
        )
        raise RuntimeError(
            "The Cloud Security Ops Agent is unreachable, so the request "
            "was answered by a fallback model without cloud tools.{0} Verify "
            "the agent endpoint, name, and API key, then try again.".format(
                suffix
            )
        )

    if record:
        try:
            _record(agent, prompt, result, conversation_id, user_id)
        except Exception:
            pass

    out = {
        "reply": result.get("reply", ""),
        "usage": result.get("usage") or {},
        "agent": {
            "id": agent.get("id", ""),
            "name": agent.get("name", ""),
            "type": agent.get("type", ""),
            "model": result.get("model") or agent.get("model", ""),
        },
        "routed_via": result.get("routed_via", ""),
    }
    if action == "incident_counts":
        out["counts"] = parse_counts(out.get("reply"))
    return out
