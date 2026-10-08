import json
import logging
import os
import re
import time
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

CHAT_TIMEOUT = 120


class FoundryHTTPError(RuntimeError):
    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = status_code

# Tool schemas in Azure AI Foundry Responses API format (flat function objects).
TOOL_SCHEMAS = [
    {
        "type": "function",
        "name": "run_compliance_assessment",
        "description": "Run a compliance assessment against the firewall and return the compliance results summary.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "type": "function",
        "name": "run_full_assessment",
        "description": "Run the full firewall assessment and return detailed results.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "type": "function",
        "name": "executive_summary",
        "description": "Generate an executive summary of the latest firewall assessment.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "type": "function",
        "name": "generate_excel_report",
        "description": "Generate an Excel report of the firewall assessment results.",
        "parameters": {"type": "object", "properties": {}},
    },
]


def _post(url, api_key, payload):
    response = requests.post(
        url,
        headers={"api-key": api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=CHAT_TIMEOUT,
    )

    if response.status_code != 200:
        raise FoundryHTTPError(
            response.status_code,
            "Azure AI Foundry returned HTTP {status}: {body}".format(
                status=response.status_code,
                body=response.text[:300],
            ),
        )

    return response.json()


def _agent_key_env_name(agent):
    """Per-agent API key env var, e.g. FOUNDRY_API_KEY_INCIDENT_RESPONSE_AGENT_CLOUD_SECURITY.

    Derived from the agent id so every Foundry project (firewall, cloud, ...)
    can carry its own key without sharing the firewall's FOUNDRY_API_KEY.
    """
    agent_id = agent.get("id") or agent.get("agent_id") or agent.get("name") or ""
    slug = re.sub(r"[^A-Z0-9]+", "_", agent_id.upper()).strip("_")
    return "FOUNDRY_API_KEY_{0}".format(slug)


def _resolve_api_key(agent):
    """Resolve the agent's API key.

    Keys live in Application Settings or the ``agents`` table (which is
    populated from Application Settings at deploy time) - never Key Vault.
    A placeholder value is treated as unset, so an agent-specific
    ``FOUNDRY_API_KEY_<AGENT_ID>`` Application Setting is preferred, falling
    back to the shared ``FOUNDRY_API_KEY`` Application Setting.
    """
    key = (agent.get("api_key", "") or "").strip()
    if not key or key.startswith("PLACEHOLDER"):
        return os.environ.get(_agent_key_env_name(agent)) or os.environ.get("FOUNDRY_API_KEY", "")
    return key


def _system_prompt(agent):
    agent_type = (agent.get("type") or "").lower()
    agent_name = agent.get("name", "")
    agent_key = " ".join([
        agent_type,
        agent_name.lower(),
        str(agent.get("id") or "").lower(),
        str(agent.get("agent_id") or "").lower(),
    ])
    if "orchestrat" in agent_key or "maestro" in agent_key:
        return (
            "You are Maestro AI on the LTM Security Platform. "
            "Coordinate network, cloud, and firewall specialist agents. "
            "Route requests, summarize results, and keep answers concise with clear next steps."
        )
    if "netsec" in agent_type or "execution" in agent_type or "netsec" in agent_name.lower():
        return (
            "You are the Firewall Execution Agent, an AI security agent that makes "
            "manual and bulk configuration changes to the Palo Alto firewall from "
            "Excel playbook workbooks (address/service objects, groups, zones, VRs, "
            "routes, security and NAT policies, interfaces). "
            "The playbook panel drives changes through dry-run previews first; "
            "changes only reach the firewall when the Function App is deployed with "
            "NETSEC_FW_DRY_RUN=0. Keep answers short and point users to the "
            "Workspace Action chip for manual and bulk playbooks."
        )
    if "firewall" in agent_type or "firewall" in agent_name.lower():
        return (
            "You are the Firewall Audit Agent, an AI security agent specialized in Palo Alto Networks firewall compliance. "
            "You have live access to a Palo Alto firewall (vmpafw01, PAN-OS 10.2.10-h9) and perform assessments across "
            "44 controls spanning inventory, health, HA, security policy, threat prevention, network segmentation, VPN, "
            "logging, administration, and backup. "
            "Use the `run_compliance_assessment` tool to get live assessment data, and `run_full_assessment` for detailed results. "
            "Use `executive_summary` for management-ready summaries and `generate_excel_report` to produce downloadable workbooks. "
            "When users ask about security posture, call the appropriate tool to get real data instead of guessing. "
            "Format responses with clear headings, bullet points, and severity indicators. "
            "Always reference the actual assessment data and offer to run a fresh assessment if needed."
        )
    if "cloud" in agent_type or "incident" in agent_type or "cloud" in agent_name.lower():
        return (
            "You are the Cloud Incident Response Agent, an AI security agent specialized in Azure cloud security incident response. "
            "Provide structured incident response guidance."
        )
    return (
        "You are an AI security agent on the LTM Security Platform. "
        "Provide concise, actionable security guidance. Format responses with clear headings and bullet points."
    )


def is_cloud_agent(agent):
    if not agent:
        return False
    text = " ".join([
        str(agent.get("type") or ""),
        str(agent.get("name") or ""),
        str(agent.get("id") or ""),
    ]).lower()
    return "cloud" in text or "incident" in text


def _normalize_messages(messages):
    return [
        {"role": m.get("role", "user"), "content": m.get("content", "")}
        for m in messages
        if m.get("role") in ("user", "assistant")
    ]


def _merge_usage(total, usage):
    for key in ("total_tokens", "prompt_tokens", "completion_tokens", "input_tokens", "output_tokens"):
        value = usage.get(key)
        if value:
            total[key] = total.get(key, 0) + value


def _call_tool(tool_registry, function_call):
    name = function_call.get("name", "")
    arguments = function_call.get("arguments") or "{}"
    try:
        args = json.loads(arguments)
    except json.JSONDecodeError:
        args = {}
    try:
        result = tool_registry.call_tool(name, **args)
        return json.dumps(result, default=str)
    except Exception as error:
        return json.dumps({"error": str(error)})


def _extract_reply(data):
    content_parts = []
    function_calls = []
    for item in data.get("output") or []:
        item_type = item.get("type")
        if item_type == "message":
            for part in item.get("content") or []:
                if part.get("type") in ("output_text", "text"):
                    text = (part.get("text") or "").strip()
                    if text:
                        content_parts.append(text)
        elif item_type == "function_call":
            function_calls.append(item)
    content = "\n\n".join(content_parts).strip() or None
    return content, function_calls


def _function_call_item(function_call):
    return {
        "type": "function_call",
        "id": function_call.get("id", ""),
        "call_id": function_call.get("call_id", ""),
        "name": function_call.get("name", ""),
        "arguments": function_call.get("arguments", "{}"),
    }


def _responses_url(agent_endpoint):
    endpoint = agent_endpoint.rstrip("/")
    if endpoint.endswith("/openai/v1/responses"):
        return endpoint
    if endpoint.endswith("/openai/v1"):
        return endpoint + "/responses"
    return endpoint + "/openai/v1/responses"


_AGENT_ROUTE_UNAVAILABLE = set()


def _agent_route_cache_key(agent_endpoint, agent_name):
    return "{0}|{1}".format(agent_endpoint.rstrip("/"), agent_name)


def _foundry_agent_responses_url(agent_endpoint, agent_name):
    """URL for a Foundry prompt agent, which runs its own instructions and
    server-side tools (e.g. an OpenAPI tool backed by an Azure Function).
    """
    endpoint = agent_endpoint.rstrip("/")
    return "{0}/agents/{1}/endpoint/protocols/openai/responses?api-version=v1".format(
        endpoint,
        quote(agent_name, safe=""),
    )


def _error_suggests_missing_agent(exc):
    lowered = str(exc).lower()
    return any(
        marker in lowered
        for marker in ("not found", "does not exist", "not exist", "no agent")
    )


def _run_responses(url, api_key, conversation, model, ephemeral, sys_prompt, started):
    """Run one chat over the Foundry Responses API.

    ``ephemeral`` agents (the historical behaviour) are defined per call with
    a model, platform instructions, and the firewall tool schemas. Foundry
    prompt agents instead resolve their definition server-side, so only the
    input history is sent.
    """
    from gateway import tools as tool_registry

    def build_payload(next_input):
        payload = {"input": next_input}
        if ephemeral:
            payload["model"] = model
            payload["tools"] = TOOL_SCHEMAS
            if sys_prompt:
                payload["instructions"] = sys_prompt
        return payload

    data = _post(url, api_key, build_payload(conversation))
    content, function_calls = _extract_reply(data)
    total_usage = dict(data.get("usage") or {})

    max_rounds = 3
    while function_calls and max_rounds > 0:
        max_rounds -= 1

        next_input = list(conversation)
        for function_call in function_calls:
            next_input.append(_function_call_item(function_call))
        for function_call in function_calls:
            next_input.append({
                "type": "function_call_output",
                "call_id": function_call.get("call_id") or function_call.get("id"),
                "output": _call_tool(tool_registry, function_call),
            })

        data = _post(url, api_key, build_payload(next_input))
        content, function_calls = _extract_reply(data)
        _merge_usage(total_usage, data.get("usage") or {})

    if content is None:
        content = "Assessment completed. Check the outputs above for detailed results."

    return {
        "reply": content,
        "usage": total_usage,
        "latency_ms": int((time.monotonic() - started) * 1000),
        "model": data.get("model") or model,
    }


def chat(agent, messages):
    """Route a chat to a Foundry prompt agent when one exists for the agent,
    otherwise fall back to the ephemeral model+platform-tool Responses call.
    """
    agent_endpoint = (agent.get("agent_endpoint") or "").rstrip("/")
    api_key = _resolve_api_key(agent)
    model = agent.get("model", "gpt-5.1")

    if not agent_endpoint:
        raise ValueError("Agent is missing the agent endpoint.")
    if not api_key:
        raise ValueError("Agent is missing the API key.")

    conversation = _normalize_messages(messages)
    started = time.monotonic()

    agent_name = (agent.get("agent_id") or agent.get("name") or "").strip()
    cache_key = _agent_route_cache_key(agent_endpoint, agent_name)
    fallback_status = None

    if agent_name and cache_key not in _AGENT_ROUTE_UNAVAILABLE:
        try:
            url = _foundry_agent_responses_url(agent_endpoint, agent_name)
            result = _run_responses(
                url, api_key, conversation, model,
                ephemeral=False, sys_prompt=None, started=started,
            )
            result["routed_via"] = "foundry_agent"
            result["agent_route"] = url
            result["fallback_status"] = None
            return result
        except FoundryHTTPError as exc:
            if (
                exc.status_code in (404, 403)
                or (exc.status_code == 400 and _error_suggests_missing_agent(exc))
            ):
                fallback_status = exc.status_code
                logger.warning(
                    "Foundry prompt-agent route unavailable for agent %r "
                    "(endpoint=%s): HTTP %s - falling back to an ephemeral "
                    "model call without the agent's tools.",
                    agent_name, cache_key, exc.status_code,
                )
                _AGENT_ROUTE_UNAVAILABLE.add(cache_key)
            else:
                raise

    logger.warning(
        "Routing agent %r via ephemeral model call (no Foundry prompt-agent "
        "route): the agent's server-side tools are not available.",
        agent_name or agent.get("name"),
    )
    sys_prompt = _system_prompt(agent)
    url = _responses_url(agent_endpoint)
    result = _run_responses(
        url, api_key, conversation, model,
        ephemeral=True, sys_prompt=sys_prompt, started=started,
    )
    result["routed_via"] = "ephemeral_model"
    result["agent_route"] = None
    result["fallback_status"] = fallback_status
    return result
