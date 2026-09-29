from gateway import foundry_client
from gateway import session_manager
from gateway import tools

from services import agents_service
from services import app_insights
from services import insights_service

HISTORY_LIMIT = 10


class AgentGateway:
    def chat(self, user_id="anonymous", message=None, messages=None, conversation_id=None, agent_id=None, tool=None):
        agent = self._resolve_agent(agent_id)
        if not agent:
            raise ValueError("No connected agent is configured.")

        if conversation_id and user_id and user_id != "anonymous":
            existing = session_manager.get_conversation(
                conversation_id,
                user_id=user_id,
            )
            if existing is None:
                raise ValueError(
                    "This conversation does not exist or belongs to another account."
                )
        conversation = session_manager.get_or_create(
            conversation_id,
            user_id=user_id,
        )
        conversation_id = conversation["id"]

        if messages is None:
            history = session_manager.get_messages(
                conversation_id,
                limit=HISTORY_LIMIT,
                user_id=user_id,
            )
            messages = list(history)
            if message:
                messages.append({"role": "user", "content": message})

        from services import telemetry_map_service

        try:
            result = foundry_client.chat(agent, messages)
            if (
                foundry_client.is_cloud_agent(agent)
                and result.get("routed_via") == "ephemeral_model"
            ):
                status = result.get("fallback_status")
                suffix = (
                    " (agent route returned HTTP {0})".format(status)
                    if status else ""
                )
                raise RuntimeError(
                    "The Cloud Security Ops Agent is unreachable, so the "
                    "request was answered by a fallback model without cloud "
                    "tools{suffix}. Verify the agent endpoint, name, and API "
                    "key, then try again.".format(suffix=suffix)
                )
        except Exception:
            telemetry_map_service.record_request(agent.get("id", ""), error=True)
            raise

        telemetry_map_service.record_request(agent.get("id", ""), error=False)

        if message:
            session_manager.add_message(
                conversation_id,
                "user",
                message,
                user_id=user_id,
                meta={"tool": tool or None},
            )
            session_manager.add_message(
                conversation_id,
                "assistant",
                result.get("reply", ""),
                user_id=user_id,
                meta={
                    "tool": tool or None,
                    "usage": result.get("usage") or {},
                    "agentName": agent.get("name", ""),
                },
            )

        self._record(
            agent=agent,
            messages=messages,
            usage=result.get("usage"),
            latency_ms=result.get("latency_ms"),
            reply=result.get("reply", ""),
            conversation_id=conversation_id,
            user_id=user_id,
        )

        result["conversation_id"] = conversation_id
        result["agent"] = {
            "id": agent.get("id", ""),
            "name": agent.get("name", ""),
            "type": agent.get("type", ""),
            "model": result.get("model") or agent.get("model", ""),
        }
        return result

    def run(self, agent, prompt, user_id="anonymous", conversation_id=None):
        agent_id = agent
        if isinstance(agent, dict):
            agent_id = agent.get("id")
        return self.chat(
            user_id=user_id,
            message=prompt,
            conversation_id=conversation_id,
            agent_id=agent_id,
        )

    def agents(self):
        return agents_service.list_agents()

    def tools(self):
        return tools.list_tools()

    def conversations(self, user_id=None):
        return session_manager.list_conversations(user_id=user_id)

    def _resolve_agent(self, agent_id):
        if agent_id:
            return agents_service.get_agent(agent_id)
        return agents_service.get_agent("master-orchestrator-agent") or agents_service.get_connected_agent()

    def _record(self, agent, messages, usage, latency_ms, reply, conversation_id, user_id=None):
        try:
            insights_service.record_turn(
                agent=agent,
                messages=messages,
                usage=usage,
                latency_ms=latency_ms,
                reply=reply,
                conversation_id=conversation_id,
                user_id=user_id,
            )
            app_insights.track_agent_chat(
                agent=agent,
                usage=usage,
                latency_ms=latency_ms,
                conversation_id=conversation_id,
            )
        except Exception:
            pass


gateway = AgentGateway()
