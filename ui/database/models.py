"""SQLAlchemy ORM models for the LTM Security Platform.

PostgreSQL is the single source of truth. Each table is owned by the
repository layer (``database/repositories/``); services never touch raw
sessions or JSON documents.

Tables map to the pre-migration JSON documents as follows:

* ``users.json``              -> ``users``
* ``agents.json``             -> ``agents``
* ``sessions.json``           -> ``conversations`` + ``messages``
* ``insights.json``           -> ``insights`` (rich ``data`` JSONB payload)
* ``reports_history.json``    -> ``reports_history``
* ``assessment_history.json`` -> ``assessment_history``
* ``assessment_stats.json``   -> ``assessment_stats``
* ``telemetry_metrics.json``  -> ``telemetry_metrics``
* ``telemetry_history.json``  -> ``telemetry_history``

Additional tables:
* ``findings``             - per-assessment finding rows
* ``agent_activity_logs``  - audit trail for agent/function actions
* ``managed_firewalls``    - admin firewall registry (Settings > Firewall Inventory)
* ``firewall_inventory``   - live collector snapshots (managed by the collector)
"""

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.types import JSON

from database.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(512), nullable=False)
    role = Column(String(64), default="Security Analyst")
    status = Column(String(32), default="approved")
    created = Column(Float)


class Agent(Base):
    __tablename__ = "agents"

    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    type = Column(String(64))
    model = Column(String(64))
    agent_endpoint = Column(String(512))
    api_key = Column(String(512))
    connected = Column(Boolean, default=False)
    created_at = Column(String(64))
    agent_id = Column(String(255))


class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(String(64), primary_key=True)
    user_id = Column(String(64), default="anonymous", index=True)
    title = Column(String(255), default="")
    created = Column(Float)
    updated = Column(Float)


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    conversation_id = Column(
        String(64),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role = Column(String(16), nullable=False)
    content = Column(Text, default="")
    tool = Column(String(64))
    ts = Column(Float, index=True)
    meta = Column(JSON)


class Insight(Base):
    """One row per chat conversation with aggregate usage telemetry.

    ``data`` carries the JSONB payload with ``created``, ``updated`` and the
    ``turns`` list (token usage per assistant turn).
    """

    __tablename__ = "insights"

    id = Column(String(64), primary_key=True)
    user_id = Column(String(64), default="anonymous")
    agent_id = Column(String(64), index=True)
    agent_name = Column(String(255))
    agent_type = Column(String(64))
    model = Column(String(64))
    data = Column(JSON)


class ReportHistory(Base):
    __tablename__ = "reports_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(64), default="anonymous", index=True)
    name = Column(String(255))
    type = Column(String(64))
    generated_by = Column(String(255))
    firewall = Column(String(64), index=True)
    ts = Column(Float, index=True)
    status = Column(String(32))
    size = Column(String(32))
    download_url = Column(String(512))


class AssessmentHistory(Base):
    """One row per assessment run.

    Metadata columns power the Compliance Trend chart and the assessment
    summary. ``payload`` carries the full run output (sections + findings) so
    the dashboard and findings pages can be served purely from PostgreSQL.
    """

    __tablename__ = "assessment_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    firewall_name = Column(String(64), index=True, default="vmpafw01")
    assessment_id = Column(String(64), index=True)
    executed_at = Column(Float, index=True)
    compliance_score = Column(Float)
    security_score = Column(Float)
    control_count = Column(Integer, default=0)
    status = Column(String(32), default="Completed")
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    payload = Column(JSON)


class AssessmentStats(Base):
    __tablename__ = "assessment_stats"

    id = Column(Integer, primary_key=True, default=1)
    assessments_run = Column(Integer, default=0)
    last_assessment_ts = Column(Float)


class TelemetryMetric(Base):
    __tablename__ = "telemetry_metrics"

    agent_id = Column(String(64), primary_key=True)
    requests = Column(Integer, default=0)
    errors = Column(Integer, default=0)
    first_ts = Column(Float)
    last_ts = Column(Float)


class TelemetryHistory(Base):
    __tablename__ = "telemetry_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(64), index=True)
    agent_name = Column(String(255))
    label = Column(String(255))
    ts = Column(Float, index=True)
    nodes = Column(JSON)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(String(64), index=True)
    firewall_name = Column(String(64), index=True, default="vmpafw01")
    control = Column(String(255), index=True)
    status = Column(String(32))
    risk = Column(String(32))
    metric = Column(String(255))
    observed = Column(Text)
    expected = Column(Text)
    finding = Column(Text)
    remediation = Column(Text)
    risk_score = Column(Float)


class AgentActivityLog(Base):
    """Audit trail of agent/function actions (assessments, incident actions)."""

    __tablename__ = "agent_activity_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(64), index=True)
    run_id = Column(String(64), index=True)
    activity = Column(String(128), index=True)
    function_name = Column(String(255))
    status = Column(String(32), default="Completed")
    message = Column(Text)
    ts = Column(Float, index=True)
    meta = Column(JSON)


class DemoRequest(Base):
    """Landing-page demo request lead with the requester's notes."""

    __tablename__ = "demo_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    company = Column(String(255), default="")
    role = Column(String(128), default="")
    message = Column(Text, default="")
    status = Column(String(32), default="new")
    created = Column(Float, index=True)


class ManagedFirewall(Base):
    """Admin-registered firewall connection inventory.

    Distinct from the live ``firewall_inventory`` collector snapshots: this
    table holds the static registry of firewalls the platform manages, entered
    under Settings > Firewall Inventory (device name, host name, host IP and
    host key). ``clone_of`` records the source device when a row is a clone.
    ``vendor``/``port``/``username`` are optional asset details captured when
    firewalls are imported in bulk from the Firewall Inventory template.
    ``status``/``last_checked`` persist the last live/down reachability probe
    result for the host IP.
    """

    __tablename__ = "managed_firewalls"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_name = Column(String(64), unique=True, nullable=False)
    host_name = Column(String(255), nullable=False)
    host_ip = Column(String(64), nullable=False)
    host_key = Column(String(1024))
    vendor = Column(String(128))
    port = Column(Integer)
    username = Column(String(128))
    clone_of = Column(String(64))
    status = Column(String(16), default="down")
    last_checked = Column(Float)
    created = Column(Float, index=True)
