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
* ``managed_firewalls``    - admin firewall registry (Settings > Asset Inventory)
* ``cloud_tenants``        - admin cloud tenant registry (Settings > Asset Inventory)
* ``firewall_inventory``   - live collector snapshots (managed by the collector)
* ``automation_jobs``      - LEGACY bulk commit jobs (kept for compatibility)
* ``security_jobs``        - CANONICAL firewall-change jobs (single + bulk)
* ``security_job_operations`` - CANONICAL operations for a security_jobs row
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON

from database.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(512), nullable=False)
    role = Column(String(64), default="")
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
    assessment_id = Column(String(64), index=True)
    job_id = Column(String(64))
    security_domain = Column(String(64))
    storage_reference = Column(String(1024))


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
    device_type = Column(String(64))
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


class CloudTenant(Base):
    """Admin-registered cloud tenant inventory.

    Settings > Asset Inventory > Cloud stores the tenants the platform
    assesses: tenant name, tenant id, cloud provider, primary domain and
    status.
    """

    __tablename__ = "cloud_tenants"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_name = Column(String(255), unique=True, nullable=False)
    tenant_id = Column(String(128), unique=True, nullable=False)
    cloud_provider = Column(String(128), default="Azure")
    primary_domain = Column(String(255), nullable=False)
    status = Column(String(32), default="active")
    created = Column(Float, index=True)


class AutomationJob(Base):
    """One Firewall Execution bulk commit, with nested playbook operations."""

    __tablename__ = "automation_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(64), default="anonymous", index=True)
    firewall_name = Column(String(255), default="")
    security_domain = Column(String(64), default="Network security")
    workbook_name = Column(String(255), default="")
    actions = Column(JSON)
    playbooks = Column(JSON)
    sheets = Column(JSON)
    status = Column(String(32), default="failed", index=True)
    created = Column(Float, index=True)
    operations = Column(JSON)


class SecurityJob(Base):
    """Canonical firewall-change job written by the execution agent."""

    __tablename__ = "security_jobs"

    id = Column(UUID(as_uuid=False), primary_key=True)
    job_id = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(String(64), default="anonymous", index=True)
    agent_id = Column(String(64))
    conversation_id = Column(String(64))
    security_domain = Column(String(64), default="network_security")
    job_type = Column(String(64), default="firewall_change")
    operation = Column(String(64), default="")
    source_type = Column(String(64), default="")
    source_name = Column(String(255), default="")
    source_file_id = Column(String(64))
    target_asset_id = Column(String(64))
    firewall_host = Column(String(255), default="")
    device_group = Column(String(255), default="")
    status = Column(String(32), default="awaiting_approval", index=True)
    approval_status = Column(String(32), default="pending", index=True)
    requested_payload = Column(JSONB)
    normalized_payload = Column(JSONB)
    execution_plan = Column(JSONB)
    payload_hash = Column(String(128))
    plan_hash = Column(String(128))
    requested_by = Column(String(64))
    approved_by = Column(String(64))
    result = Column(JSONB)
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    approved_at = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    operations = relationship(
        "SecurityJobOperation",
        primaryjoin="SecurityJob.job_id==SecurityJobOperation.job_id",
        foreign_keys="SecurityJobOperation.job_id",
        order_by="SecurityJobOperation.sequence",
        viewonly=True,
    )


class SecurityJobOperation(Base):
    """One PAN-OS change belonging to a canonical security job."""

    __tablename__ = "security_job_operations"

    id = Column(UUID(as_uuid=False), primary_key=True)
    job_id = Column(String(64), nullable=False, index=True)
    sequence = Column(Integer, default=0)
    source_sheet = Column(String(255))
    source_row = Column(Integer)
    category = Column(String(64))
    action = Column(String(32))
    object_name = Column(String(255))
    requested_fields = Column(JSONB)
    normalized_fields = Column(JSONB)
    status = Column(String(32), default="pending", index=True)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    result = Column(JSONB)
    error_code = Column(String(64))
    error_message = Column(Text)


class FirewallJob(Base):
    """One firewall execution task, tracked from request to completion.

    This is the durable job ledger: PostgreSQL owns status and history while
    Azure Service Bus delivers work and Durable Functions orchestrate the
    long-running execution. ``task_id`` is also the Service Bus ``SessionId``
    scope (firewall host + device group) used to serialize work per device.
    """

    __tablename__ = "firewall_jobs"
    __table_args__ = (
        Index("ix_firewall_jobs_host_group", "firewall_host", "device_group"),
    )

    task_id = Column(UUID(as_uuid=False), primary_key=True)
    user_id = Column(String(64), default="anonymous", index=True)
    session_id = Column(String(255), default="", index=True)
    firewall_host = Column(String(255), default="")
    device_group = Column(String(255), default="")
    operation = Column(String(64), default="")
    panos_job_id = Column(String(64))
    status = Column(String(32), default="QUEUED", index=True)
    requested_payload = Column(JSONB)
    result = Column(JSONB)
    error_message = Column(Text)
    approval_status = Column(String(32), default="PENDING", index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ZeroTrustAssessment(Base):
    """One Zero Trust assessment run (historical table).

    Live runs are written to canonical ``assessments`` /
    ``assessment_findings`` / ``assessment_evidence``. This table retains
    pre-migration rows. ``report`` holds graded findings and per-pillar
    scores, ``evidence`` the raw collector output, and ``summary`` the
    compact counts. Dashboard reads do not use this model.
    """

    __tablename__ = "zero_trust_assessments"
    __table_args__ = (
        Index("idx_zero_trust_assessments_completed_at", "completed_at"),
    )

    assessment_id = Column(String(64), primary_key=True)
    status = Column(String(32), default="queued", index=True)
    scope = Column(String(32), default="tenant")
    tenant_id = Column(String(64))
    subscription_id = Column(String(64))
    started_at = Column(DateTime(timezone=True))
    updated_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    progress = Column(Integer, default=0)
    message = Column(Text)
    score = Column(Integer)
    summary = Column(JSONB)
    evidence = Column(JSONB)
    report = Column(JSONB)
    error = Column(Text)
