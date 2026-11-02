"""Firewall job lifecycle constants (execution-agent copy).

Canonical statuses live on ``security_jobs`` / ``security_job_operations``.
PostgreSQL is the source of truth; Service Bus delivers work and SignalR
wakes the Jobs page.
"""

AWAITING_APPROVAL = "awaiting_approval"
QUEUED = "queued"
RUNNING = "running"
COMMITTING = "committing"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"
TIMEOUT = "timeout"
REJECTED_STATUS = "rejected"

PENDING_APPROVAL = AWAITING_APPROVAL
APPROVED = QUEUED
STARTING = RUNNING
APPLYING_CONFIG = RUNNING
POST_VALIDATION = RUNNING
SUCCEEDED = COMPLETED

ACTIVE_STATUSES = frozenset(
    {
        QUEUED,
        RUNNING,
        COMMITTING,
    }
)

TERMINAL_STATUSES = frozenset(
    {COMPLETED, FAILED, CANCELLED, TIMEOUT, REJECTED_STATUS}
)

ALL_STATUSES = (
    AWAITING_APPROVAL,
    QUEUED,
    RUNNING,
    COMMITTING,
    COMPLETED,
    FAILED,
    CANCELLED,
    TIMEOUT,
    REJECTED_STATUS,
)

PENDING = "pending"
APPROVED_APPROVAL = "approved"
REJECTED = "rejected"

APPROVAL_STATUSES = (PENDING, APPROVED_APPROVAL, REJECTED)

OP_PENDING = "pending"
OP_RUNNING = "running"
OP_SUCCESS = "success"
OP_FAILED = "failed"
OP_SKIPPED = "skipped"

FIREWALL_DOWN_MESSAGE = "cannot proceed firewall is down"
