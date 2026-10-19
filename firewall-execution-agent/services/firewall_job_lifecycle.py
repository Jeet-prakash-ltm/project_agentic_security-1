"""Firewall job lifecycle constants (execution-agent copy).

Keep in sync with ``ui/database/firewall_job_lifecycle.py``. PostgreSQL is the
source of truth; Service Bus delivers work, Durable Functions orchestrate the
long-running execution and SignalR pushes transitions to the browser.
"""

PENDING_APPROVAL = "PENDING_APPROVAL"
APPROVED = "APPROVED"
QUEUED = "QUEUED"
STARTING = "STARTING"
APPLYING_CONFIG = "APPLYING_CONFIG"
COMMITTING = "COMMITTING"
RUNNING = "RUNNING"
POST_VALIDATION = "POST_VALIDATION"
SUCCEEDED = "SUCCEEDED"
FAILED = "FAILED"
CANCELLED = "CANCELLED"
TIMEOUT = "TIMEOUT"

ACTIVE_STATUSES = frozenset(
    {
        APPROVED,
        QUEUED,
        STARTING,
        APPLYING_CONFIG,
        COMMITTING,
        RUNNING,
        POST_VALIDATION,
    }
)

TERMINAL_STATUSES = frozenset({SUCCEEDED, FAILED, CANCELLED, TIMEOUT})

ALL_STATUSES = (
    PENDING_APPROVAL,
    APPROVED,
    QUEUED,
    STARTING,
    APPLYING_CONFIG,
    COMMITTING,
    RUNNING,
    POST_VALIDATION,
    SUCCEEDED,
    FAILED,
    CANCELLED,
    TIMEOUT,
)

PENDING = "PENDING"
APPROVED_APPROVAL = "APPROVED"
REJECTED = "REJECTED"

APPROVAL_STATUSES = (PENDING, APPROVED_APPROVAL, REJECTED)

FIREWALL_DOWN_MESSAGE = "cannot proceed firewall is down"
