"""PostgreSQL job ledger for firewall executions.

The execution agent owns the write path for job state; the platform UI reads
the same ``firewall_jobs`` table. ``DATABASE_URL`` is provided through Azure
Function App > Configuration > Application Settings and is never logged.
"""

import contextlib
import json
import logging
import os

logger = logging.getLogger("firewall.jobs.store")

SCHEMA = """
CREATE TABLE IF NOT EXISTS firewall_jobs (
    task_id UUID PRIMARY KEY,
    user_id VARCHAR(64) DEFAULT 'anonymous',
    session_id VARCHAR(255),
    firewall_host VARCHAR(255) DEFAULT '',
    device_group VARCHAR(255) DEFAULT '',
    operation VARCHAR(64) DEFAULT '',
    panos_job_id VARCHAR(64),
    status VARCHAR(32) DEFAULT 'QUEUED',
    requested_payload JSONB,
    result JSONB,
    error_message TEXT,
    approval_status VARCHAR(32) DEFAULT 'PENDING',
    created_at TIMESTAMPTZ DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ DEFAULT now()
)
"""

INDEXES = (
    "CREATE INDEX IF NOT EXISTS ix_firewall_jobs_user_id "
    "ON firewall_jobs (user_id)",
    "CREATE INDEX IF NOT EXISTS ix_firewall_jobs_status "
    "ON firewall_jobs (status)",
    "CREATE INDEX IF NOT EXISTS ix_firewall_jobs_host_group "
    "ON firewall_jobs (firewall_host, device_group)",
    "CREATE INDEX IF NOT EXISTS ix_firewall_jobs_approval_status "
    "ON firewall_jobs (approval_status)",
)

COLUMNS = (
    "task_id",
    "user_id",
    "session_id",
    "firewall_host",
    "device_group",
    "operation",
    "panos_job_id",
    "status",
    "requested_payload",
    "result",
    "error_message",
    "approval_status",
    "created_at",
    "started_at",
    "completed_at",
    "updated_at",
)

TIMESTAMP_COLUMNS = frozenset(
    {"created_at", "started_at", "completed_at", "updated_at"}
)

_schema_ready = False


def database_url():
    return (os.environ.get("DATABASE_URL") or "").strip()


def is_configured():
    return bool(database_url())


@contextlib.contextmanager
def _connection():
    import psycopg2
    import psycopg2.extras

    url = database_url()
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not configured for the execution agent."
        )
    conn = psycopg2.connect(
        url,
        cursor_factory=psycopg2.extras.RealDictCursor,
        connect_timeout=10,
    )
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_schema():
    """Create the ledger table and indexes when missing (additive only)."""
    global _schema_ready
    if _schema_ready:
        return
    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA)
            for statement in INDEXES:
                cur.execute(statement)
    _schema_ready = True


def _serialize(row):
    if row is None:
        return None
    out = dict(row)
    if out.get("task_id") is not None:
        out["task_id"] = str(out["task_id"])
    for key in TIMESTAMP_COLUMNS:
        value = out.get(key)
        if value is not None:
            out[key] = value.isoformat()
    return out


def create_job(job):
    ensure_schema()
    columns = (
        "task_id",
        "user_id",
        "session_id",
        "firewall_host",
        "device_group",
        "operation",
        "status",
        "requested_payload",
        "approval_status",
    )
    placeholders = ", ".join(["%s"] * len(columns))
    values = [job.get(column) for column in columns]
    values[columns.index("requested_payload")] = json.dumps(
        job.get("requested_payload") or {}
    )
    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO firewall_jobs ({0}) VALUES ({1}) RETURNING *".format(
                    ", ".join(columns), placeholders
                ),
                values,
            )
            row = cur.fetchone()
    return _serialize(row)


def get_job(task_id):
    ensure_schema()
    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM firewall_jobs WHERE task_id = %s", (task_id,)
            )
            row = cur.fetchone()
    return _serialize(row)


def list_jobs(user_id=None, status=None, limit=100):
    ensure_schema()
    clauses = []
    values = []
    if user_id:
        clauses.append("user_id = %s")
        values.append(user_id)
    if status:
        clauses.append("status = %s")
        values.append(status)
    where = " WHERE {0}".format(" AND ".join(clauses)) if clauses else ""
    values.append(max(1, min(int(limit or 100), 500)))
    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM firewall_jobs{0} "
                "ORDER BY created_at DESC LIMIT %s".format(where),
                values,
            )
            rows = cur.fetchall()
    return [_serialize(row) for row in rows]


def update_job(task_id, **fields):
    ensure_schema()
    allowed = set(COLUMNS) - {"task_id", "created_at"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_job(task_id)

    assignments = []
    values = []
    for key, value in updates.items():
        if key in TIMESTAMP_COLUMNS and value == "now()":
            assignments.append("{0} = now()".format(key))
            continue
        assignments.append("{0} = %s".format(key))
        if key in ("requested_payload", "result") and not isinstance(value, str):
            value = json.dumps(value)
        values.append(value)
    assignments.append("updated_at = now()")
    values.append(task_id)

    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE firewall_jobs SET {0} WHERE task_id = %s RETURNING *".format(
                    ", ".join(assignments)
                ),
                values,
            )
            row = cur.fetchone()
    return _serialize(row)
