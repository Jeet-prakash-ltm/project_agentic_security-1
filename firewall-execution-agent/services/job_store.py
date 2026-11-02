"""PostgreSQL job ledger for firewall executions.

The execution agent owns the write path for job state. Canonical tables:

* ``security_jobs``            one row per write request
* ``security_job_operations``  one row per PAN-OS change in that job

``DATABASE_URL`` is provided through Azure Function App configuration and is
never logged. Legacy ``firewall_jobs`` is not written for new executions.
"""

import contextlib
import json
import logging
import os
import uuid

logger = logging.getLogger("firewall.jobs.store")

JOB_COLUMNS = (
    "id",
    "job_id",
    "user_id",
    "agent_id",
    "conversation_id",
    "security_domain",
    "job_type",
    "operation",
    "source_type",
    "source_name",
    "source_file_id",
    "target_asset_id",
    "firewall_host",
    "device_group",
    "status",
    "approval_status",
    "requested_payload",
    "normalized_payload",
    "execution_plan",
    "payload_hash",
    "plan_hash",
    "requested_by",
    "approved_by",
    "result",
    "error_message",
    "created_at",
    "approved_at",
    "started_at",
    "completed_at",
    "updated_at",
)

JOB_JSON_COLUMNS = frozenset(
    {"requested_payload", "normalized_payload", "execution_plan", "result"}
)

JOB_TIMESTAMP_COLUMNS = frozenset(
    {"created_at", "approved_at", "started_at", "completed_at", "updated_at"}
)

OP_COLUMNS = (
    "id",
    "job_id",
    "sequence",
    "source_sheet",
    "source_row",
    "category",
    "action",
    "object_name",
    "requested_fields",
    "normalized_fields",
    "status",
    "started_at",
    "completed_at",
    "result",
    "error_code",
    "error_message",
)

OP_JSON_COLUMNS = frozenset({"requested_fields", "normalized_fields", "result"})

OP_TIMESTAMP_COLUMNS = frozenset({"started_at", "completed_at"})

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
    """Canonical tables are created by platform migration, not here."""
    global _schema_ready
    _schema_ready = True


def _publish(job):
    try:
        from services import job_events

        job_events.publish(job)
    except Exception:
        logger.warning("SignalR publish skipped for job update", exc_info=True)


def _serialize_job(row):
    if row is None:
        return None
    out = dict(row)
    if out.get("id") is not None:
        out["id"] = str(out["id"])
    if out.get("job_id") is not None:
        out["job_id"] = str(out["job_id"])
    out["task_id"] = out.get("job_id")
    for key in JOB_TIMESTAMP_COLUMNS:
        value = out.get(key)
        if value is not None:
            out[key] = value.isoformat()
    return out


def _serialize_op(row):
    if row is None:
        return None
    out = dict(row)
    if out.get("id") is not None:
        out["id"] = str(out["id"])
    if out.get("job_id") is not None:
        out["job_id"] = str(out["job_id"])
    for key in OP_TIMESTAMP_COLUMNS:
        value = out.get(key)
        if value is not None:
            out[key] = value.isoformat()
    return out


def _dump(value):
    if isinstance(value, str):
        return value
    return json.dumps(value if value is not None else {})


def create_job(job, operations=None):
    ensure_schema()
    columns = [
        "id",
        "job_id",
        "user_id",
        "agent_id",
        "conversation_id",
        "security_domain",
        "job_type",
        "operation",
        "source_type",
        "source_name",
        "source_file_id",
        "target_asset_id",
        "firewall_host",
        "device_group",
        "status",
        "approval_status",
        "requested_payload",
        "normalized_payload",
        "execution_plan",
        "payload_hash",
        "plan_hash",
        "requested_by",
        "approved_by",
        "result",
        "error_message",
    ]
    job_id = str(job.get("job_id") or uuid.uuid4())
    job["job_id"] = job_id
    job["id"] = str(job.get("id") or uuid.uuid4())
    values = []
    for column in columns:
        value = job.get(column)
        if column in JOB_JSON_COLUMNS:
            value = _dump(value or {})
        values.append(value)
    placeholders = ", ".join(["%s"] * len(columns))
    op_rows = list(operations or [])
    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO security_jobs ({0}) VALUES ({1}) RETURNING *".format(
                    ", ".join(columns), placeholders
                ),
                values,
            )
            row = cur.fetchone()
            job_id = str(row["job_id"])
            for item in op_rows:
                cur.execute(
                    """
                    INSERT INTO security_job_operations (
                        id, job_id, sequence, source_sheet, source_row, category,
                        action, object_name, requested_fields, normalized_fields,
                        status
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        str(item.get("id") or uuid.uuid4()),
                        job_id,
                        int(item.get("sequence") or 0),
                        item.get("source_sheet"),
                        item.get("source_row"),
                        item.get("category"),
                        item.get("action"),
                        item.get("object_name"),
                        _dump(item.get("requested_fields") or {}),
                        _dump(item.get("normalized_fields") or {}),
                        item.get("status") or "pending",
                    ),
                )
    serialized = _serialize_job(row)
    serialized["operations"] = list_operations(serialized["job_id"])
    _publish(serialized)
    return serialized


def get_job(job_id, include_operations=False):
    ensure_schema()
    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM security_jobs WHERE job_id = %s", (str(job_id),)
            )
            row = cur.fetchone()
    job = _serialize_job(row)
    if job and include_operations:
        job["operations"] = list_operations(job["job_id"])
    return job


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
                "SELECT * FROM security_jobs{0} "
                "ORDER BY created_at DESC LIMIT %s".format(where),
                values,
            )
            rows = cur.fetchall()
    return [_serialize_job(row) for row in rows]


def list_operations(job_id):
    ensure_schema()
    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM security_job_operations "
                "WHERE job_id = %s ORDER BY sequence ASC",
                (str(job_id),),
            )
            rows = cur.fetchall()
    return [_serialize_op(row) for row in rows]


def update_job(job_id, **fields):
    ensure_schema()
    allowed = set(JOB_COLUMNS) - {"id", "job_id", "created_at"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_job(job_id)
    assignments = []
    values = []
    for key, value in updates.items():
        if key in JOB_TIMESTAMP_COLUMNS and value == "now()":
            assignments.append("{0} = now()".format(key))
            continue
        assignments.append("{0} = %s".format(key))
        if key in JOB_JSON_COLUMNS and not isinstance(value, str):
            value = json.dumps(value)
        values.append(value)
    assignments.append("updated_at = now()")
    values.append(str(job_id))
    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE security_jobs SET {0} WHERE job_id = %s RETURNING *".format(
                    ", ".join(assignments)
                ),
                values,
            )
            row = cur.fetchone()
    job = _serialize_job(row)
    _publish(job)
    return job


def update_operation(job_id, sequence, **fields):
    ensure_schema()
    allowed = set(OP_COLUMNS) - {"id", "job_id", "sequence"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return None
    assignments = []
    values = []
    for key, value in updates.items():
        if key in OP_TIMESTAMP_COLUMNS and value == "now()":
            assignments.append("{0} = now()".format(key))
            continue
        assignments.append("{0} = %s".format(key))
        if key in OP_JSON_COLUMNS and not isinstance(value, str):
            value = json.dumps(value)
        values.append(value)
    values.extend([str(job_id), int(sequence)])
    with _connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE security_job_operations SET {0} "
                "WHERE job_id = %s AND sequence = %s RETURNING *".format(
                    ", ".join(assignments)
                ),
                values,
            )
            row = cur.fetchone()
    return _serialize_op(row)
