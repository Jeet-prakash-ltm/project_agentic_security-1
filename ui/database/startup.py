"""Fail-fast startup validation and schema reconciliation.

The application requires PostgreSQL: if ``DATABASE_URL`` is missing or the
database cannot be reached the app refuses to start (no JSON fallback).

Startup checks:

1. ``DATABASE_URL`` is configured.
2. PostgreSQL is reachable.
3. Required tables exist (created automatically when missing).
4. Required columns/indexes exist (added automatically when missing).

Only additive DDL is ever applied at startup (``CREATE TABLE IF NOT EXISTS``,
``ADD COLUMN IF NOT EXISTS``, ``CREATE INDEX IF NOT EXISTS``); no data is ever
dropped or altered destructively.
"""

import logging

log = logging.getLogger("startup")

REQUIRED_TABLES = [
    "users",
    "agents",
    "conversations",
    "messages",
    "findings",
    "insights",
    "reports_history",
    "assessment_history",
    "assessment_stats",
    "telemetry_history",
    "telemetry_metrics",
    "agent_activity_logs",
    "managed_firewalls",
    "automation_jobs",
]


def validate_environment():
    """Return the configured database URL or raise a clear startup error."""
    from database.db import get_database_url

    url = get_database_url()
    if not url:
        raise RuntimeError(
            "STARTUP FAILED: DATABASE_URL is not set. Configure PostgreSQL via "
            "DATABASE_URL (Azure App Service > Configuration > Application "
            "Settings). PostgreSQL is the only supported storage layer."
        )
    return url


def reconcile_schema():
    """Apply additive schema changes so the ORM models match the database.

    Returns a dict with counts of applied statements. Never drops data.
    """
    from database.db import Base, create_all, get_engine
    from database.schema_validation import alter_statements, compare_schema

    engine = get_engine()

    create_all()

    drifts = compare_schema(engine)
    statements = alter_statements(drifts, engine)
    applied = {"tables": 0, "columns": 0, "indexes": 0}

    for statement in statements:
        with engine.begin() as conn:
            conn.execute(__import__("sqlalchemy").text(statement))
        if statement.lstrip().upper().startswith("CREATE TABLE"):
            applied["tables"] += 1
        elif statement.lstrip().upper().startswith("CREATE INDEX"):
            applied["indexes"] += 1
        elif statement.lstrip().upper().startswith("ALTER TABLE"):
            applied["columns"] += 1

    return applied


def validate_runtime():
    """Run the full startup validation and return a report dict.

    Raises ``RuntimeError`` when the environment/database cannot support the
    application so callers can fail fast.
    """
    from database.db import check_connection, get_engine, missing_tables
    from database.schema_validation import compare_schema

    url = validate_environment()

    ok, message = check_connection()
    if not ok:
        raise RuntimeError("STARTUP FAILED: {0}".format(message))

    try:
        applied = reconcile_schema()
    except Exception as exc:
        raise RuntimeError(
            "STARTUP FAILED: schema reconciliation could not complete: {0}".format(
                str(exc)[:300]
            )
        )

    engine = get_engine()
    absent = missing_tables()
    drift = compare_schema(engine)

    report = {
        "database_url_configured": bool(url),
        "database": message,
        "tables_missing": absent,
        "schema_drift": len(drift),
        "schema_applied": applied,
    }

    if absent:
        raise RuntimeError(
            "STARTUP FAILED: required tables are still missing after "
            "reconciliation: {0}".format(", ".join(sorted(absent)))
        )

    try:
        from services.bootstrap import run_bootstrap

        run_bootstrap()
    except Exception as exc:
        log.warning("Bootstrap (admin seed / legacy reclaim) failed: %s", exc)

    log.info(
        "Startup validation passed: %s (schema drift=%s, applied=%s)",
        message,
        len(drift),
        applied,
    )
    return report


def log_startup_status():
    """Non-fatal status helper used by health pages/tests."""
    try:
        return validate_runtime()
    except RuntimeError as exc:
        return {"error": str(exc)}
