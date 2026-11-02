"""Format-agnostic workbook execution (no playbooks).

Every sheet in the uploaded workbook is classified into a configuration category
(from its title or its column signatures), its rows are normalised to the
canonical headers the apply handlers expect, and each row is executed.

Two safety layers are applied to every row before anything is pushed:

* value/format validation (:mod:`workbook.validators`) rejects malformed input;
* referential integrity (:mod:`workbook.dependencies`) makes sure referenced
  objects exist, creating the creatable ones first.

Sheets are executed in dependency order (objects before groups before rules) and
one bad row never aborts the rest.
"""

import logging

from workbook import common
from workbook import dependencies
from workbook import fields
from workbook import sheets
from workbook import validators
from workbook import workbook

logger = logging.getLogger("netsec.runner")

_TOOLS = {
    "create": "setConfig",
    "update": "editConfig",
    "delete": "deleteConfig",
}


def _empty_counts():
    return {
        "rows": 0,
        "created": 0,
        "updated": 0,
        "deleted": 0,
        "errors": 0,
        "skipped": 0,
    }


def _sheet_action(row):
    if not isinstance(row, dict):
        return ""
    for key, value in row.items():
        if fields.norm(key) == "action":
            return common.to_text(value)
    return ""


def _name_of(category, values):
    if category == "interface":
        return common.to_text(values.get("Interface") or values.get("Name"))
    return common.to_text(values.get("Name"))


def _plan_sheet(title, data, row_limit=None):
    """Detect the category and normalise rows for one sheet (no side effects)."""
    headers = data.get("headers") or []
    raw_rows = data.get("rows") or []
    category = fields.detect_category(title, headers)
    planned = []
    for index, row in enumerate(raw_rows):
        if row_limit is not None and index >= row_limit:
            break
        row_key = fields.row_category(row, category)
        normalized = fields.normalize_row(row, row_key) if row_key else {}
        if row_key:
            validators.normalize_identifiers(row_key, normalized)
        planned.append(
            {
                "row": index + 2,
                "category": row_key,
                "action": _sheet_action(row),
                "values": normalized,
            }
        )
    return category, planned


def _validate(category, values, action):
    try:
        validators.validate_row(category, values, action)
        return None
    except validators.ValidationFailure as exc:
        return str(exc)


def analyze_workbook(parsed, row_limit=None):
    """Return a detection/plan report for a parsed workbook. No firewall calls."""
    report = []
    total_rows = 0
    undetected = []
    for title, data in parsed.items():
        if not data.get("row_count"):
            continue
        category, planned = _plan_sheet(title, data, row_limit=row_limit)
        rows = []
        for entry in planned:
            action = common.resolve_action(entry["category"], entry["action"], entry["values"]) \
                if entry["action"] else "create"
            issues = []
            if entry["category"]:
                problem = _validate(entry["category"], entry["values"], action)
                if problem:
                    issues.append(problem)
            rows.append(
                {
                    "row": entry["row"],
                    "category": entry["category"],
                    "kind": fields.kind_of(entry["category"]) if entry["category"] else None,
                    "action": action,
                    "name": _name_of(entry["category"], entry["values"])
                    if entry["category"] else None,
                    "valid": not issues,
                    "issues": issues,
                }
            )
        total_rows += len(rows)
        if not category:
            undetected.append(title)
        report.append(
            {
                "sheet": title,
                "detected_category": category,
                "kind": fields.kind_of(category) if category else None,
                "detected": bool(category),
                "row_count": len(rows),
                "headers": list(data.get("headers") or []),
                "rows": rows,
            }
        )
    status = "successful" if not undetected else "partial"
    return {
        "status": status,
        "sheets": report,
        "counts": {"sheets": len(report), "rows": total_rows},
        "undetected_sheets": undetected,
        "categories": sheets.categories(),
    }


def _apply_dependencies(client, category, values, inventory, auto_create):
    """Create missing referenced objects, returning (rows applied, warnings)."""
    deps, errors, warnings, replacements = dependencies.plan(
        category, values, inventory, auto_create=auto_create,
        dry_run=bool(getattr(client, "dry_run", False)),
    )
    if errors:
        raise ValueError(" ".join(errors))
    values = dependencies.apply_replacements(values, replacements)
    applied = []
    for dep in deps:
        handler = sheets.find_handler(dep["category"])
        if handler is None:
            continue
        handler[1](client, dep["row"])
        applied.append({"category": dep["category"], "name": dep["name"]})
    return values, applied, warnings


def _run_sheet(client, title, data, default_category, row_limit=None,
               inventory=None, auto_create=True):
    headers = data.get("headers") or []
    raw_rows = data.get("rows") or []
    counts = _empty_counts()
    per_row = []
    for index, row in enumerate(raw_rows):
        if row_limit is not None and index >= row_limit:
            break
        counts["rows"] += 1
        sheet_action = _sheet_action(row)
        category = fields.row_category(row, default_category)
        record = {"row": index + 2, "sheet": title, "category": category}
        if sheet_action:
            record["action"] = sheet_action
        if not category:
            counts["errors"] += 1
            record.update({"op": "error", "error": "Could not detect the configuration category for this row."})
            per_row.append(record)
            continue
        handler = sheets.find_handler(category)
        if handler is None:
            counts["errors"] += 1
            record.update({"op": "error", "error": "No handler for category {0}.".format(category)})
            per_row.append(record)
            continue
        kind, apply = handler
        try:
            values = fields.normalize_row(row, category)
            validators.normalize_identifiers(category, values)
            action = common.resolve_action(category, sheet_action, values)
            values["Action"] = action
            record["tool"] = _TOOLS[action]
            validators.validate_row(category, values, action)
            created = []
            if action != "delete":
                values, created, warnings = _apply_dependencies(
                    client, category, values, inventory, auto_create
                )
                if warnings:
                    record["warnings"] = warnings
            result = apply(client, values)
            op = result.get("op", action)
            count_key = {"create": "created", "update": "updated", "delete": "deleted"}.get(op)
            if count_key:
                counts[count_key] += 1
            record.update(
                {
                    "op": op,
                    "tool": _TOOLS.get(op, record.get("tool")),
                    "dry_run": bool(result.get("dry_run", client.dry_run)),
                    "kind": result.get("kind", kind),
                    "name": result.get("name", ""),
                    "detail": result.get("detail", ""),
                    "xpath": result.get("xpath", ""),
                    "action": sheet_action or action,
                }
            )
            if created:
                record["dependencies_created"] = created
        except validators.ValidationFailure as exc:
            counts["errors"] += 1
            record.update({"op": "error", "error": str(exc)[:300]})
            logger.warning("workbook sheet %s row %s validation failed: %s", title, index + 2, exc)
        except Exception as exc:  # noqa: BLE001 - per-row isolation
            counts["errors"] += 1
            record.update({"op": "error", "error": str(exc)[:300]})
            logger.warning("workbook sheet %s row %s failed: %s", title, index + 2, exc)
        per_row.append(record)

    return {
        "sheet": title,
        "category": default_category,
        "kind": fields.kind_of(default_category) if default_category else None,
        "detected": bool(default_category),
        "counts": counts,
        "rows": per_row,
        "summary": _sheet_summary(title, counts, client.dry_run),
    }


def _sheet_summary(kind, counts, dry_run):
    prefix = "Dry-run" if dry_run else "Applied"
    if not counts["rows"]:
        return "{0} {1}: no data rows.".format(prefix, kind)
    return (
        "{0} {1}: {2} row(s) ({3} created, {4} updated, {5} deleted, {6} errors).".format(
            prefix,
            kind,
            counts["rows"],
            counts["created"],
            counts["updated"],
            counts["deleted"],
            counts["errors"],
        )
    )


def run_workbook(client, workbook_path, row_limit=None, commit=None,
                 inventory=None, auto_create=True):
    """Parse ``workbook_path``, validate, resolve dependencies, apply and commit.

    ``commit`` defaults to ``not client.dry_run``: under dry run nothing is sent
    to the firewall; in apply mode the candidate changes are committed once after
    the last row so they actually take effect.
    """
    parsed = workbook.read_workbook(workbook_path)
    sheets_in_order = []
    undetected = []
    for title, data in parsed.items():
        if not data.get("row_count"):
            continue
        category = fields.detect_category(title, data.get("headers") or [])
        if not category:
            undetected.append(title)
        sheets_in_order.append((title, data, category))

    if inventory is None:
        inventory = dependencies.Inventory()
    # Seed the inventory with every object the workbook itself creates so that a
    # rule referencing a workbook-defined object validates even before it is
    # applied (the object is created first because of the dependency ordering).
    for title, data, category in sheets_in_order:
        if not category:
            continue
        _category, planned = _plan_sheet(title, data, row_limit=row_limit)
        for entry in planned:
            if not entry["category"]:
                continue
            kind = dependencies.DEFINES_KIND.get(entry["category"])
            if not kind:
                continue
            name = _name_of(entry["category"], entry["values"])
            if name:
                inventory.add(kind, name)

    sheets_in_order.sort(key=lambda item: dependencies.category_rank(item[2] or ""))

    operations = [
        _run_sheet(client, title, data, category, row_limit=row_limit,
                   inventory=inventory, auto_create=auto_create)
        for title, data, category in sheets_in_order
    ]

    totals = _empty_counts()
    for op in operations:
        for key, value in (op.get("counts") or {}).items():
            totals[key] = totals.get(key, 0) + int(value or 0)

    do_commit = commit if commit is not None else (not client.dry_run)
    committed = False
    commit_error = None
    if do_commit and not client.dry_run and totals["rows"] and not totals["errors"]:
        try:
            client.commit(description="netsec workbook run")
            committed = True
        except Exception as exc:  # noqa: BLE001
            commit_error = str(exc)[:300]
            logger.warning("workbook commit failed: %s", exc)

    failed = totals["errors"] > 0
    return {
        "sheets": [op.get("sheet") for op in operations if op.get("detected")],
        "undetected_sheets": undetected,
        "operations": operations,
        "counts": totals,
        "committed": committed,
        "commit_required": not client.dry_run and totals["rows"] > 0 and not totals["errors"],
        "commit_error": commit_error,
        "dry_run": bool(client.dry_run),
        "status": "failed" if failed else "successful",
    }
