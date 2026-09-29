from workbook import common
from workbook import sheets
from workbook import workbook

_TOOLS = {
    "create": "setConfig",
    "update": "editConfig",
    "delete": "deleteConfig",
}


def _sheet_action(row):
    if not isinstance(row, dict):
        return ""
    for key, value in row.items():
        if str(key or "").strip().lower() == "action":
            return common.to_text(value)
    return ""


def _empty_counts():
    return {
        "rows": 0,
        "created": 0,
        "updated": 0,
        "deleted": 0,
        "errors": 0,
        "skipped": 0,
    }


def _run_sheet(client, title, data, row_limit=None):
    handler = sheets.find_handler(title)
    counts = _empty_counts()
    per_row = []
    if handler is None:
        return {
            "sheet": title,
            "kind": title,
            "skipped": True,
            "reason": "Unknown sheet",
            "counts": counts,
            "rows": [],
        }

    kind, apply = handler
    for index, row in enumerate(data.get("rows") or []):
        if row_limit is not None and index >= row_limit:
            break
        counts["rows"] += 1
        sheet_action = _sheet_action(row)
        record = {"row": index + 2, "sheet": title}
        if sheet_action:
            record["action"] = sheet_action
        try:
            action = common.normalize_action(sheet_action)
            record["tool"] = _TOOLS[action]
            result = apply(client, row)
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
                    "action": sheet_action or op,
                }
            )
        except Exception as exc:
            counts["errors"] += 1
            record.update({"op": "error", "error": str(exc)[:300]})
        per_row.append(record)

    return {
        "sheet": title,
        "kind": kind,
        "skipped": False,
        "counts": counts,
        "rows": per_row,
        "summary": _sheet_summary(kind, counts, client.dry_run),
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


def run_workbook(client, workbook_path, row_limit=None):
    parsed = workbook.read_workbook(workbook_path)
    operations = []
    for title, data in parsed.items():
        if not data.get("row_count"):
            continue
        operations.append(_run_sheet(client, title, data, row_limit=row_limit))

    failed = any(((op.get("counts") or {}).get("errors") or 0) for op in operations)
    totals = _empty_counts()
    for op in operations:
        for key, value in (op.get("counts") or {}).items():
            totals[key] = totals.get(key, 0) + int(value or 0)
    return {
        "sheets": [op.get("sheet") for op in operations if not op.get("skipped")],
        "operations": operations,
        "counts": totals,
        "committed": False,
        "commit_required": True,
        "dry_run": bool(client.dry_run),
        "status": "failed" if failed else "successful",
    }
