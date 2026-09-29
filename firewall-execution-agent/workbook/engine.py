"""Playbook execution engine.

Runs a single playbook against a parsed workbook and a :class:`PanosClient`.
Every row is executed independently so one bad row never aborts the rest; the
engine returns per-row outcomes plus aggregate counts and a human summary
suitable for rendering in the AI Workspace chat.
"""

import logging

from workbook import catalog
from workbook import common
from workbook import workbook

logger = logging.getLogger("netsec.engine")


def _find_sheet(rows, playbook):
    target = (playbook.get("sheet") or "").strip().lower().replace(" ", "")
    for title, data in rows.items():
        if title.strip().lower().replace(" ", "") == target:
            return data
    raise ValueError(
        "The uploaded workbook has no {0!r} sheet (found: {1}).".format(
            playbook.get("sheet"), ", ".join(sorted(rows.keys())) or "none"
        )
    )


def _op_label(op):
    return {
        "create": "created",
        "update": "updated",
        "delete": "deleted",
    }.get(op, op)


def _count_key(op):
    return {"create": "created", "update": "updated", "delete": "deleted"}.get(op, op)


def _sheet_action(row):
    """Return the original Action cell from a workbook row."""
    if not isinstance(row, dict):
        return ""
    for key, value in row.items():
        if str(key or "").strip().lower() == "action":
            return common.to_text(value)
    return ""


def run_playbook(
    client,
    playbook_id,
    workbook_path=None,
    rows=None,
    row_limit=None,
    commit=None,
):
    """Execute ``playbook_id`` against workbook rows.

    Pass either ``workbook_path`` (parsed automatically) or already-parsed
    ``rows``. Returns a result dict safe to JSON-serialize.

    ``commit`` defaults to ``not client.dry_run``: under dry run nothing is
    sent to the firewall at all, while in apply mode (``NETSEC_FW_DRY_RUN=0``)
    the candidate changes are committed to the running configuration after the
    last row so they actually take effect.
    """
    playbook = catalog.find_playbook(playbook_id)
    if playbook is None:
        raise ValueError("Unknown playbook id: {0}".format(playbook_id))
    if rows is None:
        if not workbook_path:
            raise ValueError("run_playbook requires a workbook path or rows.")
        rows = workbook.read_workbook(workbook_path)
    sheet = _find_sheet(rows, playbook)

    logger.info(
        "Running playbook %s (%s) dry_run=%s on %s rows",
        playbook_id, playbook.get("title"), client.dry_run, sheet["row_count"],
    )

    per_row = []
    counts = {
        "rows": 0,
        "created": 0,
        "updated": 0,
        "deleted": 0,
        "errors": 0,
        "skipped": 0,
    }
    apply = playbook["apply"]

    for index, row in enumerate(sheet["rows"]):
        if row_limit is not None and index >= row_limit:
            break
        counts["rows"] += 1
        sheet_action = _sheet_action(row)
        record = {"row": index + 2}
        if sheet_action:
            record["action"] = sheet_action
        try:
            result = apply(client, row)
            op = result.get("op", "create")
            counts[_count_key(op)] = counts.get(_count_key(op), 0) + 1
            record.update(
                {
                    "op": op,
                    "dry_run": bool(result.get("dry_run", client.dry_run)),
                    "kind": result.get("kind", playbook.get("title")),
                    "name": result.get("name", ""),
                    "detail": result.get("detail", ""),
                }
            )
        except Exception as exc:  # noqa: BLE001 - per-row isolation
            counts["errors"] += 1
            record.update({"op": "error", "error": str(exc)[:300]})
            logger.warning(
                "playbook %s row %s failed: %s", playbook_id, index + 2, exc
            )
        per_row.append(record)

    committed = False
    commit_error = None
    if (commit is None and not client.dry_run) or commit is True:
        if client.dry_run:
            logger.info("commit skipped: dry run")
        else:
            try:
                client.commit(
                    description="netsec playbook {0}".format(playbook_id)
                )
                committed = True
            except Exception as exc:  # noqa: BLE001 - surfaced on the result
                commit_error = str(exc)[:300]
                logger.warning("playbook %s commit failed: %s", playbook_id, exc)

    summary_text = _summary_text(playbook, counts, client.dry_run)
    if committed:
        summary_text += (
            " Changes were committed to the running firewall configuration."
        )
    elif commit_error:
        summary_text += " Commit FAILED: {0}.".format(commit_error)
    return {
        "playbook_id": playbook_id,
        "playbook_title": playbook.get("title"),
        "category": playbook.get("category"),
        "sheet": playbook.get("sheet"),
        "dry_run": bool(client.dry_run),
        "counts": counts,
        "rows": per_row,
        "committed": committed,
        "commit_error": commit_error,
        "summary": summary_text,
    }


def _summary_text(playbook, counts, dry_run):
    label = "previewed" if dry_run else "applied"
    prefix = "Dry-run" if dry_run else "Applied"
    created = "{0} {1}".format(counts["created"], _op_label("create"))
    updated = "{0} {1}".format(counts["updated"], _op_label("update"))
    deleted = "{0} {1}".format(counts["deleted"], _op_label("delete"))
    segments = [created, updated, deleted]
    if counts["errors"]:
        segments.append("{0} errors".format(counts["errors"]))
    if counts["skipped"]:
        segments.append("{0} skipped".format(counts["skipped"]))
    if not counts["rows"]:
        return "{0} playbook {1}: no data rows found in sheet {2}.".format(
            prefix, playbook.get("title"), playbook.get("sheet")
        )
    return (
        "{0} playbook {1}: {2} row(s) {3} against the firewall "
        "({4}).".format(
            prefix,
            playbook.get("title"),
            counts["rows"],
            label,
            ", ".join(segments),
        )
    )
