"""Single structured configuration change (no playbooks, no raw xpath).

The agent captures the values a user provided and calls this module with a
category, an action and a bag of fields. The module normalises the fields to the
canonical headers, applies the change through the same per-row handler used by
the workbook runner, and (unless dry run) commits the candidate configuration so
the change takes effect.
"""

from workbook import common
from workbook import dependencies
from workbook import fields
from workbook import sheets
from workbook import validators

_VALID_ACTIONS = ("create", "update", "delete")


def _resolve_category(value):
    if not value:
        return None
    key = fields.norm(value)
    for candidate in fields.CATEGORY_KEYS:
        if fields.norm(candidate) == key:
            return candidate
    for candidate in fields.CATEGORY_KEYS:
        aliases = {fields.norm(a) for a in fields.SPEC[candidate]["sheet_aliases"]}
        if key in aliases or fields.norm(fields.kind_of(candidate)) == key:
            return candidate
    for candidate in fields.CATEGORY_KEYS:
        keywords = {fields.norm(k) for k in fields.SPEC[candidate].get("keywords") or []}
        if key in keywords:
            return candidate
    return None


def prepare_change(category, action=None, name=None, fields_map=None):
    """Validate a single change and normalise it to a canonical row.

    Does no network I/O, so callers can reject bad input before opening a
    firewall connection. Returns a dict consumed by :func:`apply_change`.
    """
    resolved = _resolve_category(category)
    if not resolved:
        raise ValueError(
            "Unknown category {0!r}. Valid categories: {1}.".format(
                category, ", ".join(fields.CATEGORY_KEYS)
            )
        )

    normalized_action = common.normalize_action(action or "create")
    if normalized_action not in _VALID_ACTIONS:
        raise ValueError(
            "Unsupported action {0!r} (expected create, update or delete).".format(
                action
            )
        )

    handler = sheets.find_handler(resolved)
    if handler is None:
        raise ValueError("No handler registered for category {0!r}.".format(resolved))
    kind, _apply = handler

    values = {}
    if isinstance(fields_map, dict):
        for key, value in fields_map.items():
            values[key] = value
    if name not in (None, ""):
        if resolved == "interface":
            values.setdefault("Interface", name)
            values.setdefault("Name", name)
        else:
            values.setdefault("Name", name)
    values["Action"] = normalized_action

    row = fields.normalize_row(values, resolved)
    validators.normalize_identifiers(resolved, row)

    if normalized_action != "delete":
        required = list((fields.SPEC.get(resolved) or {}).get("required") or [])
        missing = [
            key for key in required
            if key != "Name" and not common.to_text(row.get(key))
        ]
        if missing:
            raise ValueError(
                "Missing required field(s) for {0}: {1}.".format(
                    resolved, ", ".join(missing)
                )
            )

    validators.validate_row(resolved, row, normalized_action)

    return {
        "category": resolved,
        "kind": kind,
        "action": normalized_action,
        "row": row,
    }


def apply_change(
    client,
    change,
    commit=None,
    description=None,
    inventory=None,
    auto_create=True,
):
    """Apply a prepared change (see :func:`prepare_change`) and optionally commit.

    Referenced objects (zones, addresses, services, ...) are checked against the
    firewall inventory first; creatable literals are created before the change,
    and anything missing that cannot be created raises so no broken configuration
    is pushed. Returns a JSON-serialisable dict describing the outcome.
    """
    resolved = change["category"]
    normalized_action = change["action"]
    kind = change["kind"]
    row = change["row"]

    handler = sheets.find_handler(resolved)
    if handler is None:
        raise ValueError("No handler registered for category {0!r}.".format(resolved))
    _kind, apply = handler

    dependencies_created = []
    warnings = []
    if normalized_action != "delete":
        inv = inventory if inventory is not None else dependencies.Inventory()
        deps, errors, warnings, replacements = dependencies.plan(
            resolved, row, inv, auto_create=auto_create,
            dry_run=bool(getattr(client, "dry_run", False)),
        )
        if errors:
            raise ValueError(
                "Cannot apply {0}: {1}".format(resolved, " ".join(errors))
            )
        row = dependencies.apply_replacements(row, replacements)
        for dep in deps:
            dep_handler = sheets.find_handler(dep["category"])
            if dep_handler is None:
                continue
            dep_handler[1](client, dep["row"])
            dependencies_created.append(
                {"category": dep["category"], "name": dep["name"]}
            )

    name = row.get("Name")

    result = apply(client, row)

    do_commit = commit if commit is not None else (not client.dry_run)
    committed = False
    commit_error = None
    if do_commit and not client.dry_run:
        try:
            client.commit(description=description or "netsec change {0} {1}".format(
                resolved, normalized_action
            ))
            committed = True
        except Exception as exc:  # noqa: BLE001
            commit_error = str(exc)[:300]

    return {
        "category": resolved,
        "kind": result.get("kind", kind),
        "action": normalized_action,
        "op": result.get("op", normalized_action),
        "name": result.get("name", name or ""),
        "detail": result.get("detail", ""),
        "xpath": result.get("xpath", ""),
        "dry_run": bool(result.get("dry_run", client.dry_run)),
        "committed": committed,
        "commit_error": commit_error,
        "dependencies_created": dependencies_created,
        "warnings": warnings,
    }
