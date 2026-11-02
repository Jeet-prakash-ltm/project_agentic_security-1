"""Authoritative validation, normalisation and execution-plan generation.

The Function App never trusts browser-normalised JSON. Every write is turned
into a list of canonical operations before a ``security_jobs`` row is created.
"""

from workbook import common
from workbook import dependencies
from workbook.changes import prepare_change
from workbook.runner import _name_of, _plan_sheet, _validate
from workbook import fields
from workbook import sheets
from workbook import workbook as workbook_mod


class JobValidationError(ValueError):
    pass


SOURCE_TYPES = ("ai_workspace", "automation_hub", "conversation", "workbook")
ROW_ACTIONS = ("create", "update", "delete")
PANOS_ACTIONS = {
    "create": "set",
    "update": "edit",
    "delete": "delete",
}


def _clean(value, limit=255):
    return str(value or "").strip()[:limit]


def _object_name(category, values, fallback=""):
    if not category:
        return _clean(fallback, 255)
    return _clean(_name_of(category, values) or fallback, 255)


def _change_from_payload(item, sequence, source_sheet=None, source_row=None):
    if not isinstance(item, dict):
        raise JobValidationError("Each change must be an object.")
    category = item.get("category") or item.get("type") or item.get("kind")
    action = item.get("action") or item.get("row_action") or "create"
    name = item.get("name") or item.get("object_name")
    fields_map = (
        item.get("fields")
        or item.get("values")
        or item.get("attributes")
        or item.get("requested_fields")
        or {}
    )
    if not isinstance(fields_map, dict):
        raise JobValidationError("change fields must be an object.")
    try:
        prepared = prepare_change(
            category,
            action=action,
            name=name,
            fields_map=fields_map,
        )
    except Exception as exc:
        raise JobValidationError(str(exc))
    row = dict(prepared.get("row") or {})
    object_name = _object_name(prepared["category"], row, name or "")
    return {
        "sequence": sequence,
        "source_sheet": _clean(item.get("source_sheet") or source_sheet, 255) or None,
        "source_row": item.get("source_row") if item.get("source_row") is not None else source_row,
        "category": prepared["category"],
        "action": prepared["action"],
        "object_name": object_name,
        "requested_fields": dict(fields_map),
        "normalized_fields": row,
        "kind": prepared.get("kind") or fields.kind_of(prepared["category"]),
        "status": "pending",
    }


def _operations_from_changes(changes):
    if not isinstance(changes, list) or not changes:
        raise JobValidationError("changes must be a non-empty list.")
    operations = []
    for index, item in enumerate(changes, start=1):
        operations.append(_change_from_payload(item, index))
    return operations


def _operations_from_workbook(parsed, row_limit=None):
    operations = []
    sequence = 0
    undetected = []
    for title, data in parsed.items():
        if not data.get("row_count"):
            continue
        category, planned = _plan_sheet(title, data, row_limit=row_limit)
        if not category:
            undetected.append(title)
        for entry in planned:
            sequence += 1
            row_category = entry.get("category")
            values = dict(entry.get("values") or {})
            raw_action = entry.get("action") or ""
            issues = []
            action = "create"
            if row_category:
                action = common.resolve_action(row_category, raw_action, values)
                values["Action"] = action
                problem = _validate(row_category, values, action)
                if problem:
                    issues.append(problem)
            else:
                issues.append("Could not detect the configuration category for this row.")
            if issues:
                raise JobValidationError(
                    "{0} row {1}: {2}".format(
                        title, entry.get("row"), "; ".join(issues)
                    )
                )
            operations.append(
                {
                    "sequence": sequence,
                    "source_sheet": title,
                    "source_row": entry.get("row"),
                    "category": row_category,
                    "action": action,
                    "object_name": _object_name(row_category, values),
                    "requested_fields": dict(entry.get("values") or values),
                    "normalized_fields": values,
                    "kind": fields.kind_of(row_category) if row_category else None,
                    "status": "pending",
                }
            )
    if not operations:
        raise JobValidationError("Workbook contains no executable configuration rows.")
    if undetected:
        raise JobValidationError(
            "Could not detect categories for sheet(s): {0}.".format(
                ", ".join(undetected)
            )
        )
    operations.sort(
        key=lambda item: (
            dependencies.category_rank(item.get("category") or ""),
            item.get("sequence") or 0,
        )
    )
    for index, item in enumerate(operations, start=1):
        item["sequence"] = index
    return operations


def _legacy_xpath_operation(requested, sequence=1):
    action = _clean(requested.get("action"), 16).lower()
    panos_to_row = {"set": "create", "edit": "update", "delete": "delete"}
    row_action = panos_to_row.get(action) or action
    if row_action not in ROW_ACTIONS:
        raise JobValidationError(
            "requested_payload.action must be one of: set, edit, delete, create, update."
        )
    xpath = _clean(requested.get("xpath"), 2048)
    if not xpath:
        raise JobValidationError("requested_payload.xpath is required.")
    if row_action in ("create", "update") and not requested.get("element"):
        raise JobValidationError(
            "requested_payload.element is required for {0}.".format(row_action)
        )
    category = _clean(requested.get("category"), 128) or "PAN-OS"
    name = _clean(requested.get("name") or requested.get("object_name"), 255)
    fields_map = requested.get("fields") if isinstance(requested.get("fields"), dict) else {}
    normalized = {
        "Action": row_action,
        "xpath": xpath,
    }
    if requested.get("element"):
        normalized["element"] = requested.get("element")
    if name:
        normalized["Name"] = name
    normalized.update(fields_map)
    return [
        {
            "sequence": sequence,
            "source_sheet": None,
            "source_row": None,
            "category": category,
            "action": row_action,
            "object_name": name,
            "requested_fields": dict(requested),
            "normalized_fields": normalized,
            "kind": fields.kind_of(category) if category != "PAN-OS" else "PAN-OS",
            "status": "pending",
            "legacy_xpath": True,
        }
    ]


def _preflight_references(operations, inventory=None, auto_create=True):
    inv = inventory
    warnings = []
    if inv is None:
        from workbook.adapter import WorkbookPanosClient

        inv = dependencies.Inventory(client_factory=lambda: WorkbookPanosClient())
    for item in operations:
        if item.get("legacy_xpath"):
            continue
        if item.get("action") == "delete":
            continue
        category = item.get("category")
        row = dict(item.get("normalized_fields") or {})
        deps, errors, item_warnings, replacements = dependencies.plan(
            category, row, inv, auto_create=auto_create, dry_run=True
        )
        if errors:
            raise JobValidationError(
                "Cannot apply {0} {1}: {2}".format(
                    category, item.get("object_name") or "", " ".join(errors)
                )
            )
        row = dependencies.apply_replacements(row, replacements)
        item["normalized_fields"] = row
        if deps:
            item["dependencies"] = [
                {"category": dep.get("category"), "name": dep.get("name")}
                for dep in deps
            ]
        if item_warnings:
            item["warnings"] = item_warnings
            warnings.extend(item_warnings)
        kind = dependencies.DEFINES_KIND.get(category)
        name = item.get("object_name")
        if kind and name:
            inv.add(kind, name)
    return warnings


def build_plan(payload, workbook_bytes=None, inventory=None, auto_create=True):
    """Validate a write request and return operations + execution plan."""
    payload = payload or {}
    operation = _clean(payload.get("operation"), 64).lower()
    changes = payload.get("changes")
    requested = payload.get("requested_payload")
    if isinstance(requested, dict) and not changes:
        nested = requested.get("changes")
        if isinstance(nested, list):
            changes = nested

    if workbook_bytes:
        parsed = workbook_mod.read_workbook_bytes(workbook_bytes) \
            if hasattr(workbook_mod, "read_workbook_bytes") else None
        if parsed is None:
            import os
            import tempfile

            handle, path = tempfile.mkstemp(suffix=".xlsx")
            os.close(handle)
            try:
                with open(path, "wb") as handle:
                    handle.write(workbook_bytes)
                parsed = workbook_mod.read_workbook(path)
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        operations = _operations_from_workbook(parsed, row_limit=payload.get("row_limit"))
        if not operation:
            operation = "apply_bulk"
    elif isinstance(changes, list):
        operations = _operations_from_changes(changes)
        if not operation:
            operation = "apply_bulk" if len(operations) > 1 else "apply_change"
    elif isinstance(requested, dict) and (
        requested.get("category") or requested.get("name") or requested.get("fields")
    ) and not requested.get("xpath"):
        operations = _operations_from_changes([requested])
        if not operation:
            operation = "apply_change"
    elif isinstance(requested, dict) and requested.get("xpath"):
        operations = _legacy_xpath_operation(requested)
        if not operation:
            operation = "apply_change"
    else:
        raise JobValidationError(
            "Provide changes[], requested_payload, or a workbook."
        )

    if operation not in ("apply_change", "apply_bulk", "commit"):
        if len(operations) > 1:
            operation = "apply_bulk"
        else:
            operation = "apply_change"

    warnings = _preflight_references(
        operations, inventory=inventory, auto_create=auto_create
    )
    execution_plan = {
        "operation": operation,
        "operation_count": len(operations),
        "commit": True,
        "categories": sorted(
            {item.get("category") for item in operations if item.get("category")}
        ),
        "actions": sorted(
            {item.get("action") for item in operations if item.get("action")}
        ),
        "warnings": warnings,
        "steps": [
            {
                "sequence": item["sequence"],
                "category": item.get("category"),
                "action": item.get("action"),
                "object_name": item.get("object_name"),
                "panos_action": PANOS_ACTIONS.get(item.get("action"), item.get("action")),
            }
            for item in operations
        ],
    }
    normalized_payload = {
        "operation": operation,
        "changes": [
            {
                "sequence": item["sequence"],
                "category": item.get("category"),
                "action": item.get("action"),
                "object_name": item.get("object_name"),
                "fields": item.get("normalized_fields") or {},
                "source_sheet": item.get("source_sheet"),
                "source_row": item.get("source_row"),
            }
            for item in operations
        ],
    }
    return {
        "operation": operation,
        "operations": operations,
        "execution_plan": execution_plan,
        "normalized_payload": normalized_payload,
        "warnings": warnings,
    }


def apply_operation(client, item, inventory=None, auto_create=True):
    """Apply one prepared operation to candidate config. Does not commit."""
    if item.get("legacy_xpath"):
        fields_map = item.get("normalized_fields") or {}
        action = (item.get("action") or "").lower()
        xpath = fields_map.get("xpath")
        element = fields_map.get("element")
        if action == "create":
            return client.set(xpath, element)
        if action == "update":
            return client.edit(xpath, element)
        return client.delete(xpath)

    category = item.get("category")
    handler = sheets.find_handler(category)
    if handler is None:
        raise ValueError("No handler for category {0}.".format(category))
    _kind, apply = handler
    row = dict(item.get("normalized_fields") or {})
    row["Action"] = item.get("action") or row.get("Action") or "create"
    created = []
    warnings = []
    if row["Action"] != "delete" and inventory is not None:
        deps, errors, warnings, replacements = dependencies.plan(
            category,
            row,
            inventory,
            auto_create=auto_create,
            dry_run=bool(getattr(client, "dry_run", False)),
        )
        if errors:
            raise ValueError(" ".join(errors))
        row = dependencies.apply_replacements(row, replacements)
        for dep in deps:
            dep_handler = sheets.find_handler(dep["category"])
            if dep_handler is None:
                continue
            dep_handler[1](client, dep["row"])
            created.append({"category": dep["category"], "name": dep["name"]})
    result = apply(client, row)
    if created:
        result["dependencies_created"] = created
    if warnings:
        result["warnings"] = warnings
    return result
