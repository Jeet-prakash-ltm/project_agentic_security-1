"""Interactive UI blocks for agent chat replies.

Specialist agents (Maestro AI in particular) can answer with prose that asks
the user for information (rule name, zones, action, ...) or presents a set of
choices. Rendered as plain markdown that is hard to act on, so this module
turns such replies into a small, safe, declarative UI schema - cards, option
buttons, and input forms - that the workspace chat renders natively.

Two paths feed the schema:

* The model is instructed (see ``foundry_client.UI_BLOCK_DIRECTIVE``) to emit a
  fenced ``ui`` block containing JSON. ``parse_interactive_blocks`` extracts it,
  normalises every value, and strips the block from the visible text.
* When a hosted Foundry prompt agent answers in its own voice and ignores the
  protocol, ``derive_blocks_from_questions`` detects the common
  "please provide: ..." answer pattern and synthesises a form so the reply is
  still actionable.

Everything is normalised against a strict allow-list: unexpected block/field
types are dropped and all strings are length-capped, so no arbitrary HTML or
script from the model ever reaches the browser.
"""

import json
import re

MAX_BLOCKS = 12
MAX_FIELDS = 24
MAX_OPTIONS = 24
MAX_TEXT = 4000
MAX_LABEL = 200
MAX_VALUE = 600

BLOCK_TYPES = {
    "text", "note", "callout", "card", "kv", "table",
    "options", "buttons", "form", "confirm", "steps", "divider",
}

FIELD_TYPES = {
    "text", "textarea", "number", "email", "url", "tel", "date",
    "select", "multiselect", "radio", "boolean", "tags",
}

_CHOICE_FIELD_TYPES = {"select", "multiselect", "radio"}

UI_FENCE_LANGS = {
    "", "ui", "ui-blocks", "ui_blocks", "blocks", "json",
    "interactive", "ui-json", "ui_json",
}

_FENCE_RE = re.compile(r"```[ \t]*([A-Za-z0-9_\-]*)[ \t]*\r?\n(.*?)```", re.DOTALL)

_LEAD_INS = (
    "please provide",
    "please specify",
    "please confirm",
    "provide the following",
    "provide me",
    "i need the following",
    "i need these",
    "need the following",
    "need a few details",
    "need more details",
    "need some details",
    "share the following",
    "tell me the following",
    "specify the following",
    "confirm the following",
    "give me the following",
    "the following details",
    "a few details before",
)

def _as_str(value, limit=MAX_VALUE):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if len(text) > limit:
        text = text[:limit].rstrip() + "\u2026"
    return text


def _slug(value, fallback="field"):
    slug = re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")
    return slug or fallback


def _unique(name, used):
    base = name or "field"
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = "{0}_{1}".format(base, suffix)
        suffix += 1
    used.add(candidate)
    return candidate


def _normalize_options(raw):
    options = []
    if not isinstance(raw, list):
        return options
    for item in raw[:MAX_OPTIONS]:
        if isinstance(item, str):
            label = _as_str(item, MAX_LABEL)
            value = label
            description = ""
        elif isinstance(item, dict):
            label = _as_str(
                item.get("label") or item.get("title") or item.get("value"),
                MAX_LABEL,
            )
            value = _as_str(item.get("value") or label, MAX_VALUE) or label
            description = _as_str(item.get("description") or item.get("help"))
        else:
            continue
        if not label:
            continue
        options.append({"label": label, "value": value, "description": description})
    return options


def _normalize_field(raw, used_names):
    if not isinstance(raw, dict):
        return None
    label = _as_str(raw.get("label") or raw.get("title") or raw.get("name"), MAX_LABEL)
    name = _slug(raw.get("name") or label, "field")
    name = _unique(name, used_names)

    field_type = _as_str(raw.get("type"), 32).lower() or "text"
    if field_type not in FIELD_TYPES:
        field_type = "text"

    options = _normalize_options(raw.get("options") or raw.get("choices"))
    if options and field_type == "text":
        field_type = "select"

    field = {
        "name": name,
        "label": label or name.replace("_", " ").title(),
        "type": field_type,
        "placeholder": _as_str(raw.get("placeholder"), MAX_LABEL),
        "help": _as_str(raw.get("help") or raw.get("description")),
        "required": bool(raw.get("required")),
    }
    default = raw.get("value")
    if default is not None and not isinstance(default, (list, dict)):
        field["value"] = _as_str(default, MAX_VALUE)
    if options:
        field["options"] = options
    if field_type == "multiselect" and isinstance(raw.get("value"), list):
        field["value"] = [_as_str(v, MAX_VALUE) for v in raw["value"][:MAX_OPTIONS]]
    return field


def _normalize_kv_items(raw):
    items = []
    if isinstance(raw, dict):
        raw = [{"label": k, "value": v} for k, v in raw.items()]
    if not isinstance(raw, list):
        return items
    for item in raw[:MAX_FIELDS]:
        if isinstance(item, dict):
            label = _as_str(item.get("label") or item.get("key") or item.get("name"), MAX_LABEL)
            value = _as_str(item.get("value") or item.get("text"))
        else:
            continue
        if label or value:
            items.append({"label": label, "value": value})
    return items


def _normalize_table(raw):
    columns = raw.get("columns") or raw.get("headers") or []
    if isinstance(columns, list):
        columns = [_as_str(c, MAX_LABEL) for c in columns[:12] if _as_str(c, MAX_LABEL)]
    else:
        columns = []
    rows = []
    for row in (raw.get("rows") or [])[:40]:
        if isinstance(row, dict):
            if not columns:
                columns = [_as_str(k, MAX_LABEL) for k in list(row.keys())[:12]]
            rows.append([_as_str(row.get(c)) for c in columns])
        elif isinstance(row, list):
            rows.append([_as_str(cell) for cell in row[:12]])
    return columns, rows


def _normalize_block(raw):
    if not isinstance(raw, dict):
        return None
    block_type = _as_str(raw.get("type"), 32).lower()
    if block_type not in BLOCK_TYPES:
        return None

    if block_type == "text":
        text = _as_str(raw.get("text") or raw.get("content"), MAX_TEXT)
        return {"type": "text", "text": text} if text else None

    if block_type in ("note", "callout"):
        text = _as_str(raw.get("text") or raw.get("content"), MAX_TEXT)
        if not text:
            return None
        tone = _as_str(raw.get("tone") or raw.get("variant"), 24).lower()
        if tone not in ("info", "warn", "warning", "success", "danger", "error"):
            tone = "info"
        return {"type": "callout", "tone": tone, "text": text}

    if block_type == "divider":
        return {"type": "divider"}

    if block_type == "card":
        block = {
            "type": "card",
            "title": _as_str(raw.get("title"), MAX_LABEL),
            "subtitle": _as_str(raw.get("subtitle") or raw.get("description"), MAX_TEXT),
            "items": _normalize_kv_items(raw.get("items") or raw.get("fields")),
        }
        if not (block["title"] or block["subtitle"] or block["items"]):
            return None
        return block

    if block_type == "kv":
        items = _normalize_kv_items(raw.get("items") or raw.get("fields"))
        if not items:
            return None
        return {
            "type": "kv",
            "title": _as_str(raw.get("title"), MAX_LABEL),
            "items": items,
        }

    if block_type == "table":
        columns, rows = _normalize_table(raw)
        if not rows:
            return None
        return {
            "type": "table",
            "title": _as_str(raw.get("title"), MAX_LABEL),
            "columns": columns,
            "rows": rows,
        }

    if block_type in ("options", "buttons"):
        options = _normalize_options(raw.get("options") or raw.get("items"))
        if not options:
            return None
        block = {
            "type": block_type,
            "title": _as_str(raw.get("title") or raw.get("prompt"), MAX_LABEL),
            "description": _as_str(raw.get("description")),
            "options": options,
        }
        if block_type == "options":
            block["multi"] = bool(raw.get("multi") or raw.get("multiple"))
        if raw.get("submit_label"):
            block["submit_label"] = _as_str(raw.get("submit_label"), MAX_LABEL)
        return block

    if block_type == "confirm":
        return {
            "type": "confirm",
            "title": _as_str(raw.get("title"), MAX_LABEL),
            "text": _as_str(raw.get("text") or raw.get("description"), MAX_TEXT),
            "confirm_label": _as_str(raw.get("confirm_label"), MAX_LABEL) or "Confirm",
            "confirm_value": _as_str(raw.get("confirm_value"), MAX_VALUE) or "Confirmed",
            "cancel_label": _as_str(raw.get("cancel_label"), MAX_LABEL) or "Cancel",
            "cancel_value": _as_str(raw.get("cancel_value"), MAX_VALUE) or "Cancelled",
        }

    if block_type == "steps":
        items = _normalize_kv_items(raw.get("items") or raw.get("steps"))
        if not items:
            return None
        return {"type": "steps", "title": _as_str(raw.get("title"), MAX_LABEL), "items": items}

    if block_type == "form":
        used = set()
        fields = []
        for field_raw in (raw.get("fields") or [])[:MAX_FIELDS]:
            field = _normalize_field(field_raw, used)
            if field:
                fields.append(field)
        block = {
            "type": "form",
            "id": _slug(raw.get("id"), "form"),
            "title": _as_str(raw.get("title"), MAX_LABEL),
            "description": _as_str(raw.get("description") or raw.get("subtitle"), MAX_TEXT),
            "submit_label": _as_str(raw.get("submit_label"), MAX_LABEL) or "Submit",
            "submit_message": _as_str(raw.get("submit_message"), MAX_TEXT),
            "fields": fields,
        }
        if not fields and not block["title"]:
            return None
        return block

    return None


def _blocks_from_payload(payload):
    if isinstance(payload, dict):
        if isinstance(payload.get("ui"), list):
            payload = payload["ui"]
        elif isinstance(payload.get("blocks"), list):
            payload = payload["blocks"]
        elif "type" in payload:
            payload = [payload]
        else:
            return None
    if not isinstance(payload, list):
        return None
    if not any(
        isinstance(item, dict) and str(item.get("type", "")).lower() in BLOCK_TYPES
        for item in payload
    ):
        return None
    blocks = []
    for item in payload[:MAX_BLOCKS]:
        block = _normalize_block(item)
        if block:
            blocks.append(block)
    return blocks or None


def parse_interactive_blocks(text):
    """Split an agent reply into (visible_text, blocks).

    Fenced ``ui``/``json`` blocks that decode to the block schema are removed
    from the visible text and returned as normalised blocks.
    """
    text = text or ""
    blocks = []
    spans = []

    for match in _FENCE_RE.finditer(text):
        lang = (match.group(1) or "").lower()
        if lang not in UI_FENCE_LANGS:
            continue
        body = match.group(2).strip()
        if not body or body[0] not in "[{":
            continue
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            continue
        parsed = _blocks_from_payload(payload)
        if not parsed:
            continue
        blocks.extend(parsed)
        spans.append(match.span())

    if not blocks:
        return text, []

    cleaned = text
    for start, end in reversed(spans):
        cleaned = cleaned[:start] + cleaned[end:]
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()

    seen = []
    for block in blocks[:MAX_BLOCKS]:
        if block not in seen:
            seen.append(block)
    return cleaned, seen


_BULLET_RE = re.compile(r"^(?:[-*\u2022\u25cf\u25aa]|\d+[.)])\s+(.*)$")


def _is_lead_line(line):
    stripped = line.strip()
    simplified = stripped.rstrip(":").strip().lower()
    if simplified in _GENERIC_LEADS:
        return True
    if len(stripped) <= 48 and stripped.endswith(":"):
        return any(
            verb in simplified
            for verb in ("provide", "specify", "confirm", "tell", "share", "give", "need", "select", "choose")
        )
    return False


def _split_items(lines, start_index):
    """Collect the ask-list that follows a lead-in line.

    Skips blank lines and "Please provide:" style lead lines, then reads the
    first non-empty run. Handles both bulleted/numbered lists and plain
    one-per-line lists (the shape Maestro tends to answer with).
    """
    index = start_index
    skipped = []
    block = []
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped:
            index += 1
            continue
        if not block and _is_lead_line(lines[index]):
            skipped.append(index)
            index += 1
            continue
        if block:
            break
        run = []
        while index < len(lines) and lines[index].strip():
            run.append(index)
            index += 1
        if len(run) >= 2:
            block = run
            break
        skipped.extend(run)

    if not block:
        return [], [], skipped

    if all(_BULLET_RE.match(lines[k].strip()) for k in block):
        items = [_BULLET_RE.match(lines[k].strip()).group(1).strip() for k in block]
        return items, block, skipped

    items = []
    buffer = None
    for k in block:
        raw = lines[k]
        stripped = raw.strip()
        match = _BULLET_RE.match(stripped)
        if match:
            if buffer is not None:
                items.append(buffer)
            buffer = match.group(1).strip()
        elif buffer is not None and raw[:1] in (" ", "\t"):
            buffer = (buffer + " " + stripped).strip()
        else:
            if buffer is not None:
                items.append(buffer)
            buffer = stripped
    if buffer is not None:
        items.append(buffer)
    return items, block, skipped


def _guess_field(raw):
    text = re.sub(r"\s+", " ", raw or "").strip().rstrip(".").strip()
    if not text:
        return None

    label = text
    help_text = ""
    for sep in (" \u2014 ", " \u2013 ", " - ", ": "):
        if sep in label:
            head, tail = label.split(sep, 1)
            head, tail = head.strip(), tail.strip()
            if head and tail:
                label, help_text = head, tail
            break
    label = re.sub(r"^(?:if you want this|if you would like this|do you want|whether)\s+", "", label, flags=re.IGNORECASE)
    label = label.rstrip("?").strip()
    if not label:
        label = text.split("?")[0].strip() or text

    combined = (label + " " + help_text).lower()
    lower = label.lower()
    field_type = "text"
    options = None

    if "action" in lower:
        field_type, options = "select", ["allow", "deny", "drop"]
    elif re.search(r"\byes\s*/\s*no\b|\byes or no\b|\btrue\s*/?\s*false\b|\bwhether\b", combined):
        field_type = "boolean"
    elif re.search(r"\ballow\b", combined) and re.search(r"\bdeny\b|\bdrop\b", combined):
        field_type = "select"
        options = ["allow", "deny", "drop"]
    else:
        match = re.search(
            r"(?:options?|choices?|one of|values?)\s*:?\s*([a-z0-9][a-z0-9 ,/\-]{2,80})$",
            combined,
        )
        if match:
            tokens = re.split(r"\s*(?:,|/|\bor\b)\s*", match.group(1).strip())
            tokens = [t.strip() for t in tokens if t.strip() and len(t.strip()) <= 40]
            if 2 <= len(tokens) <= 8:
                field_type = "select"
                options = tokens

    if field_type == "text" and any(
        k in lower for k in ("description", "details", "notes", "handling", "comment", "reason")
    ):
        field_type = "textarea"

    field = {
        "name": _slug(label, "field"),
        "label": label,
        "type": field_type,
        "placeholder": "",
        "help": help_text,
        "required": False,
    }
    if options:
        field["options"] = _normalize_options(options)
    if "immediately" in combined or "applied now" in combined or "apply now" in combined:
        field["type"] = "boolean"
        field.pop("options", None)
    return field


_GENERIC_LEADS = {
    "please provide", "please specify", "please confirm", "provide the following",
    "specify the following", "confirm the following", "provide me", "tell me the following",
    "the following details", "share the following", "give me the following",
}


def _form_title(lead):
    cleaned = lead.rstrip(":").strip().rstrip(".").strip()
    if cleaned.lower() in _GENERIC_LEADS:
        return "Additional details required"
    if 0 < len(cleaned) <= 90:
        return cleaned
    return "Additional details required"


def derive_blocks_from_questions(text):
    """Best-effort form synthesis for "please provide: ..." replies."""
    text = text or ""
    lines = text.split("\n")

    lead_index = -1
    for i, line in enumerate(lines):
        low = line.strip().lower()
        if low and any(k in low for k in _LEAD_INS):
            lead_index = i
            break
    if lead_index == -1:
        return text, []

    items, item_lines, skipped = _split_items(lines, lead_index + 1)
    if len(items) < 2:
        return text, []

    used = set()
    fields = []
    for raw in items:
        field = _guess_field(raw)
        if not field:
            continue
        field["name"] = _unique(field["name"], used)
        fields.append(field)
    if len(fields) < 2:
        return text, []

    title = _form_title(lines[lead_index].strip())

    remove = set(item_lines) | set(skipped)
    if _is_lead_line(lines[lead_index]) or title != "Additional details required":
        remove.add(lead_index)
    cleaned_lines = [line for i, line in enumerate(lines) if i not in remove]
    cleaned = re.sub(r"\n{3,}", "\n\n", "\n".join(cleaned_lines)).strip()

    form = {
        "type": "form",
        "id": "clarification",
        "title": title,
        "description": "",
        "submit_label": "Submit",
        "submit_message": "",
        "fields": fields,
    }
    return cleaned, [form]


def finalize(reply):
    """Return (visible_text, blocks) for an agent reply."""
    text, blocks = parse_interactive_blocks(reply)
    if blocks:
        return text, blocks
    return derive_blocks_from_questions(text)
