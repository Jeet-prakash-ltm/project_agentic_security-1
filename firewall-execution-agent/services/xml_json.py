from xml.etree import ElementTree as ET


class PanosXmlError(Exception):
    pass


def _snake(name):
    return str(name or "").replace("-", "_")


def _text(node):
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value or None


def _leaf(elem):
    text = _text(elem)
    attrs = dict(elem.attrib or {})
    if not attrs:
        return text
    payload = {_snake(key): value for key, value in attrs.items()}
    if text is not None:
        payload["value"] = text
    return payload


def _elem_to_value(elem):
    if elem is None:
        return None

    children = list(elem)
    if not children:
        return _leaf(elem)

    grouped = {}
    for child in children:
        value = _elem_to_value(child)
        tag = _snake(child.tag)
        if tag in grouped:
            existing = grouped[tag]
            if not isinstance(existing, list):
                grouped[tag] = [existing]
            grouped[tag].append(value)
        else:
            grouped[tag] = value

    if list(grouped.keys()) == ["member"]:
        members = grouped["member"]
        if not isinstance(members, list):
            members = [members]
        members = [item for item in members if item not in (None, "")]
        if elem.attrib:
            payload = {_snake(key): value for key, value in elem.attrib.items()}
            payload["members"] = members
            return payload
        return members

    payload = grouped
    text = _text(elem)
    if text is not None:
        payload["value"] = text
    for key, value in (elem.attrib or {}).items():
        payload[_snake(key)] = value
    return payload


def _message_from(root):
    msg = root.find(".//msg")
    if msg is None:
        msg = root.find(".//result")
    if msg is None:
        return "PAN-OS request failed"
    lines = []
    for line in msg.itertext():
        line = (line or "").strip()
        if line:
            lines.append(line)
    return " ".join(lines) if lines else "PAN-OS request failed"


def parse_panos_xml(xml_text):
    if xml_text is None:
        return {}
    if isinstance(xml_text, bytes):
        xml_text = xml_text.decode("utf-8", errors="ignore")
    xml_text = str(xml_text).strip()
    if not xml_text:
        return {}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise PanosXmlError("Firewall returned unparseable XML: {0}".format(exc))

    status = (root.attrib.get("status") or "success").lower()
    if status not in ("success", "ok"):
        raise PanosXmlError(_message_from(root))

    result = root.find("result")
    msg = root.find("msg")
    if result is not None:
        parsed = _elem_to_value(result)
    elif msg is not None:
        parsed = {"message": _message_from(root)}
    else:
        parsed = _elem_to_value(root) or {}

    if not isinstance(parsed, dict):
        parsed = {"result": parsed}

    code = root.attrib.get("code")
    if code and "code" not in parsed:
        parsed["code"] = code
    parsed.pop("xml", None)
    return parsed


def _first(parsed, *keys):
    if not isinstance(parsed, dict):
        return None
    for key in keys:
        value = parsed.get(key)
        if value not in (None, ""):
            return value
    return None


def flatten_system_info(parsed):
    system = parsed
    if isinstance(parsed, dict) and isinstance(parsed.get("system"), dict):
        system = parsed["system"]
    if not isinstance(system, dict):
        return parsed if isinstance(parsed, dict) else {}

    payload = {
        "hostname": _first(system, "hostname"),
        "model": _first(system, "model"),
        "panos_version": _first(system, "sw_version", "sw-version"),
        "uptime": _first(system, "uptime"),
        "management_ip": _first(system, "ip_address", "ip-address"),
    }
    serial = _first(system, "serial")
    if serial:
        payload["serial"] = serial
    family = _first(system, "family")
    if family:
        payload["family"] = family
    return payload


def is_system_info_cmd(cmd):
    text = str(cmd or "").lower()
    return "system" in text and "info" in text


def agent_payload(xml_text, extra=None, flatten_system=False):
    parsed = parse_panos_xml(xml_text)
    if flatten_system:
        parsed = flatten_system_info(parsed)
    if extra:
        merged = dict(extra)
        merged.update(parsed)
        parsed = merged
    parsed.pop("xml", None)
    return parsed
