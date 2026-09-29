"""Bulk operations for shared address / address-group / service / service-group
objects on PAN-OS (create, update and delete per workbook row).

Each public ``apply_*`` function follows the same contract::

    result = apply_addresses(client, row)

where ``row`` is a dict of spreadsheet cells keyed by column header and
``result`` describes what happened for that row::

    {"op": "create"|"update"|"delete", "kind": str, "name": str,
     "dry_run": bool, "detail": str}
"""

from workbook import common


def _addr_type_value(row):
    kind = common.to_text(row.get("Address Type")).lower()
    value = common.to_text(row.get("Address Value") or row.get("Value"))
    if kind in ("ip-netmask", "ipnetmask", "netmask", "ip"):
        kind = "ip-netmask"
    elif kind in ("ip-range", "range"):
        kind = "ip-range"
    elif kind in ("fqdn", "dns", "hostname"):
        kind = "fqdn"
    elif not kind:
        if not value:
            raise ValueError("Address requires an Address Value or Address Type.")
        if "/" in value or ":" in value and "/" in value:
            kind = "ip-netmask"
        elif "-" in value:
            kind = "ip-range"
        else:
            kind = "fqdn"
    if kind not in ("ip-netmask", "ip-range", "fqdn"):
        raise ValueError("Unsupported Address Type {0!r}.".format(kind))
    if not value:
        raise ValueError("Address Type {0} requires an Address Value.".format(kind))
    return kind, value


def _common_columns(row):
    tags = common.split_members(row.get("Tags") or row.get("Tag"))
    description = common.to_text(row.get("Description"))
    return tags, description


def apply_addresses(client, row):
    """Create / update / delete an address object entry."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    base = common.vsys_base()
    entry_xpath = base + '/address/entry[@name="{0}"]'.format(name)

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "Address", "name": name,
                       "detail": "Deleted address {0}".format(name)})
        return result

    kind, value = _addr_type_value(row)
    tags, description = _common_columns(row)

    inner = "<{0}>{1}</{0}>".format(kind, common.xml_escape(value))
    if tags:
        inner += common.member_list_xml("tag", tags)
    if description:
        inner += "<description>{0}</description>".format(common.xml_escape(description))
    element = common.entry_xml(name, inner)

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "Address", "name": name,
                       "detail": "Updated address {0}".format(name)})
        return result
    result = client.set(base + "/address", element)
    result.update({"op": "create", "kind": "Address", "name": name,
                   "detail": "Created address {0}".format(name)})
    return result


def apply_address_groups(client, row):
    """Create / update / delete a static address group."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    members = common.split_members(row.get("Members"))
    tags, description = _common_columns(row)
    base = common.vsys_base()
    entry_xpath = base + '/address-group/entry[@name="{0}"]'.format(name)

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "Address Group", "name": name,
                       "detail": "Deleted address group {0}".format(name)})
        return result

    group_type = common.to_text(row.get("Group Type")).lower()
    if group_type and group_type not in ("static",):
        raise ValueError(
            "Only static address groups are supported (Group Type {0!r}).".format(
                group_type
            )
        )
    if not members:
        raise ValueError("Address group {0} has no Members.".format(name))

    inner = common.member_list_xml("static", members)
    if tags:
        inner += common.member_list_xml("tag", tags)
    if description:
        inner += "<description>{0}</description>".format(common.xml_escape(description))
    element = common.entry_xml(name, inner)

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "Address Group", "name": name,
                       "detail": "Updated address group {0}".format(name)})
        return result
    result = client.set(base + "/address-group", element)
    result.update({"op": "create", "kind": "Address Group", "name": name,
                   "detail": "Created address group {0}".format(name)})
    return result


def apply_services(client, row):
    """Create / update / delete a service object (tcp/udp/sctp)."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    protocol = common.to_text(row.get("Protocol")).lower()
    port = common.to_text(row.get("Port"))
    source_port = common.to_text(row.get("Source Port"))
    tags, description = _common_columns(row)
    base = common.vsys_base()
    entry_xpath = base + '/service/entry[@name="{0}"]'.format(name)

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "Service", "name": name,
                       "detail": "Deleted service {0}".format(name)})
        return result

    if protocol not in ("tcp", "udp", "sctp"):
        raise ValueError(
            "Service {0} requires Protocol tcp, udp or sctp (got {1!r}).".format(
                name, protocol
            )
        )
    if not port:
        raise ValueError("Service {0} requires a Port.".format(name))
    inner = "<protocol><{0}><port>{1}</port>".format(
        common.xml_escape(protocol), common.xml_escape(port)
    )
    if source_port:
        inner += "<source-port>{0}</source-port>".format(common.xml_escape(source_port))
    inner += "</{0}></protocol>".format(common.xml_escape(protocol))
    if tags:
        inner += common.member_list_xml("tag", tags)
    if description:
        inner += "<description>{0}</description>".format(common.xml_escape(description))
    element = common.entry_xml(name, inner)

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "Service", "name": name,
                       "detail": "Updated service {0}".format(name)})
        return result
    result = client.set(base + "/service", element)
    result.update({"op": "create", "kind": "Service", "name": name,
                   "detail": "Created service {0}".format(name)})
    return result


def apply_service_groups(client, row):
    """Create / update / delete a service group (static members)."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    members = common.split_members(row.get("Members"))
    tags, description = _common_columns(row)
    base = common.vsys_base()
    entry_xpath = base + '/service-group/entry[@name="{0}"]'.format(name)

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "Service Group", "name": name,
                       "detail": "Deleted service group {0}".format(name)})
        return result

    if not members:
        raise ValueError("Service group {0} has no Members.".format(name))
    inner = common.member_list_xml("members", members)
    if tags:
        inner += common.member_list_xml("tag", tags)
    if description:
        inner += "<description>{0}</description>".format(common.xml_escape(description))
    element = common.entry_xml(name, inner)

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "Service Group", "name": name,
                       "detail": "Updated service group {0}".format(name)})
        return result
    result = client.set(base + "/service-group", element)
    result.update({"op": "create", "kind": "Service Group", "name": name,
                   "detail": "Created service group {0}".format(name)})
    return result


REGISTRY = {
    "addresses": {"apply": apply_addresses, "kind": "Address Objects"},
    "address_groups": {"apply": apply_address_groups, "kind": "Address Groups"},
    "services": {"apply": apply_services, "kind": "Service Objects"},
    "service_groups": {"apply": apply_service_groups, "kind": "Service Groups"},
}
