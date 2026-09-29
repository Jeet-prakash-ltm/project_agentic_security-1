"""Bulk operations for PAN-OS security policies and NAT policies."""

from workbook import common

RULE_ACTIONS = ("allow", "deny", "drop", "reset-client", "reset-server", "reset-both")


def _rulebase():
    return common.vsys_base() + "/rulebase"


def apply_security_rules(client, row):
    """Create / update / delete a security rule."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    entry_xpath = _rulebase() + '/security/rules/entry[@name="{0}"]'.format(name)

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "Security Rule", "name": name,
                       "detail": "Deleted security rule {0}".format(name)})
        return result

    rule_action = common.to_text(row.get("Rule Action") or "allow").lower()
    if rule_action not in RULE_ACTIONS:
        raise ValueError(
            "Security rule {0} has unsupported Rule Action {1!r}.".format(
                name, rule_action
            )
        )
    from_zones = common.split_members(row.get("From")) or ["any"]
    to_zones = common.split_members(row.get("To")) or ["any"]
    sources = common.split_members(row.get("Source")) or ["any"]
    destinations = common.split_members(row.get("Destination")) or ["any"]
    users = common.split_members(row.get("Users") or row.get("Source Users")) or ["any"]
    applications = common.split_members(row.get("Applications")) or ["any"]
    services = common.split_members(row.get("Services")) or ["application-default"]
    categories = common.split_members(row.get("Categories")) or ["any"]
    description = common.to_text(row.get("Description"))
    log_setting = common.to_text(row.get("Log Setting"))
    disabled = common.to_text(row.get("Disabled")).lower() in ("1", "yes", "true", "on")

    inner = (
        common.member_list_xml("from", from_zones)
        + common.member_list_xml("to", to_zones)
        + common.member_list_xml("source", sources)
        + common.member_list_xml("destination", destinations)
        + common.member_list_xml("source-user", users)
        + common.member_list_xml("category", categories)
        + common.member_list_xml("application", applications)
        + common.member_list_xml("service", services)
    )
    if description:
        inner += "<description>{0}</description>".format(common.xml_escape(description))
    if log_setting:
        inner += "<log-setting>{0}</log-setting>".format(common.xml_escape(log_setting))
    inner += "<action>{0}</action>".format(common.xml_escape(rule_action))
    inner += "<disabled>{0}</disabled>".format("yes" if disabled else "no")
    element = common.entry_xml(name, inner)

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "Security Rule", "name": name,
                       "detail": "Updated security rule {0}".format(name)})
        return result
    result = client.set(_rulebase() + "/security/rules", element)
    result.update({"op": "create", "kind": "Security Rule", "name": name,
                   "detail": "Created security rule {0}".format(name)})
    return result


def _source_translation_xml(row, name):
    nat_type = common.to_text(row.get("NAT Type")).lower()
    if nat_type in ("no", "none"):
        return ""
    stype = common.to_text(row.get("Source Translation") or "dynamic-ip-and-port").lower()
    if stype not in ("dynamic-ip-and-port", "dynamic-ip", "static-ip"):
        raise ValueError(
            "NAT rule {0} has unsupported Source Translation {1!r}.".format(name, stype)
        )
    interface = common.to_text(row.get("Translated Interface"))
    pool = common.to_text(row.get("Source Translated Address"))
    if interface:
        st_inner = (
            "<interface-address><interface>{0}</interface></interface-address>".format(
                common.xml_escape(interface)
            )
        )
    elif pool:
        if stype == "static-ip":
            st_inner = (
                "<translated-address><entry name=\"{0}\"/></translated-address>".format(
                    common.xml_escape(pool)
                )
            )
        else:
            st_inner = (
                "<translated-address><member>{0}</member></translated-address>".format(
                    common.xml_escape(pool)
                )
            )
    else:
        raise ValueError(
            "NAT rule {0} requires a Translated Interface or Source Translated "
            "Address.".format(name)
        )
    return "<source-translation><{0}>{1}</{0}></source-translation>".format(
        common.xml_escape(stype), st_inner
    )


def _destination_translation_xml(row, name):
    nat_type = common.to_text(row.get("NAT Type")).lower()
    if nat_type in ("source", "no", "none"):
        return ""
    address = common.to_text(row.get("Destination Translated Address"))
    port = common.to_text(row.get("Destination Translated Port"))
    if not address and not port:
        raise ValueError(
            "NAT rule {0} has NAT Type {1} but no destination translation "
            "columns.".format(name, nat_type)
        )
    inner = ""
    if address:
        inner += "<translated-address>{0}</translated-address>".format(
            common.xml_escape(address)
        )
    if port:
        inner += "<translated-port>{0}</translated-port>".format(
            common.xml_escape(port)
        )
    return "<destination-translation>{0}</destination-translation>".format(inner)


def apply_nat_rules(client, row):
    """Create / update / delete a NAT rule."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    entry_xpath = _rulebase() + '/nat/rules/entry[@name="{0}"]'.format(name)

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "NAT Rule", "name": name,
                       "detail": "Deleted NAT rule {0}".format(name)})
        return result

    from_zones = common.split_members(row.get("From")) or ["any"]
    to_zones = common.split_members(row.get("To")) or ["any"]
    sources = common.split_members(row.get("Source")) or ["any"]
    destinations = common.split_members(row.get("Destination")) or ["any"]
    # NAT rule service is a single scalar (``any`` or one service object name).
    service = common.to_text(row.get("Service") or "any")
    description = common.to_text(row.get("Description"))
    nat_type = common.to_text(row.get("NAT Type") or "source").lower()
    disabled = common.to_text(row.get("Disabled")).lower() in ("1", "yes", "true", "on")

    inner = (
        common.member_list_xml("from", from_zones)
        + common.member_list_xml("source", sources)
        + common.member_list_xml("destination", destinations)
        + common.member_list_xml("to", to_zones)
    )
    if service:
        inner += "<service>{0}</service>".format(common.xml_escape(service))
    if description:
        inner += "<description>{0}</description>".format(common.xml_escape(description))
    if nat_type in ("source",):
        inner += _source_translation_xml(row, name)
    elif nat_type in ("destination",):
        inner += _destination_translation_xml(row, name)
    inner += "<disabled>{0}</disabled>".format("yes" if disabled else "no")
    element = common.entry_xml(name, inner)

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "NAT Rule", "name": name,
                       "detail": "Updated NAT rule {0}".format(name)})
        return result
    result = client.set(_rulebase() + "/nat/rules", element)
    result.update({"op": "create", "kind": "NAT Rule", "name": name,
                   "detail": "Created NAT rule {0}".format(name)})
    return result


REGISTRY = {
    "security_rules": {"apply": apply_security_rules, "kind": "Security Rules"},
    "nat_rules": {"apply": apply_nat_rules, "kind": "NAT Rules"},
}
