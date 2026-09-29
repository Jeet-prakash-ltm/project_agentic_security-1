"""Bulk operations for PAN-OS network configuration:

* zones (interface membership, zone-protection / log settings)
* virtual routers (basic settings: interface membership, comment)
* static routes (IPv4/IPv6 unicast)
* interface management profiles (ping/telnet/ssh/https/http/snmp access)
* layer3 interfaces (IP addresses + management profile + MTU)

All functions honour the shared per-row contract used by the playbook engine.
"""

from workbook import common

ZONE_MODES = ("tap", "virtual-wire", "layer2", "layer3", "external")


def _profile_name(value):
    return common.to_text(value)


def apply_zones(client, row):
    """Create / update / delete a security zone."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    mode = common.to_text(row.get("Type") or "layer3").lower()
    interfaces = common.split_members(row.get("Interfaces"))
    zone_profile = _profile_name(row.get("Zone Protection Profile"))
    log_setting = _profile_name(row.get("Log Setting"))
    base = common.vsys_base()
    entry_xpath = base + '/zone/entry[@name="{0}"]'.format(name)

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "Zone", "name": name,
                       "detail": "Deleted zone {0}".format(name)})
        return result

    if mode not in ZONE_MODES:
        raise ValueError(
            "Zone {0} has unsupported Type {1!r}.".format(name, mode)
        )
    network_inner = common.member_list_xml(mode, interfaces)
    if zone_profile:
        network_inner += (
            "<zone-protection-profile>{0}</zone-protection-profile>".format(
                common.xml_escape(zone_profile)
            )
        )
    if log_setting:
        network_inner += "<log-setting>{0}</log-setting>".format(
            common.xml_escape(log_setting)
        )
    inner = "<network>{0}</network>".format(network_inner)
    if mode in ("layer2", "layer3") and common.to_text(row.get("Enable User Identification")) not in ("", "no", "No"):
        inner += "<enable-user-identification>yes</enable-user-identification>"
    element = common.entry_xml(name, inner)

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "Zone", "name": name,
                       "detail": "Updated zone {0}".format(name)})
        return result
    result = client.set(base + "/zone", element)
    result.update({"op": "create", "kind": "Zone", "name": name,
                   "detail": "Created zone {0}".format(name)})
    return result


def apply_virtual_routers(client, row):
    """Create / update / delete a virtual router (device level)."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    interfaces = common.split_members(row.get("Interfaces"))
    base = common.network_base()
    entry_xpath = base + '/virtual-router/entry[@name="{0}"]'.format(name)

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "Virtual Router", "name": name,
                       "detail": "Deleted virtual router {0}".format(name)})
        return result

    inner = ""
    if interfaces:
        inner += common.member_list_xml("interface", interfaces)
    element = common.entry_xml(name, inner)

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "Virtual Router", "name": name,
                       "detail": "Updated virtual router {0}".format(name)})
        return result
    result = client.set(base + "/virtual-router", element)
    result.update({"op": "create", "kind": "Virtual Router", "name": name,
                   "detail": "Created virtual router {0}".format(name)})
    return result


def apply_static_routes(client, row):
    """Create / update / delete a static route on a virtual router."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    vr = common.to_text(row.get("Virtual Router"))
    common.ensure(["Virtual Router"], row)
    destination = common.to_text(row.get("Destination"))
    next_hop_type = common.to_text(row.get("Next Hop Type") or "ip-address").lower()
    next_hop = common.to_text(row.get("Next Hop"))
    interface = common.to_text(row.get("Interface"))
    metric = common.to_text(row.get("Metric"))
    admin_distance = common.to_text(row.get("Admin Distance"))
    version = common.to_text(row.get("Version") or "ipv4").lower()
    comment = common.to_text(row.get("Description"))

    if action == "delete":
        pass
    else:
        if not destination:
            raise ValueError("Static route {0} requires a Destination.".format(name))

    family = "ipv6" if version in ("ipv6", "v6") else "ip"
    entry_xpath = (
        common.network_base()
        + '/virtual-router/entry[@name="{0}"]/routing-table/{1}/static-route/entry[@name="{2}"]'.format(
            common.xml_escape(vr), family, common.xml_escape(name)
        )
    )

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "Static Route", "name": name,
                       "detail": "Deleted static route {0} on {1}".format(name, vr)})
        return result

    inner = "<destination>{0}</destination>".format(common.xml_escape(destination))
    if next_hop_type == "discard":
        inner += "<nexthop><discard/></nexthop>"
    elif next_hop_type in ("ip-address", "next-vr", "fqdn"):
        if not next_hop:
            raise ValueError(
                "Static route {0} requires a Next Hop value.".format(name)
            )
        inner += "<nexthop><{0}>{1}</{0}></nexthop>".format(
            common.xml_escape(next_hop_type), common.xml_escape(next_hop)
        )
    else:
        raise ValueError(
            "Static route {0} has unsupported Next Hop Type {1!r}.".format(
                name, next_hop_type
            )
        )
    if interface:
        inner += "<interface>{0}</interface>".format(common.xml_escape(interface))
    if metric:
        inner += "<metric>{0}</metric>".format(common.xml_escape(metric))
    if admin_distance:
        inner += "<admin-distance>{0}</admin-distance>".format(
            common.xml_escape(admin_distance)
        )
    if comment:
        inner += "<description>{0}</description>".format(common.xml_escape(comment))
    element = common.entry_xml(name, inner)

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "Static Route", "name": name,
                       "detail": "Updated static route {0} on {1}".format(name, vr)})
        return result
    result = client.set(
        common.network_base()
        + '/virtual-router/entry[@name="{0}"]/routing-table/{1}/static-route'.format(
            common.xml_escape(vr), family
        ),
        element,
    )
    result.update({"op": "create", "kind": "Static Route", "name": name,
                   "detail": "Created static route {0} on {1}".format(name, vr)})
    return result


_MGMT_ACCESS = ("ping", "telnet", "ssh", "https", "http", "snmp", "response-pages")


def apply_interface_management_profiles(client, row):
    """Create / update / delete an interface management profile."""
    name = common.to_text(row.get("Name"))
    common.ensure(["Name"], row)
    action = common.normalize_action(row.get("Action"))
    base = common.network_base() + "/profiles/interface-management-profile"
    entry_xpath = base + '/entry[@name="{0}"]'.format(name)

    if action == "delete":
        result = client.delete(entry_xpath)
        result.update({"op": "delete", "kind": "Interface Mgmt Profile", "name": name,
                       "detail": "Deleted interface management profile {0}".format(name)})
        return result

    inner = []
    for access in _MGMT_ACCESS:
        header = " ".join(part.title() for part in access.split("-"))
        cell = common.to_text(row.get(header))
        enabled = cell.lower() in ("1", "yes", "true", "on", "y", "enable")
        if cell.lower() in ("no", "0", "false", "off", "n", "disable"):
            enabled = False
        inner.append("<{0}>{1}</{0}>".format(common.xml_escape(access), "yes" if enabled else "no"))
    element = common.entry_xml(name, "".join(inner))

    if action == "update":
        result = client.edit(entry_xpath, element)
        result.update({"op": "update", "kind": "Interface Mgmt Profile", "name": name,
                       "detail": "Updated interface management profile {0}".format(name)})
        return result
    result = client.set(base, element)
    result.update({"op": "create", "kind": "Interface Mgmt Profile", "name": name,
                   "detail": "Created interface management profile {0}".format(name)})
    return result


# PAN-OS stores layer3 interface IPs directly under the ethernet entry's
# <layer3><ip> container on this platform. Sub-interface <units> are only
# needed for tagged/VLAN interfaces which are out of scope for this playbook.
INTERFACE_STYLE_DIRECT = "direct"


def _interface_entry_xpath(interface):
    return (
        common.network_base()
        + '/interface/ethernet/entry[@name="{0}"]'.format(common.xml_escape(interface))
    )


def apply_interfaces(client, row):
    """Apply IP addresses + management profile + MTU to a layer3 interface.

    PAN-OS stores these directly under the ethernet entry's ``layer3``
    container (``<layer3><ip><entry name="10.0.0.1/24"/>...</ip>``) and rejects
    full-container edits, so each managed child is merged with ``action=set``
    (removing the previous value first) to keep behaviour idempotent.
    """
    interface = common.to_text(row.get("Interface"))
    common.ensure(["Interface"], row)
    action = common.normalize_action(row.get("Action"))
    ips = common.split_members(row.get("IP Addresses") or row.get("IP"))
    mgmt_profile = _profile_name(row.get("Management Profile"))
    mtu = common.to_text(row.get("MTU"))
    comment = common.to_text(row.get("Description"))

    layer3_xpath = _interface_entry_xpath(interface) + "/layer3"

    for ip in ips:
        if "/" not in ip:
            raise ValueError(
                "Interface {0} IP {1!r} must include a prefix (e.g. 10.0.0.1/24).".format(
                    interface, ip
                )
            )

    def _drop(child_xpath):
        try:
            client.delete(layer3_xpath + "/" + child_xpath)
        except Exception:
            pass

    if action == "delete":
        # Remove the configurable children; the physical interface stays.
        for child in ("ip", "interface-management-profile", "mtu", "comment"):
            _drop(child)
        result = {"dry_run": client.dry_run, "action": "delete"}
        result.update({"op": "delete", "kind": "Interface", "name": interface,
                       "detail": "Removed layer3 configuration from {0}".format(interface)})
        return result

    # create + update converge to the desired end state.
    if ips:
        _drop("ip")
        ip_entries = "".join(
            '<entry name="{0}"/>'.format(common.xml_escape(ip)) for ip in ips
        )
        result = client.set(layer3_xpath, "<ip>{0}</ip>".format(ip_entries))
    else:
        result = None
    if mgmt_profile:
        client.set(
            layer3_xpath,
            "<interface-management-profile>{0}</interface-management-profile>".format(
                common.xml_escape(mgmt_profile)
            ),
        )
    else:
        _drop("interface-management-profile")
    if mtu:
        client.set(layer3_xpath, "<mtu>{0}</mtu>".format(common.xml_escape(mtu)))
    else:
        _drop("mtu")
    entry_xpath = _interface_entry_xpath(interface)
    if comment:
        client.set(entry_xpath, "<comment>{0}</comment>".format(common.xml_escape(comment)))
    else:
        try:
            client.delete(entry_xpath + "/comment")
        except Exception:
            pass

    base = result or {"dry_run": client.dry_run, "action": "set"}
    base.update({"op": action, "kind": "Interface", "name": interface,
                 "detail": "Configured layer3 interface {0}".format(interface)})
    return base


REGISTRY = {
    "zones": {"apply": apply_zones, "kind": "Zones"},
    "virtual_routers": {"apply": apply_virtual_routers, "kind": "Virtual Routers"},
    "static_routes": {"apply": apply_static_routes, "kind": "Static Routes"},
    "interface_mgmt_profiles": {
        "apply": apply_interface_management_profiles,
        "kind": "Interface Management Profiles",
    },
    "interfaces": {"apply": apply_interfaces, "kind": "Interfaces"},
}
