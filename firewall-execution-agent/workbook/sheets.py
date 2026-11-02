"""Configuration category registry (playbook-free).

Each category maps a canonical category key to the human label and the apply
handler that executes a single normalised row against the firewall. The category
key vocabulary is defined in :mod:`workbook.fields` and is shared by the
structured single-change API, the workbook auto-detection and the runner.
"""

from workbook import network
from workbook import objects
from workbook import policies
from workbook import fields


HANDLERS = {
    "address": ("Address", objects.apply_addresses),
    "address_group": ("Address Group", objects.apply_address_groups),
    "service": ("Service", objects.apply_services),
    "service_group": ("Service Group", objects.apply_service_groups),
    "zone": ("Zone", network.apply_zones),
    "virtual_router": ("Virtual Router", network.apply_virtual_routers),
    "static_route": ("Static Route", network.apply_static_routes),
    "interface": ("Interface", network.apply_interfaces),
    "interface_mgmt_profile": (
        "Interface Management Profile",
        network.apply_interface_management_profiles,
    ),
    "security_rule": ("Security Rule", policies.apply_security_rules),
    "nat_rule": ("NAT Rule", policies.apply_nat_rules),
}


def find_handler(category):
    """Return ``(kind, apply)`` for a canonical category key, or ``None``."""
    if not category:
        return None
    key = fields.norm(category)
    if key in HANDLERS:
        return HANDLERS[key]
    for candidate in fields.CATEGORY_KEYS:
        if fields.norm(candidate) == key:
            return HANDLERS.get(candidate)
    return None


def categories():
    """Catalogue payload for the agent/UI: key, label, required headers."""
    result = []
    for key in fields.CATEGORY_KEYS:
        handler = HANDLERS.get(key)
        spec = fields.SPEC.get(key) or {}
        result.append(
            {
                "category": key,
                "kind": handler[0] if handler else fields.kind_of(key),
                "required": list(spec.get("required") or []),
                "headers": fields.headers_of(key),
            }
        )
    return result
