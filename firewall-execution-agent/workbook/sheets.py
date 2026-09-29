from workbook import network
from workbook import objects
from workbook import policies


def _key(name):
    return str(name or "").strip().lower().replace(" ", "").replace("_", "").replace("-", "")


HANDLERS = {
    "addresses": ("Addresses", objects.apply_addresses),
    "addressgroups": ("Address Groups", objects.apply_address_groups),
    "services": ("Services", objects.apply_services),
    "servicegroups": ("Service Groups", objects.apply_service_groups),
    "zones": ("Zones", network.apply_zones),
    "virtualrouters": ("Virtual Routers", network.apply_virtual_routers),
    "staticroutes": ("Static Routes", network.apply_static_routes),
    "interfacemanagementprofiles": ("Interface Management Profiles", network.apply_interface_management_profiles),
    "interfaces": ("Interfaces", network.apply_interfaces),
    "securityrules": ("Security Rules", policies.apply_security_rules),
    "natrules": ("NAT Rules", policies.apply_nat_rules),
}


def find_handler(sheet_title):
    return HANDLERS.get(_key(sheet_title))
