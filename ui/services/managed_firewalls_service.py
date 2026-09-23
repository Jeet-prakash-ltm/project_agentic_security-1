"""Managed firewall registry service (table ``managed_firewalls``).

Administrators register the firewalls the platform manages from
Settings > Firewall Inventory: device name (the firewall's logical name),
host name, host IP and host key. Host keys are stored so agents can connect
and are always masked in API responses.

Live/down status is determined by a short TCP reachability probe of each
registered host IP (management HTTPS 443, then SSH 22). Results are cached in
memory for a short TTL and persisted on the row (``status``/``last_checked``)
so every state is also stored in the database.
"""

import concurrent.futures
import ipaddress
import socket
import threading
import time

from database.db import get_session
from database.repositories import ManagedFirewallsRepository

_lock = threading.Lock()

# Seconds before the stored probe result is considered stale and re-probed.
PROBE_TTL = 60

# Fallback hosts seeded on bootstrap so existing platform firewalls appear in
# the inventory automatically (host key is empty until one is registered).
DEFAULT_FIREWALLS = [
    {
        "device_name": "vmpafw01",
        "host_name": "20.44.53.215",
        "host_ip": "20.44.53.215",
        "host_key": "",
    }
]

# In-memory probe cache: host_ip -> (checked_at, live).
_probe_cache = {}


def _mask_key(value):
    if not value:
        return None
    return "••••••••" + (value[-4:] if len(value) > 4 else "")


def _public(entry):
    if not entry:
        return None
    return {
        "id": entry.id,
        "device_name": entry.device_name,
        "device_type": entry.device_type or "Firewall",
        "host_name": entry.host_name,
        "host_ip": entry.host_ip,
        "host_key": _mask_key(entry.host_key),
        "has_host_key": bool(entry.host_key),
        "vendor": entry.vendor,
        "port": entry.port,
        "username": entry.username,
        "clone_of": entry.clone_of,
        "status": entry.status or "down",
        "last_checked": entry.last_checked,
        "created": entry.created,
    }


def _repo():
    return ManagedFirewallsRepository(get_session())


# --------------------------------------------------
# Reachability probe
# --------------------------------------------------

def _port_open(host_ip, port, timeout):
    try:
        with socket.create_connection((host_ip, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_host(host_ip):
    host_ip = (host_ip or "").strip()
    if not host_ip:
        return False
    cached = _probe_cache.get(host_ip)
    if cached and time.time() - cached[0] < PROBE_TTL:
        return cached[1]
    live = _port_open(host_ip, 443, 1.5) or _port_open(host_ip, 22, 1.5)
    _probe_cache[host_ip] = (time.time(), live)
    return live


def _probe_many(host_ips):
    """Probe unique host IPs concurrently and return ``{ip: live}``."""
    unique = list(dict.fromkeys(host_ips or []))
    if not unique:
        return {}
    results = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(8, len(unique))
    ) as pool:
        for ip, live in zip(unique, pool.map(_probe_host, unique)):
            results[ip] = live
    return results


def probe_host(host_ip, force=False):
    """Return True when ``host_ip`` answers on a management port.

    When ``force`` is True the short in-memory probe cache is bypassed so a
    caller that just wants a fresh read (e.g. before running a live
    assessment) is not served a stale result.
    """
    host_ip = (host_ip or "").strip()
    if force:
        _probe_cache.pop(host_ip, None)
    return _probe_host(host_ip)


def resolve_device_host(firewall_id):
    """Return the management host IP for a firewall logical name.

    Prefers an exact match in the inventory registry. Mirrors such as
    ``vmpafw02`` that share the real system fall back to the registered
    default (``vmpafw01``) host. Returns ``None`` when no host is known.
    """
    firewall_id = (firewall_id or "").strip()
    if not firewall_id:
        return None
    repo = _repo()
    for candidate in (firewall_id, "vmpafw01"):
        if not candidate:
            continue
        entry = repo.by_device_name(candidate)
        if entry and (entry.host_ip or "").strip():
            return entry.host_ip.strip()
    return None


def _needs_probe(entry, now):
    if not (entry.host_ip or "").strip():
        return False
    if entry.last_checked is None:
        return True
    return now - entry.last_checked >= PROBE_TTL


# --------------------------------------------------
# List / create / clone / remove
# --------------------------------------------------

def list_firewalls():
    """Return every registered firewall, probing stale statuses first."""
    repo = _repo()
    entries = repo.list_all()
    now = time.time()
    stale = [entry for entry in entries if _needs_probe(entry, now)]
    if stale:
        live_by_ip = _probe_many([entry.host_ip for entry in stale])
        for entry in stale:
            entry.status = "live" if live_by_ip.get(entry.host_ip) else "down"
            entry.last_checked = now
        repo.session.commit()
    return [_public(entry) for entry in entries]


def get_by_device_name(device_name):
    """Return one registered firewall by logical device name, or ``None``."""
    device_name = (device_name or "").strip()
    if not device_name:
        return None
    return _public(_repo().by_device_name(device_name))



def _persist_probe(entry):
    live = _probe_host(entry.host_ip)
    entry.status = "live" if live else "down"
    entry.last_checked = time.time()
    return entry


def add_firewall(device_name, host_name, host_ip, host_key):
    """Register a firewall inventory entry (administrator action)."""
    device_name = (device_name or "").strip()
    host_name = (host_name or "").strip()
    host_ip = (host_ip or "").strip()
    host_key = (host_key or "").strip()

    if not device_name or not host_name or not host_ip or not host_key:
        raise ValueError(
            "Device name, host name, host IP, and host key are required."
        )
    try:
        ipaddress.ip_address(host_ip)
    except ValueError:
        raise ValueError("Enter a valid host IP address.")

    with _lock:
        repo = _repo()
        if repo.by_device_name(device_name):
            raise ValueError(
                "A firewall with this device name already exists."
            )
        entry = repo.create(
            {
                "device_name": device_name,
                "host_name": host_name,
                "host_ip": host_ip,
                "host_key": host_key,
                "status": "down",
                "last_checked": None,
                "created": time.time(),
            }
        )
        _persist_probe(entry)
        repo.session.commit()

    return _public(entry)


def import_firewall(device_name, host_ip, vendor=None, port=None, username=None, password=None, device_type=None):
    """Register a firewall from a bulk inventory import.

    Unlike :func:`add_firewall` the credential fields are optional - the
    Firewall Inventory template only guarantees a device name and IP address.
    The management host name falls back to the IP address and the password is
    stored as the (masked) host key.
    """
    device_name = (device_name or "").strip()
    host_ip = (host_ip or "").strip()
    vendor = (vendor or "").strip()
    username = (username or "").strip()
    password = (password or "").strip()
    device_type = (device_type or "").strip() or "Firewall"

    if not device_name:
        raise ValueError("Firewall name is required.")
    if len(device_name) > 64:
        raise ValueError("Firewall name must be 64 characters or fewer.")
    if not host_ip:
        raise ValueError("IP address is required.")
    try:
        ipaddress.ip_address(host_ip)
    except ValueError:
        raise ValueError("Enter a valid IP address.")

    port_value = None
    if port not in (None, ""):
        try:
            port_value = int(port)
        except (TypeError, ValueError):
            raise ValueError("Port must be a number.")
        if not 1 <= port_value <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

    with _lock:
        repo = _repo()
        if repo.by_device_name(device_name):
            raise ValueError("A firewall with this name already exists.")
        entry = repo.create(
            {
                "device_name": device_name,
                "device_type": device_type,
                "host_name": host_ip,
                "host_ip": host_ip,
                "host_key": password,
                "vendor": vendor,
                "port": port_value,
                "username": username,
                "status": "down",
                "last_checked": None,
                "created": time.time(),
            }
        )
        _persist_probe(entry)
        repo.session.commit()

    return _public(entry)


def remove_by_device_name(device_name):
    """Remove a registered firewall by logical name (bulk import action)."""
    device_name = (device_name or "").strip()
    if not device_name:
        raise ValueError("Firewall name is required.")
    with _lock:
        repo = _repo()
        entry = repo.by_device_name(device_name)
        if entry is None:
            raise ValueError("Firewall not found in the inventory.")
        repo.delete_id(entry.id)
    return device_name


def clone_firewall(source_id, clone_device_name):
    """Clone a registered firewall under a new device name.

    The clone copies the source host name/IP/key and is recorded as a clone
    of the source device (``clone_of``) so the original appears alongside it.
    """
    clone_device_name = (clone_device_name or "").strip()
    if not clone_device_name:
        raise ValueError("A name is required for the clone.")
    if len(clone_device_name) > 64:
        raise ValueError("Device name must be 64 characters or fewer.")

    with _lock:
        repo = _repo()
        source = repo.get(source_id)
        if source is None:
            raise ValueError("Firewall inventory entry not found.")
        if source.clone_of:
            raise ValueError(
                "A cloned firewall cannot be cloned. Clone an original "
                "firewall only."
            )
        if repo.by_device_name(clone_device_name):
            raise ValueError(
                "A firewall with this device name already exists."
            )
        entry = repo.create(
            {
                "device_name": clone_device_name,
                "device_type": source.device_type or "Firewall",
                "host_name": source.host_name,
                "host_ip": source.host_ip,
                "host_key": source.host_key or "",
                "vendor": source.vendor,
                "port": source.port,
                "username": source.username,
                "clone_of": source.device_name,
                "status": "down",
                "last_checked": None,
                "created": time.time(),
            }
        )
        _persist_probe(entry)
        repo.session.commit()

    return _public(entry)


def remove_firewall(firewall_id):
    """Remove a firewall inventory entry (administrator action)."""
    with _lock:
        deleted = _repo().delete_id(firewall_id)
    if deleted is None:
        raise ValueError("Firewall inventory entry not found.")
    return deleted


def ensure_defaults():
    """Seed the default platform firewalls when they are not registered yet.

    Called from startup bootstrap; idempotent.
    """
    repo = _repo()
    seeded = 0
    for spec in DEFAULT_FIREWALLS:
        if repo.by_device_name(spec["device_name"]):
            continue
        entry = repo.create(
            {
                "device_name": spec["device_name"],
                "host_name": spec["host_name"],
                "host_ip": spec["host_ip"],
                "host_key": spec["host_key"],
                "status": "down",
                "last_checked": None,
                "created": time.time(),
            }
        )
        _persist_probe(entry)
        repo.session.commit()
        seeded += 1
    return seeded
