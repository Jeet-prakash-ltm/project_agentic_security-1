"""Cloud tenant registry service (table ``cloud_tenants``).

Administrators register the cloud tenants the platform assesses from
Settings > Asset Inventory > Cloud: tenant name, tenant id, cloud
provider name and primary domain.
"""

import threading
import time

from database.db import get_session
from database.repositories import CloudTenantsRepository

_lock = threading.Lock()

ALLOWED_STATUSES = ("active", "inactive")
ALLOWED_PROVIDERS = ("Azure", "AWS", "GCP")


def _public(entry):
    if not entry:
        return None
    return {
        "id": entry.id,
        "tenant_name": entry.tenant_name,
        "tenant_id": entry.tenant_id,
        "cloud_provider": entry.cloud_provider or "Azure",
        "primary_domain": entry.primary_domain,
        "status": entry.status or "active",
        "created": entry.created,
    }


def _repo():
    return CloudTenantsRepository(get_session())


def _normalize_provider(value):
    text = (value or "").strip()
    if not text:
        return "Azure"
    for allowed in ALLOWED_PROVIDERS:
        if text.lower() == allowed.lower():
            return allowed
    raise ValueError("Cloud provider must be Azure, AWS, or GCP.")


def _normalize_status(value):
    text = (value or "active").strip().lower()
    if text in ("live", "enabled", "on"):
        text = "active"
    if text in ("down", "disabled", "off"):
        text = "inactive"
    if text not in ALLOWED_STATUSES:
        raise ValueError("Status must be Active or Inactive.")
    return text


def list_tenants():
    """Return every registered cloud tenant."""
    with _lock:
        return [_public(entry) for entry in _repo().list_all()]


def add_tenant(tenant_name, tenant_id, cloud_provider=None, primary_domain=None, status=None):
    """Register a cloud tenant inventory entry (administrator action)."""
    tenant_name = (tenant_name or "").strip()
    tenant_id = (tenant_id or "").strip()
    primary_domain = (primary_domain or "").strip()
    provider = _normalize_provider(cloud_provider)
    status_value = _normalize_status(status)

    if not tenant_name:
        raise ValueError("Tenant name is required.")
    if len(tenant_name) > 255:
        raise ValueError("Tenant name must be 255 characters or fewer.")
    if not tenant_id:
        raise ValueError("Tenant ID is required.")
    if len(tenant_id) > 128:
        raise ValueError("Tenant ID must be 128 characters or fewer.")
    if not primary_domain:
        raise ValueError("Primary domain is required.")
    if "." not in primary_domain or " " in primary_domain:
        raise ValueError("Enter a valid primary domain.")

    with _lock:
        repo = _repo()
        if repo.by_tenant_name(tenant_name):
            raise ValueError("A tenant with this name already exists.")
        if repo.by_tenant_id(tenant_id):
            raise ValueError("A tenant with this ID already exists.")
        entry = repo.create(
            {
                "tenant_name": tenant_name,
                "tenant_id": tenant_id,
                "cloud_provider": provider,
                "primary_domain": primary_domain,
                "status": status_value,
                "created": time.time(),
            }
        )
    return _public(entry)


def remove_tenant(tenant_pk):
    """Remove a registered tenant by numeric id."""
    with _lock:
        deleted = _repo().delete_id(int(tenant_pk))
        if deleted is None:
            raise ValueError("Tenant not found in the inventory.")
    return deleted


def remove_by_tenant_name(tenant_name):
    """Remove a registered tenant by logical name (bulk import action)."""
    tenant_name = (tenant_name or "").strip()
    if not tenant_name:
        raise ValueError("Tenant name is required.")
    with _lock:
        repo = _repo()
        entry = repo.by_tenant_name(tenant_name)
        if entry is None:
            raise ValueError("Tenant not found in the inventory.")
        repo.session.delete(entry)
        repo.session.commit()
    return tenant_name
