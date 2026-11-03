"""Cloud tenants repository (table ``cloud_tenants``).

Holds the admin-registered cloud tenant inventory entered under
Settings > Asset Inventory > Cloud (tenant name, tenant id, cloud
provider, primary domain, status).
"""

from database.models import CloudTenant
from database.repositories.base import BaseRepository


class CloudTenantsRepository(BaseRepository):
    model = CloudTenant

    def list_all(self):
        return (
            self.session.query(CloudTenant)
            .order_by(CloudTenant.created.asc(), CloudTenant.id.asc())
            .all()
        )

    def by_tenant_name(self, tenant_name):
        return (
            self.session.query(CloudTenant)
            .filter(CloudTenant.tenant_name == tenant_name)
            .first()
        )

    def by_tenant_id(self, tenant_id):
        return (
            self.session.query(CloudTenant)
            .filter(CloudTenant.tenant_id == tenant_id)
            .first()
        )

    def create(self, data):
        entry = CloudTenant(
            tenant_name=(data.get("tenant_name") or "").strip(),
            tenant_id=(data.get("tenant_id") or "").strip(),
            cloud_provider=(data.get("cloud_provider") or "").strip() or "Azure",
            primary_domain=(data.get("primary_domain") or "").strip(),
            status=data.get("status") or "active",
            created=data.get("created"),
        )
        self.session.add(entry)
        self.session.commit()
        return entry

    def update(self, pk, **fields):
        entry = self.session.get(CloudTenant, pk)
        if entry is None:
            return None
        for key, value in fields.items():
            if hasattr(entry, key):
                setattr(entry, key, value)
        self.session.commit()
        return entry

    def delete_id(self, pk):
        entry = self.session.get(CloudTenant, pk)
        if entry is None:
            return None
        self.session.delete(entry)
        self.session.commit()
        return pk
