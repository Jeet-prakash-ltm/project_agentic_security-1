"""Managed firewalls repository (table ``managed_firewalls``).

Holds the admin-registered firewall inventory entered under
Settings > Firewall Inventory (device name, host name, host IP, host key),
including clones (``clone_of``) and the last live/down probe result
(``status``/``last_checked``).
"""

from database.models import ManagedFirewall
from database.repositories.base import BaseRepository


class ManagedFirewallsRepository(BaseRepository):
    model = ManagedFirewall

    def list_all(self):
        return (
            self.session.query(ManagedFirewall)
            .order_by(ManagedFirewall.created.asc(), ManagedFirewall.id.asc())
            .all()
        )

    def by_device_name(self, device_name):
        return (
            self.session.query(ManagedFirewall)
            .filter(ManagedFirewall.device_name == device_name)
            .first()
        )

    def create(self, data):
        entry = ManagedFirewall(
            device_name=(data.get("device_name") or "").strip(),
            host_name=(data.get("host_name") or "").strip(),
            host_ip=(data.get("host_ip") or "").strip(),
            host_key=(data.get("host_key") or "").strip(),
            vendor=(data.get("vendor") or "").strip() or None,
            port=data.get("port"),
            username=(data.get("username") or "").strip() or None,
            clone_of=(data.get("clone_of") or "").strip() or None,
            status=data.get("status") or "down",
            last_checked=data.get("last_checked"),
            created=data.get("created"),
        )
        self.session.add(entry)
        self.session.commit()
        return entry

    def delete_id(self, pk):
        entry = self.session.get(ManagedFirewall, pk)
        if entry is None:
            return None
        self.session.delete(entry)
        self.session.commit()
        return pk
