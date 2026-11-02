from connectors.panos_client import PanosClient
from services.settings import Settings
from services.xml_json import parse_panos_xml


class WorkbookPanosClient:
    def __init__(self):
        self._inner = None
        self.dry_run = bool(Settings.DRY_RUN)
        self.host = Settings.FW_HOST

    def _conn(self):
        if self._inner is None:
            self._inner = PanosClient()
        return self._inner

    def get(self, xpath):
        """Read configuration (used for dependency/inventory checks)."""
        return self._conn().get(xpath)

    def _mutate(self, action, xpath, element=None):
        if self.dry_run:
            return {
                "dry_run": True,
                "action": action,
                "xpath": xpath,
                "element": element,
            }
        client = self._conn()
        if action == "set":
            xml = client.set(xpath, element)
        elif action == "edit":
            xml = client.edit(xpath, element)
        elif action == "delete":
            xml = client.delete(xpath)
        else:
            raise ValueError("Unsupported config action {0}".format(action))
        parse_panos_xml(xml)
        return {"dry_run": False, "action": action, "xpath": xpath}

    def set(self, xpath, element):
        return self._mutate("set", xpath, element)

    def edit(self, xpath, element):
        return self._mutate("edit", xpath, element)

    def delete(self, xpath):
        return self._mutate("delete", xpath)

    def commit(self, description=None):
        if self.dry_run:
            return {"dry_run": True, "action": "commit"}
        xml = self._conn().commit()
        parse_panos_xml(xml)
        return {"dry_run": False, "action": "commit", "description": description or ""}
