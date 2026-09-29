from connectors.panos_client import PanosClient
from services.settings import Settings
from services.xml_json import parse_panos_xml


class WorkbookPanosClient:
    def __init__(self):
        self._inner = PanosClient()
        self.dry_run = bool(Settings.DRY_RUN)
        self.host = Settings.FW_HOST

    def _mutate(self, action, xpath, element=None):
        if self.dry_run:
            return {
                "dry_run": True,
                "action": action,
                "xpath": xpath,
                "element": element,
            }
        if action == "set":
            xml = self._inner.set(xpath, element)
        elif action == "edit":
            xml = self._inner.edit(xpath, element)
        elif action == "delete":
            xml = self._inner.delete(xpath)
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
        xml = self._inner.commit()
        parse_panos_xml(xml)
        return {"dry_run": False, "action": "commit", "description": description or ""}
