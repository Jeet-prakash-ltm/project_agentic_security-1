from connectors.utils.xml_parser import XMLParser


class HAConfigurationCollector:

    def __init__(
        self,
        firewall
    ):
        self.firewall = firewall

    def collect(self):

        result = {
            "ha_enabled": False,
            "local_state": None,
            "peer_state": None,
            "config_sync": None,
            "runtime_sync": None,
            "link_monitoring": None,
            "path_monitoring": None
        }

        try:

            xml_response = self.firewall.op(
                "show high-availability state",
                xml=True
            )

            root = XMLParser.get_root(
                xml_response
            )

            result["ha_enabled"] = True

            result["local_state"] = (
                self._find_text(
                    root,
                    ".//state"
                )
            )

            result["peer_state"] = (
                self._find_text(
                    root,
                    ".//peer-state"
                )
            )

            result["config_sync"] = (
                self._find_text(
                    root,
                    ".//running-sync"
                )
            )

            result["runtime_sync"] = (
                self._find_text(
                    root,
                    ".//running-sync-enabled"
                )
            )

            result["link_monitoring"] = (
                self._enabled_flag(
                    root,
                    ".//link-monitoring"
                )
            )

            result["path_monitoring"] = (
                self._enabled_flag(
                    root,
                    ".//path-monitoring"
                )
            )

        except Exception as e:

            result["error"] = str(e)

        return result

    def _find_text(
        self,
        root,
        xpath
    ):

        if root is None:
            return None

        node = root.find(
            xpath
        )

        if (
            node is not None
            and node.text
        ):

            return node.text.strip()

        return None

    def _enabled_flag(self, root, xpath):
        if root is None:
            return False
        node = root.find(xpath)
        if node is None:
            return False
        text = (node.text or "").strip().lower()
        if text in ("yes", "enabled", "true", "on"):
            return True
        enabled = node.find(".//enabled")
        if enabled is not None and (enabled.text or "").strip().lower() in (
            "yes",
            "enabled",
            "true",
            "on",
        ):
            return True
        return bool(list(node))