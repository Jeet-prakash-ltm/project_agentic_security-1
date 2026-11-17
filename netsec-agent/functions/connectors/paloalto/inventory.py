from connectors.utils.xml_parser import (
    XMLParser
)


class InventoryCollector:

    def __init__(
        self,
        firewall
    ):
        self.firewall = firewall

    def collect(self):

        response = self.firewall.op(
            "show system info",
            xml=True
        )

        root = XMLParser.get_root(
            response
        )

        system = root.find(
            ".//system"
        )

        if system is None:

            return {}

        return {

            "hostname":
                XMLParser.get_text(
                    system,
                    "hostname"
                ),

            "model":
                XMLParser.get_text(
                    system,
                    "model"
                ),

            "serial":
                XMLParser.get_text(
                    system,
                    "serial"
                ),

            "version":
                XMLParser.get_text(
                    system,
                    "sw-version"
                ),

            "uptime":
                XMLParser.get_text(
                    system,
                    "uptime"
                ),

            "vendor":
                "PaloAlto",

            "app_version":
                XMLParser.get_text(
                    system,
                    "app-version"
                ),

            "threat_version":
                XMLParser.get_text(
                    system,
                    "threat-version"
                ),

            "av_version":
                XMLParser.get_text(
                    system,
                    "av-version"
                ),

            "wildfire_version":
                XMLParser.get_text(
                    system,
                    "wildfire-version"
                ),

            "threat_release_date":
                XMLParser.get_text(
                    system,
                    "threat-release-date"
                ),

            "wildfire_release_date":
                XMLParser.get_text(
                    system,
                    "wildfire-release-date"
                ),

            "app_release_date":
                XMLParser.get_text(
                    system,
                    "app-release-date"
                ),
        }