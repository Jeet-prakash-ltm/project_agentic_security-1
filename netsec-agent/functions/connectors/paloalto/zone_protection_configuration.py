from connectors.utils.xml_parser import (
    XMLParser
)


class ZoneProtectionConfigurationCollector:

    def __init__(
        self,
        firewall
    ):
        self.firewall = firewall

    def collect(self):

        result = {
            "zone_protection_profiles": [],
            "dos_profiles": [],
            "packet_attack_protection": False
        }

        try:

            config = self.firewall.xapi.show(
                "/config/devices/entry"
            )

            root = XMLParser.get_root(
                config
            )

            for profile in root.findall(
                ".//zone-protection-profile/entry"
            ):

                profile_name = profile.get(
                    "name"
                )

                if profile_name:

                    result[
                        "zone_protection_profiles"
                    ].append(
                        profile_name
                    )

            for profile in root.findall(
                ".//dos-protection/entry"
            ):

                profile_name = profile.get(
                    "name"
                )

                if profile_name:

                    result[
                        "dos_profiles"
                    ].append(
                        profile_name
                    )

            result["zone_protection_enabled"] = bool(
                result["zone_protection_profiles"]
            )
            result["dos_protection_enabled"] = bool(
                result["dos_profiles"]
            )
            result["packet_attack_protection"] = bool(
                result["zone_protection_profiles"]
            )

        except Exception as e:

            result["error"] = str(e)

        return result