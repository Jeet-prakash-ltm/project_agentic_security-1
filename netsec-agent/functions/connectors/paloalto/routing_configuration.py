from connectors.utils.xml_parser import (
    XMLParser
)


class RoutingConfigurationCollector:

    def __init__(
        self,
        firewall
    ):
        self.firewall = firewall

    def collect(self):

        result = {
            "virtual_routers": [],
            "static_routes": [],
            "bgp_enabled": False,
            "ospf_enabled": False,
            "route_leaks": 0
        }

        try:

            config = self.firewall.xapi.show(
                "/config/devices/entry/network"
            )

            root = XMLParser.get_root(
                config
            )

            for vr in root.findall(
                ".//virtual-router/entry"
            ):

                vr_name = vr.get(
                    "name"
                )

                if vr_name:

                    result[
                        "virtual_routers"
                    ].append(
                        vr_name
                    )

            for route in root.findall(
                ".//routing-table/ip/static-route/entry"
            ):

                result[
                    "static_routes"
                ].append({
                    "name": route.get(
                        "name"
                    )
                })

            if root.findall(
                ".//protocol/bgp"
            ):

                result[
                    "bgp_enabled"
                ] = True

            if root.findall(
                ".//protocol/ospf"
            ):

                result[
                    "ospf_enabled"
                ] = True

        except Exception as e:

            result["error"] = str(e)

        return result