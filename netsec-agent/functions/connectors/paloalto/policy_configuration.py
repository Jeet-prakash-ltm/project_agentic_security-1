from connectors.utils.xml_parser import (
    XMLParser
)


class PolicyConfigurationCollector:

    def __init__(
        self,
        firewall
    ):
        self.firewall = firewall

    def collect(self):

        result = {
            "security_rules": [],
            "nat_rules": [],
            "zones": [],
            "zone_count": 0,
            "any_any_rules": 0,
            "unused_rule_percent": 0,
            "documented_rule_percent": 0,
            "default_deny_present": False,
            "appid_rule_percent": 0,
            "shadowed_rules": 0
        }

        try:

            config_xml = self.firewall.xapi.show(
                "/config/devices/entry/vsys/entry"
            )

            root = XMLParser.get_root(
                config_xml
            )

            security_rules = self._get_security_rules(
                root
            )

            nat_rules = self._get_nat_rules(
                root
            )

            zones = self._get_zones(
                root
            )

            result["security_rules"] = security_rules
            result["nat_rules"] = nat_rules
            result["zones"] = zones

            result["zone_count"] = len(
                zones
            )

            result["any_any_rules"] = (
                self._count_any_any_rules(
                    security_rules
                )
            )

            result["unused_rule_percent"] = (
                self._unused_rule_percent(
                    security_rules
                )
            )

            result["documented_rule_percent"] = (
                self._documented_rule_percent(
                    security_rules
                )
            )

            result["default_deny_present"] = (
                self._default_deny_present(
                    security_rules
                )
            )

            result["appid_rule_percent"] = (
                self._appid_rule_percent(
                    security_rules
                )
            )

            result["shadowed_rules"] = len(
                self._shadowed_rules(
                    security_rules
                )
            )

            result["stale_nat_rules"] = 0

        except Exception as e:

            result["error"] = str(e)

        return result

    def _get_security_rules(
        self,
        root
    ):

        rules = []

        for rule in root.findall(
            ".//rulebase/security/rules/entry"
        ):

            rules.append({

                "name":
                    rule.get("name"),

                "action":
                    XMLParser.get_text(
                        rule,
                        "action"
                    ),

                "description":
                    XMLParser.get_text(
                        rule,
                        "description"
                    ),

                "source":
                    XMLParser.get_members(
                        rule,
                        "./source/member"
                    ),

                "destination":
                    XMLParser.get_members(
                        rule,
                        "./destination/member"
                    ),

                "application":
                    XMLParser.get_members(
                        rule,
                        "./application/member"
                    ),

                "service":
                    XMLParser.get_members(
                        rule,
                        "./service/member"
                    ),

                "disabled":
                    XMLParser.get_text(
                        rule,
                        "disabled",
                        "no"
                    ),

                "hit_count":
                    0
            })

        return rules

    def _get_nat_rules(
        self,
        root
    ):

        nat_rules = []

        for rule in root.findall(
            ".//rulebase/nat/rules/entry"
        ):

            nat_rules.append({

                "name":
                    rule.get("name")
            })

        return nat_rules

    def _get_zones(
        self,
        root
    ):

        zones = []

        for zone in root.findall(
            ".//zone/entry"
        ):

            zone_name = zone.get(
                "name"
            )

            if zone_name:

                zones.append(
                    zone_name
                )

        return zones

    def _count_any_any_rules(
        self,
        rules
    ):

        count = 0

        for rule in rules:

            if (
                "any" in rule["source"]
                and
                "any" in rule["destination"]
                and
                rule["action"] == "allow"
            ):

                count += 1

        return count

    def _unused_rule_percent(
        self,
        rules
    ):

        if not rules:
            return 0

        unused = len([
            r
            for r in rules
            if r.get(
                "hit_count",
                0
            ) == 0
        ])

        return round(
            (
                unused / len(rules)
            ) * 100,
            2
        )

    def _documented_rule_percent(
        self,
        rules
    ):

        if not rules:
            return 0

        documented = len([
            r
            for r in rules
            if r.get(
                "description"
            )
        ])

        return round(
            (
                documented / len(rules)
            ) * 100,
            2
        )

    def _default_deny_present(
        self,
        rules
    ):

        for rule in rules:

            if (
                rule.get("action") == "deny"
                and
                rule.get("name")
                and
                "deny" in rule["name"].lower()
            ):

                return True

        return False

    def _appid_rule_percent(
        self,
        rules
    ):

        if not rules:
            return 0

        appid_rules = len([
            r
            for r in rules
            if "any" not in r.get(
                "application",
                []
            )
        ])

        return round(
            (
                appid_rules / len(rules)
            ) * 100,
            2
        )

    def _shadowed_rules(
        self,
        rules
    ):

        shadowed = []

        for rule in rules:

            if (
                rule.get(
                    "hit_count",
                    0
                ) == 0
                and
                rule.get("action") == "allow"
            ):

                shadowed.append(
                    rule["name"]
                )

        return shadowed