from connectors.utils.xml_parser import XMLParser


class AdministrationConfigurationCollector:

    def __init__(
        self,
        firewall
    ):
        self.firewall = firewall

    def collect(self):

        result = {
            "administrators": [],
            "management_allowed_ips": [],
            "https_enabled": False,
            "ssh_enabled": False,
            "ntp_servers": [],
            "panorama_managed": False,
            "admin_timeout_minutes": None,
            "default_admin_disabled": None,
            "management_acl_enabled": False,
            "ntp_server_count": 0,
        }

        try:

            config = self.firewall.xapi.show(
                "/config/devices/entry"
            )

            root = XMLParser.get_root(
                config
            )

            try:
                mgt = self.firewall.xapi.show(
                    "/config/mgt-config"
                )
                mgt_root = XMLParser.get_root(
                    mgt
                )
            except Exception:
                mgt_root = None

            admin_roots = [root]
            if mgt_root is not None:
                admin_roots.append(mgt_root)

            for admin_root in admin_roots:
                for admin in admin_root.findall(
                    ".//users/entry"
                ) + admin_root.findall(
                    ".//administrators/entry"
                ):
                    name = admin.get("name")
                    if name and name not in result["administrators"]:
                        result["administrators"].append(name)

            if root.findall(
                ".//panorama-server"
            ):

                result[
                    "panorama_managed"
                ] = True

            for ntp in root.findall(
                ".//ntp-servers//ntp-server-address"
            ) + root.findall(
                ".//ntp-servers/primary-ntp-server"
            ) + root.findall(
                ".//ntp-servers/secondary-ntp-server"
            ):

                address = ntp.text or XMLParser.get_text(
                    ntp,
                    "ntp-server-address"
                )
                if address:
                    address = address.strip()
                    if address not in result["ntp_servers"]:
                        result["ntp_servers"].append(address)

            for permitted in root.findall(
                ".//permitted-ip/entry"
            ):
                name = permitted.get("name")
                if name and name not in result["management_allowed_ips"]:
                    result["management_allowed_ips"].append(name)

            idle = XMLParser.get_text(
                root,
                ".//idle-timeout"
            )
            if idle:
                try:
                    result["admin_timeout_minutes"] = int(idle)
                except (TypeError, ValueError):
                    result["admin_timeout_minutes"] = idle

            https_server = root.find(
                ".//deviceconfig/system/service/disable-https"
            )

            if (
                https_server is None
                or https_server.text != "yes"
            ):

                result[
                    "https_enabled"
                ] = True

            ssh_server = root.find(
                ".//deviceconfig/system/service/disable-ssh"
            )

            if (
                ssh_server is None
                or ssh_server.text != "yes"
            ):

                result[
                    "ssh_enabled"
                ] = True

            result["ntp_server_count"] = len(result["ntp_servers"])
            result["management_acl_enabled"] = bool(
                result["management_allowed_ips"]
            )
            if result.get("admin_timeout_minutes") is None:
                result["admin_timeout_minutes"] = 60
            admins = [
                str(name or "").strip().lower()
                for name in result["administrators"]
            ]
            if admins:
                result["default_admin_disabled"] = "admin" not in admins
            else:
                result["default_admin_disabled"] = False

        except Exception as e:

            result["error"] = str(e)

        return result