import os
import socket
import ssl
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone

from panos.firewall import Firewall

from connectors.paloalto.inventory import (
    InventoryCollector
)

from connectors.paloalto.health_status import (
    HealthStatusCollector
)

from connectors.paloalto.ha_configuration import (
    HAConfigurationCollector
)

from connectors.paloalto.policy_configuration import (
    PolicyConfigurationCollector
)

from connectors.paloalto.security_services import (
    SecurityServicesCollector
)

from connectors.paloalto.routing_configuration import (
    RoutingConfigurationCollector
)

from connectors.paloalto.vpn_configuration import (
    VPNConfigurationCollector
)

from connectors.paloalto.logging_configuration import (
    LoggingConfigurationCollector
)

from connectors.paloalto.administration_configuration import (
    AdministrationConfigurationCollector
)

from connectors.paloalto.zone_protection_configuration import (
    ZoneProtectionConfigurationCollector
)

from connectors.paloalto.backup_configuration import (
    BackupConfigurationCollector
)


COLLECTOR_TIMEOUT = int(os.environ.get("PA_COLLECTOR_TIMEOUT", "20"))
CONNECT_TIMEOUT = int(os.environ.get("PA_CONNECT_TIMEOUT", "4"))
KEYGEN_TIMEOUT = int(os.environ.get("PA_KEYGEN_TIMEOUT", "8"))


def _ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class PaloAltoConnector:

    def __init__(
        self,
        hostname,
        username,
        password
    ):

        self.hostname = hostname
        self.username = username
        self.password = password
        self.api_key = None
        self.firewall = None

    def _reachable(self):
        try:
            with socket.create_connection(
                (self.hostname, 443),
                timeout=CONNECT_TIMEOUT,
            ):
                return True
        except Exception:
            return False

    def _fetch_api_key(self):
        query = urllib.parse.urlencode(
            {
                "type": "keygen",
                "user": self.username,
                "password": self.password,
            }
        )
        url = "https://{0}/api/?{1}".format(self.hostname, query)
        request = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(
            request,
            timeout=KEYGEN_TIMEOUT,
            context=_ssl_context(),
        ) as response:
            body = response.read()
        root = ET.fromstring(body)
        if root.attrib.get("status") != "success":
            raise RuntimeError("firewall keygen failed")
        key = root.findtext(".//key")
        if not key:
            raise RuntimeError("firewall keygen returned no key")
        return key

    def _make_firewall(self):
        kwargs = {
            "hostname": self.hostname,
            "api_key": self.api_key,
        }
        try:
            firewall = Firewall(timeout=COLLECTOR_TIMEOUT, **kwargs)
        except TypeError:
            firewall = Firewall(**kwargs)
        try:
            firewall.timeout = COLLECTOR_TIMEOUT
        except Exception:
            pass
        return firewall

    def _connect(self):
        if not self._reachable():
            raise RuntimeError(
                "firewall unreachable at {0}:443".format(self.hostname)
            )
        self.api_key = self._fetch_api_key()
        self.firewall = self._make_firewall()
        return self.firewall

    def get_inventory(self):

        return (
            InventoryCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_health_status(self):

        return (
            HealthStatusCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_ha_configuration(self):

        return (
            HAConfigurationCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_policy_configuration(self):

        return (
            PolicyConfigurationCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_security_services(self):

        return (
            SecurityServicesCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_routing_configuration(self):

        return (
            RoutingConfigurationCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_vpn_configuration(self):

        return (
            VPNConfigurationCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_logging_configuration(self):

        return (
            LoggingConfigurationCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_administration_configuration(self):

        return (
            AdministrationConfigurationCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_zone_protection_configuration(self):

        return (
            ZoneProtectionConfigurationCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def get_backup_configuration(self):

        return (
            BackupConfigurationCollector(
                self.firewall or self._connect()
            ).collect()
        )

    def _collect_named(self, collector_cls):
        firewall = self._make_firewall()
        return collector_cls(firewall).collect()

    def run_full_assessment(self):

        assessment = {}
        errors = {}
        ok = 0
        started = time.time()

        collectors = {
            "inventory": InventoryCollector,
            "health_status": HealthStatusCollector,
            "ha_configuration": HAConfigurationCollector,
            "policy_configuration": PolicyConfigurationCollector,
            "security_services": SecurityServicesCollector,
            "routing_configuration": RoutingConfigurationCollector,
            "vpn_configuration": VPNConfigurationCollector,
            "logging_configuration": LoggingConfigurationCollector,
            "administration_configuration": AdministrationConfigurationCollector,
            "zone_protection_configuration": ZoneProtectionConfigurationCollector,
            "backup_configuration": BackupConfigurationCollector,
        }

        try:
            self._connect()
        except Exception as exc:
            message = str(exc)
            for name in collectors:
                assessment[name] = {"error": message}
                errors[name] = message
            assessment["collection_status"] = "FAILED"
            assessment["collection_errors"] = errors
            assessment["collectors_ok"] = 0
            assessment["collectors_failed"] = len(collectors)
            assessment["collectors_total"] = len(collectors)
            assessment["collection_seconds"] = round(time.time() - started, 2)
            return assessment

        workers = min(4, len(collectors))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._collect_named, cls): name
                for name, cls in collectors.items()
            }
            for fut, name in futures.items():
                try:
                    payload = fut.result(timeout=COLLECTOR_TIMEOUT)
                except FuturesTimeout:
                    payload = {
                        "error": "timeout after {0}s".format(COLLECTOR_TIMEOUT)
                    }
                except Exception as exc:
                    payload = {"error": str(exc)}
                assessment[name] = payload
                if isinstance(payload, dict) and payload.get("error"):
                    errors[name] = str(payload.get("error"))
                else:
                    ok += 1

        for name in list(errors):
            try:
                payload = self._collect_named(collectors[name])
            except Exception as exc:
                payload = {"error": str(exc)}
            assessment[name] = payload
            if isinstance(payload, dict) and payload.get("error"):
                errors[name] = str(payload.get("error"))
            else:
                errors.pop(name, None)
                ok += 1

        self._enrich_metrics(assessment)

        failed = len(errors)
        total = len(collectors)
        if ok == 0:
            collection_status = "FAILED"
        elif failed:
            collection_status = "PARTIAL"
        else:
            collection_status = "SUCCESS"
        assessment["collection_status"] = collection_status
        assessment["collection_errors"] = errors
        assessment["collectors_ok"] = ok
        assessment["collectors_failed"] = failed
        assessment["collectors_total"] = total
        assessment["collection_seconds"] = round(time.time() - started, 2)
        return assessment

    def _hours_since(self, value):
        if not value:
            return None
        text = str(value).strip()
        for fmt in (
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d",
            "%Y-%m-%d",
        ):
            try:
                parsed = datetime.strptime(text[:19], fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                delta = datetime.now(timezone.utc) - parsed
                return round(delta.total_seconds() / 3600.0, 2)
            except Exception:
                continue
        return None

    def _enrich_metrics(self, assessment):
        inventory = assessment.get("inventory")
        if not isinstance(inventory, dict):
            inventory = {}
        hours = self._hours_since(
            inventory.get("threat_release_date")
            or inventory.get("app_release_date")
        )
        if hours is not None:
            inventory["content_update_hours"] = hours
        elif str(inventory.get("threat_version") or "0") in ("0", "none", ""):
            inventory["content_update_hours"] = 99999
        wildfire_hours = self._hours_since(inventory.get("wildfire_release_date"))
        if wildfire_hours is not None:
            inventory["wildfire_update_minutes"] = round(wildfire_hours * 60.0, 2)
        elif str(inventory.get("wildfire_version") or "0") in ("0", "none", ""):
            inventory["wildfire_update_minutes"] = 99999
        if "critical_cves" not in inventory:
            inventory["critical_cves"] = 0
        assessment["inventory"] = inventory

        ha = assessment.get("ha_configuration")
        if isinstance(ha, dict) and ha.get("config_sync") is None:
            ha["config_sync"] = "unknown"

        security = assessment.get("security_services")
        if isinstance(security, dict) and security.get("tls_minimum_version") is None:
            security["tls_minimum_version"] = "1.0"

        logging = assessment.get("logging_configuration")
        if isinstance(logging, dict):
            if logging.get("traffic_logging_enabled") is None:
                logging["traffic_logging_enabled"] = bool(
                    logging.get("log_forwarding_profiles")
                    or logging.get("syslog_servers")
                )
            if logging.get("retention_days") is None:
                logging["retention_days"] = 0
            if not logging.get("snmp_version"):
                logging["snmp_version"] = "none"

        policy = assessment.get("policy_configuration")
        if isinstance(policy, dict) and policy.get("stale_nat_rules") is None:
            policy["stale_nat_rules"] = 0

        zone = assessment.get("zone_protection_configuration")
        if isinstance(zone, dict):
            zone["zone_protection_enabled"] = bool(
                zone.get("zone_protection_profiles")
            )
            zone["dos_protection_enabled"] = bool(zone.get("dos_profiles"))
            if zone.get("packet_attack_protection") is None:
                zone["packet_attack_protection"] = bool(
                    zone.get("zone_protection_profiles")
                )
