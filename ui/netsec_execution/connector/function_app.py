"""PAN-OS client that talks to the Firewall Execution Function App.

Playbooks still use the Excel workbook + ``PanosClient`` surface
(``set`` / ``edit`` / ``delete`` / ``commit``). This adapter sends those
calls to the Azure Function App that backs the Foundry
``Firewall-Excecution-Agent`` OpenAPI tool, instead of hitting the firewall
XML API from the UI App Service.
"""

import logging
import os

import requests

from netsec_execution.connector.panos import PanosError

logger = logging.getLogger("netsec.function_app")

DEFAULT_FUNCTION_URL = (
    "https://firewall-execution-agent-gahmfgfghubpa6gk"
    ".southindia-01.azurewebsites.net/api"
)
TIMEOUT = int(os.environ.get("NETSEC_FUNCTION_TIMEOUT", "60") or "60")


def _env(name, default=""):
    return (os.environ.get(name) or "").strip() or default


def _key_usable(key):
    key = (key or "").strip()
    return bool(key) and not key.startswith("PLACEHOLDER")


class FunctionAppPanosClient:
    """``PanosClient``-compatible wrapper around the execution Function App."""

    def __init__(self, base_url=None, function_key=None):
        self.base_url = (base_url or _env(
            "NETSEC_FUNCTION_URL", DEFAULT_FUNCTION_URL
        )).rstrip("/")
        self.function_key = function_key or _env("NETSEC_FUNCTION_KEY")
        self.timeout = TIMEOUT
        self._info = None

    @property
    def configured(self):
        return bool(self.base_url) and _key_usable(self.function_key)

    def missing_config(self):
        missing = []
        if not self.base_url:
            missing.append("NETSEC_FUNCTION_URL")
        if not _key_usable(self.function_key):
            missing.append("NETSEC_FUNCTION_KEY")
        return missing

    def _load_info(self):
        if self._info is not None:
            return self._info
        if not self.configured:
            self._info = {}
            return self._info
        try:
            self._info = self._get("panos/info", timeout=10)
        except Exception as exc:
            logger.warning("Function App info probe failed: %s", exc)
            self._info = {}
        return self._info

    @property
    def host(self):
        info = self._load_info()
        return (
            info.get("host")
            or "Firewall-Execution-Agent"
        )

    @property
    def dry_run(self):
        info = self._load_info()
        if "dry_run" in info:
            return bool(info.get("dry_run"))
        return True

    def describe(self):
        return "{0} | dry_run={1} | via=function_app".format(
            self.host, "on" if self.dry_run else "off"
        )

    def _headers(self):
        return {
            "Content-Type": "application/json",
            "x-functions-key": self.function_key,
        }

    def _url(self, path):
        return "{0}/{1}".format(self.base_url, path.lstrip("/"))

    def _raise_for_payload(self, response):
        try:
            data = response.json()
        except ValueError:
            data = {}
        if response.status_code >= 400:
            message = (
                data.get("message")
                or data.get("error")
                or "Function App returned HTTP {0}".format(response.status_code)
            )
            raise PanosError(message, status_code=response.status_code)
        if isinstance(data, dict) and (data.get("status") or "").lower() == "error":
            raise PanosError(data.get("message") or "Function App error")
        return data if isinstance(data, dict) else {}

    def _get(self, path, timeout=None):
        try:
            response = requests.get(
                self._url(path),
                headers=self._headers(),
                params={"code": self.function_key},
                timeout=timeout or self.timeout,
            )
        except requests.RequestException as exc:
            raise PanosError("Could not reach Function App: {0}".format(exc))
        return self._raise_for_payload(response)

    def _post(self, path, body):
        try:
            response = requests.post(
                self._url(path),
                headers=self._headers(),
                params={"code": self.function_key},
                json=body or {},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise PanosError("Could not reach Function App: {0}".format(exc))
        return self._raise_for_payload(response)

    def _mutate(self, action, xpath, element=None):
        body = {"xpath": xpath}
        if element is not None:
            body["element"] = element
        data = self._post("panos/config/{0}".format(action), body)
        status = (data.get("status") or "").lower()
        return {
            "dry_run": status == "preview" or self.dry_run,
            "action": data.get("action") or data.get("operation") or action,
            "xpath": data.get("xpath") or xpath,
            "element": element,
        }

    def get(self, xpath):
        data = self._post("panos/config/get", {"xpath": xpath})
        return data

    def exists(self, xpath):
        try:
            data = self.get(xpath)
        except PanosError:
            return False
        if not isinstance(data, dict):
            return False
        if (data.get("status") or "").lower() == "error":
            return False
        return bool(data.get("xpath") or data.get("status"))

    def set(self, xpath, element):
        return self._mutate("set", xpath, element)

    def edit(self, xpath, element):
        return self._mutate("edit", xpath, element)

    def delete(self, xpath):
        return self._mutate("delete", xpath)

    def commit(self, description=None):
        if self.dry_run:
            logger.info("DRY RUN: Function App commit skipped (%s)", description or "")
            return {"dry_run": True, "action": "commit"}
        data = self._post("panos/commit", {})
        status = (data.get("status") or "").lower()
        return {
            "dry_run": status == "preview",
            "action": "commit",
        }


def make_client():
    """Prefer the Function App; fall back to a direct PAN-OS XML client."""
    client = FunctionAppPanosClient()
    if client.configured:
        return client
    from netsec_execution.connector.panos import PanosClient
    return PanosClient()
