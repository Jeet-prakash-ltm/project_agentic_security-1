"""Minimal PAN-OS XML-API client (plain Python, ``requests`` only).

The client talks directly to a Palo Alto Networks firewall over the XML API:

* ``type=keygen`` exchanges the configured administrator credentials for an
  API key (the key is kept in memory and never persisted or logged).
* ``type=config`` drives ``action=get`` / ``action=set`` / ``action=edit`` /
  ``action=delete`` against the candidate configuration.
* ``type=op`` runs operational commands (e.g. ``show``).

Configuration comes from environment variables (never from committed code):

* ``NETSEC_FW_HOST``      firewall host or IP (required to run)
* ``NETSEC_FW_USERNAME``  administrator username (used for keygen)
* ``NETSEC_FW_PASSWORD``  administrator password (used for keygen)
* ``NETSEC_FW_API_KEY``   optional pre-generated API key (skips keygen)
* ``NETSEC_FW_PORT``      HTTPS port (default 443)
* ``NETSEC_FW_VERIFY_TLS``  ``0`` (default) to disable TLS certificate checks
* ``NETSEC_FW_TIMEOUT``   request timeout in seconds (default 30)
* ``NETSEC_FW_DRY_RUN``   ``1`` (default) previews config changes without
  sending them; set ``0`` to apply changes to the firewall.

Every mutating call honours ``dry_run`` so bulk playbooks are safe to preview.
"""

import logging
import os
import xml.etree.ElementTree as ET

import requests

logger = logging.getLogger("netsec.panos")


class PanosError(RuntimeError):
    """Raised when the firewall returns ``status="error"`` or is unreachable."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _env(name, default=""):
    return (os.environ.get(name) or "").strip() or default


def _env_bool(name, default="0"):
    value = _env(name, default).lower()
    return value in ("1", "true", "yes", "on")


def xml_escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def entry_xml(name, inner=None):
    """Build an ``<entry name="...">`` element string."""
    return '<entry name="{0}">{1}</entry>'.format(xml_escape(name), inner or "")


def member_list_xml(tag, values):
    """Build ``<tag><member>v</member>...</tag>`` from a list of values.

    ``tag`` is the plural XML container used by PAN-OS for rule from/to/source
    and object member lists (e.g. ``from``, ``source``, ``tag``).
    """
    items = []
    for value in values or []:
        value = str(value).strip()
        if value:
            items.append("<member>{0}</member>".format(xml_escape(value)))
    if not items:
        return ""
    return "<{0}>{1}</{0}>".format(xml_escape(tag), "".join(items))


class PanosClient:
    """Direct PAN-OS XML-API client with optional dry-run previewing."""

    def __init__(
        self,
        host=None,
        username=None,
        password=None,
        api_key=None,
        port=None,
        verify_tls=None,
        dry_run=None,
        timeout=None,
    ):
        self.host = host or _env("NETSEC_FW_HOST")
        self.username = username or _env("NETSEC_FW_USERNAME")
        self.password = password or _env("NETSEC_FW_PASSWORD")
        self.port = int(port or _env("NETSEC_FW_PORT", "443") or 443)
        self.verify_tls = bool(
            verify_tls if verify_tls is not None else _env_bool("NETSEC_FW_VERIFY_TLS")
        )
        self.timeout = int(timeout or _env("NETSEC_FW_TIMEOUT", "30") or 30)
        self._key = api_key or _env("NETSEC_FW_API_KEY") or None
        if dry_run is None:
            dry_run = _env_bool("NETSEC_FW_DRY_RUN", "0")
        self.dry_run = bool(dry_run)

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    @property
    def base_url(self):
        return "https://{0}:{1}/api/".format(self.host, self.port)

    @property
    def configured(self):
        return bool(self.host and (self._key or (self.username and self.password)))

    def missing_config(self):
        missing = []
        if not self.host:
            missing.append("NETSEC_FW_HOST")
        if not self._key and not (self.username and self.password):
            missing.append("NETSEC_FW_USERNAME / NETSEC_FW_PASSWORD (or NETSEC_FW_API_KEY)")
        return missing

    def describe(self):
        parts = [self.host or "?", "dry_run={0}".format("on" if self.dry_run else "off")]
        return " | ".join(parts)

    # ------------------------------------------------------------------
    # Low level HTTP / XML handling
    # ------------------------------------------------------------------

    def _request(self, params):
        if not self.host:
            raise PanosError("Firewall host is not configured.")
        headers = {"Accept": "application/xml"}
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                verify=self.verify_tls,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise PanosError(
                "Could not reach firewall {0}: {1}".format(self.host, exc)
            )
        if response.status_code != 200:
            raise PanosError(
                "Firewall returned HTTP {0}".format(response.status_code),
                status_code=response.status_code,
            )
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as exc:
            raise PanosError(
                "Firewall returned an unparseable response: {0}".format(exc)
            )
        if root.tag == "response" and (root.attrib.get("status") or "success") != "success":
            message = self._error_message(root)
            raise PanosError(
                "PAN-OS error{0}: {1}".format(
                    " (HTTP {0})".format(response.status_code) if response.status_code != 200 else "",
                    message,
                )
            )
        return root

    def _error_message(self, root):
        try:
            msg = root.find(".//msg")
            if msg is None:
                msg = root.find(".//result")
            if msg is not None and msg.text and msg.text.strip():
                return msg.text.strip()
            if msg is not None:
                lines = []
                for line in msg.itertext():
                    line = (line or "").strip()
                    if line:
                        lines.append(line)
                if lines:
                    return " ".join(lines)
        except Exception:
            pass
        return "unknown PAN-OS error"

    def _config(self, action, xpath, element=None):
        """Run a candidate-config ``type=config`` action.

        Mutating actions honour ``dry_run`` and return a preview dict instead
        of sending anything to the firewall.
        """
        if action in ("set", "edit", "delete") and self.dry_run:
            logger.info("DRY RUN: config %s %s", action, xpath)
            return {
                "dry_run": True,
                "action": action,
                "xpath": xpath,
                "element": element,
            }
        params = {
            "type": "config",
            "action": action,
            "xpath": xpath,
            "key": self.api_key(),
        }
        if element is not None:
            params["element"] = element
        root = self._request(params)
        logger.info("config %s %s -> ok", action, xpath)
        return {"dry_run": False, "action": action, "xpath": xpath}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def api_key(self):
        """Return the cached API key, requesting one via keygen when needed."""
        if self._key:
            return self._key
        if not (self.username and self.password):
            raise PanosError(
                "No firewall API key configured and no credentials available "
                "for keygen."
            )
        root = self._request(
            {
                "type": "keygen",
                "user": self.username,
                "password": self.password,
            }
        )
        key_el = root.find(".//key")
        if key_el is None or not (key_el.text or "").strip():
            raise PanosError("Firewall keygen did not return an API key.")
        self._key = key_el.text.strip()
        return self._key

    def op(self, cmd):
        """Run an operational command and return the parsed response root."""
        root = self._request({"type": "op", "cmd": cmd, "key": self.api_key()})
        return root

    def get(self, xpath):
        """Read part of the candidate configuration. Returns parsed root."""
        return self._request(
            {"type": "config", "action": "get", "xpath": xpath, "key": self.api_key()}
        )

    def exists(self, xpath):
        """Best-effort existence check for an entry xpath (reads config)."""
        try:
            root = self.get(xpath)
        except PanosError:
            return False
        result = root.find("result")
        if result is None:
            return False
        # A populated <entry .../> result means the node exists.
        return len(list(result)) > 0 or bool((result.text or "").strip())

    def set(self, xpath, element):
        """Create (or update) a config node with ``action=set``."""
        return self._config("set", xpath, element)

    def edit(self, xpath, element):
        """Replace a config node with ``action=edit`` (creates if missing)."""
        return self._config("edit", xpath, element)

    def delete(self, xpath):
        """Delete a config node with ``action=delete``."""
        return self._config("delete", xpath)

    def commit(self, description=None):
        """Commit the candidate configuration (no-op under dry run)."""
        if self.dry_run:
            logger.info("DRY RUN: commit skipped (%s)", description or "")
            return {"dry_run": True, "action": "commit"}
        root = self._request(
            {
                "type": "commit",
                "cmd": "<commit><description>{0}</description></commit>".format(
                    xml_escape(description or "netsec execution playbook")
                ),
                "key": self.api_key(),
            }
        )
        return {"dry_run": False, "action": "commit"}
