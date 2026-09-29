import requests
from xml.etree import ElementTree

from services.settings import Settings


class PanosClient:

    def __init__(self):

        Settings.validate()

        self.host = Settings.FW_HOST
        self.port = Settings.FW_PORT
        self.timeout = Settings.TIMEOUT
        self.verify = Settings.VERIFY_TLS

        self.base_url = (
            f"https://{self.host}:{self.port}/api/"
        )

        self.api_key = (
            Settings.FW_API_KEY
            or self._keygen()
        )

    def _keygen(self):

        params = {
            "type": "keygen",
            "user": Settings.FW_USERNAME,
            "password": Settings.FW_PASSWORD
        }

        response = requests.get(
            self.base_url,
            params=params,
            timeout=self.timeout,
            verify=self.verify
        )

        response.raise_for_status()

        root = ElementTree.fromstring(
            response.text
        )

        key = root.find(".//key")

        if key is None:
            raise Exception(
                "Unable to generate API key"
            )

        return key.text

    def _call(self, params):

        params["key"] = self.api_key

        response = requests.get(
            self.base_url,
            params=params,
            timeout=self.timeout,
            verify=self.verify
        )

        response.raise_for_status()

        return response.text

    def get(self, xpath):

        return self._call({
            "type": "config",
            "action": "get",
            "xpath": xpath
        })

    def set(self, xpath, element):

        return self._call({
            "type": "config",
            "action": "set",
            "xpath": xpath,
            "element": element
        })

    def edit(self, xpath, element):

        return self._call({
            "type": "config",
            "action": "edit",
            "xpath": xpath,
            "element": element
        })

    def delete(self, xpath):

        return self._call({
            "type": "config",
            "action": "delete",
            "xpath": xpath
        })

    def commit(self):

        return self._call({
            "type": "commit",
            "cmd": "<commit></commit>"
        })

    def op(self, cmd):

        return self._call({
            "type": "op",
            "cmd": cmd
        })

    def test_connection(self):

        return self.op(
            "<show><system><info/></system></show>"
        )