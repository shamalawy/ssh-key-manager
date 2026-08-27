"""SKM inventory plugin for Nornir.

Nornir's model maps onto SKM's cleanly: an SKM target is a host, its tags are
groups, and the connector (or the netdev profile, when there is one) is the
platform — which is what NAPALM and Netmiko dispatch on.

Register it once at import time and name it in your configuration:

    from nornir import InitNornir
    from skm_inventory import SKMInventory  # noqa: F401  (registers on import)

    nr = InitNornir(inventory={
        "plugin": "SKMInventory",
        "options": {"server": "https://skm.internal", "tags": ["production"]},
    })

The token comes from ``SKM_TOKEN``. Passing it as an option works too, but a
Nornir config file is usually committed, and a token in version control is a
credential in version control.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from nornir.core.inventory import (
    ConnectionOptions,
    Defaults,
    Group,
    Groups,
    Host,
    Hosts,
    Inventory,
    ParentGroups,
)
from nornir.core.plugins.inventory import InventoryPluginRegister


class SKMInventoryError(Exception):
    """Raised when the inventory cannot be read."""


class SKMInventory:
    """Reads hosts from an SKM instance."""

    def __init__(
        self,
        server: Optional[str] = None,
        token: Optional[str] = None,
        tags: Optional[List[str]] = None,
        validate_certs: bool = True,
        default_username: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        self.server = (server or os.environ.get("SKM_SERVER", "http://localhost:8080")).rstrip("/")
        self.token = token or os.environ.get("SKM_TOKEN", "")
        self.tags = tags or []
        self.validate_certs = validate_certs
        self.default_username = default_username
        self.timeout = timeout

        if not self.token:
            raise SKMInventoryError(
                "SKM inventory: no token. Set SKM_TOKEN, or pass token= in the "
                "plugin options (the environment variable is the better place)."
            )

    def load(self) -> Inventory:
        payload = self._fetch()

        groups = Groups()
        for name in payload.get("groups", {}):
            groups[name] = Group(name=name)

        hosts = Hosts()
        for name, spec in payload.get("hosts", {}).items():
            parents = [groups[g] for g in spec.get("groups", []) if g in groups]

            data: Dict[str, Any] = dict(spec.get("data") or {})
            data["skm_platform"] = spec.get("platform")

            hosts[name] = Host(
                name=name,
                hostname=spec.get("hostname"),
                port=spec.get("port") or 22,
                username=spec.get("username") or self.default_username,
                platform=spec.get("platform"),
                groups=ParentGroups(parents),
                data=data,
                connection_options={
                    # SKM never hands out private keys through this path, so
                    # the credential comes from the operator's own agent or
                    # ssh_config. That is deliberate: an inventory fetch is not
                    # an audited key reveal.
                    "netmiko": ConnectionOptions(extras={"use_keys": True}),
                },
            )

        return Inventory(hosts=hosts, groups=groups, defaults=Defaults())

    def _fetch(self) -> Dict[str, Any]:
        url = f"{self.server}/api/v1/inventory/nornir"
        if self.tags:
            url += "?" + urllib.parse.urlencode([("tag", t) for t in self.tags])

        request = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        })

        context = None
        if not self.validate_certs:
            context = ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise SKMInventoryError(
                f"SKM inventory: the server returned HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise SKMInventoryError(
                f"SKM inventory: cannot reach {self.server}: {exc.reason}"
            ) from exc


InventoryPluginRegister.register("SKMInventory", SKMInventory)
