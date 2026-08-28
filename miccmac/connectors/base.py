"""Connector interface: a connector's job is to collect facts about a target
device and return them in the shape check modules expect via
context["facts"] -- the extensibility seam documented in the README and
docs/methodology.md. Connectors never evaluate checks themselves.
"""
from __future__ import annotations

from typing import Protocol


class ConnectorError(RuntimeError):
    """Raised when a connector cannot reach or query a target."""


class Connector(Protocol):
    def collect_facts(self, target: str) -> dict:
        """Return a facts dict, e.g.:

            {
                "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04"},
                "system_info": {...},          # raw osquery system_info row
                "deb_packages": [...],         # raw osquery deb_packages rows
            }

        Raises ConnectorError if the target can't be reached or queried.
        """
        ...
