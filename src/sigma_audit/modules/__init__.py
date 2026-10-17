"""Module registry."""

from __future__ import annotations

from typing import List

from sigma_audit.base import Module
from sigma_audit.modules.firewall import FirewallModule
from sigma_audit.modules.network import NetworkModule, NmapModule
from sigma_audit.modules.ssh import SshModule


def all_modules() -> List[Module]:
    return [SshModule(), FirewallModule(), NetworkModule(), NmapModule()]
