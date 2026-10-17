"""Module registry."""

from __future__ import annotations

from typing import List

from mizar.base import Module
from mizar.modules.docker import DockerModule
from mizar.modules.filesystem import FilesystemModule
from mizar.modules.firewall import FirewallModule
from mizar.modules.logs import LogsModule
from mizar.modules.lynis import LynisModule
from mizar.modules.malware import MalwareModule
from mizar.modules.network import NetworkModule, NmapModule
from mizar.modules.packages import PackagesModule
from mizar.modules.ssh import SshModule


def all_modules() -> List[Module]:
    return [
        SshModule(),
        FirewallModule(),
        NetworkModule(),
        NmapModule(),
        PackagesModule(),
        LogsModule(),
        FilesystemModule(),
        LynisModule(),
        MalwareModule(),
        DockerModule(),
    ]
