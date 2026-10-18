"""sshd configuration checks, plus ssh-audit when it is installed."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from mizar.base import Module, lacks_privileges
from mizar.context import Context
from mizar.models import Finding, SkipReason, Status

SSHD_PATHS = ("sshd", "/usr/sbin/sshd")
MAX_AUTH_TRIES = 4
MAX_NAMES = 8
CANNOT_CONNECT = "cannot connect to"


def summarize_recommendations(section: Dict[str, Any]) -> str:
    """Turn ssh-audit's nested advice into lines like `del kex: a, b`."""
    lines = []
    for action, groups in section.items():
        for group, items in groups.items():
            names = [i["name"] if isinstance(i, dict) else str(i) for i in items]
            more = (
                f" (+{len(names) - MAX_NAMES} more)" if len(names) > MAX_NAMES else ""
            )
            lines.append(f"{action} {group}: {', '.join(names[:MAX_NAMES])}{more}")
    return "\n".join(lines)


def parse_sshd_config(output: str) -> Dict[str, str]:
    config: Dict[str, str] = {}
    for line in output.splitlines():
        key, _, value = line.partition(" ")
        if key:
            config[key.lower()] = value.strip()
    return config


class SshModule(Module):
    name = "ssh"
    profile = "quick"
    tools = ("sshd", "ssh-audit")
    description = "sshd_config hardening and weak algorithms"

    def run(self, ctx: Context) -> List[Finding]:
        config, problem = self._load_config(ctx)
        findings = [problem] if problem else self._check_config(config)
        findings.append(self._ssh_audit(ctx, config.get("port")))
        return findings

    def _load_config(self, ctx: Context) -> Tuple[Dict[str, str], Optional[Finding]]:
        for path in SSHD_PATHS:
            result = ctx.run([path, "-T"])
            if not result.not_found:
                break
        else:
            return {}, self.skip(
                "ssh.config",
                "sshd configuration",
                SkipReason.NOT_APPLICABLE,
                "sshd is not installed",
            )
        if result.returncode != 0:
            if lacks_privileges(ctx, result):
                return {}, self.skip(
                    "ssh.config",
                    "sshd configuration",
                    SkipReason.NO_PRIVILEGES,
                    "sshd -T needs root",
                )
            return {}, self.finding(
                "ssh.config",
                Status.ERROR,
                "sshd -T failed",
                result.stderr.strip(),
            )
        return parse_sshd_config(result.stdout), None

    def _check_config(self, config: Dict[str, str]) -> List[Finding]:
        root = config.get("permitrootlogin", "")
        password = config.get("passwordauthentication", "")
        empty = config.get("permitemptypasswords", "")
        tries = int(config.get("maxauthtries", "6"))
        return [
            self.finding(
                "ssh.permit_root_login",
                Status.CRIT if root == "yes" else Status.OK,
                "Root login over SSH",
                f"permitrootlogin {root}",
                "Set PermitRootLogin to no or prohibit-password.",
            ),
            self.finding(
                "ssh.password_auth",
                Status.WARN if password == "yes" else Status.OK,
                "Password authentication",
                f"passwordauthentication {password}",
                "Use keys and set PasswordAuthentication no.",
            ),
            self.finding(
                "ssh.max_auth_tries",
                Status.WARN if tries > MAX_AUTH_TRIES else Status.OK,
                "Authentication attempts per connection",
                f"maxauthtries {tries}",
                f"Set MaxAuthTries to {MAX_AUTH_TRIES} or less.",
            ),
            self.finding(
                "ssh.empty_passwords",
                Status.CRIT if empty == "yes" else Status.OK,
                "Empty passwords",
                f"permitemptypasswords {empty}",
                "Set PermitEmptyPasswords no.",
            ),
        ]

    def _ssh_audit(self, ctx: Context, port: Optional[str]) -> Finding:
        title = "Key exchange, cipher and MAC algorithms (ssh-audit)"
        if not ctx.has("ssh-audit"):
            return self.skip(
                "ssh.audit", title, SkipReason.TOOL_MISSING, "ssh-audit not found"
            )
        cmd = ["ssh-audit", "-j"] + (["-p", port] if port else []) + [ctx.target]
        # ssh-audit's exit code reflects findings, so only the JSON is trusted.
        result = ctx.run(cmd)
        if CANNOT_CONNECT in result.stdout + result.stderr:
            return self.skip(
                "ssh.audit",
                title,
                SkipReason.NOT_APPLICABLE,
                f"nothing is listening on {ctx.target}:{port or 22}",
            )
        try:
            data = json.loads(result.stdout)
            recs = data["recommendations"]
        except (ValueError, KeyError, TypeError):
            return self.finding(
                "ssh.audit", Status.ERROR, title, "could not parse ssh-audit output"
            )
        advice = "Remove or replace the algorithms listed by ssh-audit."
        if recs.get("critical"):
            return self.finding(
                "ssh.audit",
                Status.CRIT,
                title,
                summarize_recommendations(recs["critical"]),
                advice,
            )
        if recs.get("warning"):
            return self.finding(
                "ssh.audit",
                Status.WARN,
                title,
                summarize_recommendations(recs["warning"]),
                advice,
            )
        return self.finding("ssh.audit", Status.OK, title)
