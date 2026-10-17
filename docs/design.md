# mizar design

A read-only security analyzer for Linux servers. It never changes the system
and never installs anything.

## Principles
- Own checks (`sshd -T`, `ss`, `find`, log parsing) work on a bare Linux box.
  Wrappers around external tools (lynis, ssh-audit, rkhunter, ...) enrich them.
- Active scanning (nmap) is opt-in: `--active`, target defaults to `127.0.0.1`.
- No root is fine: checks that need it become `SKIPPED (no_privileges)`.
- Runtime is Python stdlib only; floor is Python 3.8 (Debian 11, Ubuntu 20.04).

## Finding
`id`, `module`, `status`, `title`, `evidence`, `recommendation`, `skip_reason`.

Statuses: `OK`, `WARN`, `CRIT`, `SKIPPED`, `ERROR` (the check itself crashed).
Skip reasons: `tool_missing`, `not_applicable`, `no_privileges`, `timeout`,
`not_enabled`.

Skipped checks never count as passed. The report always shows coverage:
executed / skipped / errored.

## CLI
```
mizar [run] [--profile quick|standard|full] [--modules a,b] [--skip x,y]
            [--format text|json] [--output DIR] [--no-save] [--min-severity ok|warn|crit]
            [--active] [--target HOST] [--timeout SEC] [--strict]
            [--no-color] [-q] [-v]
mizar doctor
mizar list
mizar report FILE.json
```
No arguments means `run --profile standard` (passive only).

## Exit codes
| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | WARN found |
| 2 | CRIT found |
| 3 | a check errored, or usage/internal error |
| 4 | `--strict` and some checks were skipped |

Precedence: 2, then 3, then 4, then 1.

## JSON report
`schema_version`, `tool_version`, `host`, `distro`, `timestamp`, `profile`,
`coverage` (`executed`, `skipped`, `errors`), `findings[]`.
`--format` only picks what goes to stdout; `report.json` and `report.txt` are
saved unless `--no-save`. Default output dir: `./mizar-reports/<host>-<timestamp>/` with `report.json`
and `report.txt`.

## Modules
| Module | Profile | Notes |
|---|---|---|
| ssh | quick | `sshd -T`; ssh-audit if installed |
| firewall | quick | ufw / nft / iptables, default deny inbound |
| network | standard | `ss -tulpn`: public and risky listeners |
| nmap | standard | active only (`--active`), scans `--target` |
| packages | standard | pending updates, unattended-upgrades, needrestart |
| logs | standard | failed logins by IP, root logins |
| filesystem | standard | UID 0, empty passwords, SUID/world-writable in risky dirs |
| lynis | standard | runs `lynis audit system`, parses `/var/log/lynis-report.dat` |
| malware | full | rkhunter, chkrootkit |
| docker | full | docker-bench-security, only when Docker exists |

Deferred: OpenSCAP, AIDE, ClamAV, testssl.sh / nikto / nuclei,
debsecan / trivy / grype.
