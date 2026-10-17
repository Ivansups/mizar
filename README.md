# sigma-audit

A read-only security audit for Linux servers. It looks at SSH, the firewall,
listening ports, pending updates, login history, file permissions and, when
installed, Lynis, rkhunter, chkrootkit and docker-bench-security. It never
changes the system and never installs anything.

> Use it only on servers you own or have permission to scan. Scanning other
> people's hosts, for example with nmap, may be illegal.

## Install

Needs Python 3.8 or newer, which every current Debian, Ubuntu and RHEL ships.

```bash
curl -LO https://github.com/Ivansups/sigma-audit/releases/latest/download/sigma-audit
curl -LO https://github.com/Ivansups/sigma-audit/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS && sudo install -m 755 sigma-audit /usr/local/bin/sigma-audit
```

## Run

```bash
sudo sigma-audit
```

That runs the `standard` profile (passive checks only), prints a summary and
saves `report.json` and `report.txt` to `./sigma-reports/<host>-<time>/`.
Without root the checks that need it are reported as `SKIPPED (no_privileges)`.

## Statuses

| Status | Meaning |
|---|---|
| `OK` | check passed |
| `WARN` / `CRIT` | a problem was found |
| `SKIPPED` | not checked: `tool_missing`, `not_applicable`, `no_privileges`, `timeout` or `not_enabled` |
| `ERROR` | the check itself failed |

A skipped check is never counted as passed. The report ends with coverage,
for example `34 executed, 7 skipped, 0 errors`.

## Usage

```
sigma-audit [run] [--profile quick|standard|full] [--modules a,b] [--skip x,y]
            [--format text|json] [--output DIR] [--no-save]
            [--min-severity ok|warn|crit] [--active] [--target HOST]
            [--timeout SEC] [--strict] [--no-color] [-q] [-v]
sigma-audit list      # modules and the tools they use
sigma-audit doctor    # which optional tools are installed
sigma-audit report FILE.json
```

`--active` enables the nmap scan of `--target` (default `127.0.0.1`).

Exit codes: `0` clean, `1` WARN, `2` CRIT, `3` a check errored or bad usage,
`4` `--strict` and some checks were skipped.

## Modules

| Module | Profile | Optional tool |
|---|---|---|
| ssh | quick | ssh-audit |
| firewall | quick | ufw / nft / iptables |
| network | standard | |
| nmap | standard, `--active` | nmap |
| packages | standard | needrestart |
| logs | standard | |
| filesystem | standard | |
| lynis | standard | lynis |
| malware | full | rkhunter, chkrootkit |
| docker | full | docker-bench-security |

Planned: OpenSCAP, AIDE, ClamAV, testssl.sh / nikto / nuclei, trivy / grype.

## Develop

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
scripts/build.sh
```

Runtime code uses only the standard library and must stay compatible with
Python 3.8.

## License

MIT
