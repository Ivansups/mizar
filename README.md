# mizar

A read-only security audit for Linux servers. It looks at SSH, the firewall,
listening ports, pending updates, login history, file permissions and, when
installed, Lynis, rkhunter, chkrootkit and docker-bench-security. It never
changes the system and never installs anything.

> Use it only on servers you own or have permission to scan. Scanning other
> people's hosts, for example with nmap, may be illegal.

## Install

Needs Python 3.8 or newer, which every current Debian, Ubuntu and RHEL ships.

```bash
curl -LO https://github.com/Ivansups/mizar/releases/latest/download/mizar
curl -LO https://github.com/Ivansups/mizar/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS && sudo install -m 755 mizar /usr/local/bin/mizar
```

## Run

```bash
sudo mizar
```

That runs the `standard` profile (passive checks only), prints a summary and
saves `report.json` and `report.txt` to `./mizar-reports/<host>-<time>/`.
Without root the checks that need it are reported as `SKIPPED (no_privileges)`.

## Use with AI agents

A skill for Claude Code and an `AGENTS.md` for other agents are included.

```
/plugin marketplace add Ivansups/mizar
/plugin install mizar@mizar
```

Or copy the skill by hand:

```bash
mkdir -p ~/.claude/skills/mizar
curl -fsSL https://raw.githubusercontent.com/Ivansups/mizar/master/skills/mizar/SKILL.md \
  -o ~/.claude/skills/mizar/SKILL.md
```

The skill does not install `mizar` itself; install the CLI as shown above.

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
mizar [run] [--profile quick|standard|full] [--modules a,b] [--skip x,y]
            [--format text|json] [--output DIR] [--no-save]
            [--min-severity ok|warn|crit] [--active] [--target HOST]
            [--timeout SEC] [--strict] [--no-color] [-q] [-v]
mizar list      # modules and the tools they use
mizar doctor    # which optional tools are installed
mizar report FILE.json
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

Full suite against a real system (Ubuntu 20.04, Python 3.8, with lynis, nmap,
ssh-audit, rkhunter, chkrootkit and the rest installed):

```bash
docker build -f docker/Dockerfile.test -t mizar-test .
docker run --rm mizar-test
```

Runtime code uses only the standard library and must stay compatible with
Python 3.8.

## License

MIT
