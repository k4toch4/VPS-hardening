# VPS-Hardening-Verified

![Lynis](https://img.shields.io/badge/Lynis-63%20%E2%86%92%2083-brightgreen)
![Ubuntu](https://img.shields.io/badge/Ubuntu-26.04%20LTS-E95420?logo=ubuntu&logoColor=white)
![Shell](https://img.shields.io/badge/Bash-ShellCheck%20clean-4EAA25?logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

In this project we are hardening an Ubuntu Server from **Lynis hardening index 63 to 83**, measured block by block, verified from outside with **nmap** and packaged as a reusable, self replicated bash script that reproduces the result on a clean install.

The manual hardening reached 83, then the VM was rolled back to a fresh install, `harden.sh` was run alone, and Lynis measured **83 again** with the same 19 open suggestions.

## Results

| Metric | Before (fresh install) | After (`harden.sh`) |
|---|---|---|
| Lynis hardening index | **63** | **83** |
| Lynis suggestions | 42 | 19 |
| Lynis warnings | 0 | 0 |
| SSH password authentication | accepted | refused: `Permission denied (publickey)` |
| Root login over SSH | `prohibit-password` (Ubuntu default) | `no` |
| Incoming firewall policy | none (no packet filter) | deny by default, SSH rate-limited |
| Brute-force protection | none | fail2ban (tested: attacker banned after 3 attempts) |
| Audit trail | none | auditd (CIS-based rules), process accounting |
| File integrity monitoring | none | AIDE baseline + daily check, rkhunter |

### Seen from the outside (nmap from the host)

| Check | Before | After |
|---|---|---|
| Open TCP ports (all 65,535) | 22 | 22 |
| Every other TCP port | `closed` (RST reply) | `filtered` (no response) |
| Top 50 UDP ports | `closed` | `open\|filtered` (no response) |
| SSH version detection (`-sV`) | OpenSSH version disclosed | `tcpwrapped`: no banner returned |
| Unprivileged host discovery | host up | "Host seems down" (needs `-Pn`) |

A default-deny firewall that silently drops packets makes closed ports indistinguishable from non-existent ones, slows down scans, and even hides the host from nmap's default discovery (which probes ports 80/443). During version detection the scanner never received the SSH banner, most likely because its repeated connections to port 22 triggered the UFW rate limit (`limit 22/tcp`) and fail2ban.

### Verification: manual vs. script

Per-test diff between the manual result (`fase2-final`) and the script run on a fresh install (`after-script`):

```diff
< USB-1000: assigned partial number of hardening points (2 of 3)
> USB-1000: assigned maximum number of hardening points for this item (3)
< PKGS-7394: assigned maximum number of hardening points for this item (3)
```

No hardening test scored lower with the script. The only differences: USB-1000 improved (the module blacklist was added after `fase2-final`), and PKGS-7394 did not run because 5 package updates had been published that day: an external factor, not a hardening difference. Points: 275/331 → 273/328, both index **83**.

### Progress per block

Each block was applied manually, measured with Lynis, and snapshotted before moving on.

| # | Block | Main changes | Lynis | Δ |
|---|---|---|---|---|
| 0 | Baseline | Fresh Ubuntu Server 26.04.1 LTS | 63 | — |
| 1 | SSH | Key-only auth, no root login, session limits, `LogLevel VERBOSE` | 71 | +8 |
| 2 | Firewall | UFW default-deny + rate-limited SSH, fail2ban | 73 | +2 |
| 3 | Updates | Full upgrade, unattended security upgrades verified | 74 | +1 |
| 4 | Kernel & network | sysctl hardening, fixed UFW/apport overrides, module blacklist | 73 | −1 |
| 5 | Audit & integrity | auditd rules, acct, AIDE, rkhunter, debsums, apt-show-versions | 80 | +7 |
| 6 | Accounts | Password quality (NIST-based), `login.defs` (umask 027, yescrypt) | 82 | +2 |
| 7 | Final details | Legal banners, cron permissions, compiler restriction, unused services | 83 | +1 |

## Quick start

> ⚠️ **Read before running.** This script disables SSH password login and root login. The account you run it from **must already log in with an SSH key** and belong to the `sudo` group. The script checks this and refuses to continue otherwise, but keep a console (provider web console, `virsh console`, etc.) at hand anyway.

```bash
# 1. From your machine: make sure key login works
ssh-copy-id youruser@your-server

# 2. On the server
git clone https://github.com/k4toch4/VPS-Hardening.git
cd VPS-Hardening-Verified
sudo ./harden.sh --dry-run     # preview every change, nothing is modified
sudo ./harden.sh               # apply
sudo reboot                    # needed for kernel modules and locked audit rules
```

### Options

| Option | Description |
|---|---|
| `-n`, `--dry-run` | Show what would change; change nothing |
| `--only LIST` | Run only these modules, e.g. `--only ssh,firewall` |
| `--skip LIST` | Skip modules, e.g. `--skip integrity` |
| `--admin-user USER` | Account that must keep SSH access (default: the user running `sudo`) |
| `--config-dir DIR` | Directory with the config files (default: `./config`) |
| `--rollback DIR` | Restore the files saved in a backup directory |
| `-l`, `--list` | List modules |

### Modules

| Module | Block | What it does |
|---|---|---|
| `updates` | 3 | `apt upgrade`, ensures unattended security upgrades are on |
| `ssh` | 1 | Installs `sshd_config.d/01-hardening.conf`, validates with `sshd -t`, checks the effective config with `sshd -T` |
| `firewall` | 2 | UFW: deny incoming, allow outgoing, `limit 22/tcp`, IPv6 on |
| `fail2ban` | 2/7 | SSH jail with incremental bans via UFW + systemd sandboxing drop-in |
| `kernel` | 4 | sysctl hardening, fixes values overridden by UFW and apport, blacklists DCCP/SCTP/RDS/TIPC/usb-storage |
| `audit` | 5 | auditd with CIS-based rules, process accounting, AIDE, rkhunter, debsums |
| `accounts` | 6 | `pwquality.conf` and `login.defs` settings |
| `misc` | 7 | Banners, cron ownership/permissions, `dpkg-statoverride` on the assembler, masks unused services |
| `integrity` | 5 | rkhunter and AIDE baselines, taken last so they include every change |

### Safety features

- **Lockout guard**: aborts if the admin user has no SSH public key or no sudo rights.
- **Validation before reload**: `sshd -t` (restores the previous file on failure), `fail2ban-client -t`.
- **Backups**: every file is copied to `/var/backups/vps-hardening/<timestamp>/` before its first change; new files are recorded so a rollback deletes them.
- **Idempotent**: running it again only fixes what drifted (useful after updates, which can silently undo hardening).
- **Context-aware**: keeps `open-vm-tools` on VMware and `multipathd` if multipath devices are in use.
- Full log in `/var/log/vps-hardening.log`.

### Rollback

```bash
sudo ./harden.sh --rollback /var/backups/vps-hardening/<timestamp>
```

Restores every modified file and deletes the ones the script created. Installed packages, UFW rules, masked services and `dpkg-statoverride` entries are intentionally not reverted automatically; original cron permissions are saved in `permissions.txt` inside the backup.

---

## Measuring

[`scripts/audit.sh`](scripts/audit.sh) runs Lynis and stores a **verified** snapshot of the results. It was written after several manual measurements turned out to be wrong (see lessons learned).

```bash
sudo ./scripts/audit.sh after-script fase2-final
```

It refuses to run without root, never overwrites a previous measurement, checks that the Lynis log was produced by *this* run, verifies the copies byte by byte, records the context (UTC date, kernel, Lynis version, pending reboot, upgradable packages) and prints a per-test diff against a previous measurement.

External scans were run **from the host, not from the server**, to see what an attacker sees:

```bash
sudo nmap -sS -sV -p- -T4 --reason -oA reports/<stage>/nmap-tcp <IP>
sudo nmap -sU --top-ports 50 --reason -oA reports/<stage>/nmap-udp <IP>
nmap -Pn -p 22 --script ssh-auth-methods,ssh2-enum-algos -oA reports/<stage>/nmap-ssh <IP>   # -Pn: host hides from discovery after hardening
```
## Methodology

- **Lab**: Ubuntu Server 26.04.1 LTS (kernel 7.0) in a QEMU/KVM virtual machine managed with libvirt, on the default NAT network. Disk images stored in the user's home with ACLs limited to the QEMU user.
- **Fixed tool versions**: the same Lynis release (cloned from the official CISOfy repository and pinned to a tag) was used for every measurement, so scores are comparable. See `reports/*/environment.txt`.
- **Snapshots** before every block, so any change could be measured, compared and reverted.
- **One change set per block**, then a full Lynis run and a saved report.
- **Verification**: rollback to the clean snapshot, `harden.sh` only, same measurement. Matching score and suggestions = reproducible.
- All logs and timestamps are in **UTC**.

---

## Design decisions (what was *not* applied, on purpose)

| Lynis suggestion | Decision | Reason |
|---|---|---|
| AUTH-9282 / AUTH-9286 (password expiry) | Not applied | NIST SP 800-63B advises against forced periodic password changes; they lead to weaker, predictable passwords |
| Composition rules (`minclass`) | Not applied | NIST favors length (15) + blocklist (`dictcheck`) over "one uppercase, one digit" rules. CIS uses `minclass = 4`; both are defensible, this project follows NIST |
| FILE-6310 (separate `/home`, `/var`) | Not applied | Requires reinstalling; recommended for new servers |
| LOGG-2154 (remote logging) | Not applied | No log server in the lab; future work |
| BOOT-5122 (GRUB password) | Not applied | On a VPS, boot-console access belongs to the provider |
| `kernel.modules_disabled = 1` | Not applied | Blocks loading any module until reboot; breaks hardware and services |
| `net.ipv4.tcp_timestamps = 0` | Not applied | Small information-leak gain vs. loss of TCP protections (PAWS) |
| `net.ipv6.conf.*.accept_ra = 0` | Not applied | Many VPS providers configure IPv6 through router advertisements |
| SSH port change | Not applied | Security through obscurity; also needs extra steps with socket activation |
| Automatic reboot after updates | Off | Avoids unplanned downtime; reboots are done manually after checking `/var/run/reboot-required` |
| Egress (outgoing) filtering | Not applied | Outgoing traffic allowed; restricting it would break apt, DNS and NTP without a defined allowlist |

## Evidence

- **fail2ban works, not just runs**: three failed SSH attempts from the host → IP banned and visible both in `fail2ban-client status sshd` and as a `DENY` rule at the top of `ufw status`; unbanned through the console. Repeated after adding the systemd sandbox to confirm the sandbox did not break banning.
- **auditd**: `touch /etc/passwd` → `ausearch -k identity -i` shows who, when and with which command.
- **AIDE**: a test line added to `/etc/hosts` is reported by `aide --check`.
- **SSH**: `ssh -o PubkeyAuthentication=no` → `Permission denied (publickey)`.
- **Firewall from outside**: full TCP scan shows only port 22; everything else, TCP and UDP, gets no response at all.
- **systemd sandboxing**: `systemd-analyze security fail2ban` exposure reduced while banning still works.

## Lessons learned

1. **Measure the measurement.** The first Lynis run scored **1** because Lynis skipped its own tests due to file permissions. Later, a run without `sudo` gave a lower score in non-privileged mode, and several "saved" reports were stale copies of a previous run. All of this led to `audit.sh`.
2. **The score is not the security.** Firewall + fail2ban added only +2; updates +0 to +1; the module blacklist +0 visible points. SSH keys added +8. Lynis also truncates (83.8 % shows as 83), and one unpatched package costs up to 25 points while a module blacklist is worth 1.
3. **The config you write is not always the config that applies.** UFW re-applied its own sysctl file (`log_martians=0`), apport reset `fs.suid_dumpable` to 2, `USERGROUPS_ENAB` turns `UMASK 027` into an effective `007` for users with private groups, and in `sshd_config.d` the **first** value wins.
4. **Hardening can introduce vulnerabilities.** A `chown 755` typed instead of `chmod 755` made a non-existent UID the owner of root's crontab: a potential privilege escalation, and cron silently stopped running system jobs. The next Lynis run caught it (SCHD-7704). Scripts don't make that typo.
5. **When a tool's result doesn't make sense, read its source.** Lynis checks the module blacklist with a strict regex (`^install <module> /bin/(true|false)$`); reading the test code revealed the file on disk was empty.
6. 6. **Updates move the score and can undo hardening.** New security patches published between two runs lowered the index; `apt full-upgrade` can remove packages. An idempotent script can be re-run after updates.
7. **`--no-install-recommends` has side effects.** It skipped `aide-common`, which contains `aideinit` and the configuration.
8. **Evidence must live outside the system under test.** Rolling back a snapshot deletes every report stored inside the VM.

---

## Limitations

- Tested on **Ubuntu Server 26.04 LTS** in a local KVM VM, not on an Internet-exposed VPS (no real attack traffic; provider firewalls not involved).
- A Lynis index is a configuration audit, not a penetration test or a compliance certification.
- The SSH port is assumed to be 22.
- `harden.sh` reproduces this project's configuration; review `config/` before using it on another server.

---

## Repository structure

```
.
├── harden.sh                 # reproducible hardening script
├── config/etc/...            # every config file, at its target path
├── scripts/audit.sh          # verified Lynis measurement
├── reports/                  # Lynis + nmap outputs per stage
└── docs/                     # per-block progress and design decisions
```

## License

[MIT](LICENSE)
