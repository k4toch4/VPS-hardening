#!/usr/bin/env bash
# harden.sh - Reproducible hardening for Ubuntu Server (tested on Ubuntu 26.04 LTS).
# Part of VPS-Hardening-Verified: reproduces the manual hardening (Lynis 63 -> 83).
#
# Run it from the admin account, which must ALREADY log in with an SSH key:
#   sudo ./harden.sh --dry-run      # preview every change
#   sudo ./harden.sh                # apply everything
#   sudo ./harden.sh --only ssh,firewall
#   sudo ./harden.sh --rollback /var/backups/vps-hardening/<timestamp>
#
# Every file is backed up before it is touched. The script is idempotent:
# running it again only fixes what drifted (e.g. after package updates).
set -euo pipefail

readonly SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/config"
BACKUP_ROOT=/var/backups/vps-hardening
LOG_FILE=/var/log/vps-hardening.log
SSH_PORT=22

DRY_RUN=0
ONLY=""
SKIP=""
ADMIN_USER="${SUDO_USER:-}"
ROLLBACK_DIR=""
BACKUP_DIR=""
REBOOT_NEEDED=0

# Execution order matters: updates first, integrity baselines (AIDE) last.
MODULES=(updates ssh firewall fail2ban kernel audit accounts misc integrity)

declare -A MODULE_DESC=(
    [updates]="Block 3 - apt upgrade + automatic security updates"
    [ssh]="Block 1 - key-only SSH, no root login, session limits"
    [firewall]="Block 2 - UFW: deny incoming, rate-limited SSH"
    [fail2ban]="Block 2/7 - fail2ban for SSH + systemd sandboxing"
    [kernel]="Block 4 - sysctl, UFW/apport overrides, module blacklist"
    [audit]="Block 5 - auditd rules, process accounting, AIDE, rkhunter"
    [accounts]="Block 6 - password quality (NIST) and login.defs"
    [misc]="Block 7 - banners, cron permissions, compilers, unused services"
    [integrity]="Block 5 - rkhunter and AIDE baselines (slow, runs last)"
)

# Config files (relative to CONFIG_DIR and to /) each module needs.
declare -A MODULE_FILES=(
    [ssh]="etc/ssh/sshd_config.d/01-hardening.conf"
    [fail2ban]="etc/fail2ban/jail.local etc/systemd/system/fail2ban.service.d/override.conf"
    [kernel]="etc/sysctl.d/99-hardening.conf etc/modprobe.d/hardening-blacklist.conf"
    [audit]="etc/audit/rules.d/hardening.rules"
    [accounts]="etc/security/pwquality.conf"
    [misc]="etc/issue etc/issue.net"
)

# =====================================================================
# Helpers
# =====================================================================
log()  { printf '%s\n' "$*"; }
info() { printf '\n==> %s\n' "$*"; }
warn() { printf '    WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Execute a command, or only print it in dry-run mode.
run() {
    if (( DRY_RUN )); then
        printf '    [dry-run] %s\n' "$*"
    else
        printf '    $ %s\n' "$*"
        "$@"
    fi
}

in_list() { [[ ",$2," == *",$1,"* ]]; }

# Prints the unit state ("enabled", "masked"...) or nothing if it does not exist.
unit_state() {
    local s
    s=$(systemctl is-enabled "$1" 2>/dev/null || true)
    [[ "$s" == "not-found" ]] && s=""
    printf '%s' "$s"
}

# Install only the packages that are missing.
apt_install() {
    local missing=() p status
    for p in "$@"; do
        status=$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null || true)
        [[ "$status" == "install ok installed" ]] || missing+=("$p")
    done
    if (( ${#missing[@]} == 0 )); then
        log "    packages already installed: $*"
        return 0
    fi
    # --no-install-recommends keeps the attack surface small; that is why
    # aide-common must be listed explicitly (lesson from block 5).
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        -o Dpkg::Options::=--force-confold "${missing[@]}"
}

# Save a file before its first modification in this run.
# Files that did not exist are recorded so a rollback can delete them.
backup_file() {
    local f="$1"
    if (( DRY_RUN )); then return 0; fi
    [[ -n "$BACKUP_DIR" ]] || die "internal error: backup directory not set"
    if grep -qxF -- "$f" "$BACKUP_DIR/changed.list" "$BACKUP_DIR/created.list" 2>/dev/null; then
        return 0
    fi
    if [[ -e "$f" ]]; then
        cp -a --parents -- "$f" "$BACKUP_DIR/files/"
        printf '%s\n' "$f" >> "$BACKUP_DIR/changed.list"
    else
        printf '%s\n' "$f" >> "$BACKUP_DIR/created.list"
    fi
}

# Undo the change to a single file (used when validation fails).
restore_file() {
    local f="$1"
    if [[ -e "$BACKUP_DIR/files$f" ]]; then
        cp -a -- "$BACKUP_DIR/files$f" "$f"
    else
        rm -f -- "$f"
    fi
}

# Record owner/permissions before changing them (rollback reference).
record_perms() {
    if (( DRY_RUN )); then return 0; fi
    stat -c '%a %U:%G %n' -- "$1" >> "$BACKUP_DIR/permissions.txt"
}

# Copy CONFIG_DIR/<rel> to /<rel> with the given mode, owned by root.
install_file() {
    local rel="$1" mode="$2"
    local src="$CONFIG_DIR/$rel" dst="/$rel"
    [[ -f "$src" ]] || die "missing config file: $src"

    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        if [[ "$(stat -c '%a %U %G' "$dst")" != "${mode#0} root root" ]]; then
            run chown root:root "$dst"
            run chmod "$mode" "$dst"
        else
            log "    unchanged: $dst"
        fi
        return 0
    fi

    if (( DRY_RUN )); then
        log "    [dry-run] would install $dst (mode $mode)"
        if [[ -f "$dst" ]]; then
            diff -u "$dst" "$src" | sed 's/^/      /' || true
        fi
        return 0
    fi

    backup_file "$dst"
    install -D -o root -g root -m "$mode" "$src" "$dst"
    log "    installed: $dst"
}

# Make sure exactly one line matching REGEX exists in FILE and equals LINE.
# Replaces the first match, deletes duplicates, appends if absent.
set_line() {
    local file="$1" regex="$2" line="$3" tmp
    if [[ ! -f "$file" ]]; then
        warn "$file not found, cannot set '$line'"
        return 0
    fi
    tmp=$(mktemp)
    REGEX="$regex" LINE="$line" awk '
        $0 ~ ENVIRON["REGEX"] { if (!done) { print ENVIRON["LINE"]; done = 1 }; next }
        { print }
        END { if (!done) print ENVIRON["LINE"] }
    ' "$file" > "$tmp"

    if cmp -s "$file" "$tmp"; then
        rm -f "$tmp"
        log "    unchanged: $file ($line)"
        return 0
    fi
    if (( DRY_RUN )); then
        log "    [dry-run] $file: set '$line'"
        rm -f "$tmp"
        return 0
    fi
    backup_file "$file"
    cat "$tmp" > "$file"     # keeps the original owner and permissions
    rm -f "$tmp"
    log "    updated: $file ($line)"
}

# Disable and mask a unit, if it exists and is not masked yet.
disable_unit() {
    local u="$1" state
    state=$(unit_state "$u")
    case "$state" in
        "")      log "    not present: $u" ;;
        masked)  log "    already masked: $u" ;;
        *)       run systemctl disable --now "$u"
                 run systemctl mask "$u" ;;
    esac
}

# =====================================================================
# Safety: never lock the admin out
# =====================================================================
check_admin_access() {
    local home ak groups
    [[ -n "$ADMIN_USER" ]] || die "cannot tell who the admin is: run with sudo or pass --admin-user USER"
    [[ "$ADMIN_USER" != "root" ]] || die "admin user cannot be root: root SSH login gets disabled"
    id "$ADMIN_USER" >/dev/null 2>&1 || die "user '$ADMIN_USER' does not exist"

    home=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
    ak="$home/.ssh/authorized_keys"
    if ! grep -qE '^[^#]*(ssh-(ed25519|rsa)|ecdsa-sha2-|sk-(ssh|ecdsa))' "$ak" 2>/dev/null; then
        die "no SSH public key in $ak. Password login is about to be disabled and you would be locked out. Run ssh-copy-id first."
    fi

    groups=" $(id -nG "$ADMIN_USER") "
    if [[ "$groups" != *" sudo "* && "$groups" != *" admin "* ]]; then
        die "'$ADMIN_USER' is not in the sudo group: nobody could administer the server after root login is disabled"
    fi
    log "    lockout guard OK: '$ADMIN_USER' has an SSH key and sudo rights"
}

# =====================================================================
# Modules
# =====================================================================
mod_updates() {
    run apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::=--force-confold
    apt_install unattended-upgrades

    local f=/etc/apt/apt.conf.d/20auto-upgrades
    if [[ ! -f "$f" ]]; then
        if (( DRY_RUN )); then
            log "    [dry-run] would create $f"
        else
            backup_file "$f"
            printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > "$f"
            log "    created: $f"
        fi
    else
        set_line "$f" '^APT::Periodic::Update-Package-Lists[[:space:]]' 'APT::Periodic::Update-Package-Lists "1";'
        set_line "$f" '^APT::Periodic::Unattended-Upgrade[[:space:]]' 'APT::Periodic::Unattended-Upgrade "1";'
    fi
    # Automatic reboot intentionally left at the Ubuntu default (off): see DECISIONS.md
    run systemctl enable --now unattended-upgrades.service
    if [[ -f /var/run/reboot-required ]]; then REBOOT_NEEDED=1; fi
}

mod_ssh() {
    apt_install openssh-server
    check_admin_access
    install_file etc/ssh/sshd_config.d/01-hardening.conf 0644

    if (( ! DRY_RUN )); then
        if ! sshd -t; then
            restore_file /etc/ssh/sshd_config.d/01-hardening.conf
            die "sshd -t rejected the new configuration; previous configuration restored"
        fi
        # In sshd_config.d the FIRST value wins: confirm no other file overrides ours.
        if ! sshd -T 2>/dev/null | grep -qx 'passwordauthentication no'; then
            warn "effective config still allows passwords: check other files in /etc/ssh/sshd_config.d/"
        fi
    fi
    run systemctl try-reload-or-restart ssh.service
}

mod_firewall() {
    apt_install ufw
    set_line /etc/default/ufw '^IPV6=' 'IPV6=yes'
    # The SSH rule is added BEFORE enabling, so the current session survives.
    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw limit "$SSH_PORT/tcp" comment 'SSH with rate limiting'
    run ufw logging low
    run ufw --force enable
}

mod_fail2ban() {
    apt_install fail2ban
    command -v ufw >/dev/null 2>&1 || warn "jail.local uses banaction = ufw, but ufw is not installed"
    install_file etc/fail2ban/jail.local 0644
    install_file etc/systemd/system/fail2ban.service.d/override.conf 0644

    if (( ! DRY_RUN )); then
        local out
        if ! out=$(fail2ban-client -t 2>&1); then
            printf '%s\n' "$out" >&2
            die "fail2ban-client -t rejected the configuration"
        fi
    fi
    run systemctl daemon-reload
    run systemctl enable fail2ban.service
    run systemctl restart fail2ban.service
}

mod_kernel() {
    install_file etc/sysctl.d/99-hardening.conf 0644

    # UFW applies its own sysctl file and resets log_martians to 0 (block 4 finding).
    if [[ -f /etc/ufw/sysctl.conf ]]; then
        set_line /etc/ufw/sysctl.conf '^#?[[:space:]]*net/ipv4/conf/all/log_martians[[:space:]]*=' 'net/ipv4/conf/all/log_martians=1'
        set_line /etc/ufw/sysctl.conf '^#?[[:space:]]*net/ipv4/conf/default/log_martians[[:space:]]*=' 'net/ipv4/conf/default/log_martians=1'
    fi

    # apport resets fs.suid_dumpable to 2 at boot (block 4 finding).
    if [[ -f /etc/default/apport ]]; then
        set_line /etc/default/apport '^enabled=' 'enabled=0'
    fi
    if [[ -n "$(unit_state apport.service)" ]]; then
        run systemctl disable --now apport.service
    fi

    run sysctl -q --system
    if command -v ufw >/dev/null 2>&1 && [[ "$(ufw status 2>/dev/null || true)" == *"Status: active"* ]]; then
        run ufw reload
    fi

    # Uncommon protocols and USB storage (NETW-3200, USB-1000).
    install_file etc/modprobe.d/hardening-blacklist.conf 0644
    if command -v update-initramfs >/dev/null 2>&1; then
        run update-initramfs -u
    elif command -v dracut >/dev/null 2>&1; then
        run dracut -f
    else
        warn "no initramfs tool found: the module blacklist applies after reboot only"
    fi
    REBOOT_NEEDED=1
}

mod_audit() {
    apt_install auditd acct aide aide-common debsums apt-show-versions rkhunter
    install_file etc/audit/rules.d/hardening.rules 0640

    if (( DRY_RUN )); then
        log "    [dry-run] augenrules --load"
    elif [[ "$(auditctl -s 2>/dev/null || true)" == *"enabled 2"* ]]; then
        # -e 2 makes loaded rules immutable: changes need a reboot.
        warn "audit rules are locked (-e 2): new rules load after reboot"
        REBOOT_NEEDED=1
    else
        run augenrules --load
    fi
    run systemctl enable --now auditd.service
    run systemctl enable --now acct.service
    run apt-show-versions -i
}

mod_accounts() {
    apt_install libpam-pwquality
    install_file etc/security/pwquality.conf 0644

    local kv key val
    for kv in "UMASK 027" "USERGROUPS_ENAB yes" "HOME_MODE 0750" \
              "ENCRYPT_METHOD YESCRYPT" "YESCRYPT_COST_FACTOR 5" \
              "SHA_CRYPT_MIN_ROUNDS 5000" "SHA_CRYPT_MAX_ROUNDS 50000"; do
        key=${kv%% *}
        val=${kv#* }
        set_line /etc/login.defs "^[[:space:]]*${key}([[:space:]]|\$)" "$(printf '%s\t%s' "$key" "$val")"
    done
    # PASS_MAX_DAYS / PASS_MIN_DAYS intentionally untouched: NIST SP 800-63B
    # advises against forced periodic password changes (see DECISIONS.md).
}

mod_misc() {
    # Legal banners without OS version (BANN-7126, BANN-7130).
    install_file etc/issue 0644
    install_file etc/issue.net 0644

    # Cron: owned by root, closed permissions (FILE-7524, SCHD-7704).
    # Uses chown root:root explicitly: a wrong owner here allows privilege escalation.
    local p want
    for p in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [[ -e "$p" ]] || continue
        if [[ -d "$p" ]]; then want=700; else want=600; fi
        if [[ "$(stat -c '%a %U %G' "$p")" == "$want root root" ]]; then
            log "    unchanged: $p ($want root:root)"
        else
            record_perms "$p"
            run chown root:root "$p"
            run chmod "$want" "$p"
        fi
    done

    # Compilers/assemblers only for root (HRDN-7222). dpkg-statoverride
    # survives package upgrades, a plain chmod would not.
    local c bin real seen=" "
    for c in as cc gcc; do
        bin=$(command -v "$c" 2>/dev/null) || continue
        real=$(readlink -f "$bin")
        [[ "$seen" == *" $real "* ]] && continue     # cc and gcc may be the same binary
        seen+="$real "
        if dpkg-statoverride --list "$real" >/dev/null 2>&1; then
            log "    statoverride already set: $real"
        else
            run dpkg-statoverride --update --add root root 0750 "$real"
        fi
    done

    # Services with no use on this server (BOOT-5264).
    local virt
    virt=$(systemd-detect-virt 2>/dev/null || true)
    disable_unit ModemManager.service
    if [[ "$virt" == "vmware" ]]; then
        log "    keeping open-vm-tools: running on VMware"
    else
        disable_unit open-vm-tools.service
    fi
    disable_unit iscsid.socket
    disable_unit iscsid.service
    if command -v multipath >/dev/null 2>&1 && [[ -n "$(multipath -ll 2>/dev/null || true)" ]]; then
        warn "multipath devices in use: keeping multipathd"
    else
        disable_unit multipathd.socket
        disable_unit multipathd.service
    fi
}

mod_integrity() {
    # Baselines must be taken LAST, once every other change is in place.
    if (( DRY_RUN )); then
        log "    [dry-run] rkhunter --propupd --nocolors"
        log "    [dry-run] aideinit -y -f   (several minutes)"
        return 0
    fi
    if command -v rkhunter >/dev/null 2>&1; then
        run rkhunter --propupd --nocolors
    else
        warn "rkhunter not installed: run the 'audit' module first"
    fi
    if command -v aideinit >/dev/null 2>&1; then
        log "    building the AIDE database: several minutes, no progress output"
        run aideinit -y -f
    else
        warn "aideinit not found: is aide-common installed?"
    fi
}

# =====================================================================
# Rollback
# =====================================================================
do_rollback() {
    local d="$ROLLBACK_DIR" f
    [[ -d "$d/files" ]] || die "not a harden.sh backup directory: $d"
    info "Restoring files from $d"

    if (( DRY_RUN )); then
        find "$d/files" -type f -printf '    [dry-run] restore /%P\n'
        if [[ -s "$d/created.list" ]]; then
            sed 's/^/    [dry-run] remove /' "$d/created.list"
        fi
        return 0
    fi

    cp -a "$d/files/." /
    find "$d/files" -type f -printf '    restored: /%P\n'
    if [[ -s "$d/created.list" ]]; then
        while IFS= read -r f; do
            if [[ -n "$f" ]]; then
                rm -f -- "$f"
                log "    removed: $f"
            fi
        done < "$d/created.list"
    fi
    systemctl daemon-reload || warn "systemctl daemon-reload failed"

    cat <<EOF

Files restored. NOT undone automatically (by design, review manually):
  - installed packages, UFW rules, masked services, dpkg-statoverride entries
  - cron ownership/permissions: original values in $d/permissions.txt
Next: sudo systemctl restart ssh fail2ban; sudo sysctl --system; then reboot.
EOF
}

# =====================================================================
# CLI
# =====================================================================
usage() {
    cat <<EOF
harden.sh $SCRIPT_VERSION - reproducible hardening for Ubuntu Server

Usage: sudo $0 [options]

Options:
  -n, --dry-run          Show what would change, change nothing
      --only LIST        Run only these modules (comma separated)
      --skip LIST        Skip these modules (comma separated)
      --admin-user USER  Account that must keep SSH access (default: \$SUDO_USER)
      --config-dir DIR   Directory with the config files (default: $CONFIG_DIR)
      --rollback DIR     Restore the files saved in a backup directory
  -l, --list             List modules and exit
  -h, --help             Show this help

Backups: $BACKUP_ROOT/<timestamp>/    Log: $LOG_FILE
EOF
}

list_modules() {
    local m
    for m in "${MODULES[@]}"; do
        printf '  %-10s %s\n' "$m" "${MODULE_DESC[$m]}"
    done
}

parse_args() {
    while (( $# )); do
        case "$1" in
            -n|--dry-run)  DRY_RUN=1 ;;
            --only)        ONLY="${2:?--only needs a list}"; shift ;;
            --skip)        SKIP="${2:?--skip needs a list}"; shift ;;
            --admin-user)  ADMIN_USER="${2:?--admin-user needs a user}"; shift ;;
            --config-dir)  CONFIG_DIR="${2:?--config-dir needs a directory}"; shift ;;
            --rollback)    ROLLBACK_DIR="${2:?--rollback needs a directory}"; shift ;;
            -l|--list)     list_modules; exit 0 ;;
            -h|--help)     usage; exit 0 ;;
            *)             usage >&2; die "unknown option: $1" ;;
        esac
        shift
    done
}

main() {
    parse_args "$@"
    [[ $EUID -eq 0 ]] || die "must run as root: sudo $0 $*"

    if [[ -n "$ROLLBACK_DIR" ]]; then
        do_rollback
        exit 0
    fi

    # Validate module names.
    local m name selected=()
    for name in ${ONLY//,/ } ${SKIP//,/ }; do
        [[ -n "${MODULE_DESC[$name]+x}" ]] || die "unknown module '$name' (see --list)"
    done
    for m in "${MODULES[@]}"; do
        if [[ -n "$ONLY" ]] && ! in_list "$m" "$ONLY"; then continue; fi
        if [[ -n "$SKIP" ]] && in_list "$m" "$SKIP"; then continue; fi
        selected+=("$m")
    done
    (( ${#selected[@]} > 0 )) || die "no modules selected"

    # Fail early if a config file is missing, before touching anything.
    local rel
    for m in "${selected[@]}"; do
        for rel in ${MODULE_FILES[$m]:-}; do
            [[ -f "$CONFIG_DIR/$rel" ]] || die "module '$m' needs $CONFIG_DIR/$rel"
        done
    done

    local os_id os_name
    # shellcheck disable=SC1091  # system file, not part of this repo
    os_id=$( . /etc/os-release && echo "${ID:-unknown}" )
    # shellcheck disable=SC1091
    os_name=$( . /etc/os-release && echo "${PRETTY_NAME:-unknown}" )
    [[ "$os_id" == "ubuntu" ]] || warn "tested on Ubuntu only, this is: $os_name"

    if (( ! DRY_RUN )); then
        BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$BACKUP_DIR/files"
        chmod 700 "$BACKUP_ROOT" "$BACKUP_DIR"
        touch "$BACKUP_DIR/changed.list" "$BACKUP_DIR/created.list"
        exec > >(tee -a "$LOG_FILE") 2>&1
    fi

    info "harden.sh $SCRIPT_VERSION on $os_name ($(date -u '+%Y-%m-%d %H:%M:%S') UTC)"
    log "    modules: ${selected[*]}"
    if (( DRY_RUN )); then log "    DRY RUN: nothing will be changed"; fi
    if [[ -n "$BACKUP_DIR" ]]; then log "    backups: $BACKUP_DIR"; fi

    for m in "${selected[@]}"; do
        info "[$m] ${MODULE_DESC[$m]}"
        "mod_$m"
    done

    info "Done"
    if (( DRY_RUN )); then
        log "    dry run finished: run without --dry-run to apply"
    else
        log "    backups saved in $BACKUP_DIR (undo: sudo $0 --rollback $BACKUP_DIR)"
        log "    log: $LOG_FILE"
    fi
    if (( REBOOT_NEEDED )); then
        log "    REBOOT REQUIRED for kernel modules / audit rules / updates: sudo reboot"
    fi
    log "    then measure: sudo ./scripts/audit.sh <label> [previous-label]"
}

# Allow sourcing the file (for tests) without running main.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
