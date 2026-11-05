#!/usr/bin/env bash
# audit.sh - Run Lynis and store a verified snapshot of its results.
#
# Usage:   sudo ./audit.sh <label> [previous-label]
# Example: sudo ./audit.sh fase2-final
#          sudo ./audit.sh after-script fase2-final   # also diffs against it
#
# Output in $REPORT_ROOT/<label>/:
#   lynis.log, lynis-report.dat  verified copies of the Lynis output
#   lynis-stdout.txt             what Lynis printed on screen
#   environment.txt              context of the measurement (date, OS, updates...)
#   points.txt                   hardening points assigned per test ID
#   summary.txt                  index, points, warnings, suggestions
#   diff-vs-<previous>.txt       per-test changes (only if previous-label given)
#
# Environment overrides: LYNIS_DIR, REPORT_ROOT
set -euo pipefail

# ---------- Configuration ----------
# Under sudo, $HOME points to /root. SUDO_USER holds the user who ran sudo,
# so we look up THAT user's home to find Lynis and store the reports.
REAL_USER="${SUDO_USER:-root}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
LYNIS_DIR="${LYNIS_DIR:-$REAL_HOME/lynis}"
REPORT_ROOT="${REPORT_ROOT:-$REAL_HOME/reports}"

# Lynis always writes its results here (system log location, root-only).
LOG=/var/log/lynis.log
DAT=/var/log/lynis-report.dat

LABEL="${1:-}"
PREV="${2:-}"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# ---------- 1. Preconditions ----------
# Without root, Lynis runs in non-privileged mode: fewer tests, lower score,
# and it does not update /var/log/lynis.log.
[[ $EUID -eq 0 ]] || die "must run as root: sudo $0 <label> [previous-label]"
[[ -n "$LABEL" ]] || die "usage: sudo $0 <label> [previous-label]"
[[ "$LABEL" =~ ^[A-Za-z0-9._-]+$ ]] || die "label may only contain letters, digits, '.', '_' and '-'"
[[ -x "$LYNIS_DIR/lynis" ]] || die "lynis not found in $LYNIS_DIR (set LYNIS_DIR=/path/to/lynis)"

DEST="$REPORT_ROOT/$LABEL"
# Never overwrite a previous measurement.
if [[ -e "$DEST" ]]; then
    die "$DEST already exists; choose another label"
fi
if [[ -n "$PREV" && ! -f "$REPORT_ROOT/$PREV/points.txt" ]]; then
    die "previous measurement '$PREV' not found in $REPORT_ROOT"
fi

# If anything fails from here on, remove the half-written folder so the
# label can be reused and no incomplete measurement is left behind.
COMPLETED=0
cleanup() {
    if [[ $COMPLETED -ne 1 ]]; then
        rm -rf -- "$DEST"
    fi
}
trap cleanup EXIT

# ---------- 2. Run Lynis ----------
mkdir -p "$DEST"
START=$(date +%s)
info "Running Lynis (takes a few minutes)..."
# --quick: no pauses waiting for Enter. --no-colors: clean text output.
set +e
( cd "$LYNIS_DIR" && ./lynis audit system --quick --no-colors ) > "$DEST/lynis-stdout.txt" 2>&1
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
    echo "WARNING: Lynis exited with code $RC (see lynis-stdout.txt); validating its log anyway" >&2
fi

# ---------- 3. Verify the log comes from THIS run ----------
[[ -f "$LOG" && -f "$DAT" ]] || die "Lynis did not produce $LOG and $DAT"
[[ $(stat -c %Y "$LOG") -ge $START ]] || die "$LOG was not updated by this run (stale log)"
[[ $(stat -c %Y "$DAT") -ge $START ]] || die "$DAT was not updated by this run (stale report)"

# ---------- 4. Copy and verify the copies ----------
cp -p "$LOG" "$DAT" "$DEST/"
cmp -s "$LOG" "$DEST/lynis.log"        || die "copy of lynis.log does not match the original"
cmp -s "$DAT" "$DEST/lynis-report.dat" || die "copy of lynis-report.dat does not match the original"

# ---------- 5. Context of the measurement ----------
# External factors (pending updates, pending reboot) change the score
# without any configuration change; record them with every measurement.
# shellcheck disable=SC1091  # system file, not part of this repo
os_name() { ( . /etc/os-release && echo "$PRETTY_NAME" ); }
if [[ -f /var/run/reboot-required ]]; then REBOOT=yes; else REBOOT=no; fi
if command -v apt-show-versions >/dev/null 2>&1; then
    UPGRADABLE=$(apt-show-versions -u 2>/dev/null | wc -l || true)
else
    UPGRADABLE="n/a (apt-show-versions not installed)"
fi
{
    echo "label:               $LABEL"
    echo "date_utc:            $(date -u '+%Y-%m-%d %H:%M:%S')"
    echo "hostname:            $(hostname)"
    echo "os:                  $(os_name)"
    echo "kernel:              $(uname -r)"
    echo "lynis_version:       $(grep '^lynis_version=' "$DAT" | cut -d= -f2 || true)"
    echo "reboot_required:     $REBOOT"
    echo "upgradable_packages: $UPGRADABLE"
} > "$DEST/environment.txt"

# ---------- 6. Points per test ----------
# One line per scored test, e.g. "SSH-7408: assigned maximum number of hardening points for this item (3)"
awk '
    /Performing test ID/ { match($0, /[A-Z]+-[0-9]+/); id = substr($0, RSTART, RLENGTH) }
    /Hardening: assigned/ {
        line = $0
        sub(/.*Hardening: /, "", line)
        sub(/\. Currently.*/, "", line)
        print id ": " line
    }
' "$LOG" > "$DEST/points.txt"

# ---------- 7. Summary ----------
INDEX=$(grep '^hardening_index=' "$DAT" | cut -d= -f2 || true)
TOTALS=$(grep -o 'Currently having [0-9]* points (out of [0-9]*)' "$LOG" | tail -1 || true)
POINTS=$(sed -E 's/.*having ([0-9]+) points.*/\1/' <<< "$TOTALS")
MAX=$(sed -E 's/.*out of ([0-9]+).*/\1/' <<< "$TOTALS")
WARNINGS=$(grep -c '^warning\[\]=' "$DAT" || true)
SUGGESTIONS=$(grep -c '^suggestion\[\]=' "$DAT" || true)

{
    echo "Hardening index: ${INDEX:-?}"
    echo "Points:          ${POINTS:-?} of ${MAX:-?}"
    echo "Warnings:        $WARNINGS"
    echo "Suggestions:     $SUGGESTIONS"
    echo "Reboot pending:  $REBOOT"
    echo "Upgradable pkgs: $UPGRADABLE"
} | tee "$DEST/summary.txt"

# ---------- 8. Optional comparison ----------
if [[ -n "$PREV" ]]; then
    DIFF_FILE="$DEST/diff-vs-$PREV.txt"
    diff "$REPORT_ROOT/$PREV/points.txt" "$DEST/points.txt" > "$DIFF_FILE" || true
    echo
    info "Per-test changes vs '$PREV' (< before, > now):"
    if [[ -s "$DIFF_FILE" ]]; then
        cat "$DIFF_FILE"
    else
        echo "(no changes in per-test points)"
    fi
fi

# ---------- 9. Hand the files back to the real user ----------
chown -R "$REAL_USER": "$DEST"
COMPLETED=1
echo
info "Saved to $DEST"
