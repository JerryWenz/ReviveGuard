#!/usr/bin/env bash
# ReviveGuard installer for Debian/Ubuntu. Run as root.
#
#   curl -fsSLO https://raw.githubusercontent.com/JerryWenz/ReviveGuard/<ref>/install.sh
#   less install.sh            # read it first (press q to quit the viewer)
#   sudo bash install.sh
#
# What it does (and asks before doing it):
#   1. installs python3, python3-venv, ca-certificates with apt (only what is missing)
#   2. creates a virtualenv in /opt/reviveguard and installs ReviveGuard into it
#   3. links /usr/local/bin/reviveguard
#   4. runs a read-only audit
# It never changes SSH, firewall or any other system configuration.
#
# Options: --yes (no prompt)  --no-audit  --help
# Environment: REVIVEGUARD_REF (git ref, default below), REVIVEGUARD_SRC (local path or URL to
# install from instead), REVIVEGUARD_PREFIX (default /opt/reviveguard), REVIVEGUARD_BIN_DIR.
set -euo pipefail

REF="${REVIVEGUARD_REF:-claude/quirky-franklin-vnj8hz}" # switch to a release tag/main once merged
REPO="JerryWenz/ReviveGuard"
PREFIX="${REVIVEGUARD_PREFIX:-/opt/reviveguard}"
BIN_DIR="${REVIVEGUARD_BIN_DIR:-/usr/local/bin}"
SRC="${REVIVEGUARD_SRC:-https://github.com/${REPO}/archive/${REF}.tar.gz}"
ASSUME_YES=0
RUN_AUDIT=1

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --yes|-y) ASSUME_YES=1 ;;
    --no-audit) RUN_AUDIT=0 ;;
    --help|-h) sed -n '2,17p' "$0"; exit 0 ;;
    *) die "unknown option: $arg" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash install.sh)"
[ -r /etc/os-release ] || die "cannot detect the operating system"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}${ID_LIKE:-}" in
  *debian*|*ubuntu*) ;;
  *) die "unsupported system '${PRETTY_NAME:-unknown}': Debian/Ubuntu only" ;;
esac

# Python >= 3.10 and the venv module are required.
python_ok() {
  command -v python3 >/dev/null 2>&1 &&
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null &&
    python3 -c 'import venv, ensurepip' 2>/dev/null
}
NEED_PKGS=()
python_ok || NEED_PKGS+=(python3 python3-venv)
[ -e /etc/ssl/certs/ca-certificates.crt ] || NEED_PKGS+=(ca-certificates)

say "ReviveGuard installer on ${PRETTY_NAME:-this system}"
say "  install into : ${PREFIX} (virtualenv), command: ${BIN_DIR}/reviveguard"
say "  source       : ${SRC}"
if [ "${#NEED_PKGS[@]}" -gt 0 ]; then
  say "  apt packages : ${NEED_PKGS[*]} (missing, will be installed; 'apt-get update' runs first)"
else
  say "  apt packages : none needed"
fi
say "  then         : $([ "$RUN_AUDIT" -eq 1 ] && echo 'read-only audit' || echo 'no audit')"

if [ "$ASSUME_YES" -ne 1 ]; then
  [ -t 0 ] || die "no terminal for confirmation; re-run with --yes"
  printf 'Continue? [y/N] '
  read -r answer
  case "$answer" in y|Y|yes|YES) ;; *) say "Cancelled. Nothing was changed."; exit 1 ;; esac
fi

if [ "${#NEED_PKGS[@]}" -gt 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends "${NEED_PKGS[@]}"
  python_ok || die "Python >= 3.10 with venv is still unavailable (this release needs 3.10+)"
fi

python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --quiet --upgrade pip
"$PREFIX/venv/bin/python" -m pip install --quiet "$SRC"
mkdir -p "$BIN_DIR"
ln -sf "$PREFIX/venv/bin/reviveguard" "$BIN_DIR/reviveguard"

"$BIN_DIR/reviveguard" --version
say
say "Installed. Useful commands:"
say "  reviveguard audit      # read-only report"
say "  reviveguard fix        # review and apply fixes one by one (asks before every change)"
say "  reviveguard history    # what was changed;  reviveguard rollback  # undo file changes"
if [ "$RUN_AUDIT" -eq 1 ]; then
  say
  "$BIN_DIR/reviveguard" audit || true
fi
