#!/usr/bin/env bash
#
# Install the RFID Manager services on this machine.
#
# The systemd units, sudoers file and polkit rule need to know which user runs
# the service and where the repo lives. Rather than hardcode that, this script
# detects the invoking user and the repo path and substitutes them in, so the
# project installs cleanly on any Debian host regardless of username or clone
# location.
#
# Usage:
#   sudo bash install.sh
#
set -euo pipefail

# ── who and where ────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "This script writes to /etc and manages services — run it with sudo:" >&2
  echo "  sudo bash install.sh" >&2
  exit 1
fi

TARGET_USER="${SUDO_USER:-}"
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
  echo "Could not determine a non-root user to run the service as." >&2
  echo "Invoke as your normal login, e.g.:  sudo bash install.sh" >&2
  exit 1
fi
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing RFID Manager"
echo "  user : $TARGET_USER"
echo "  path : $REPO_DIR"

# ── dependency check (warn only) ─────────────────────────────────────────────
missing=()
for bin in lsusb nfc-list nfc-mfclassic systemctl; do
  command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo
  echo "WARNING: missing commands: ${missing[*]}"
  echo "Install the runtime dependencies first (see README), e.g.:"
  echo "  sudo apt install libnfc-bin pcscd usbutils"
  echo "  pip3 install fastapi 'uvicorn[standard]' pydantic"
  echo
fi

# ── render + install unit / sudoers / polkit files ───────────────────────────
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for unit in rfid-manager.service rfid-launcher.service; do
  sed -e "s|^User=.*|User=$TARGET_USER|" \
      -e "s|^WorkingDirectory=.*|WorkingDirectory=$REPO_DIR|" \
      "$REPO_DIR/$unit" > "$TMP/$unit"
  install -m 0644 "$TMP/$unit" "/etc/systemd/system/$unit"
  echo "installed /etc/systemd/system/$unit"
done

# sudoers: first column is the username; validate with visudo before installing
sed "s|^user |$TARGET_USER |" "$REPO_DIR/sudoers-rfid-manager" > "$TMP/rfid-manager"
visudo -cf "$TMP/rfid-manager" >/dev/null
install -m 0440 "$TMP/rfid-manager" /etc/sudoers.d/rfid-manager
echo "installed /etc/sudoers.d/rfid-manager"

# polkit rule: grant the same user non-interactive PC/SC access
sed "s|subject.user == \"user\"|subject.user == \"$TARGET_USER\"|" \
    "$REPO_DIR/49-rfid-manager-pcsc.rules" > "$TMP/49-rfid-manager-pcsc.rules"
install -m 0644 "$TMP/49-rfid-manager-pcsc.rules" /etc/polkit-1/rules.d/49-rfid-manager-pcsc.rules
echo "installed /etc/polkit-1/rules.d/49-rfid-manager-pcsc.rules"

# ── enable ───────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now rfid-launcher.service   # manager stays disabled; started on demand

echo
echo "Done. Launcher is enabled on :8029; the manager starts on demand on :8030."
