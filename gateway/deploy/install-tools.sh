#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Error: run this script as root (e.g. sudo bash install-tools.sh)." >&2
  exit 1
fi

echo "Updating apt package index..."
DEBIAN_FRONTEND=noninteractive apt-get update

echo "Pre-configuring non-interactive dumpcap capability prompt (no setuid)..."
echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections

echo "Installing required diagnostic binaries: nmap and tshark..."
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nmap tshark

echo "Verifying binaries on PATH..."
for bin in nmap tshark; do
  resolved="$(command -v "${bin}" || true)"
  if [[ -z "${resolved}" ]]; then
    echo "Verification failed: ${bin} was not found on PATH." >&2
    exit 1
  fi
  echo "OK: ${bin} -> ${resolved} ($("${bin}" --version | head -n 1))"
done

echo "Required tools installed successfully."
