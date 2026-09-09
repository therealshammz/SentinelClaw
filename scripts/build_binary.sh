#!/usr/bin/env sh
# Build a standalone SentinelClaw binary with PyInstaller (P6-29).
#
# Usage:
#   scripts/build_binary.sh [extra PyInstaller args...]
#
# Produces:
#   dist/sentinelclaw          (Linux)
#   dist/sentinelclaw          (macOS)
#
# Windows binaries are built with scripts/build_binary.ps1 (or the CI
# build job, which uploads the .exe as an artifact).
#
# Optional runtime extras (pcap, evtx, yara) are only bundled when they
# are importable in this environment; install them first to include
# them, e.g.: python3 -m pip install -e ".[build,pcap,evtx,yara]"
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

python3 -m pip install -e ".[build]"

python3 -m PyInstaller --noconfirm --clean packaging/sentinelclaw.spec "$@"

echo
echo "Built: $(ls -1 dist/sentinelclaw 2>/dev/null || true)"
echo "Smoke test: dist/sentinelclaw --help"
