#!/usr/bin/env bash
# Freeze the Python backend into a self-contained folder (no Python needed on the target).
#   packaging/build-backend.sh            -> dist/homesentry-backend/homesentry-backend
# Run on the OS you are building for (PyInstaller does not cross-compile).
set -euo pipefail
cd "$(dirname "$0")/.."
uv sync -q -p 3.13
rm -rf build/pyi dist/homesentry-backend
uv run --with 'pyinstaller>=6.11' pyinstaller -y --clean --log-level WARN \
  --name homesentry-backend --onedir --noupx \
  --workpath build/pyi --distpath dist --specpath build/pyi \
  --collect-data homesentry \
  --collect-submodules uvicorn \
  --collect-all zeroconf \
  --hidden-import homesentry.web.app \
  --hidden-import homesentry.portscan --hidden-import homesentry.mdns \
  --hidden-import homesentry.sensors --hidden-import homesentry.probe \
  --hidden-import homesentry.service --hidden-import homesentry.netinfo \
  packaging/entry.py
du -sh dist/homesentry-backend
dist/homesentry-backend/homesentry-backend --help | head -3
