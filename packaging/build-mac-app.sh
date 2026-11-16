#!/usr/bin/env bash
# Build HomeSentry.app + .dmg on a Mac (Apple Silicon or Intel builds its own arch).
#   packaging/build-mac-app.sh
# Needs: uv, Rust (cargo), Node/npm, Xcode Command Line Tools.
# Signing: ad-hoc ("-") by default, fine for your own Macs. For distribution set
#   APPLE_SIGNING_IDENTITY="Developer ID Application: <Name> (<TEAMID>)"
# and notarize the dmg afterwards (see packaging/README.md).
set -euo pipefail
cd "$(dirname "$0")/.."
ident=${APPLE_SIGNING_IDENTITY:--}

echo "== backend (frozen Python)"
packaging/build-backend.sh >/dev/null
# every Mach-O inside the bundle must be signed (ad-hoc or Developer ID) or Gatekeeper and
# notarization reject the app; Tauri signs only its own binary
# Hardened runtime only with a real identity: under ad-hoc signing every binary is its own
# "team", so library validation refuses to load libpython into the backend.
if [[ "$ident" == "-" ]]; then sign=(codesign --force -s -); else
  sign=(codesign --force --timestamp --options runtime -s "$ident"); fi
find dist/homesentry-backend -type f \( -perm -u+x -o -name '*.dylib' -o -name '*.so' \) -print0 |
  while IFS= read -r -d '' f; do
    if file -b "$f" | grep -q Mach-O; then "${sign[@]}" "$f"; fi
  done

echo "== icon"
uv run python packaging/make_icon.py desktop/app-icon.png
cd desktop
npm install --no-audit --no-fund --silent
npx tauri icon app-icon.png -o src-tauri/icons >/dev/null

echo "== app"
if [[ "$ident" != "-" ]]; then
  export APPLE_SIGNING_IDENTITY="$ident"
else
  export APPLE_SIGNING_IDENTITY="-"
fi
npx tauri build --bundles app
cd src-tauri/target/release/bundle

echo "== dmg"
# plain hdiutil image: Tauri's DMG step scripts Finder over AppleScript, which times out
# headless (SSH, launchd) - this works anywhere
ver=$(plutil -extract CFBundleShortVersionString raw macos/HomeSentry.app/Contents/Info.plist)
arch=$(uname -m)
stage=$(mktemp -d)
cp -R macos/HomeSentry.app "$stage/"
ln -s /Applications "$stage/Applications"
mkdir -p dmg
rm -f "dmg/HomeSentry_${ver}_${arch}.dmg"
hdiutil create -quiet -volname HomeSentry -srcfolder "$stage" -fs HFS+ -format UDZO \
  -ov "dmg/HomeSentry_${ver}_${arch}.dmg"
rm -rf "$stage"
if [[ "$ident" != "-" ]]; then codesign --force --timestamp -s "$ident" dmg/*.dmg; fi
codesign -v --deep --strict macos/HomeSentry.app && echo "app signature OK ($ident)"
ls -la macos/ dmg/
