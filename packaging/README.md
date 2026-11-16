# Packaging HomeSentry

The desktop app is the appliance in a window. A Tauri shell (`desktop/`, ~300 lines of Rust)
starts the **frozen backend**, which is the same Python package that runs on the Linux box,
built with PyInstaller. The backend runs on a random `127.0.0.1` port with a one-time session
token, and the shell shows the UI in a native webview. Closing the window leaves monitoring
running from the menu bar. New medium-or-worse timeline events become native notifications.
Nothing listens beyond loopback.

```
HomeSentry.app/Contents/
  MacOS/homesentry-desktop          Tauri shell (Rust)
  Resources/backend/homesentry-backend   frozen Python (uvicorn + FastAPI + zeroconf, ~47 MB)
  Info.plist                        NSLocalNetworkUsageDescription + NSBonjourServices
```

Data lives in `~/Library/Application Support/HomeSentry/` and config in its `config/` subfolder
(mode-600 `.env` files, the same as on Linux). Logs go to `~/Library/Logs/com.vsletten.homesentry/`.

## Build (on a Mac)

```bash
packaging/build-mac-app.sh   # needs uv, cargo, node; ad-hoc signed
```

Output: `desktop/src-tauri/target/release/bundle/{macos/HomeSentry.app,dmg/HomeSentry_*.dmg}`.
PyInstaller doesn't cross-compile, so each architecture builds on its own kind of Mac (CI does
both; see `.github/workflows/mac-app.yml`).

## Local Network permission (macOS 15+)

Apps need the user's OK before they can talk to LAN devices. The first scan makes macOS show
*"HomeSentry would like to find and connect to devices on your local network"*, using the
`NSLocalNetworkUsageDescription` text. If it's denied, sends to LAN addresses fail at once while
internet access keeps working. HomeSentry detects that case
(`netinfo.local_network_blocked`). The scan then changes nothing in the inventory, the UI shows
a red banner with the settings path, and the shell sends one notification. You can change the
choice later in **System Settings → Privacy & Security → Local Network**.

Processes started by `launchd` outside an app bundle (`homesentry service install` from a uv
install) are denied without a prompt. This was verified on macOS 26.6. On a headless Mac mini,
use the app, or run it from Terminal (Terminal's own permission covers its children).

## Signing & notarization (for distribution)

You only need this to hand the app to someone else. Ad-hoc builds run on your own Macs
(right-click → Open the first time).

1. **Certificate.** In the Apple Developer account (team `NZDV3AFAEG`), go to Certificates →
   **Developer ID Application**. Create it in Xcode → Settings → Accounts → Manage
   Certificates → **+** → Developer ID Application, on the Mac that will sign. It lands in the
   login keychain. Check with `security find-identity -v -p codesigning`.
2. **Notary credentials.** Create an app-specific password at appleid.apple.com, then store it
   in the keychain once, so it never sits in a file or a chat:
   `xcrun notarytool store-credentials homesentry-notary --apple-id <id> --team-id NZDV3AFAEG`
3. **Build signed:**
   `APPLE_SIGNING_IDENTITY="Developer ID Application: Victor Sletten (NZDV3AFAEG)" packaging/build-mac-app.sh`
   This signs every Mach-O in the backend with the hardened runtime, then the app.
4. **Notarize + staple:**
   ```bash
   DMG=desktop/src-tauri/target/release/bundle/dmg/HomeSentry_*.dmg
   xcrun notarytool submit $DMG --keychain-profile homesentry-notary --wait
   xcrun stapler staple $DMG
   spctl -a -vvv -t install $DMG     # "accepted, source=Notarized Developer ID"
   ```

The hardened runtime needs no extra entitlements. The backend is a separate signed executable,
not a library the shell loads, and it uses no JIT and no unsigned code.

## Release from CI

`.github/workflows/mac-app.yml` builds both architectures on GitHub's macOS runners whenever a
`v*` tag is pushed (or on demand). Without signing secrets it uploads ad-hoc builds. With these
repository secrets it signs, notarizes and staples:

| secret | what |
|---|---|
| `MACOS_CERT_P12` | base64 of the Developer ID Application cert + key exported as .p12 |
| `MACOS_CERT_PASSWORD` | the .p12 export password |
| `APPLE_ID`, `APPLE_APP_PASSWORD` | notarization login (app-specific password) |
