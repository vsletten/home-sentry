# home-sentry

Local-first home network security appliance: discover every device, identify it
(rules, learned KB, AI-guided photo wizard), build threat profiles, watch for change, and
turn it all into a score and a short, ranked list of things to actually do.

**Privacy line:** the inventory, photos and evidence stay on the box
(`~/.local/share/homesentry/`). Only wizard inference requests leave, and those carry
the MAC *vendor* only, never MACs, IPs or serials. UPnP serial numbers are never collected.

## Shape

```
discover (ARP sweep · mDNS · SSDP/UPnP · port/service scan · gateway reader · tailscale;
          unprivileged, built in: no nmap, no avahi; Linux + macOS)
   → evidence (SQLite)
   → identify (deterministic rules + learned KB)        ← no LLM, free, instant
   → wizard  (photo → vision reader → transcript; glm-5.3 reasons)  ← what rules can't pin
   → confirm (locks identity, teaches the KB)
   → threats (exposure rules · EOL kernels + OS releases · CVE leads: NVD + CISA KEV)
   → watch   (snapshot before/after every scan → diff → timeline events → optional push)
   → plan    (posture score 0-100 · findings → playbooks → actions ranked by gain/minute)
   → ask     (household analyst over the whole picture, devices as opaque handles)
```

| Page | What it's for |
|---|---|
| **Overview** | Score gauge + trend, the next three actions, recent changes, devices by network |
| **Plan** | Every action ranked by score gained per minute, with steps, the devices it covers, a score ladder, and *accept risk* (with a reason) for things you won't fix |
| **Map** | Server-rendered SVG topology, zero JS: lanes by role, color = worst risk, and dashed *hidden network* pockets for boxes that NAT their own clients |
| **Timeline** | New devices, ports opening/closing, firmware updates, findings appearing/escalating/resolving, infrastructure going dark |
| **Ask** | "What should I fix first?" Chat with an analyst that sees the whole house |
| **Report** | One printable page (`homesentry report -o x.html`): score, plan, week's changes, inventory, blind spots |
| **Guides** | Local runbooks (e.g. a Wi-Fi cutover), strict slug names, read-only |

**Monitoring.** `homesentry watch` is one tick: quick scan always, port scan every 12h,
gateway read every 6h, outside-in every 24h (each only if configured). Every scan diffs a
before/after snapshot into the timeline. The first port scan of a device is a baseline (no
"port opened" storm), a failed port scan is never read as "everything closed", and only
infrastructure (gateway, NAS, APs...) going offline is news: laptops sleeping isn't.
A file lock keeps the timer and the Scan button from racing.

**Score.** 100 minus a weight per open finding (critical 10 · high 5 · medium 2 · low 0.5).
Each device's total saturates smoothly toward 18, so one hopeless box can't sink the house
alone but every fix on it still moves the score. Unidentified devices cost 1 each (max 6).
Accepted risks don't count, and they're keyed by finding *identity*: the CVE count rising
doesn't resurrect them, a different version does.

**Playbooks** (`src/homesentry/kbdata/playbooks.yaml`, override or extend with
`~/.local/share/homesentry/kb/playbooks.yaml`) map findings to plain-language actions with
effort, who does it, and steps. A device-level playbook (e.g. *cloud-managed ISP Wi-Fi:
replace it*) claims every finding on that device, so you get one real fix instead of six
symptoms. Household playbooks group the same fix across devices ("update the two Macs").

**Ask HomeSentry's privacy line.** The analyst gets the inventory as opaque handles (`[D7]`)
plus type, make, model, firmware and findings, never labels, hostnames, IPs or MACs. Your
question is rewritten the same way before it leaves (names → handles, any IP/MAC →
redacted), and the answer is turned back into clickable device names locally.

**Alerts (optional).** `~/.config/homesentry/notify.env` (mode 600) with
`NOTIFY_URL=` (an ntfy topic or any webhook), optional `NOTIFY_TOKEN=`,
`NOTIFY_MIN_SEVERITY=medium`. A push leaves the house, so it names devices by *type* only
("nas: Went offline"); `NOTIFY_NAMES=1` opts in to your labels. Event titles never carry IPs
or MACs. Off unless configured; a failed push never breaks a scan.

**Threat intel is pull-only:** NVD is queried per `vendor:product` with no version, KEV is
downloaded whole, and all version matching happens locally. Cached in
`~/.local/share/homesentry/intel/` (KEV 1 day, NVD 7 days). Banner-derived findings are
*leads*: distro builds are downgraded to info, and computers are capped at medium
because their fix is an OS update.

**Gateway reader (optional):** put `GATEWAY_USER`/`GATEWAY_PASS` in
`~/.config/homesentry/gateway.env` (mode 600) and every scan logs into a Comcast/Xfinity
RDK-B gateway (`*.jst` UI) over HTTPS, reads a fixed allowlist of status pages, and logs out.
It adds the gateway's exact model/firmware, DHCP hostnames, devices the gateway remembers but
that are offline now, and config findings (port forwards, DMZ, UPnP, remote management,
firewall levels, Wi-Fi security). It never follows links: on this firmware even deleting a
port-forward rule is a plain GET. Serial, WPS PIN, WAN IP and Wi-Fi keys are never collected,
and gateway config never reaches the LLM. `homesentry gateway` prints a summary.

**Outside-in check (optional):** `~/.config/homesentry/probe.env` with `PROBE_SSH=<ssh alias>`
(and `PROBE_SSH_AGENT=` if the key lives in a desktop agent). `homesentry outside` (or the
🌍 button) pipes a stdlib TCP connect-scan of ~1000 ports to `python3 -` on that host over
SSH: nothing installed there, it targets whatever address the probe host sees us coming from,
and it never prints that address back. No third-party port-check service involved.

**Retiring devices:** decommissioned devices can be retired from the device page. They stay
hidden even though the gateway remembers them, and come back automatically (flagged) if they
ever talk on the LAN again.

**Multiple networks:** every physical interface with an RFC 1918 address is scanned
(USB-Ethernet into a mesh router, a Wi-Fi card, ...). Tailscale peers with a direct LAN
path add device names and OS. A machine on both the wired LAN and a Wi-Fi network that a
router NATs sees both: that is how the hidden Wi-Fi side of a double NAT gets inventoried.

## Platforms

Linux and macOS today (Windows next). Everything OS-specific about reading the network is in
`netinfo.py` (Linux: `ip -j` + `/sys`; macOS: `route`, `ifconfig`, `arp`, `ipconfig`), behind
pure parsers that are tested on every OS. The rest is the same Python everywhere:

| Collector | How | Notes |
|---|---|---|
| ARP sweep | one empty UDP datagram per address, then the OS neighbor table | no root, no nmap |
| mDNS | python-zeroconf, shares UDP 5353 with avahi / mDNSResponder | avahi only as fallback |
| Ports | `portscan.py`: asyncio connects + read-only protocol probes | see below |
| MAC vendors | bundled IEEE MA-L table (`scripts/build_oui.py`) | same names on every OS |

**The port scanner** connects to ~140 home-relevant TCP ports (a superset of the classic
top-100), at most 12 at a time per host (a 2007 set-top box drops ports at 24), and retries
timeouts by how the host behaves (a mostly-refusing host gets every timeout retried; a
filtering one only the common ports). Then it identifies what answered: SSH greeting, HTTP
`Server`/title (and error-page signatures), TLS, DNS `version.bind`, SMB1 session setup
(real Samba versions where nmap says "3.X - 4.X"), AFP status, RTSP, VNC, MySQL. Output uses
nmap's product naming, so CVE matching reads the same either way. It **never sends a byte to
raw-print ports** (9100-9107, LPD 515): anything sent there comes out of the printer.
`HOMESENTRY_PORTSCAN=nmap` switches to `nmap -sT -sV` if you prefer it.

**Sensors: seeing behind a Wi-Fi router's NAT.** A machine joined to the Wi-Fi (a Mac mini, a
laptop) sees a network the appliance's wire never touches. List it in
`~/.config/homesentry/sensors.env` (mode 600): `SENSORS=macbot-zero` (ssh aliases,
comma-separated; `SENSOR_SSH_AGENT=` if the key lives in a desktop agent). Every scan then runs
`homesentry probe --json --skip <networks we scan ourselves>` on each sensor over SSH, in parallel
with the local scan, and folds the result in through the same pipeline. The sensor stores
nothing. Its own Wi-Fi address and the router's inner address are recognized as devices we
already know (the router by its neighboring MAC, Macs by their AirPlay device id), so the map
draws the network *inside* its router's pocket, and the first sight of a network is one timeline
event, not a "new device!" per phone. A sensor that's asleep is skipped; its network keeps its
last known state. `homesentry ingest probe.json` folds in a probe run by hand.

**Checking another machine's view:** `homesentry probe [--ports] [--json]` runs every
collector and stores nothing. `scripts/remote-test.sh <ssh-host> [--ports]` syncs this tree to
a machine you own, runs the tests and a live probe there, and `homesentry compare` diffs the
result against the local inventory (from a backup copy) as the answer key.

The KB (`src/homesentry/kbdata/devices/*.yaml` seed + `~/.local/share/homesentry/kb/` learned) holds generic
device knowledge only, so the next device of the same model is recognized automatically.


## Desktop app (macOS)

`HomeSentry.app` is the appliance in a window. A small native shell (Tauri, `desktop/`) runs a
frozen copy of this same package on a random loopback port with a one-time session token,
shows the UI, keeps monitoring from the menu bar when the window is closed, and turns
medium-or-worse timeline events into native notifications. Data lives in
`~/Library/Application Support/HomeSentry/`. If macOS's Local Network permission is off, the app
says so and doesn't invent a clean bill of health. Build with `packaging/build-mac-app.sh`;
signing, notarization and CI releases are in [packaging/README.md](packaging/README.md).
Headless Mac without the app: `homesentry service install` (a LaunchAgent).

## Run

```bash
uv sync -p 3.13
.venv/bin/homesentry scan            # ~20s; add --ports for the port/service scan (~45s)
.venv/bin/homesentry probe --ports   # what this machine sees, stored nowhere
.venv/bin/homesentry list
.venv/bin/homesentry threats        # re-run the threat pass (cached intel, ~2s)
.venv/bin/homesentry plan           # score + ranked actions in the terminal
.venv/bin/homesentry report -o report.html
.venv/bin/homesentry doctor         # tools, config file modes, intel age, scan age, units
OLLAMA_API_KEY=... .venv/bin/homesentry serve --host <tailnet-ip> --port 8720
```

### Install as an appliance (systemd user units)

```bash
uv tool install --force --reinstall /path/to/home-sentry/main   # → ~/.local/bin/homesentry
echo "HOMESENTRY_BIND=<tailnet-ip>" >> ~/.config/homesentry/env  # + OLLAMA_API_KEY=...
chmod 600 ~/.config/homesentry/env
cp deploy/systemd/homesentry*.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now homesentry.service homesentry-watch.timer
loginctl enable-linger "$USER"     # keep running without a login session
homesentry doctor
```

No nmap needed. If you opt in to it (`HOMESENTRY_PORTSCAN=nmap`), use the **distro nmap**
(`apt install nmap`), not the snap: the units are sandboxed (`NoNewPrivileges`,
`ProtectSystem=strict`, `PrivateTmp`) and snap's launcher refuses to run under any of them.
`homesentry doctor` flags it.

The UI binds `$HOMESENTRY_BIND` (loopback if unset, never all interfaces) and has no login:
put it on an address only you can reach, like a tailnet IP. `/healthz` returns 503 when the
last scan is older than 6h, for whatever watches your watchers.

Env: `OLLAMA_API_KEY`; `HOMESENTRY_MODEL` (reasoning, default `glm-5.3`, needs no vision);
`HOMESENTRY_VISION_MODEL` (photo reader, default `glm-5.3-flash`, must list `vision` in
`/api/show` capabilities); `HOMESENTRY_THINK` (default `low`); `HOMESENTRY_LLM_BASE`
(default `https://ollama.com`; a local Ollama works); `HOMESENTRY_HOME` (data dir);
`HOMESENTRY_CONFIG` (secrets dir, default `~/.config/homesentry`); `HOMESENTRY_BIND`.

Photo turns run in two stages: the vision model transcribes the photo (serials masked), then
the reasoning model works from the transcript. The transcript stays in the chat history.


### Host firewall

With a stateful host firewall in front of the scanner, two discovery replies need explicit rules,
because devices answer multicast probes by unicast from addresses the firewall never saw a packet go to:

- **SSDP/UPnP:** HomeSentry sends its M-SEARCH from a fixed UDP port, **1901** unless
  `HOMESENTRY_SSDP_PORT` sets another (`0` means ephemeral, which a firewall can't admit). Allow the
  port you use: `ufw allow in on <lan-if> proto udp from <lan-cidr> to any port <port>`.
  Device-description fetches only follow a `LOCATION` on the responding device's own private IP.
- **mDNS:** allow `5353/udp` in from the LAN, and replies *from* port 5353.

Port scans are full TCP connects, which conntrack tracks, so they need no rule.

## Tests

```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check .
```

`tests/conftest.py` points `HOMESENTRY_HOME` and `HOMESENTRY_CONFIG` at a fresh temp dir for
every test, so no test can read the owner's real gateway password or log in to real hardware.
Fixtures are synthetic (`10.99.0.0/24`, `00:11:22:*`): never paste real scan output into tests.
