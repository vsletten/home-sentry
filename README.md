# home-sentry

Local-first home network security prototype: discover devices, identify them
(auto + AI-guided wizard with photos), and, next, build threat profiles.

**Privacy line:** the inventory, photos and evidence stay on the box
(`~/.local/share/homesentry/`). Only wizard inference requests leave, and those carry
the MAC *vendor* only, never MACs, IPs or serials. UPnP serial numbers are never collected.

## v0 shape

```
discover (ARP sweep · mDNS · SSDP/UPnP · nmap -sV, all unprivileged)
   → evidence (SQLite)
   → identify (deterministic rules + learned KB)        ← no LLM, free, instant
   → wizard  (photo → vision reader → transcript; glm-5.3 reasons)  ← what rules can't pin
   → confirm (locks identity, teaches the KB)
   → threats (exposure rules · EOL kernels · CVE leads: NVD per product + CISA KEV)
```

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
path add device names and OS.

The KB (`kb/devices/*.yaml` seed + `~/.local/share/homesentry/kb/` learned) holds generic
device knowledge only, so the next device of the same model is recognized automatically.

## Run

```bash
uv sync -p 3.13
.venv/bin/homesentry scan            # ~10s; add --ports for an nmap service scan (~90s)
.venv/bin/homesentry list
.venv/bin/homesentry threats        # re-run the threat pass (cached intel, ~2s)
OLLAMA_API_KEY=... .venv/bin/homesentry serve --host <tailnet-ip> --port 8720
```

Env: `OLLAMA_API_KEY`; `HOMESENTRY_MODEL` (reasoning, default `glm-5.3`, needs no vision);
`HOMESENTRY_VISION_MODEL` (photo reader, default `glm-5.3-flash`, must list `vision` in
`/api/show` capabilities); `HOMESENTRY_THINK` (default `low`); `HOMESENTRY_LLM_BASE`
(default `https://ollama.com`; a local Ollama works); `HOMESENTRY_HOME` (data dir).

Photo turns run in two stages: the vision model transcribes the photo (serials masked), then
the reasoning model works from the transcript. The transcript stays in the chat history.

## Tests

```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check .
```
