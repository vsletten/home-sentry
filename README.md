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
   → wizard  (Ollama: evidence + your words + photos)   ← for what rules can't pin
   → confirm (locks identity, teaches the KB)
```

The KB (`kb/devices/*.yaml` seed + `~/.local/share/homesentry/kb/` learned) holds generic
device knowledge only, so the next device of the same model is recognized automatically.

## Run

```bash
uv sync -p 3.13
.venv/bin/homesentry scan            # ~10s; add --ports for an nmap service scan (~90s)
.venv/bin/homesentry list
OLLAMA_API_KEY=... .venv/bin/homesentry serve --host <tailnet-ip> --port 8720
```

Env: `OLLAMA_API_KEY`, `HOMESENTRY_MODEL` (default `kimi-k3`, must support vision),
`HOMESENTRY_LLM_BASE` (default `https://ollama.com`; a local Ollama works),
`HOMESENTRY_HOME` (data dir).

## Tests

```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check .
```
