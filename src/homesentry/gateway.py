"""Read-only reader for Comcast/Xfinity RDK-B gateways (the `*.jst` web UI on
Technicolor/Vantiva, Arris and Sagemcom boxes, e.g. CGA4131COM, XB6/7/8).

Safety model. "Only GET requests" is NOT read-only on this firmware: deleting a
port-forward rule is a plain GET link (`actionHandler/ajax_port_forwarding.jst?del=1`).
So the reader:
  - fetches ONLY the fixed page names in PAGES and OPTIONAL_PAGES (plus the login POST and
    the logout page); an optional page that 404s on some firmware is skipped, not fatal;
  - never follows links, never touches actionHandler/, never submits a form;
  - refuses anything else at the transport layer (_get), with a test proving it.

Privacy. Credentials come from ~/.config/homesentry/gateway.env (mode 600) and are never
logged or stored. Serial numbers, WPS PIN, CM MAC, WAN IP and Wi-Fi keys are not
collected: the parsers pick named fields only. network_setup.jst shows the WAN address too;
only its four DNS-server fields are read (the DNS watch compares them scan to scan).
"""

from __future__ import annotations

import html as htmllib
import re
from pathlib import Path
from typing import Any

import httpx


def env_path() -> Path:
    from . import config_dir

    return config_dir() / "gateway.env"


LOGIN = "check.jst"
LOGOUT = "home_loggedout.jst"
PAGES = (
    "hardware.jst",
    "software.jst",
    "connection_status.jst",
    "connected_devices_computers.jst",
    "firewall_settings_ipv4.jst",
    "firewall_settings_ipv6.jst",
    "port_forwarding.jst",
    "dmz.jst",
    "device_discovery.jst",
    "remote_management.jst",
)
# Read if present. Older RDK-B builds may not serve these; a 404 must not fail the read.
OPTIONAL_PAGES = ("network_setup.jst",)


class GatewayError(RuntimeError):
    pass


def load_credentials(path: Path | None = None) -> tuple[str, str] | None:
    path = path or env_path()
    if not path.exists():
        return None
    if path.stat().st_mode & 0o077:
        raise GatewayError(f"{path} must be mode 600 (it holds the gateway admin password)")
    env = {}
    for line in path.read_text().splitlines():
        k, sep, v = line.partition("=")
        if sep:
            env[k.strip()] = v.strip().strip("\"'")
    if not env.get("GATEWAY_USER") or not env.get("GATEWAY_PASS"):
        raise GatewayError(f"{path} needs GATEWAY_USER and GATEWAY_PASS")
    return env["GATEWAY_USER"], env["GATEWAY_PASS"]


class RdkbReader:
    def __init__(self, host: str, client: httpx.Client | None = None):
        self.host = host
        # self-signed cert on the gateway; TLS still keeps the password off the wire
        self.c = client or httpx.Client(
            base_url=f"https://{host}", verify=False, timeout=20, follow_redirects=False
        )

    def _get(self, page: str) -> str:
        if page not in PAGES and page not in OPTIONAL_PAGES and page != LOGOUT:
            raise GatewayError(f"refusing non-allowlisted gateway page: {page!r}")
        r = self.c.get(f"/{page}")
        if r.status_code != 200:
            raise GatewayError(f"{page}: HTTP {r.status_code} (session expired?)")
        return r.text

    @staticmethod
    def detect(login_html: str) -> bool:
        return 'action="check.jst"' in login_html and 'name="password"' in login_html

    def login(self, user: str, password: str) -> None:
        if not self.detect(self.c.get("/").text):
            raise GatewayError("not an RDK-B (*.jst) gateway login page")
        r = self.c.post(f"/{LOGIN}", data={"username": user.lower(), "password": password})
        loc = r.headers.get("location", "")
        if r.status_code != 302 or "at_a_glance" not in loc:
            # one attempt only: these gateways lock the account after repeated failures
            raise GatewayError("gateway login failed (not retrying, to avoid a lockout)")

    def read(self, user: str, password: str) -> dict[str, Any]:
        self.login(user, password)
        try:
            pages = {p: self._get(p) for p in PAGES}
            for p in OPTIONAL_PAGES:
                try:
                    pages[p] = self._get(p)
                except (GatewayError, httpx.HTTPError):
                    pass
        finally:
            try:
                self._get(LOGOUT)
            except (GatewayError, httpx.HTTPError):
                pass
        return parse_all(pages)


# ---- parsers (pure; tested with synthetic HTML) ------------------------------
def _field(h: str, label: str) -> str | None:
    lab = re.escape(label).replace("\\&", "(?:&|&amp;)")
    m = re.search(rf'readonlyLabel">\s*{lab}:?\s*</span>\s*<span class="value">\s*([^<]*?)\s*<', h)
    return htmllib.unescape(m.group(1)).strip() or None if m else None


def _js_bool(h: str, var: str) -> bool | None:
    m = re.search(rf"var\s+{re.escape(var)}\s*=\s*(true|false)\s*;", h)
    return m.group(1) == "true" if m else None


def _checked_radio(h: str, name: str) -> str | None:
    for tag in re.findall(r"<input[^>]*>", h):
        if f'name="{name}"' in tag and re.search(r"\schecked\b", tag):
            v = re.search(r'value="([^"]*)"', tag)
            return v.group(1) if v else None
    return None


def parse_hardware(h: str) -> dict[str, Any]:
    return {
        "model": _field(h, "Model"),
        "vendor": _field(h, "Vendor"),
        "hw_rev": _field(h, "Hardware Revision"),
    }  # serial deliberately skipped


def parse_software(h: str) -> dict[str, Any]:
    return {
        "firmware": _field(h, "Software Image Name"),
        "docsis": _field(h, "eMTA & DOCSIS Software Version"),
    }


def parse_wifi(h: str) -> list[dict[str, Any]]:
    out = []
    for band in ("2.4 GHz", "5 GHz", "6 GHz"):
        status = _field(h, f"Wireless Network (Wi-Fi {band})")
        if status is None:
            continue
        i = h.find(f"Wireless Network (Wi-Fi {band})")
        sec = _field(h[i:], "Security")
        out.append(
            {
                "band": band,
                "active": status.lower() == "active",
                "security": re.sub(r"\s+", " ", sec or ""),
            }
        )
    return out


ROW_IP = re.compile(r"IPV4 Address</b><br/></dd>\s*([\d.]+)")
ROW_MAC = re.compile(r"MAC Address</b><br/></dd>\s*([0-9A-Fa-f:]{17})")


def parse_clients(h: str) -> list[dict[str, Any]]:
    out = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", h, re.S):
        name = re.search(r"<u>([^<]*)</u>", row)
        mac = ROW_MAC.search(row)
        if not name or not mac:
            continue
        ip = ROW_IP.search(row)
        hn = htmllib.unescape(name.group(1)).strip()
        mac_l = mac.group(1).lower()
        out.append(
            {
                "hostname": None if hn.lower() == mac_l else hn,  # unnamed clients show MAC
                "mac": mac_l,
                "ip": ip.group(1) if ip else None,
                "online": 'headers="offline-device' not in row,
                "reserved": ">Reserved IP<" in row,
            }
        )
    return out


def parse_wan_dns(h: str) -> list[str]:
    """The resolvers the gateway itself forwards to (Device.DNS.Client.Server.*), from the
    four DNS fields of network_setup.jst. Nothing else on that page is read."""
    import ipaddress

    out = []
    for label in (
        "Primary DNS Server (IPv4)",
        "Secondary DNS Server (IPv4)",
        "Primary DNS Server (IPv6)",
        "Secondary DNS Server (IPv6)",
    ):
        v = _field(h, label)
        if not v:
            continue
        try:
            ipaddress.ip_address(v)
        except ValueError:
            continue  # "-NA-", "::" placeholders
        if v not in out:
            out.append(v)
    return out


def parse_port_forwarding(h: str) -> dict[str, Any]:
    m = re.search(r'#pf_switch"\)\.radioswitch\(\{.*?state:\s*(true|false)', h, re.S)
    rules = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", h, re.S):

        def cell(hdr: str, row: str = row) -> str | None:
            c = re.search(rf"headers=['\"]{hdr}['\"][^>]*>(.*?)</td>", row, re.S)
            return re.sub(r"<[^>]+>", "", c.group(1)).strip() if c else None

        name = cell("service-name")
        if not name or name == "null":
            continue
        act = re.search(r"headers=['\"]active['\"][^>]*>(.*?)</td>", row, re.S)
        rules.append(
            {
                "name": htmllib.unescape(name),
                "proto": cell("service-type"),
                "start": cell("start-port"),
                "end": cell("end-port"),
                "target": cell("server-ip"),
                "active": bool(act and re.search(r"\schecked\b", act.group(1))),
            }
        )
    return {"enabled": (m.group(1) == "true") if m else None, "rules": rules}


def parse_all(pages: dict[str, str]) -> dict[str, Any]:
    g = lambda p: pages.get(p, "")  # noqa: E731
    return {
        **parse_hardware(g("hardware.jst")),
        **parse_software(g("software.jst")),
        "wifi": parse_wifi(g("connection_status.jst")),
        "clients": parse_clients(g("connected_devices_computers.jst")),
        "firewall_v4": _checked_radio(g("firewall_settings_ipv4.jst"), "firewall_level"),
        "firewall_v6": _checked_radio(g("firewall_settings_ipv6.jst"), "firewall_level"),
        "port_forwarding": parse_port_forwarding(g("port_forwarding.jst")),
        "dmz": _js_bool(g("dmz.jst"), "jsEnableDMZ"),
        "upnp": _js_bool(g("device_discovery.jst"), "jsEnableUPnP"),
        "zeroconf": _js_bool(g("device_discovery.jst"), "jsEnableZero"),
        "remote_mgmt_https": _js_bool(g("remote_management.jst"), "HTTPS"),
        "wan_dns": parse_wan_dns(g("network_setup.jst")),
    }


# ---- findings -----------------------------------------------------------------
RISKY_FORWARD_PORTS = {
    "11434": "Ollama's API has no authentication: anyone could run, pull or delete models",
    "22": "SSH exposed to the internet attracts constant brute-force attempts",
    "23": "Telnet is unencrypted and a classic botnet entry point",
    "3389": "Remote Desktop is a top ransomware entry point",
    "5900": "VNC exposed to the internet is routinely brute-forced",
    "445": "SMB file sharing must never face the internet",
}


def config_findings(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    f: list[dict[str, Any]] = []

    def add(sev: str, title: str, detail: str, **data: Any) -> None:
        f.append(
            {"severity": sev, "kind": "config", "title": title, "detail": detail, "data": data}
        )

    if cfg.get("dmz"):
        add(
            "critical",
            "DMZ host enabled",
            "Every port of one LAN device is exposed to the internet. Turn DMZ off and "
            "forward only the ports you need.",
        )
    if cfg.get("remote_mgmt_https"):
        add(
            "high",
            "Remote management is on",
            "The gateway admin page is reachable from the internet. Turn it off unless "
            "you need it, and restrict it to one IP if you do.",
        )
    if cfg.get("upnp"):
        add(
            "medium",
            "UPnP is enabled",
            "Any device on the LAN (including malware or a compromised IoT box) can open "
            "inbound ports by itself. Turn it off unless a game console needs it.",
        )
    pf = cfg.get("port_forwarding") or {}
    for r in pf.get("rules", []):
        why = RISKY_FORWARD_PORTS.get(str(r.get("start")), "")
        where = f"{r['proto']} {r['start']}-{r['end']} → {r['target']}"
        if pf.get("enabled") and r.get("active"):
            add(
                "critical" if why else "high",
                f"Port forward '{r['name']}' is live",
                f"{where} is reachable from the internet. {why}".strip(),
                rule=where,
            )
        else:
            add(
                "low",
                f"Dormant port forward '{r['name']}'",
                f"{where} is defined but switched off. {why + '. ' if why else ''}"
                "It's one toggle away from being live; delete it if you don't need it.",
                rule=where,
            )
    if (cfg.get("firewall_v4") or "").lower() == "low":
        add(
            "low",
            "Gateway IPv4 firewall at Minimum (Low)",
            "NAT still blocks unsolicited inbound, but Typical (Medium) adds intrusion "
            "detection and drops inbound pings with no effect on normal use.",
        )
    if (cfg.get("firewall_v6") or "").lower() in ("low", "none", "off"):
        add(
            "high",
            "Gateway IPv6 firewall is permissive",
            "LAN devices have public IPv6 addresses; without the firewall they are directly "
            "reachable from the internet. Set IPv6 to Typical (Default).",
        )
    for w in cfg.get("wifi", []):
        if w["active"] and "WPA3" not in w["security"] and "WPA2" not in w["security"]:
            add(
                "high",
                f"Gateway Wi-Fi {w['band']} uses weak security ({w['security']})",
                "Switch to WPA2-AES or WPA3.",
            )
    return f
