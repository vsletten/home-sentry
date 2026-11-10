"""Threat pass v1: deterministic, local matching of what we observed against public intel.

Findings come in three kinds:
  exposure  risky services reachable on the LAN (telnet, NFS, VNC, ...)
  eol       software that will never be patched again (ancient kernels, ...)
  cve       known vulnerabilities for software versions seen in service banners

Everything derived from banners is a LEAD, not a verdict: banners can lie, and distros
backport fixes without bumping versions. The UI says so.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from typing import Any

from . import intel
from .store import Store

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# banner regex -> display name, NVD (vendor, product) candidates
SOFTWARE: list[tuple[str, str, list[tuple[str, str]]]] = [
    (r"\bOpenSSH[ _](\d+\.\d+(?:p\d+)?)", "OpenSSH", [("openbsd", "openssh")]),
    (r"\bdnsmasq[ -](\d+\.\d+)", "dnsmasq", [("thekelleys", "dnsmasq")]),
    (r"\bnginx[ /](\d+\.\d+\.\d+)", "nginx", [("f5", "nginx"), ("nginx", "nginx")]),
    (r"\bNetatalk (\d+\.\d+\.\d+)", "Netatalk", [("netatalk", "netatalk")]),
    (r"\blighttpd[ /](\d+\.\d+\.\d+)", "lighttpd", [("lighttpd", "lighttpd")]),
    (r"\bSamba smbd (\d+\.\d+\.\d+)", "Samba", [("samba", "samba")]),
    (
        r"\bDropbear sshd?\s*(\d{4}\.\d+)",
        "Dropbear SSH",
        [("dropbear_ssh_project", "dropbear_ssh")],
    ),
    (r"\bApache httpd (\d+\.\d+\.\d+)", "Apache httpd", [("apache", "http_server")]),
    (r"\bminiupnpd[ /](\d+\.\d+)", "MiniUPnPd", [("miniupnp_project", "miniupnpd")]),
]
DISTRO_MARK = re.compile(r"\b(ubuntu|debian|raspbian|fedora|red ?hat|el\d)\b", re.I)
KERNEL_RE = re.compile(r"\bLinux[/ ](\d+\.\d+(?:\.\d+)*)")

# port -> (severity, title, why)
EXPOSURE: dict[str, tuple[str, str, str]] = {
    "23": (
        "high",
        "Telnet is open",
        "Unencrypted remote login: passwords cross the network in clear text. The classic "
        "IoT botnet entry point (Mirai and friends).",
    ),
    "21": ("medium", "FTP is open", "Unencrypted file transfer; often allows anonymous login."),
    "2049": (
        "medium",
        "NFS share reachable",
        "NFS trusts client IPs, not passwords. Any device on the LAN may be able to "
        "mount it unless exports are restricted.",
    ),
    "111": ("low", "RPC portmapper exposed", "Advertises internal RPC services to the LAN."),
    "5900": (
        "medium",
        "VNC screen sharing open",
        "Remote control of the screen. Fine if intentional and password-protected.",
    ),
    "3389": ("medium", "Remote Desktop port open", "Remote control of the machine."),
    "548": (
        "low",
        "AFP file sharing open",
        "Apple Filing Protocol is deprecated (macOS no longer serves it). Prefer SMB3.",
    ),
    "139": (
        "low",
        "NetBIOS/SMB1-era file sharing open",
        "Legacy Windows file sharing transport; SMB1 was the WannaCry vector. Use SMB3 only.",
    ),
    "9100": (
        "low",
        "Raw printing port open",
        "Anyone on the LAN can print or send printer-management (PJL) commands.",
    ),
    "1883": ("medium", "MQTT broker open", "Smart-home message bus; often no authentication."),
    "554": ("low", "RTSP video stream port open", "Camera streams often have weak/no auth."),
}
INTENTIONAL_ON = {"computer"}  # remote access on your own computers is usually deliberate


def vkey(v: str) -> list[tuple[int, Any]]:
    return [(0, int(t)) if t.isdigit() else (1, t) for t in re.findall(r"\d+|[a-z]+", v.lower())]


# ---- extraction -----------------------------------------------------------------
def components(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Software+version seen in banners. One entry per (name, version)."""
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for e in evidence:
        if (e["source"], e["key"]) not in {("nmap", "open_port"), ("ssdp", "server")}:
            continue
        text = e["value"]
        for rx, name, cpes in SOFTWARE:
            if m := re.search(rx, text):
                k = (name, m.group(1))
                seen.setdefault(
                    k,
                    {
                        "name": name,
                        "version": m.group(1),
                        "cpes": cpes,
                        "backported": bool(DISTRO_MARK.search(text)),
                        "where": text[:80],
                    },
                )
        if m := KERNEL_RE.search(text):
            k = ("Linux kernel", m.group(1))
            seen.setdefault(
                k,
                {
                    "name": "Linux kernel",
                    "version": m.group(1),
                    "cpes": [],
                    "backported": False,
                    "where": text[:80],
                },
            )
    return list(seen.values())


# ---- CVE matching -----------------------------------------------------------------
def _cpe_applies(cm: dict[str, Any], vendor: str, product: str, version: str) -> bool:
    if not cm.get("vulnerable"):
        return False
    parts = cm.get("criteria", "").split(":")
    if len(parts) < 7 or parts[3] != vendor or parts[4] != product:
        return False
    ver, upd = parts[5], parts[6]
    if ver not in ("*", "-"):
        full = ver + (upd if upd not in ("*", "-") else "")
        if upd == "*":  # any update of that release, e.g. 9.6 covers 9.6p1
            return vkey(ver) == vkey(re.sub(r"p\d+$", "", version))
        return vkey(full) == vkey(version)
    bounds = {
        k: cm.get(k)
        for k in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    }
    if not any(bounds.values()):
        return False  # "all versions" entries carry no signal; skip the noise
    v = vkey(version)
    if bounds["versionStartIncluding"] and v < vkey(bounds["versionStartIncluding"]):
        return False
    if bounds["versionStartExcluding"] and v <= vkey(bounds["versionStartExcluding"]):
        return False
    if bounds["versionEndIncluding"] and v > vkey(bounds["versionEndIncluding"]):
        return False
    if bounds["versionEndExcluding"] and v >= vkey(bounds["versionEndExcluding"]):
        return False
    return True


def _walk(nodes: list[dict[str, Any]]):
    for n in nodes:
        yield from n.get("cpeMatch", [])
        yield from _walk(n.get("nodes", []))


def cve_matches(cves: list[dict[str, Any]], vendor: str, product: str, version: str):
    out = []
    for c in cves:
        hit = any(
            _cpe_applies(cm, vendor, product, version)
            for cfg in c.get("configurations", [])
            for cm in _walk(cfg.get("nodes", []))
        )
        if hit:
            out.append({"id": c["id"], "cvss": _cvss(c), "summary": _summary(c)})
    return out


def _cvss(c: dict[str, Any]) -> float | None:
    for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        for m in c.get("metrics", {}).get(k, []):
            s = m.get("cvssData", {}).get("baseScore")
            if s is not None:
                return float(s)
    return None


def _summary(c: dict[str, Any]) -> str:
    for d in c.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"][:220]
    return ""


# ---- EOL --------------------------------------------------------------------------
def kernel_eol(version: str, cycles: list[dict[str, Any]], today: dt.date | None = None):
    """Return a human EOL statement, or None if the kernel line is still supported."""
    today = today or dt.date.today()
    if not cycles:
        return None
    cyc = ".".join(version.split(".")[:2])
    for c in cycles:
        if c.get("cycle") == cyc:
            eol = c.get("eol")
            if isinstance(eol, str) and dt.date.fromisoformat(eol) < today:
                return f"Linux {cyc} reached end-of-life on {eol}"
            return None
    oldest = min((c["cycle"] for c in cycles), key=vkey)
    if vkey(cyc) < vkey(oldest):
        return (
            f"Linux {cyc} predates every kernel line still tracked (oldest: {oldest}); "
            "unpatched for over a decade"
        )
    return None


# ---- assessment -------------------------------------------------------------------
def assess_device(
    device: dict[str, Any],
    evidence: list[dict[str, Any]],
    kev: dict[str, Any],
    nvd: dict[tuple[str, str], list[dict[str, Any]]],
    kernel_cycles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    dtype = device.get("device_type") or ""

    ports = {
        e["value"].split("/")[0]: e["value"]
        for e in evidence
        if e["source"] == "nmap" and e["key"] == "open_port"
    }
    for port, (sev, title, why) in EXPOSURE.items():
        if port in ports:
            if dtype in INTENTIONAL_ON:
                sev, why = "info", why + " On your own computer this is usually deliberate."
            findings.append(
                {
                    "severity": sev,
                    "kind": "exposure",
                    "title": title,
                    "detail": why,
                    "data": {"port": ports[port]},
                }
            )

    for comp in components(evidence):
        if comp["name"] == "Linux kernel":
            if stmt := kernel_eol(comp["version"], kernel_cycles):
                findings.append(
                    {
                        "severity": "high",
                        "kind": "eol",
                        "title": f"End-of-life Linux kernel {comp['version']}",
                        "detail": stmt + ". Every kernel bug since is unfixed on this "
                        "device; treat it as untrusted and isolate it if you can.",
                        "data": {"where": comp["where"]},
                    }
                )
            continue
        hits: dict[str, dict[str, Any]] = {}
        for vendor, product in comp["cpes"]:
            for h in cve_matches(nvd.get((vendor, product), []), vendor, product, comp["version"]):
                hits[h["id"]] = h
        if not hits:
            continue
        lst = sorted(hits.values(), key=lambda h: (h["id"] in kev, h["cvss"] or 0), reverse=True)
        for h in lst:
            h["kev"] = h["id"] in kev
        n_kev = sum(h["kev"] for h in lst)
        top = max((h["cvss"] or 0) for h in lst)
        sev = "critical" if n_kev else "high" if top >= 7 else "medium" if top >= 4 else "low"
        detail = (
            f"{len(lst)} published CVEs match {comp['name']} {comp['version']} "
            f"(worst CVSS {top:g}{f', {n_kev} actively exploited (CISA KEV)' if n_kev else ''}"
            "). Version taken from a service banner, so this is a lead to confirm."
        )
        kev_hits = [h for h in lst if h["kev"]]
        if kev_hits:
            k = kev[kev_hits[0]["id"]]
            detail += (
                f" CISA KEV ({k.get('dateAdded', '?')}): {k.get('vulnerabilityName', '')}."
                " Read the CVE: many apply only to specific builds or configs."
            )
        if dtype in INTENTIONAL_ON and not comp["backported"]:
            # a computer's OS vendor ships these fixes; the action is "update the OS"
            if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index("medium"):
                sev = "medium"
            detail += " On a computer this is fixed by OS updates; check it's current."
        if comp["backported"]:
            sev = "info"
            detail += (
                " The banner shows a distro build; distros backport security fixes "
                "without changing the version, so check the package manager instead."
            )
        findings.append(
            {
                "severity": sev,
                "kind": "cve",
                "title": f"{comp['name']} {comp['version']}: {len(lst)} CVE leads",
                "detail": detail,
                "data": {"cves": lst[:25], "where": comp["where"]},
            }
        )

    nat = [
        e["value"]
        for e in evidence
        if (e["source"], e["key"]) in {("tailscale", "nat_for"), ("probe", "nat")}
    ]
    if nat and dtype != "gateway":
        findings.append(
            {
                "severity": "low",
                "kind": "config",
                "title": "Runs its own NAT network (double NAT)",
                "detail": "This box is routing, not bridging: devices on its Wi-Fi sit on a hidden "
                "private network behind it. Scans can't see or assess them, they can't easily "
                "reach devices on the main LAN (casting/AirPlay/printing), and every client "
                "pays a second NAT. For a coverage access point, switch it to bridge/AP mode.",
                "data": {"why": nat[0]},
            }
        )

    for e in evidence:
        if e["source"] == "outside" and e["key"] == "result":
            from .outside import findings as outside_findings

            findings += outside_findings(json.loads(e["value"]))
        if e["source"] == "gateway_cfg" and e["key"] == "config":
            from .gateway import config_findings

            findings += config_findings(json.loads(e["value"]))

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return findings


def run(store: Store, log=print) -> dict[str, Any]:
    devices = store.devices()
    evid = {d["id"]: store.evidence(d["id"]) for d in devices}
    needed: set[tuple[str, str]] = set()
    want_kernel = False
    for d in devices:
        for comp in components(evid[d["id"]]):
            needed.update(comp["cpes"])
            want_kernel |= comp["name"] == "Linux kernel"
    log(f"intel: {len(needed)} products to check, kernel EOL: {want_kernel}")
    kev = intel.kev()
    log(f"CISA KEV: {len(kev)} actively exploited CVEs")
    nvd = {vp: intel.nvd_product(*vp, log=log) for vp in sorted(needed)}
    cycles = intel.eol_cycles("linux") if want_kernel else []
    total: dict[str, int] = {}
    for d in devices:
        fs = assess_device(d, evid[d["id"]], kev, nvd, cycles)
        store.replace_findings(d["id"], fs)
        for f in fs:
            total[f["severity"]] = total.get(f["severity"], 0) + 1
    log("findings: " + json.dumps(total))
    return total
