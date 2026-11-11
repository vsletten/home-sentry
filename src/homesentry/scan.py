"""Orchestrates one discovery pass: collect -> store evidence -> deterministic identify."""

from __future__ import annotations

import time
from typing import Any

from . import discover, identify
from . import kb as kblib
from .store import Store


def run_scan(store: Store, ports: bool = False, log=print) -> dict[str, Any]:
    started = time.time()
    ctx = discover.lan_context()
    log(f"LAN {ctx['cidr']} on {ctx['iface']} (gateway {ctx['gateway']})")

    neigh = discover.arp_sweep(ctx["cidr"], ctx["iface"])
    neigh[ctx["local_ip"]] = ctx["mac"]
    log(f"ARP: {len(neigh)} hosts")
    names = discover.reverse_dns(list(neigh))
    mdns = discover.mdns(ctx["iface"])
    log(f"mDNS: {len(mdns)} hosts advertising")
    ssdp = discover.ssdp()
    log(f"SSDP/UPnP: {len(ssdp)} hosts")
    svc = discover.service_scan(list(neigh)) if ports else {}
    if ports:
        log(f"nmap: {len(svc)} hosts with open ports")

    entries = kblib.load()
    ids = []
    for ip, mac in neigh.items():
        vendor = discover.oui_vendor(mac)
        did = store.upsert_seen(mac, ip, names.get(ip), vendor)
        ids.append(did)
        if discover.is_random_mac(mac):
            store.add_evidence(did, "arp", "mac_randomized", "yes")
        for src, key, val in mdns.get(ip, []) + ssdp.get(ip, []) + svc.get(ip, []):
            store.add_evidence(did, src, key, val)
        if names.get(ip):
            store.add_evidence(did, "dns", "ptr", names[ip])
        g = identify.guess(
            store.evidence(did),
            vendor,
            is_gateway=ip == ctx["gateway"],
            is_self=ip == ctx["local_ip"],
            kb_entries=entries,
        )
        label = _label(store.evidence(did), names.get(ip))
        fields = {k: g[k] for k in ("device_type", "make", "model")}
        if label and not (store.device(did) or {}).get("label"):
            fields["label"] = label
        store.set_identity(did, fields, "auto", g["confidence"])
        store.clear_evidence(did, "auto")
        store.add_evidence(did, "auto", "reasons", "; ".join(g["reasons"]) or "none")

    summary = {
        "cidr": ctx["cidr"],
        "hosts": len(neigh),
        "mdns": len(mdns),
        "ssdp": len(ssdp),
        "ports": ports,
        "seconds": round(time.time() - started, 1),
    }
    store.record_scan(started, summary)
    log(f"done in {summary['seconds']}s")
    return summary


def _label(evidence: list[dict[str, Any]], ptr: str | None) -> str | None:
    for ev in evidence:
        if ev["source"] == "ssdp" and ev["key"] == "friendlyName":
            return ev["value"]
    for ev in evidence:
        if ev["source"] == "mdns" and ev["key"] == "host":
            return ev["value"].removesuffix(".local")
    return ptr.split(".")[0] if ptr else None
