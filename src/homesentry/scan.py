"""Orchestrates one discovery pass over every LAN leg: collect -> store evidence -> identify
-> threat pass."""

from __future__ import annotations

import time
from typing import Any

from . import discover, identify
from . import kb as kblib
from .store import Store


def run_scan(store: Store, ports: bool = False, threats: bool = True, log=print) -> dict[str, Any]:
    started = time.time()
    entries = kblib.load()
    peers = discover.tailscale_peers()
    if peers:
        log(f"Tailscale: {len(peers)} peers with a direct LAN path")
    nets = [
        _scan_network(store, ctx, peers, entries, ports, log) for ctx in discover.lan_contexts()
    ]
    summary: dict[str, Any] = {
        "networks": nets,
        "hosts": sum(n["hosts"] for n in nets),
        "cidr": ", ".join(n["cidr"] for n in nets),
        "ports": ports,
    }
    if threats:
        from . import threat

        try:
            summary["findings"] = threat.run(store, log=log)
        except Exception as e:  # noqa: BLE001 - an intel outage must not kill the inventory
            log(f"threat pass failed: {e}")
    summary["seconds"] = round(time.time() - started, 1)
    store.record_scan(started, summary)
    log(f"done in {summary['seconds']}s")
    return summary


def _scan_network(store, ctx, peers, entries, ports, log) -> dict[str, Any]:
    log(f"LAN {ctx['cidr']} on {ctx['iface']} (gateway {ctx['gateway'] or '?'})")
    neigh = discover.arp_sweep(ctx["cidr"], ctx["iface"])
    if ctx.get("mac"):
        neigh[ctx["local_ip"]] = ctx["mac"]
    log(f"  ARP: {len(neigh)} hosts")
    names = discover.reverse_dns(list(neigh))
    mdns = discover.mdns(ctx["iface"])
    log(f"  mDNS: {len(mdns)} hosts advertising")
    ssdp = discover.ssdp(local_ip=ctx["local_ip"])
    log(f"  SSDP/UPnP: {len(ssdp)} hosts")
    svc = discover.service_scan(list(neigh)) if ports else {}
    if ports:
        log(f"  nmap: {len(svc)} hosts with open ports")

    for ip, mac in neigh.items():
        vendor = discover.oui_vendor(mac)
        did = store.upsert_seen(mac, ip, names.get(ip), vendor, network=ctx["cidr"])
        if discover.is_random_mac(mac):
            store.add_evidence(did, "arp", "mac_randomized", "yes")
        sightings = mdns.get(ip, []) + ssdp.get(ip, []) + svc.get(ip, []) + peers.get(ip, [])
        for src, key, val in sightings:
            if val:
                store.add_evidence(did, src, key, val)
        if names.get(ip):
            store.add_evidence(did, "dns", "ptr", names[ip])
        ev = store.evidence(did)
        g = identify.guess(
            ev,
            vendor,
            is_gateway=ip == ctx["gateway"],
            is_self=ip == ctx["local_ip"],
            kb_entries=entries,
        )
        fields = {k: g[k] for k in ("device_type", "make", "model")}
        label = _label(ev, names.get(ip))
        if label and not (store.device(did) or {}).get("label"):
            fields["label"] = label
        store.set_identity(did, fields, "auto", g["confidence"])
        store.clear_evidence(did, "auto")
        store.add_evidence(did, "auto", "reasons", "; ".join(g["reasons"]) or "none")
    return {
        "cidr": ctx["cidr"],
        "iface": ctx["iface"],
        "hosts": len(neigh),
        "mdns": len(mdns),
        "ssdp": len(ssdp),
    }


def _label(evidence: list[dict[str, Any]], ptr: str | None) -> str | None:
    for src, key in (("ssdp", "friendlyName"), ("tailscale", "name"), ("mdns", "host")):
        for ev in evidence:
            if ev["source"] == src and ev["key"] == key and ev["value"]:
                return ev["value"].removesuffix(".local")
    return ptr.split(".")[0] if ptr else None
