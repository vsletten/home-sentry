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
    nets_ctx = discover.lan_contexts()
    nets = [_scan_network(store, ctx, peers, entries, ports, log) for ctx in nets_ctx]
    summary: dict[str, Any] = {
        "networks": nets,
        "hosts": sum(n["hosts"] for n in nets),
        "cidr": ", ".join(n["cidr"] for n in nets),
        "ports": ports,
    }
    gw = _gateway_pass(store, nets_ctx[0] if nets_ctx else None, entries, log)
    if gw:
        summary["gateway"] = gw
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
        ts = discover.attribute_tailscale(peers.get(ip, []), vendor, discover.is_random_mac(mac))
        sightings = mdns.get(ip, []) + ssdp.get(ip, []) + svc.get(ip, []) + ts
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


def _gateway_pass(store, ctx, entries, log) -> dict[str, Any] | None:
    """If gateway admin creds are configured, read the gateway (read-only) and fold its
    identity, DHCP names, remembered-offline clients and config into the inventory."""
    import json

    from . import gateway

    try:
        creds = gateway.load_credentials()
    except gateway.GatewayError as e:
        log(f"gateway: {e}")
        return None
    if not creds or not ctx or not ctx.get("gateway"):
        return None
    try:
        cfg = gateway.RdkbReader(ctx["gateway"]).read(*creds)
    except (gateway.GatewayError, Exception) as e:  # noqa: BLE001 - never kill the scan
        log(f"gateway: read failed: {e}")
        return None
    finally:
        creds = None

    gw = next((d for d in store.devices() if d["ip"] == ctx["gateway"] and d["mac"]), None)
    if gw:
        for k in ("model", "vendor", "hw_rev", "firmware", "docsis"):
            if cfg.get(k):
                store.add_evidence(gw["id"], "gateway", k, cfg[k])
        public = {k: v for k, v in cfg.items() if k != "clients"}
        store.clear_evidence(gw["id"], "gateway_cfg")
        store.add_evidence(gw["id"], "gateway_cfg", "config", json.dumps(public))
        g = identify.guess(
            store.evidence(gw["id"]), gw.get("oui_vendor"), is_gateway=True, kb_entries=entries
        )
        fields = {k: g[k] for k in ("device_type", "make", "model")}
        fields["firmware"] = cfg.get("firmware")
        store.set_identity(gw["id"], fields, "auto", g["confidence"])
        store.clear_evidence(gw["id"], "auto")
        store.add_evidence(gw["id"], "auto", "reasons", "; ".join(g["reasons"]))

    offline = 0
    for c in cfg["clients"]:
        if c["online"]:
            did = next((d["id"] for d in store.devices() if d["mac"] == c["mac"]), None)
            if did is None:
                continue
        else:
            if store.is_retired(c["mac"]):
                continue
            known = any(d["mac"] == c["mac"] for d in store.devices(include_retired=True))
            did = store.upsert_known(
                c["mac"], c["ip"], c["hostname"], discover.oui_vendor(c["mac"]), ctx["cidr"]
            )
            offline += not known
        if c["hostname"]:
            store.add_evidence(did, "gateway", "dhcp_name", c["hostname"])
        if c["reserved"]:
            store.add_evidence(did, "gateway", "dhcp_reserved", "yes")
        d = store.device(did) or {}
        ev = store.evidence(did)
        g = identify.guess(
            ev,
            d.get("oui_vendor"),
            is_gateway=d.get("ip") == ctx["gateway"],
            is_self=d.get("ip") == ctx["local_ip"],
            kb_entries=entries,
        )
        fields = {k: g[k] for k in ("device_type", "make", "model")}
        if not d.get("label") and (lbl := _label(ev, d.get("hostname"))):
            fields["label"] = lbl
        store.set_identity(did, fields, "auto", g["confidence"])
        store.clear_evidence(did, "auto")
        store.add_evidence(did, "auto", "reasons", "; ".join(g["reasons"]) or "none")
    summary = {
        "model": cfg.get("model"),
        "firmware": cfg.get("firmware"),
        "clients": len(cfg["clients"]),
        "new_offline": offline,
    }
    log(
        f"gateway: {cfg.get('vendor')} {cfg.get('model')} fw {cfg.get('firmware')}; "
        f"{len(cfg['clients'])} DHCP clients, {offline} new offline devices"
    )
    return summary


def _label(evidence: list[dict[str, Any]], ptr: str | None) -> str | None:
    for src, key in (
        ("ssdp", "friendlyName"),
        ("tailscale", "name"),
        ("mdns", "host"),
        ("gateway", "dhcp_name"),
    ):
        for ev in evidence:
            if ev["source"] == src and ev["key"] == key and ev["value"]:
                return ev["value"].removesuffix(".local")
    return ptr.split(".")[0] if ptr else None
