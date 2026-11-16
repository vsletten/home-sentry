"""Orchestrates one discovery pass over every LAN leg: collect -> store evidence -> identify
-> threat pass."""

from __future__ import annotations

import time
from typing import Any

from . import discover, identify, watch
from . import kb as kblib
from .store import Store


def run_scan(
    store: Store,
    ports: bool = False,
    threats: bool = True,
    gateway: bool = True,
    log=print,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One full pass. Holds the scan lock (the timer and the UI button never collide),
    diffs before/after into timeline events and records the posture score."""
    with watch.scan_lock():
        return _run_scan(store, ports, threats, gateway, log, extra or {})


def _run_scan(store, ports, threats, gateway, log, extra) -> dict[str, Any]:
    from . import sensors

    started = time.time()
    before = watch.snapshot(store)
    entries = kblib.load()
    peers = discover.tailscale_peers()
    if peers:
        log(f"Tailscale: {len(peers)} peers with a direct LAN path")
    nets_ctx = discover.lan_contexts()
    local_cidrs = [c["cidr"] for c in nets_ctx]
    try:  # remote sensors run while we scan locally; they're asked only for other networks
        pending = sensors.start(skip=local_cidrs, ports=ports)
    except PermissionError as e:
        log(f"sensors: {e}")
        pending = None
    nets = [
        _apply_network(store, _collect_local(ctx, ports, log), peers, entries, log)
        for ctx in nets_ctx
    ]
    scanned = list(local_cidrs)
    sensor_report = []
    for fut in pending or []:
        got = fut.result()
        if "error" in got:
            log(f"sensor {got['host']}: skipped ({got['error']})")
            sensor_report.append({"host": got["host"], "error": got["error"]})
            continue
        own = sensors.sensor_macs(got["probe"])
        for net in sensors.networks_from_probe(got["probe"], got["host"]):
            if net["ctx"]["cidr"] in scanned:
                continue
            nets.append(_apply_network(store, net, {}, entries, log, sensor_macs=own))
            scanned.append(net["ctx"]["cidr"])
        sensor_report.append({"host": got["host"], "errors": got["probe"].get("errors") or {}})
    ports_ok = bool(ports and nets and all(n["ports_ok"] for n in nets))
    summary: dict[str, Any] = {
        "networks": nets,
        "hosts": sum(n["hosts"] for n in nets),
        "cidr": ", ".join(n["cidr"] for n in nets),
        "ports": ports_ok,
        **extra,
    }
    if sensor_report:
        summary["sensors"] = sensor_report
    if ports and not ports_ok:
        log("port scan did not complete; keeping the previous port evidence")
    if gateway:
        gw = _gateway_pass(store, nets_ctx[0] if nets_ctx else None, entries, log)
        if gw:
            summary["gateway"] = gw
    store.mark_presence(started, networks=scanned)
    if threats:
        from . import threat

        try:
            summary["findings"] = threat.run(store, log=log)
        except Exception as e:  # noqa: BLE001 - an intel outage must not kill the inventory
            log(f"threat pass failed: {e}")
    events = watch.diff(before, watch.snapshot(store), ports_scanned=ports_ok)
    store.add_events(events)
    summary["events"] = len(events)
    if events:
        log(f"changes: {len(events)} ({', '.join(sorted({e['kind'] for e in events}))})")
    from . import plan

    sc = plan.score(store)
    summary["score"], summary["grade"] = sc["score"], sc["grade"]
    log(f"posture: {sc['score']}/100 ({sc['grade']})")
    summary["seconds"] = round(time.time() - started, 1)
    store.record_scan(started, summary)
    log(f"done in {summary['seconds']}s")
    return summary | {"event_list": events}


def ingest_probe(store: Store, probe: dict[str, Any], sensor: str, log=print) -> dict[str, Any]:
    """Fold a probe someone ran by hand into the inventory (networks the appliance itself
    scans are left alone: its own view of them is fresher and complete)."""
    from . import sensors, threat

    with watch.scan_lock():
        started = time.time()
        before = watch.snapshot(store)
        entries = kblib.load()
        try:
            local = {c["cidr"] for c in discover.lan_contexts()}
        except RuntimeError:
            local = set()
        own = sensors.sensor_macs(probe)
        nets = [
            _apply_network(store, n, {}, entries, log, sensor_macs=own)
            for n in sensors.networks_from_probe(probe, sensor)
            if n["ctx"]["cidr"] not in local
        ]
        store.mark_presence(started, networks=[n["cidr"] for n in nets])
        threat.run(store, log=log)
        events = watch.diff(before, watch.snapshot(store), ports_scanned=False)
        store.add_events(events)
        return {"networks": nets, "events": len(events)}


def _collect_local(ctx, ports, log) -> dict[str, Any]:
    log(f"LAN {ctx['cidr']} on {ctx['iface']} (gateway {ctx['gateway'] or '?'})")
    neigh = discover.arp_sweep(ctx["cidr"], ctx["iface"])
    if ctx.get("mac"):
        neigh[ctx["local_ip"]] = ctx["mac"]
    log(f"  ARP: {len(neigh)} hosts")
    names = discover.reverse_dns(list(neigh))
    mdns = discover.mdns(ctx["iface"], local_ip=ctx["local_ip"])
    log(f"  mDNS: {len(mdns)} hosts advertising")
    ssdp = discover.ssdp(local_ip=ctx["local_ip"])
    log(f"  SSDP/UPnP: {len(ssdp)} hosts")
    svc = discover.service_scan(list(neigh)) if ports else None
    if ports:
        eng = discover.port_engine()
        log(
            f"  ports ({eng}): {len(svc)} hosts with open ports"
            if svc is not None
            else f"  ports ({eng}): failed"
        )
    return {"ctx": ctx, "neigh": neigh, "names": names, "mdns": mdns, "ssdp": ssdp, "svc": svc}


def _alias(store, net, ip, mac, sensor_macs) -> int | None:
    """A device we already know under another address on another network: the sensor's own
    Wi-Fi interface, or the router that owns this network (same box, neighboring MAC)."""
    from . import sensors

    ctx = net["ctx"]
    known = [d for d in store.devices(include_retired=True) if d["mac"] and d["network"]]
    others = [d for d in known if d["network"] != ctx["cidr"]]
    if mac in sensor_macs or mac == ctx.get("mac"):
        for d in others:
            if d["mac"] in sensor_macs:
                store.add_evidence(d["id"], "sensor", "also_at", f"{ip} on {ctx['cidr']}")
                return d["id"]
    # Apple devices: the AirPlay device id is per machine, not per interface, so a MacBook on
    # Ethernet and Wi-Fi at once is one device (and its findings must count once)
    ids = sensors.apple_ids(net["mdns"].get(ip, []))
    if ids:
        for d in others:
            theirs = sensors.apple_ids(
                [(e["source"], e["key"], e["value"]) for e in store.evidence(d["id"])]
            )
            if ids & theirs:
                store.add_evidence(d["id"], "sensor", "also_at", f"{ip} on {ctx['cidr']}")
                return d["id"]
    if ip == ctx.get("gateway"):
        for d in others:
            if sensors.same_box(d["mac"], mac):
                store.add_evidence(d["id"], "sensor", "routes_network", ctx["cidr"])
                store.add_evidence(d["id"], "sensor", "inner_address", f"{ip} ({mac})")
                return d["id"]
    return None


def _apply_network(store, net, peers, entries, log, sensor_macs=frozenset()) -> dict[str, Any]:
    """Fold one collected network (local or from a sensor) into the inventory."""
    ctx = net["ctx"]
    neigh, names, mdns, ssdp, svc = (net[k] for k in ("neigh", "names", "mdns", "ssdp", "svc"))
    if net.get("via"):
        log(
            f"sensor {net['via']}: {ctx['cidr']} (gateway {ctx['gateway'] or '?'}): "
            f"{len(neigh)} hosts, {len(mdns)} mDNS, {len(ssdp)} SSDP"
            + (f", ports on {len(svc)}" if svc is not None else "")
        )
    hosts = 0
    for ip, mac in neigh.items():
        if net.get("via") and _alias(store, net, ip, mac, sensor_macs) is not None:
            continue
        hosts += 1
        vendor = discover.oui_vendor(mac)
        did = store.upsert_seen(mac, ip, names.get(ip), vendor, network=ctx["cidr"])
        if net.get("via"):
            store.clear_evidence(did, "sensor")
            store.add_evidence(did, "sensor", "seen_by", net["via"])
        if discover.is_random_mac(mac):
            store.add_evidence(did, "arp", "mac_randomized", "yes")
        rnd = discover.is_random_mac(mac)
        prior = store.evidence(did)
        selfr = mdns.get(ip, []) + [
            (e["source"], e["key"], e["value"]) for e in prior if e["source"] == "mdns"
        ]
        ts = discover.attribute_tailscale(peers.get(ip, []), vendor, rnd, self_reports=selfr)
        if ts:  # a fresh Tailscale view replaces the old one (drops stale NAT verdicts)
            store.clear_evidence(did, "tailscale")
        elif _stale_nat(prior, vendor, rnd, selfr):
            # no live sighting this time, but what we know now clears an old NAT verdict
            store.delete_evidence(did, "tailscale", "nat_for")
        if svc is not None:  # fresh port view: ports that closed must disappear
            store.clear_evidence(did, "ports")
            store.add_evidence(did, "ports", "scanned", "yes")
        sightings = mdns.get(ip, []) + ssdp.get(ip, []) + (svc or {}).get(ip, []) + ts
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
            is_self=ip == ctx["local_ip"] and not net.get("via"),
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
        "via": net.get("via"),
        "hosts": hosts,
        "mdns": len(mdns),
        "ssdp": len(ssdp),
        "ports_ok": svc is not None,
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


def _stale_nat(prior: list[dict[str, Any]], vendor, rnd: bool, selfr) -> bool:
    """True if a stored 'NATs peer X' verdict no longer holds given current self-reports."""
    for e in prior:
        if e["source"] == "tailscale" and e["key"] == "nat_for":
            name, _, os_ = e["value"].rpartition(" (")
            peer = [("tailscale", "name", name), ("tailscale", "os", os_.rstrip(")"))]
            if discover.attribute_tailscale(peer, vendor, rnd, self_reports=selfr) == peer:
                return True
    return False


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
