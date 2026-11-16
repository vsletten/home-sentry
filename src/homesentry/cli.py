"""homesentry scan | list | threats | gateway | outside | watch | plan | report | doctor | serve
| probe | compare"""

from __future__ import annotations

import argparse
import os

from . import data_dir
from .store import Store


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="homesentry")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="discover devices on the LAN")
    s.add_argument(
        "--ports", action="store_true", help="also scan ports and identify services (slower)"
    )
    sub.add_parser("list", help="print the inventory")
    sub.add_parser("threats", help="re-run the threat pass on the current inventory")
    sub.add_parser("gateway", help="read the gateway admin pages (read-only) and summarize")
    sub.add_parser("outside", help="outside-in TCP exposure check from your probe host")
    w = sub.add_parser("watch", help="one monitoring tick (what the systemd timer runs)")
    w.add_argument("--ports-every", type=float, default=12, help="hours between port scans")
    w.add_argument("--gateway-every", type=float, default=6, help="hours between gateway reads")
    w.add_argument("--outside-every", type=float, default=24, help="hours between outside-in")
    w.add_argument("--no-notify", action="store_true")
    sub.add_parser("plan", help="posture score and the ranked action plan")
    r = sub.add_parser("report", help="write the household security report (HTML)")
    r.add_argument("-o", "--out", default="homesentry-report.html")
    sub.add_parser("doctor", help="health checks (tools, configs, scans, units)")
    pr = sub.add_parser("probe", help="run every collector, store nothing, print what this sees")
    pr.add_argument("--ports", action="store_true", help="also scan ports and identify services")
    pr.add_argument("--json", action="store_true", help="machine-readable output")
    pr.add_argument("--mdns-seconds", type=float, default=8.0)
    pr.add_argument("--skip", action="append", default=[], help="CIDR to leave out (repeatable)")
    ig = sub.add_parser("ingest", help="fold a probe from another machine into the inventory")
    ig.add_argument("probe_json", help="output of `homesentry probe --json` ('-' for stdin)")
    ig.add_argument("--sensor", default="manual", help="name to record as the sensor")
    cp = sub.add_parser("compare", help="diff a probe (from another machine) against the inventory")
    cp.add_argument("probe_json", help="output of `homesentry probe --json` ('-' for stdin)")
    cp.add_argument("--json", action="store_true")
    v = sub.add_parser("serve", help="run the web UI")
    v.add_argument(
        "--host",
        default=os.environ.get("HOMESENTRY_BIND", "127.0.0.1"),
        help="bind address (default $HOMESENTRY_BIND, else loopback; use your tailnet IP)",
    )
    v.add_argument("--port", type=int, default=8720)
    a = ap.parse_args(argv)

    if a.cmd == "probe":  # before the Store: a probe on a build/test machine creates no inventory
        import json

        from . import probe

        got = probe.collect(ports=a.ports, mdns_seconds=a.mdns_seconds, skip=a.skip)
        if a.json:
            print(json.dumps(got, indent=1))
        else:
            for n in got["networks"]:
                print(f"{n['cidr']} on {n['iface']} via {n['gateway'] or '?'}: {n['counts']}")
                for ip, h in n["hosts"].items():
                    print(f"  {ip:<15} {h['vendor'] or '?':<28} {len(h['sightings'])} sightings")
            for k, v in got["errors"].items():
                print(f"ERROR {k}: {v}")
            print(f"timings: {got['timings']}  total {got['seconds']}s")
        raise SystemExit(1 if got["errors"] else 0)

    store = Store(data_dir() / "inventory.db")
    if a.cmd == "ingest":
        import json
        import sys

        from .scan import ingest_probe

        src = sys.stdin if a.probe_json == "-" else open(a.probe_json)  # noqa: SIM115
        print(json.dumps(ingest_probe(store, json.load(src), a.sensor), indent=1))
        return
    if a.cmd == "compare":
        import json
        import sys

        from . import probe

        src = sys.stdin if a.probe_json == "-" else open(a.probe_json)  # noqa: SIM115
        rep = probe.compare(json.load(src), store)
        print(json.dumps(rep, indent=1) if a.json else probe.render(rep))
        return
    if a.cmd == "scan":
        from .scan import run_scan

        run_scan(store, ports=a.ports, extra={"trigger": "cli"})
        a.cmd = "list"
    if a.cmd == "watch":
        from .watch import ScanBusy, run_watch

        try:
            run_watch(
                store,
                ports_every_h=a.ports_every,
                gateway_every_h=a.gateway_every,
                outside_every_h=a.outside_every,
                notify=not a.no_notify,
            )
        except ScanBusy as e:
            print(f"skipped: {e}")
        return
    if a.cmd == "plan":
        from . import plan

        names = {d["id"]: d["label"] or d["ip"] or "device" for d in store.devices()}
        p = plan.build(store)
        print(f"posture {p['score']}/100 ({p['grade']}); after top actions: {p['projected']}")
        for i, act in enumerate(p["actions"], 1):
            qw = " quick win" if act["quick_win"] else ""
            print(
                f"{i:>3}. +{act['gain']:<5} {act['effort_min']:>4}m [{act['worst']}] "
                f"{plan.render_title(act, names.get)}{qw}"
            )
        return
    if a.cmd == "report":
        from pathlib import Path

        from . import report

        print(report.write(store, Path(a.out)).resolve())
        return
    if a.cmd == "doctor":
        from . import doctor

        raise SystemExit(doctor.main(store))
    if a.cmd == "outside":
        from . import outside

        outside.run_and_record(store)
        return
    if a.cmd == "gateway":
        import json

        from . import discover, gateway

        creds = gateway.load_credentials()
        if not creds:
            raise SystemExit(f"no credentials: create {gateway.env_path()} (mode 600)")
        cfg = gateway.RdkbReader(discover.lan_context()["gateway"]).read(*creds)
        clients = cfg.pop("clients")
        print(json.dumps(cfg, indent=1))
        print(f"{len(clients)} DHCP clients ({sum(c['online'] for c in clients)} online)")
        for f in gateway.config_findings(cfg):
            print(f"  [{f['severity']:>8}] {f['title']}")
        return
    if a.cmd == "threats":
        from . import threat

        threat.run(store)
        for d in store.devices():
            for f in store.findings(d["id"]):
                if f["severity"] != "info":
                    print(f"  [{f['severity']:>8}] {d['label'] or d['ip']}: {f['title']}")
        return
    if a.cmd == "list":
        for d in store.devices():
            flag = "✓" if d["confirmed"] else f"{int((d['confidence'] or 0) * 100):>3}%"
            make, model = (d["make"] or "?")[:18], (d["model"] or "?")[:20]
            print(
                f"{d['id']:>3} {flag:>4} {d['ip'] or '-':<15} {d['device_type'] or '?':<12} "
                f"{make:<18} {model:<20} {d['label'] or ''}"
            )
    elif a.cmd == "serve":
        import uvicorn

        from .web.app import create_app

        uvicorn.run(create_app(store), host=a.host, port=a.port)


if __name__ == "__main__":
    main()
