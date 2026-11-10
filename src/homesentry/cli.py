"""homesentry scan | list | serve"""

from __future__ import annotations

import argparse

from . import data_dir
from .store import Store


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="homesentry")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="discover devices on the LAN")
    s.add_argument("--ports", action="store_true", help="also run an nmap service scan (slower)")
    sub.add_parser("list", help="print the inventory")
    sub.add_parser("threats", help="re-run the threat pass on the current inventory")
    sub.add_parser("gateway", help="read the gateway admin pages (read-only) and summarize")
    sub.add_parser("outside", help="outside-in TCP exposure check from your probe host")
    v = sub.add_parser("serve", help="run the web UI")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8720)
    a = ap.parse_args(argv)

    store = Store(data_dir() / "inventory.db")
    if a.cmd == "scan":
        from .scan import run_scan

        run_scan(store, ports=a.ports)
        a.cmd = "list"
    if a.cmd == "outside":
        from . import outside

        outside.run_and_record(store)
        return
    if a.cmd == "gateway":
        import json

        from . import discover, gateway

        creds = gateway.load_credentials()
        if not creds:
            raise SystemExit(f"no credentials: create {gateway.ENV_PATH} (mode 600)")
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
