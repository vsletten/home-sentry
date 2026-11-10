"""Threat intel cache: pull-only, so the outside world never learns what versions you run.

- CISA KEV: the whole catalog, downloaded and matched locally.
- NVD: fetched per vendor:product with NO version, i.e. "all CVEs for dnsmasq";
  version-range matching happens locally in threat.py.

Everything is cached under data_dir()/intel with a TTL, so repeat runs make zero requests.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

from . import data_dir

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_TTL = 86400
NVD_TTL = 7 * 86400
# NVD without an API key: 5 requests / 30 s. With NVD_API_KEY: 50 / 30 s.
NVD_GAP = 0.7 if os.environ.get("NVD_API_KEY") else 6.5

_last_nvd = 0.0


def cache_dir() -> Path:
    d = data_dir() / "intel"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _fresh(p: Path, ttl: int) -> bool:
    return p.exists() and time.time() - p.stat().st_mtime < ttl


def kev(client: httpx.Client | None = None) -> dict[str, dict[str, Any]]:
    """CVE id -> KEV entry."""
    p = cache_dir() / "kev.json"
    if not _fresh(p, KEV_TTL):
        c = client or httpx.Client(timeout=60)
        try:
            r = c.get(KEV_URL)
            r.raise_for_status()
            p.write_text(r.text)
        except httpx.HTTPError:
            if not p.exists():
                return {}
    data = json.loads(p.read_text())
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def eol_cycles(product: str, client: httpx.Client | None = None) -> list[dict[str, Any]]:
    """endoflife.date release cycles for a product (generic data, no version sent)."""
    p = cache_dir() / f"eol_{product}.json"
    if not _fresh(p, NVD_TTL):
        c = client or httpx.Client(timeout=30)
        try:
            r = c.get(f"https://endoflife.date/api/{product}.json")
            r.raise_for_status()
            p.write_text(r.text)
        except httpx.HTTPError:
            if not p.exists():
                return []
    return json.loads(p.read_text())


def nvd_product(vendor: str, product: str, client: httpx.Client | None = None, log=None):
    """All NVD CVEs whose configurations mention vendor:product (any version)."""
    global _last_nvd
    p = cache_dir() / f"nvd_{vendor}_{product}.json"
    if _fresh(p, NVD_TTL):
        return json.loads(p.read_text())
    c = client or httpx.Client(timeout=90)
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    out: list[dict[str, Any]] = []
    start = 0
    while True:
        wait = NVD_GAP - (time.time() - _last_nvd)
        if wait > 0:
            time.sleep(wait)
        params = {
            "virtualMatchString": f"cpe:2.3:a:{vendor}:{product}",  # never a version
            "resultsPerPage": 2000,
            "startIndex": start,
        }
        try:
            r = c.get(NVD_URL, params=params, headers=headers)
            _last_nvd = time.time()
            r.raise_for_status()
        except httpx.HTTPError as e:
            if log:
                log(f"NVD {vendor}:{product} failed: {e}")
            return json.loads(p.read_text()) if p.exists() else []
        j = r.json()
        out += [v["cve"] for v in j.get("vulnerabilities", [])]
        start += j.get("resultsPerPage", 0)
        if not j.get("resultsPerPage") or start >= j.get("totalResults", 0):
            break
    p.write_text(json.dumps(out))
    if log:
        log(f"NVD {vendor}:{product}: {len(out)} CVEs cached")
    return out
