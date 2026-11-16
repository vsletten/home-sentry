"""Build src/homesentry/kbdata/oui.tsv.gz from the public IEEE MA-L registry.

    curl -sSfLo oui.csv https://standards-oui.ieee.org/oui/oui.csv
    uv run python scripts/build_oui.py oui.csv

Vendor names are shortened the way people (and nmap's table) write them: corporate suffixes
dropped, "Apple, Inc." -> "Apple". One `PREFIX<TAB>Vendor` line per 24-bit OUI, sorted, gzip.
"""

from __future__ import annotations

import csv
import gzip
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src/homesentry/kbdata/oui.tsv.gz"

SUFFIX = re.compile(
    r"(?:[,.]?\s+|,)(?:inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|"
    r"gmbh|ag|sa|s\.a|s\.a\.s|sas|srl|s\.r\.l|spa|s\.p\.a|bv|b\.v|nv|n\.v|plc|pte|pty|oy|ab|as|"
    r"a/s|kg|kk|k\.k|se|lp|llp|pvt|private|group|holdings?|technolog(?:y|ies)|electronics?|"
    r"industrial|international|systems?|communications?|networks?|devices?)\.?$",
    re.I,
)
KEEP = re.compile(r"networks?|systems?|communications?|devices?|electronics?|technolog", re.I)


def short(name: str) -> str:
    n = re.sub(r"\s+", " ", name.replace("\u00a0", " ")).strip().strip(",").strip()
    n = re.sub(r"\s*\([^)]*\)\s*$", "", n)  # "(Shenzhen) Ltd" style tails
    for _ in range(4):  # "Co., Ltd." takes two passes; stop before eating the real name
        m = SUFFIX.search(n)
        if not m or m.start() == 0:
            break
        candidate = n[: m.start()].rstrip(" ,.")
        if KEEP.search(m.group(0)) and len(candidate.split()) < 2:
            break  # "Mojo Networks" stays; "Ubiquiti Networks" -> keep too (one-word stem)
        n = candidate
    n = n.strip(" ,.") or name.strip()
    # "CANON" -> "Canon", "ASUSTek COMPUTER" -> "ASUSTek Computer"; short acronyms (HP, LG, TCL,
    # INTL) and mixed tokens (TP-LINK's halves are short) stay as registered
    return re.sub(r"\b[A-Z]{5,}\b", lambda m: m.group(0).capitalize(), n)


def build(src: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    with src.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if row.get("Registry") != "MA-L":
                continue
            prefix = (row.get("Assignment") or "").strip().upper()
            name = (row.get("Organization Name") or "").strip()
            if re.fullmatch(r"[0-9A-F]{6}", prefix) and name and name.lower() != "private":
                out[prefix] = short(name)
    return out


def main() -> None:
    table = build(Path(sys.argv[1]))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{k}\t{v}\n" for k, v in sorted(table.items()))
    OUT.write_bytes(gzip.compress(body.encode(), mtime=0))
    print(f"{len(table)} prefixes -> {OUT} ({OUT.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main()
