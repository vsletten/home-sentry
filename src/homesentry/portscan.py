"""Native TCP port + service scanner: no nmap, no root, no raw packets, any OS.

Two phases per scan:
  1. connect scan: a bounded-concurrency asyncio connect() to every (host, port). Open = the
     handshake completed. Closed and filtered both read as "not open"; we never claim more.
  2. service probes on the open ports only: read a greeting (SSH, FTP, SMTP, VNC, ...) or speak
     a few bytes of the protocol (HTTP, TLS, DNS version.bind, SMB, AFP, RTSP) to learn the
     product and version. Each probe is small, read-only and protocol-legal.

Output matches the evidence the rest of HomeSentry already reads:
    ("ports", "open_port", "445/tcp microsoft-ds Samba smbd 4.6.2")
    ("ports", "http_title", "Remote UI: Login")

The same string conventions nmap uses for the products the threat engine matches (OpenSSH,
Samba smbd, Netatalk, dnsmasq, nginx, Apache httpd, lighttpd, Dropbear sshd), so a CVE lead
reads the same whichever engine produced it.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import socket
import ssl
import struct
import time
from collections.abc import Iterable

Sighting = tuple[str, str, str]
SRC = "ports"

# Port -> service name. The union of the ports that matter in homes (IoT, NAS, media, remote
# access, cameras, smart-home) and the classic top-100 TCP list, so switching engines never
# drops coverage. Port numbers and IANA-style names are facts, not anyone's database.
PORTS: dict[int, str] = {
    7: "echo", 9: "discard", 13: "daytime", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    26: "rsftp", 37: "time", 53: "domain", 79: "finger", 80: "http", 81: "http", 88: "kerberos-sec",
    106: "pop3pw", 110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 144: "news", 179: "bgp", 199: "smux", 389: "ldap",
    427: "svrloc", 443: "https", 444: "snpp", 445: "microsoft-ds", 465: "smtps", 513: "login",
    514: "shell", 515: "printer", 543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp",
    587: "submission", 631: "ipp", 636: "ldaps", 646: "ldp", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1025: "nfs-or-iis", 1026: "lsa-or-nterm", 1027: "iis",
    1028: "unknown", 1029: "ms-lsa", 1080: "socks", 1110: "nfsd-status", 1194: "openvpn",
    1400: "sonos", 1433: "ms-sql-s", 1720: "h323q931", 1723: "pptp", 1755: "wms",
    1883: "mqtt", 1900: "upnp", 2000: "cisco-sccp", 2001: "dc", 2049: "nfs", 2121: "ccproxy-ftp",
    2375: "docker", 2376: "docker-tls", 2717: "pn-requester", 3000: "http-alt", 3128: "squid-http",
    3260: "iscsi", 3306: "mysql", 3389: "ms-wbt-server", 3689: "daap", 3986: "mapper-ws_ethd",
    4443: "https-alt", 4899: "radmin", 5000: "upnp", 5001: "https-alt", 5009: "airport-admin",
    5051: "ida-agent", 5060: "sip", 5101: "admdog", 5190: "aol", 5357: "wsdapi",
    5432: "postgresql", 5443: "https-alt", 5555: "adb", 5631: "pcanywheredata", 5666: "nrpe",
    5800: "vnc-http", 8181: "http-alt",
    5900: "vnc", 5901: "vnc-1", 5985: "wsman", 6000: "X11", 6001: "X11:1", 6379: "redis",
    6466: "androidtv-remote", 6646: "unknown", 7000: "afs3-fileserver", 7070: "realserver",
    7547: "cwmp", 8000: "http-alt", 8008: "http", 8009: "ajp13", 8060: "roku-ecp",
    8080: "http-proxy", 8081: "blackice-icecap", 8088: "radan-http", 8123: "home-assistant",
    8443: "https-alt", 8554: "rtsp-alt", 8883: "secure-mqtt", 8888: "http-alt", 9000: "cslistener",
    9080: "glrpc", 9100: "jetdirect", 9200: "elasticsearch", 9443: "https-alt", 9999: "abyss",
    10000: "snet-sensor-mgmt", 11211: "memcache", 27017: "mongodb", 32400: "plex",
    32768: "filenet-tms", 34567: "dvr-xmeye", 37777: "dvr-dahua", 49152: "upnp",
    49153: "unknown", 49154: "unknown", 49155: "unknown", 49156: "unknown", 49157: "unknown",
    62078: "iphone-sync",
}  # fmt: skip

TLS_PORTS = {443, 465, 636, 990, 993, 995, 2376, 4443, 5001, 5443, 5986, 6443, 7443, 8443, 8883,
             9443}  # fmt: skip
HTTP_PORTS = {80, 81, 631, 3000, 5000, 5357, 7000, 8000, 8008, 8060, 8080, 8081, 8088, 8123,
              8181, 8888, 9000, 9080, 9200, 10000, 32400, 49152}  # fmt: skip
RTSP_PORTS = {554, 8554}
# NEVER send bytes to these. Raw-print ports print whatever arrives: an HTTP probe to 9100 is a
# page of garbage on the family printer (learned the hard way, same rule as nmap's
# `Exclude T:9100-9107`). LPD (515) queues jobs. We only note that they are open.
NO_PROBE = set(range(9100, 9108)) | {515}
SMB_PORTS = {139, 445}

CONNECT_TIMEOUT = 1.0  # LAN round trips are milliseconds; a filtered port costs this, per port
PROBE_TIMEOUT = 4.0


# ---- public API ----------------------------------------------------------------
def scan(
    ips: Iterable[str],
    ports: Iterable[int] | None = None,
    concurrency: int = 256,
    probes: bool = True,
) -> dict[str, list[Sighting]] | None:
    """Open ports + service detail per host. {} = scanned, nothing open; None = did not run."""
    ips = [ip for ip in ips if ip]
    if not ips:
        return None
    plist = sorted(set(ports or PORTS))
    try:
        return asyncio.run(_scan(ips, plist, _safe_concurrency(concurrency), probes))
    except (OSError, RuntimeError):
        return None


def _safe_concurrency(want: int) -> int:
    """macOS defaults to 256 open files per process; leave headroom for everything else."""
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 4096 and (hard == resource.RLIM_INFINITY or hard > soft):
            target = 4096 if hard == resource.RLIM_INFINITY else min(4096, hard)
            with contextlib.suppress(ValueError, OSError):
                resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
                soft = target
        return max(16, min(want, soft - 96))
    except ImportError:  # Windows: no rlimit, select() limits don't apply to the proactor
        return want


# Embedded TCP stacks (printers, cameras, DVRs) drop or wedge under a burst of SYNs: a Canon
# MFP answered nothing at all when hit with ~120 parallel connects. Cap per-host parallelism and
# retry a timed-out port once; a refused port is a definite answer and never retried.
PER_HOST = 12  # 24 already cost a 2007-era set-top box one of its three ports
# A wedged stack answers on common ports once it recovers; no need to re-walk the whole list.
RETRY_PORTS = {21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 1883, 3389, 5000, 5900, 7000, 8008,
               8080, 8443, 9100, 62078}  # fmt: skip


async def _scan(ips, plist, concurrency, probes) -> dict[str, list[Sighting]]:
    sem = asyncio.Semaphore(concurrency)
    host_sem = {ip: asyncio.Semaphore(PER_HOST) for ip in ips}

    async def attempt(ip: str, port: int, timeout: float) -> bool | None:
        """True open, False refused/unreachable, None timed out."""
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except TimeoutError:
            return None
        except OSError:
            return False
        w.close()
        with contextlib.suppress(OSError, TimeoutError, asyncio.TimeoutError):
            await asyncio.wait_for(w.wait_closed(), 0.5)
        return True

    refused: set[str] = set()  # hosts that sent at least one RST: no filtering firewall
    timed_out: dict[str, list[int]] = {}

    async def is_open(ip: str, port: int, timeout: float = CONNECT_TIMEOUT):
        async with host_sem[ip], sem:
            got = await attempt(ip, port, timeout)
            if got is False:
                refused.add(ip)
            elif got is None:
                timed_out.setdefault(ip, []).append(port)
            return (ip, port) if got else None

    first = [r for r in await asyncio.gather(*(is_open(i, p) for i in ips for p in plist)) if r]
    # Retry what timed out, judged per host (measured on a real LAN):
    #  - mostly refusing, a few timeouts (a Mac: 118 RST, 11 timeouts = RST rate limiting)
    #    -> the timeouts are anomalies: retry each of them, with a longer timeout.
    #  - mostly timeouts (set-top boxes, mesh routers: filtering, with a stray RST) -> retry
    #    only the ports worth a second look; re-walking the list costs a timeout per port.
    #    A 2007 DIRECTV box answers its 8080 late, which is why web ports are in that set.
    worth = RETRY_PORTS | HTTP_PORTS | TLS_PORTS
    again = []
    for ip, ports_ in timed_out.items():
        mostly_refusing = len(ports_) <= len(plist) // 4
        again += [(ip, p) for p in ports_ if mostly_refusing or p in worth]
    if again:
        await asyncio.sleep(0.5)
        first += [r for r in await asyncio.gather(*(is_open(i, p, 2.0) for i, p in again)) if r]
    found = sorted(set(first))
    psem = asyncio.Semaphore(min(32, concurrency))

    async def describe(ip: str, port: int) -> list[Sighting]:
        async with psem:
            if not probes:
                return [(SRC, "open_port", f"{port}/tcp {PORTS.get(port, 'unknown')}")]
            try:
                return await asyncio.wait_for(probe(ip, port), 3 * PROBE_TIMEOUT)
            except (OSError, TimeoutError, ssl.SSLError):
                return [(SRC, "open_port", f"{port}/tcp {PORTS.get(port, 'unknown')}")]

    results = await asyncio.gather(*(describe(ip, port) for ip, port in found))
    out: dict[str, list[Sighting]] = {}
    for (ip, _), sights in zip(found, results, strict=True):
        out.setdefault(ip, []).extend(sights)
    return out


# ---- service probes --------------------------------------------------------------
async def probe(ip: str, port: int) -> list[Sighting]:
    name = PORTS.get(port, "unknown")
    if port in NO_PROBE:
        return [_open(port, name, "")]
    if port in SMB_PORTS:
        detail = await _smb(ip, port)
        return [_open(port, name, detail)]
    if port == 548:
        return [_open(port, name, await _afp(ip, port))]
    if port == 53:
        return [_open(port, name, await _dns_version(ip, port))]
    if port in RTSP_PORTS:
        hdrs = await _request(ip, port, b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", tls=False)
        return [_open(port, name, product_from_server((hdrs or {}).get("server", "")))]
    if port in TLS_PORTS or port in HTTP_PORTS:
        return await _http(ip, port, name, tls=port in TLS_PORTS)
    banner = await _greeting(ip, port)
    if banner is None:
        return [_open(port, "tcpwrapped", "")]
    if banner.startswith(b"HTTP/"):
        return await _http(ip, port, "http", tls=False)
    if banner:
        return [_open(port, *describe_banner(port, banner))]
    # silent service: many speak only when spoken to; try HTTP, then TLS, as nmap's NULL probe
    # falls through to GetRequest
    got = await _http(ip, port, name, tls=False, quiet=True)
    if got:
        return got
    got = await _http(ip, port, name, tls=True, quiet=True)
    return got or [_open(port, name, "")]


def _open(port: int, name: str, detail: str) -> Sighting:
    return (SRC, "open_port", f"{port}/tcp {name} {detail}".strip())


async def _connect(ip: str, port: int, tls: bool = False):
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # identifying a device, not trusting it
    return await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ctx, server_hostname=None if not tls else ""),
        PROBE_TIMEOUT,
    )


async def _greeting(ip: str, port: int, wait: float = 2.0) -> bytes | None:
    """What the service says first. b'' = silent; None = it hung up on us (tcpwrapped)."""
    r, w = await _connect(ip, port)
    try:
        data = await asyncio.wait_for(r.read(1024), wait)
        return data if data else None
    except TimeoutError:
        return b""
    finally:
        w.close()


async def _exchange(
    ip: str, port: int, payload: bytes, n: int = 4096, tls=False, done=None
) -> bytes:
    r, w = await _connect(ip, port, tls=tls)
    buf = b""
    try:
        w.write(payload)
        await w.drain()
        end = time.monotonic() + PROBE_TIMEOUT
        while len(buf) < n and time.monotonic() < end:
            chunk = await asyncio.wait_for(r.read(n - len(buf)), max(0.1, end - time.monotonic()))
            if not chunk:
                break
            buf += chunk
            if (done or _complete)(buf):
                break
        return buf
    except TimeoutError:
        return buf
    finally:
        w.close()


def _complete(buf: bytes) -> bool:
    if buf[:5] in (b"HTTP/", b"RTSP/"):
        head, sep, body = buf.partition(b"\r\n\r\n")
        return bool(sep) and (b"</title>" in body.lower() or len(body) > 3000)
    return False


async def _request(ip, port, payload, tls) -> dict[str, str] | None:
    raw = await _exchange(ip, port, payload, n=16384, tls=tls)
    return parse_http(raw) if raw else None


async def _http(ip, port, name, tls, quiet=False) -> list[Sighting]:
    req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: HomeSentry\r\nAccept: */*\r\n\r\n"
    try:
        resp = await _request(ip, port, req.encode(), tls)
    except (OSError, TimeoutError, ssl.SSLError):
        resp = None
    if not resp or "status" not in resp:
        return [] if quiet else [_open(port, name, "")]
    svc = "https" if tls else "http"
    detail = http_product(resp)
    if not detail:  # no Server header: error pages often still sign their name (nmap's trick)
        bad = f"GET /homesentry-{port}.404 HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
        with contextlib.suppress(OSError, TimeoutError, asyncio.TimeoutError, ssl.SSLError):
            detail = http_product(await _request(ip, port, bad, tls) or {})
    out = [_open(port, svc, detail)]
    title = resp.get("title", "")
    if title and not re.match(r"^\d{3}\b|^(?:Moved|Found|Redirect|Error|Not Found)\b", title):
        out.append((SRC, "http_title", title[:200]))
    return out


# ---- parsers (pure; unit-tested) ---------------------------------------------------
def parse_http(raw: bytes) -> dict[str, str]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    out: dict[str, str] = {}
    if lines and re.match(r"^(HTTP|RTSP)/\d", lines[0]):
        out["status"] = lines[0]
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip().lower()] = v.strip()
    sig = re.search(
        rb"<(?:center|address)>\s*((?:nginx|Apache|lighttpd|openresty)/\d[\w.]*)", body, re.I
    )
    if sig:
        out["body_server"] = sig.group(1).decode("latin-1")
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()
        if title:
            out["title"] = title
    return out


# Known web UIs whose Server header says nothing useful: title/header -> nmap-style product
HTTP_FINGERPRINTS: list[tuple[str, str]] = [
    (r"^Remote UI\b|^CANON HTTP Server", "Canon printer web interface"),
    (r"\bHP (?:LaserJet|OfficeJet|DeskJet|ENVY|Smart Tank)\b", "HP printer web interface"),
    (r"\bEPSON\b", "Epson printer web interface"),
    (r"\bBrother\b.*\b(?:HL|MFC|DCP)-", "Brother printer web interface"),
]


def http_product(resp: dict[str, str]) -> str:
    server = product_from_server(resp.get("server", "") or resp.get("body_server", ""))
    title = resp.get("title", "")
    for rx, product in HTTP_FINGERPRINTS:
        if re.search(rx, title) or re.search(rx, resp.get("server", "")):
            return product
    return server


def product_from_server(server: str) -> str:
    """`nginx/1.21.0` -> `nginx 1.21.0`;
    `Apache/2.4.41 (Ubuntu)` -> `Apache httpd 2.4.41 (Ubuntu)` (nmap's naming)."""
    s = server.strip()
    if not s:
        return ""
    if m := re.match(r"^Apache/(\d[\w.]*)(.*)$", s):
        return f"Apache httpd {m.group(1)}{m.group(2)}".strip()
    return re.sub(r"^([A-Za-z][\w.-]*)/(\d[\w.-]*)", r"\1 \2", s)[:120]


def describe_banner(port: int, banner: bytes) -> tuple[str, str]:
    """(service name, product detail) from a greeting."""
    text = banner.decode("utf-8", "replace")
    if text.startswith("SSH-"):
        return "ssh", ssh_product(text.splitlines()[0])
    if text.startswith("RFB "):
        m = re.match(r"RFB (\d+)\.(\d+)", text)
        if m and m.group(2) == "889":  # Apple Screen Sharing advertises RFB 003.889
            return "vnc", "Apple remote desktop vnc"
        return "vnc", f"VNC protocol {int(m.group(1))}.{int(m.group(2))}" if m else ""
    if port == 3306 and len(banner) > 5:
        m = re.search(rb"\x0a([0-9][\w.\-]+)\x00", banner[4:])
        if m:
            ver = m.group(1).decode(errors="replace")
            return "mysql", ("MariaDB " if "mariadb" in ver.lower() else "MySQL ") + ver
    printable = re.sub(r"[^\x20-\x7e]+", " ", text).strip()
    first = printable.split("  ")[0][:100]
    name = PORTS.get(port, "unknown")
    if re.match(r"^220[ -]", first) and port not in (25, 465, 587):
        name = "ftp" if name in ("unknown", "ftp", "ccproxy-ftp") else name
    return name, first


def ssh_product(line: str) -> str:
    """`SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20` -> `OpenSSH 9.6p1 Ubuntu 3ubuntu13.20
    protocol 2.0`; `SSH-2.0-dropbear_2020.81` -> `Dropbear sshd 2020.81 protocol 2.0`."""
    m = re.match(r"^SSH-(\d+\.\d+)-(\S+)\s*(.*)$", line.strip())
    if not m:
        return ""
    proto, soft, comment = m.groups()
    if mm := re.match(r"OpenSSH_(\S+)", soft):
        prod = f"OpenSSH {mm.group(1)}"
    elif mm := re.match(r"dropbear_(\S+)", soft, re.I):
        prod = f"Dropbear sshd {mm.group(1)}"
    else:
        prod = soft.replace("_", " ")
    if comment:
        prod += " " + comment.replace("-", " ", 1)
    return f"{prod} protocol {proto}"


# ---- DNS: version.bind (CHAOS TXT) ---------------------------------------------------
def dns_version_query(qid: int = 0x4853) -> bytes:
    q = struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0) + b"\x07version\x04bind\x00"
    q += struct.pack(">HH", 16, 3)  # TXT, CH
    return struct.pack(">H", len(q)) + q


def parse_dns_txt(msg: bytes) -> str:
    """First TXT string of the first answer in a TCP DNS reply ('' if none)."""
    if len(msg) < 14:
        return ""
    data = msg[2:]
    _, flags, qd, an = struct.unpack(">HHHH", data[:8])
    if an == 0 or flags & 0x000F:
        return ""
    i = 12
    for _ in range(qd):
        i = _skip_name(data, i) + 4
    i = _skip_name(data, i)
    if i + 10 > len(data):
        return ""
    rtype, _, _, rdlen = struct.unpack(">HHIH", data[i : i + 10])
    i += 10
    if rtype != 16 or i >= len(data):
        return ""
    n = data[i]
    return data[i + 1 : i + 1 + n].decode("utf-8", "replace")


def _skip_name(data: bytes, i: int) -> int:
    while i < len(data):
        n = data[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1
    return i


async def _dns_version(ip: str, port: int) -> str:
    raw = await _exchange(
        ip, port, dns_version_query(), n=512,
        done=lambda b: len(b) >= 2 and len(b) >= 2 + struct.unpack(">H", b[:2])[0],
    )  # fmt: skip
    ver = parse_dns_txt(raw)
    if m := re.match(r"^dnsmasq-(\S+)", ver):
        return f"dnsmasq {m.group(1)}"
    return ver[:80]


# ---- SMB: SMB1 negotiate + anonymous session setup -> Samba version -------------------
def _smb1(command: int, words: bytes, data: bytes, uid: int = 0) -> bytes:
    hdr = b"\xffSMB" + bytes([command]) + b"\x00" * 4  # status
    hdr += b"\x18" + struct.pack("<H", 0x0001)  # flags (case-insens, canon); flags2: long names
    hdr += b"\x00" * 12 + struct.pack(
        "<HHHH", 0, 0xFEFF, uid, 1
    )  # pidhigh,sig,rsv / tid,pid,uid,mid
    body = bytes([len(words) // 2]) + words + struct.pack("<H", len(data)) + data
    msg = hdr + body
    return b"\x00" + struct.pack(">I", len(msg))[1:] + msg


def smb_negotiate() -> bytes:
    return _smb1(0x72, b"", b"\x02NT LM 0.12\x00")


def smb_session_setup(session_key: int) -> bytes:
    words = struct.pack("<BBHHHHIHHII", 0xFF, 0, 0, 0xFFFF, 2, 0, session_key, 0, 0, 0, 0)
    data = b"\x00" + b"\x00" + b"Unix\x00" + b"HomeSentry\x00"  # account, domain: anonymous
    return _smb1(0x73, words, data)


def parse_smb_negotiate(resp: bytes) -> dict[str, object]:
    """{'smb1': bool, 'session_key': int, 'domain': str} from a negotiate response."""
    msg = resp[4:]
    if msg[:4] == b"\xfeSMB":
        return {"smb1": False, "smb2": True}
    if msg[:4] != b"\xffSMB" or len(msg) < 37:
        return {"smb1": False}
    wc = msg[32]
    words = msg[33 : 33 + wc * 2]
    if wc != 17 or len(words) < 34:
        return {"smb1": False}
    dialect = struct.unpack("<H", words[0:2])[0]
    if dialect == 0xFFFF:
        return {"smb1": False}
    session_key = struct.unpack("<I", words[15:19])[0]
    flags2 = struct.unpack("<H", msg[10:12])[0]  # the header's flags, not CAP_UNICODE, say
    chlen = words[33]  # how this message's strings are encoded
    bc_off = 33 + wc * 2
    data = msg[bc_off + 2 :]
    rest = data[chlen:]
    domain = _smb_strings(rest, unicode=bool(flags2 & 0x8000))[:1]
    return {"smb1": True, "session_key": session_key, "domain": domain[0] if domain else ""}


def parse_smb_session(resp: bytes) -> dict[str, str]:
    """NativeOS / NativeLanMan from a session-setup response (present even on some failures)."""
    msg = resp[4:]
    if msg[:4] != b"\xffSMB" or len(msg) < 35:
        return {}
    flags2 = struct.unpack("<H", msg[10:12])[0]
    wc = msg[32]
    bc_off = 33 + wc * 2
    if bc_off + 2 > len(msg):
        return {}
    bc = struct.unpack("<H", msg[bc_off : bc_off + 2])[0]
    data = msg[bc_off + 2 : bc_off + 2 + bc]
    unicode = bool(flags2 & 0x8000)
    if unicode and (bc_off + 2) % 2:  # unicode strings are 2-byte aligned from the header
        data = data[1:]
    parts = _smb_strings(data, unicode)
    keys = ("os", "lanman", "domain")
    return {k: v for k, v in zip(keys, parts, strict=False) if v}


def _smb_strings(data: bytes, unicode: bool) -> list[str]:
    if unicode:
        return [s for s in data.decode("utf-16le", "replace").split("\x00")][:3]
    return [s.decode("latin-1") for s in data.split(b"\x00")][:3]


def nbss_session_request(called: str = "*SMBSERVER", calling: str = "HOMESENTRY") -> bytes:
    def enc(name: str, suffix: int) -> bytes:
        raw = name.upper().ljust(15)[:15].encode() + bytes([suffix])
        return (
            b"\x20" + bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 0xF))) + b"\x00"
        )

    payload = enc(called, 0x20) + enc(calling, 0x00)
    return b"\x81\x00" + struct.pack(">H", len(payload)) + payload


def smb_detail(neg: dict, sess: dict) -> str:
    lanman = sess.get("lanman", "")
    if m := re.match(r"^Samba (\d+\.\d+\.\d+\S*)", lanman):
        out = f"Samba smbd {m.group(1)}"
    elif lanman:
        out = f"{lanman} {sess.get('os', '')}".strip()
    elif neg.get("smb1"):
        out = "SMB1"
    elif neg.get("smb2"):
        out = ""  # modern SMB2/3 server: no version is disclosed, and that's the good case
    else:
        out = ""
    wg = sess.get("domain") or neg.get("domain") or ""
    return f"{out} workgroup: {wg}".strip() if wg and out else out


async def _smb(ip: str, port: int) -> str:
    r, w = await _connect(ip, port)

    async def frame() -> bytes:
        head = await asyncio.wait_for(r.readexactly(4), PROBE_TIMEOUT)
        n = struct.unpack(">I", b"\x00" + head[1:])[0]
        return head + await asyncio.wait_for(r.readexactly(n), PROBE_TIMEOUT)

    try:
        if port == 139:
            w.write(nbss_session_request())
            await w.drain()
            if (await frame())[0] != 0x82:
                return ""
        w.write(smb_negotiate())
        await w.drain()
        neg = parse_smb_negotiate(await frame())
        sess: dict[str, str] = {}
        if neg.get("smb1"):
            key = neg.get("session_key")
            w.write(smb_session_setup(key if isinstance(key, int) else 0))
            await w.drain()
            sess = parse_smb_session(await frame())
        return smb_detail(neg, sess)
    except (asyncio.IncompleteReadError, TimeoutError, OSError):
        return ""
    finally:
        w.close()


# ---- AFP: DSIGetStatus -> server name, machine type, AFP versions -----------------------
DSI_GETSTATUS = struct.pack(">BBHIII", 0, 3, 1, 0, 0, 0)


def parse_afp_status(resp: bytes) -> str:
    if len(resp) < 16 + 12:
        return ""
    b = resp[16:]
    mt_off, ver_off = struct.unpack(">HH", b[0:4])
    name = _pascal(b, 10)
    mtype = _pascal(b, mt_off)
    versions = []
    if ver_off and ver_off < len(b):
        n, i = b[ver_off], ver_off + 1
        for _ in range(n):
            v = _pascal(b, i)
            versions.append(v)
            i += 1 + len(v.encode("latin-1", "replace"))
    prod = mtype
    if m := re.match(r"^Netatalk\s*(\d+\.\d+(?:\.\d+)?)", mtype):
        prod = f"Netatalk {m.group(1)}"
    afp = [v.removeprefix("AFPX").removeprefix("AFP") for v in versions if v.startswith("AFP")]
    tail = [f"name: {name}"] if name else []
    if afp:
        tail.append(f"protocol {afp[-1]}")
    return f"{prod} {'; '.join(tail)}".strip()


def _pascal(b: bytes, off: int) -> str:
    if off >= len(b):
        return ""
    n = b[off]
    return b[off + 1 : off + 1 + n].decode("utf-8", "replace")


async def _afp(ip: str, port: int) -> str:
    raw = await _exchange(
        ip, port, DSI_GETSTATUS, n=2048,
        done=lambda b: len(b) >= 16 and len(b) >= 16 + struct.unpack(">I", b[8:12])[0],
    )  # fmt: skip
    return parse_afp_status(raw)


# ---- convenience for one-off use ----------------------------------------------------
def reachable(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False
