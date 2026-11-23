"""/var/log/ufw.log analizi: port taraması ve tekrarlayan deneme tespiti. Sadece dosya okur."""
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

KV = re.compile(r"(\w+)=(\S*)")
ISO = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})")
SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
INTERNAL = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
             "0.0.0.0/8", "224.0.0.0/4", "fc00::/7", "fe80::/10", "::1/128", "ff00::/8")]


def is_internal(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a.version == n.version and a in n for n in INTERNAL)


@dataclass
class Event:
    ts: float
    src: str
    proto: str
    dport: Optional[int]


@dataclass
class SourceReport:
    src: str
    count: int = 0
    ports: Set[int] = field(default_factory=set)
    first: float = 0.0
    last: float = 0.0
    scan: bool = False
    repeat_port: Optional[int] = None


def parse_log(text: str, year: Optional[int] = None) -> List[Event]:
    year = year or datetime.now().year
    out = []
    for line in text.splitlines():
        if "[UFW BLOCK]" not in line and "[UFW LIMIT BLOCK]" not in line:
            continue
        m = ISO.match(line); ts = None
        try:
            if m:
                ts = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S").timestamp()
            else:
                m = SYSLOG.match(line)
                if m:
                    ts = datetime(year, MONTHS[m.group(1)], int(m.group(2)),
                                  *map(int, m.group(3).split(":"))).timestamp()
        except (ValueError, KeyError):
            ts = None
        if ts is None:
            continue
        kv = dict(KV.findall(line))
        src = kv.get("SRC")
        try:
            ipaddress.ip_address(src or "")
        except ValueError:
            continue
        dport = int(kv["DPT"]) if kv.get("DPT", "").isdigit() else None
        out.append(Event(ts, src, kv.get("PROTO", "?").lower(), dport))
    return out


def analyze_events(events: List[Event], window: int = 60, scan_ports: int = 15, hits: int = 20) -> Dict[str, SourceReport]:
    by_src: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        by_src[e.src].append(e)
    reports = {}
    for src, evs in by_src.items():
        evs.sort(key=lambda e: e.ts)
        r = SourceReport(src, len(evs), {e.dport for e in evs if e.dport}, evs[0].ts, evs[-1].ts)
        lo = 0
        for hi in range(len(evs)):
            while evs[hi].ts - evs[lo].ts > window:
                lo += 1
            win = evs[lo:hi + 1]
            if len({e.dport for e in win if e.dport}) >= scan_ports:
                r.scan = True
            counts: Dict[int, int] = defaultdict(int)
            for e in win:
                if e.dport:
                    counts[e.dport] += 1
            if counts:
                p, c = max(counts.items(), key=lambda kv: kv[1])
                if c >= hits:
                    r.repeat_port = p
        reports[src] = r
    return reports


def suggestions(reports: Dict[str, SourceReport], whitelist=(), top: int = 10) -> List[SourceReport]:
    """Engelleme ÖNERİLERİ (otomatik uygulanmaz). İç ağ ve beyaz liste hariç."""
    wl = {str(ipaddress.ip_address(w)) for w in whitelist}
    flagged = [r for r in reports.values()
               if (r.scan or r.repeat_port) and not is_internal(r.src) and str(ipaddress.ip_address(r.src)) not in wl]
    flagged.sort(key=lambda r: -r.count)
    return flagged[:top]
