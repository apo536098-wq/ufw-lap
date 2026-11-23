"""`ufw status [numbered|verbose]` çıktısını ayrıştırır. Sadece metin okur; ağa dokunmaz."""
import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

LINE = re.compile(
    r"^\[\s*(?P<num>\d+)\]\s+(?P<to>.+?)\s{2,}(?P<act>ALLOW|DENY|REJECT|LIMIT)"
    r"(?:\s+(?P<dir>IN|OUT|FWD))?\s{2,}(?P<frm>.+?)\s*$")
PORTSPEC = re.compile(r"^(?P<ports>\d+(?::\d+)?(?:,\d+(?::\d+)?)*)(?:/(?P<proto>tcp|udp))?$")
ANYWHERE = re.compile(r"^Anywhere(?:/(?P<proto>tcp|udp))?$")
FULL = [(1, 65535)]


@dataclass
class ParsedRule:
    num: int
    family: int                      # 4 veya 6
    action: str                      # allow | deny | reject | limit
    direction: str                   # in | out | fwd
    ports: Optional[List[Tuple[int, int]]]   # None = tüm portlar
    proto: Optional[str]             # None = tcp+udp (port varsa) / hepsi (port yoksa)
    src: Optional[object]            # ip_network veya None (= Anywhere)
    iface: Optional[str]
    raw: str
    complex: bool = False            # uygulama profili, hedef IP, kaynak port vb.: kapsama analizinde atlanır
    note: str = ""

    @property
    def allow_like(self) -> bool:
        return self.action in ("allow", "limit")


@dataclass
class Status:
    active: Optional[bool]
    default_in: Optional[str]
    default_out: Optional[str]
    logging: Optional[str]
    rules: List[ParsedRule]


def _ports(spec: str):
    out = []
    for part in spec.split(","):
        lo, hi = (int(x) for x in part.split(":")) if ":" in part else (int(part), int(part))
        if not (1 <= lo <= hi <= 65535):
            return None
        out.append((lo, hi))
    return out


def _strip_iface(s: str):
    m = re.search(r"\s+on\s+(\S+)$", s)
    return (s[:m.start()], m.group(1)) if m else (s, None)


def parse_status(text: str) -> Status:
    active = default_in = default_out = logging = None
    rules: List[ParsedRule] = []
    for line in text.splitlines():
        s = line.rstrip()
        m = re.match(r"^Status:\s*(active|inactive)", s)
        if m:
            active = m.group(1) == "active"; continue
        m = re.match(r"^Logging:\s*(.+)$", s)
        if m:
            logging = m.group(1).strip(); continue
        m = re.match(r"^Default:\s*(\w+)\s*\(incoming\),\s*(\w+)\s*\(outgoing\)", s)
        if m:
            default_in, default_out = m.group(1), m.group(2); continue
        m = LINE.match(re.sub(r"\s+#.*$", "", s))
        if not m:
            continue
        to, frm = m.group("to").strip(), m.group("frm").strip()
        v6 = "(v6)" in to or "(v6)" in frm
        to = to.replace("(v6)", "").strip(); frm = frm.replace("(v6)", "").strip()
        to, if_to = _strip_iface(to); frm, if_frm = _strip_iface(frm)
        iface = if_to or if_frm
        ports = None; proto = None; cplx = False; note = ""
        mp, ma = PORTSPEC.match(to), ANYWHERE.match(to)
        if ma:
            proto = ma.group("proto")
        elif mp:
            ports = _ports(mp.group("ports")); proto = mp.group("proto")
            if ports is None:
                cplx = True; note = "geçersiz port"
        else:
            cplx = True; note = f"uygulama profili veya hedef: '{to}'"
        src = None
        if frm != "Anywhere":
            try:
                src = ipaddress.ip_network(frm, strict=False)
            except ValueError:
                cplx = True; note = note or f"çözümlenemeyen kaynak: '{frm}'"
        family = 6 if (v6 or (src is not None and src.version == 6)) else 4
        rules.append(ParsedRule(int(m.group("num")), family, m.group("act").lower(),
                                (m.group("dir") or "in").lower(), ports, proto, src, iface,
                                s.strip(), cplx, note))
    return Status(active, default_in, default_out, logging, rules)
