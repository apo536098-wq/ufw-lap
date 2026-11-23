"""UFW kural motoru simülatörü (bellek içi, GERÇEK AĞ TRAFİĞİ YOK).

Modellenenler:
  * user.rules mantığı: yukarıdan aşağı, ilk eşleşen kural kazanır
  * varsayılan politika (default incoming)
  * before.rules'ın en önemli kısmı: loopback, ESTABLISHED/RELATED, ICMP
    (bunlar kullanıcı kurallarından ÖNCE değerlendirilir)
  * IPv4 + IPv6, port aralığı, protokol (tcp/udp/her ikisi), alt ağ
  * ufw'ye benzer doğrulama: geçersiz IP/port, geçersiz insert sırası,
    aynı kuralı ikinci kez eklemeyi atlama
Modellenmeyenler: after.rules, rate limit (ufw limit), logging, uygulama profilleri,
interface/yön kuralları (out/forward), conntrack zaman aşımı.
"""
import ipaddress
from dataclasses import dataclass
from typing import Optional, Tuple

ACTIONS = ("allow", "deny", "reject")


class UFWError(ValueError):
    """UFW'nin 'ERROR: ...' dediği durumlar."""


def _parse_port(port) -> Optional[Tuple[int, int]]:
    if port is None:
        return None
    if isinstance(port, int):
        lo = hi = port
    else:
        s = str(port)
        try:
            lo, hi = (int(x) for x in s.split(":")) if ":" in s else (int(s), int(s))
        except ValueError:
            raise UFWError(f"Bad port '{port}'")
    if not (1 <= lo <= hi <= 65535):
        raise UFWError(f"Bad port '{port}'")
    return (lo, hi)


def _parse_src(src: str) -> str:
    if src in ("any", "Anywhere", None):
        return "any"
    try:
        return str(ipaddress.ip_network(src, strict=False))
    except ValueError:
        raise UFWError(f"Bad source address '{src}'")


@dataclass(frozen=True)
class Rule:
    action: str                       # allow | deny | reject
    port: Optional[Tuple[int, int]]   # None = tüm portlar
    proto: Optional[str]              # None = tcp+udp ("allow 80" gibi)
    src: str                          # "any" veya CIDR

    def version(self):
        return None if self.src == "any" else ipaddress.ip_network(self.src).version

    def matches(self, ip, dport, proto) -> bool:
        if self.src != "any" and ip not in ipaddress.ip_network(self.src):
            return False
        if self.port is not None:
            if proto not in ("tcp", "udp"):
                return False
            if self.proto is not None and self.proto != proto:
                return False
            return self.port[0] <= dport <= self.port[1]
        if self.proto is not None and self.proto != proto:
            return False
        return True


class UFW:
    def __init__(self):
        self.reset()

    # ---- yaşam döngüsü ----
    def reset(self):
        """ufw reset: kuralları siler VE güvenlik duvarını kapatır."""
        self.rules = []
        self.active = False
        self.default_in = "deny"   # ufw reset: incoming=deny (kurulum varsayılanı)
        self.conntrack = set()

    def enable(self):
        self.active = True

    def disable(self):
        """Kapatır; kurallar SİLİNMEZ."""
        self.active = False

    # ---- kural yönetimi ----
    def add(self, action, port=None, proto=None, src="any", pos=None) -> bool:
        if action not in ACTIONS:
            raise UFWError(f"Bad action '{action}'")
        if proto not in (None, "tcp", "udp"):
            raise UFWError(f"Unsupported protocol '{proto}'")
        rule = Rule(action, _parse_port(port), proto, _parse_src(src))
        if rule.port is None and proto is not None:
            pass  # 'deny proto tcp from X' geçerli
        if rule in self.rules:
            return False  # "Skipping adding existing rule"
        if pos is None:
            self.rules.append(rule)
        else:
            if not isinstance(pos, int) or not (1 <= pos <= len(self.rules) + 1):
                raise UFWError(f"Invalid position '{pos}'")
            self.rules.insert(pos - 1, rule)
        return True

    def delete(self, action, port=None, proto=None, src="any") -> bool:
        rule = Rule(action, _parse_port(port), proto, _parse_src(src))
        if rule not in self.rules:
            return False  # "Could not delete non-existent rule"
        self.rules.remove(rule)
        return True

    # ---- paket değerlendirme ----
    def check(self, src_ip, port, proto="tcp", state=None, iface="eth0"):
        """Gelen bir paketi değerlendirir -> (VERDICT, neden).

        state=None ise bağlantı izleme tablosuna bakılır (connect() ile eklenenler).
        """
        try:
            ip = ipaddress.ip_address(src_ip)
        except ValueError:
            raise UFWError(f"Bad source address '{src_ip}'")
        if proto not in ("tcp", "udp", "icmp"):
            raise UFWError(f"Unsupported protocol '{proto}'")
        if not self.active:
            return "ALLOW", "UFW kapalı"

        # --- before.rules (kullanıcı kurallarından ÖNCE) ---
        if iface == "lo":
            return "ALLOW", "before.rules: loopback"
        if state is None:
            state = "ESTABLISHED" if (str(ip), port, proto) in self.conntrack else "NEW"
        if state in ("ESTABLISHED", "RELATED"):
            return "ALLOW", "before.rules: conntrack"
        if proto == "icmp":
            return "ALLOW", "before.rules: ICMP"

        # --- user.rules ---
        for i, r in enumerate(self.rules, 1):
            if r.matches(ip, port, proto):
                return r.action.upper(), f"kural [{i}]"
        return self.default_in.upper(), "varsayılan politika"

    def connect(self, src_ip, port, proto="tcp"):
        """Yeni bağlantı dener; izin verilirse conntrack'e kaydeder."""
        verdict, why = self.check(src_ip, port, proto, state="NEW")
        if verdict == "ALLOW":
            self.conntrack.add((str(ipaddress.ip_address(src_ip)), port, proto))
        return verdict, why

    # ---- görüntüleme ----
    @staticmethod
    def _frm(r):
        if r.src == "any":
            return None
        n = __import__("ipaddress").ip_network(r.src)
        return str(n.network_address) if n.num_addresses == 1 else r.src

    @staticmethod
    def _to(r, v6):
        if r.port is None:
            t = "Anywhere" + (f"/{r.proto}" if r.proto else "")
        else:
            p = f"{r.port[0]}:{r.port[1]}" if r.port[0] != r.port[1] else f"{r.port[0]}"
            t = f"{p}/{r.proto}" if r.proto else p
        return t + (" (v6)" if v6 else "")

    def status_numbered(self) -> str:
        if not self.active:
            return "Status: inactive"
        rows = []
        for r in self.rules:                     # önce IPv4 görünümü
            if r.version() in (None, 4):
                rows.append((self._to(r, False), r.action.upper() + " IN",
                             self._frm(r) or "Anywhere"))
        for r in self.rules:                     # sonra IPv6 görünümü
            if r.version() in (None, 6):
                rows.append((self._to(r, True), r.action.upper() + " IN",
                             "Anywhere (v6)" if r.src == "any" else self._frm(r)))
        out = ["Status: active", "", f"     {'To':<27}{'Action':<12}From",
               f"     {'--':<27}{'------':<12}----"]
        out += [f"[{i:>2}] {to:<27}{act:<12}{frm}" for i, (to, act, frm) in enumerate(rows, 1)]
        return "\n".join(out)

    status = status_numbered
