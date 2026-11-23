"""Kural setini statik analiz eder: etkisiz/gölgelenen kurallar, riskli açıklar, varsayılan politika."""
import json
from dataclasses import dataclass, field, asdict
from typing import List

from .parser import ParsedRule, Status, FULL

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
PENALTY = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0}

RISKY = {21: "FTP (şifresiz)", 23: "Telnet (şifresiz)", 135: "RPC", 139: "NetBIOS", 445: "SMB",
         1433: "MSSQL", 2375: "Docker API (kimliksiz)", 3306: "MySQL", 3389: "RDP",
         5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
         11211: "Memcached", 27017: "MongoDB"}


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    rules: List[int] = field(default_factory=list)
    fix: List[str] = field(default_factory=list)


# ---- küme işlemleri ----
def _protos(r: ParsedRule):
    if r.ports is None:
        return {"tcp", "udp", "other"} if r.proto is None else {r.proto}
    return {"tcp", "udp"} if r.proto is None else {r.proto}

def _ports(r: ParsedRule):
    return r.ports if r.ports is not None else FULL

def _ports_subset(a, b) -> bool:
    """a aralıkları b aralıklarının içinde mi?"""
    merged = []
    for lo, hi in sorted(b):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return all(any(m_lo <= lo and hi <= m_hi for m_lo, m_hi in merged) for lo, hi in a)

def _ports_overlap(a, b) -> bool:
    return any(l1 <= h2 and l2 <= h1 for l1, h1 in a for l2, h2 in b)

def covers(j: ParsedRule, i: ParsedRule) -> bool:
    """j kuralının eşleştirdiği her paketi i kuralı da eşleştiriyor mu? (j, i'yi kapsar)"""
    if not _protos(i) <= _protos(j):
        return False
    if _protos(i) - {"other"} and not _ports_subset(_ports(i), _ports(j)):
        return False
    if j.src is not None and (i.src is None or i.src.version != j.src.version or not i.src.subnet_of(j.src)):
        return False
    if j.iface is not None and j.iface != i.iface:
        return False
    return True

def _src_strictly_broader(j: ParsedRule, i: ParsedRule) -> bool:
    """j'nin kaynak kümesi, i'nin kaynak kümesini KESİN kapsıyor mu? (dar istisna allow'ları bilerek yazılır, hata sayılmaz)"""
    if j.src is None:
        return i.src is not None
    return i.src is not None and i.src.version == j.src.version and i.src != j.src and i.src.subnet_of(j.src)

def overlaps(j: ParsedRule, i: ParsedRule) -> bool:
    common = _protos(i) & _protos(j)
    if not common:
        return False
    if common - {"other"} and not _ports_overlap(_ports(i), _ports(j)):
        return False
    if i.src is not None and j.src is not None:
        if i.src.version != j.src.version or not i.src.overlaps(j.src):
            return False
    if i.iface and j.iface and i.iface != j.iface:
        return False
    return True


# ---- ufw komutu üretimi ----
def spec(r: ParsedRule) -> str:
    port = ",".join(f"{lo}:{hi}" if lo != hi else str(lo) for lo, hi in r.ports) if r.ports else None
    act = "allow" if r.action == "limit" else r.action
    src = None
    if r.src is not None:
        src = str(r.src.network_address) if r.src.num_addresses == 1 else str(r.src)
    if src is None and port:
        return f"{act} {port}" + (f"/{r.proto}" if r.proto else "")
    if src is None:
        return f"{act} from any" + (f" proto {r.proto}" if r.proto else "")
    if port:
        return f"{act} from {src} to any port {port}" + (f" proto {r.proto}" if r.proto else "")
    return f"{act} from {src}" + (f" proto {r.proto}" if r.proto else "")

# ---- ana analiz ----
def analyze(st: Status) -> List[Finding]:
    F: List[Finding] = []
    if st.active is False:
        F.append(Finding("CRITICAL", "FIREWALL_INACTIVE", "Güvenlik duvarı kapalı",
                         "UFW inactive: kuralların hiçbiri uygulanmıyor.",
                         fix=["# SSH ile bağlıysan ÖNCE: sudo ufw allow 22/tcp", "sudo ufw enable"]))
    if st.default_in == "allow":
        F.append(Finding("CRITICAL", "DEFAULT_ALLOW_INCOMING", "Varsayılan gelen politika 'allow'",
                         "Açıkça yasaklanmayan her gelen bağlantı geçer.",
                         fix=["sudo ufw default deny incoming"]))
    elif st.default_in is None and st.active:
        F.append(Finding("INFO", "DEFAULT_UNKNOWN", "Varsayılan politika görülemedi",
                         "`ufw status numbered` politikayı göstermez. `sudo ufw status verbose` çıktısını ver."))
    if st.logging == "off":
        F.append(Finding("LOW", "LOGGING_OFF", "Loglama kapalı",
                         "Engellenen denemeler kaydedilmiyor; log analizi yapılamaz.",
                         fix=["sudo ufw logging low"]))

    for r in st.rules:
        if r.complex:
            F.append(Finding("INFO", "UNANALYZED_RULE", f"Kural [{r.num}] tam analiz edilemedi",
                             r.note or "karmaşık kural", [r.num]))

    # sıra / gölgelenme analizi (aynı aile + yön)
    for fam in (4, 6):
        seq = [r for r in st.rules if r.family == fam and r.direction == "in" and not r.complex]
        for idx, i in enumerate(seq):
            partial_done = False
            for j in seq[:idx]:
                if covers(j, i):
                    if j.allow_like == i.allow_like:
                        F.append(Finding("LOW", "REDUNDANT", f"Gereksiz kural [{i.num}]",
                                         f"[{j.num}] zaten aynı sonucu veriyor.", [i.num, j.num],
                                         [f"sudo ufw delete {spec(i)}"]))
                    elif not i.allow_like:
                        F.append(Finding("HIGH", "SHADOWED_DENY", f"Etkisiz deny kuralı [{i.num}]",
                                         f"[{j.num}] (allow) bu kuralı tamamen gölgeliyor: bu deny hiçbir pakete uygulanmaz.",
                                         [i.num, j.num],
                                         [f"sudo ufw delete {spec(i)}", f"sudo ufw insert 1 {spec(i)}"]))
                    else:
                        F.append(Finding("MEDIUM", "SHADOWED_ALLOW", f"Etkisiz allow kuralı [{i.num}]",
                                         f"[{j.num}] (deny) bu istisnayı tamamen engelliyor: yönetici/istisna IP'si kilitli kalabilir.",
                                         [i.num, j.num],
                                         [f"sudo ufw delete {spec(i)}", f"sudo ufw insert 1 {spec(i)}"]))
                    partial_done = True
                    break
            if not partial_done and not i.allow_like:
                for j in seq[:idx]:
                    if j.allow_like and overlaps(j, i) and _src_strictly_broader(j, i):
                        F.append(Finding("HIGH", "PARTIAL_OVERRIDE", f"Deny kuralı [{i.num}] kısmen etkisiz",
                                         f"Daha üstteki allow [{j.num}] bu deny'ın kapsadığı bazı paketleri önce eşleştirip geçiriyor "
                                         f"(lab'daki yanlış sıra hatası).", [i.num, j.num],
                                         [f"sudo ufw delete {spec(i)}", f"sudo ufw insert 1 {spec(i)}"]))
                        break

    # riskli açıklar (Anywhere'den gelen allow)
    for r in st.rules:
        if r.direction != "in" or not r.allow_like or r.complex or r.src is not None:
            continue
        if r.ports is None and r.proto is None:
            F.append(Finding("CRITICAL", "ALLOW_ALL", f"Kural [{r.num}] her yerden her şeye izin veriyor",
                             "Güvenlik duvarını fiilen devre dışı bırakır.", [r.num], [f"sudo ufw delete {spec(r)}"]))
            continue
        hit = sorted(p for p in RISKY if r.ports is None or any(lo <= p <= hi for lo, hi in r.ports))
        if r.ports is None:
            continue
        for p in hit:
            F.append(Finding("HIGH", "RISKY_PORT_EXPOSED", f"{RISKY[p]} (port {p}) herkese açık",
                             f"Kural [{r.num}] bu hizmeti internete açıyor.", [r.num],
                             [f"sudo ufw delete {spec(r)}",
                              f"sudo ufw allow from <güvenilir_IP> to any port {p}"]))
        if r.ports and any(lo <= 22 <= hi for lo, hi in r.ports) and r.action == "allow":
            F.append(Finding("MEDIUM", "SSH_OPEN_ANYWHERE", "SSH (22) herkese açık",
                             f"Kural [{r.num}]: brute-force denemelerine açık. Hız sınırı veya kaynak kısıtı öner.", [r.num],
                             ["sudo ufw limit 22/tcp", "# daha iyisi: sadece güvenilir IP'ye izin ver, SSH'ta parola yerine anahtar kullan"]))

    # IPv6 boşluğu
    v4_host_deny = [r for r in st.rules if r.family == 4 and not r.allow_like and r.src is not None and r.direction == "in"]
    v6_allow = [r for r in st.rules if r.family == 6 and r.allow_like and r.direction == "in"]
    if v4_host_deny and v6_allow:
        F.append(Finding("LOW", "IPV6_GAP", "IPv4 engeli IPv6'yı kapsamaz",
                         "Engellediğin kişinin IPv6 adresi varsa v6 allow kurallarından geçebilir.",
                         [r.num for r in v4_host_deny], ["sudo ufw insert 1 deny from <saldırganın_IPv6_adresi>"]))

    seen, uniq = set(), []
    for f in F:
        key = (f.code, tuple(f.fix)) if f.code in ("SSH_OPEN_ANYWHERE", "RISKY_PORT_EXPOSED", "ALLOW_ALL") else None
        if key and key in seen:
            continue
        seen.add(key); uniq.append(f)
    uniq.sort(key=lambda f: (-SEV_ORDER[f.severity], f.rules))
    return uniq


def score(findings: List[Finding]) -> int:
    return max(0, 100 - sum(PENALTY[f.severity] for f in findings))


def to_json(st: Status, findings: List[Finding]) -> str:
    return json.dumps({"score": score(findings), "active": st.active, "default_incoming": st.default_in,
                       "findings": [asdict(f) for f in findings]}, ensure_ascii=False, indent=2)
