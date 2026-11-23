"""Deney 04: 'Doğru sırada deny' yetmediğinde: lab'ın göstermediği 5 kör nokta (hepsi sahte)."""
import sys, os; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ufwsim import UFW

A = "203.0.113.5"
def base():
    fw = UFW(); fw.default_in = "deny"; fw.add("allow", 22, "tcp"); fw.add("allow", 80, "tcp"); fw.enable(); return fw
def show(label, res): print(f"  {label:<58} -> {res[0]:<6} ({res[1]})")

print("### 1) Kurulmuş bağlantı: saldırgan ZATEN bağlıyken deny eklenirse")
fw = base(); fw.connect(A, 22)
fw.delete("deny", src=A); fw.add("deny", src=A, pos=1)
show("açık SSH oturumunun paketleri (ESTABLISHED)", fw.check(A, 22))
show("aynı IP'den YENİ bağlantı (NEW)", fw.check(A, 22, state="NEW"))
print("   -> Çözüm: kural ekledikten sonra bağlantı iznini de temizle (ör. conntrack -D / oturumu sonlandır).")

print("\n### 2) ICMP (ping): deny kuralından ÖNCE before.rules kabul eder")
fw = base(); fw.add("deny", src=A, pos=1)
show("ping (icmp)", fw.check(A, 0, "icmp"))
print("   -> 'ufw deny from IP' ping'i kesmez; before.rules içinde ayrıca DROP gerekir.")

print("\n### 3) IPv6 bypass: sadece IPv4 adresi engellenirse")
fw = base(); fw.add("deny", src=A, pos=1)
show("saldırgan IPv4 (203.0.113.5) -> 22", fw.check(A, 22))
show("aynı saldırgan IPv6 (2001:db8::5) -> 22", fw.check("2001:db8::5", 22))
print("   -> Saldırganın IPv6 adresi de engellenmeli: ufw insert 1 deny from <ipv6>.")

print("\n### 4) UDP: 'allow 80/tcp' ile 'allow 80' farkı")
fw = UFW(); fw.default_in = "deny"; fw.enable(); fw.add("allow", 80, "tcp")
show("80/tcp kuralı, UDP paketi", fw.check("198.51.100.7", 80, "udp"))
fw = UFW(); fw.default_in = "deny"; fw.enable(); fw.add("allow", 80)
show("80 (proto'suz) kuralı, UDP paketi", fw.check("198.51.100.7", 80, "udp"))

print("\n### 5) insert 1, aynı kural zaten varsa atlanır")
fw = base(); fw.add("deny", src=A)                       # yanlış sıra: 3. sırada
fw.add("allow", src=A, pos=1)                            # (kazara allow, üstte)
moved = fw.add("deny", src=A, pos=1)
show(f"insert 1 sonrası (eklendi={moved})", fw.check(A, 22))
fw.delete("deny", src=A); fw.add("deny", src=A, pos=1)
show("delete + insert 1 sonrası", fw.check(A, 22))
