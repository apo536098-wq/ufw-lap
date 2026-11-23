"""Deney 02: Porta özel deny, /24 alt ağ, dar istisna, tüm permütasyonlar."""
import itertools
import sys, os; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ufwsim import UFW

def run(fw, tests):
    for ip, p in tests:
        res, why = fw.check(ip, p); print(f"   {ip:<14} -> {p:<4} {res:<6} ({why})")

def new():
    fw = UFW(); fw.default_in = "deny"; fw.enable(); return fw

print("### DENEME 1: Sadece 22'yi engelle")
fw = new(); fw.add("allow", 22, "tcp"); fw.add("allow", 80, "tcp")
fw.add("deny", 22, "tcp", "203.0.113.5", pos=1)
print(fw.status_numbered()); run(fw, [("203.0.113.5", 22), ("203.0.113.5", 80), ("198.51.100.7", 22)])

print("\n### DENEME 2: Alt ağ engeli 203.0.113.0/24")
fw = new(); fw.add("allow", 22, "tcp"); fw.add("allow", 80, "tcp")
fw.add("deny", src="203.0.113.0/24", pos=1)
print(fw.status_numbered()); run(fw, [("203.0.113.5", 80), ("203.0.113.200", 22), ("198.51.100.7", 80)])

print("\n### DENEME 3: Geniş deny + dar istisna (yönetici IP .10)")
for label, order in [("istisna ÖNCE (doğru)", [("allow", "203.0.113.10"), ("deny", "203.0.113.0/24")]),
                     ("istisna SONRA (yanlış)", [("deny", "203.0.113.0/24"), ("allow", "203.0.113.10")])]:
    fw = new()
    for a, s in order: fw.add(a, src=s)
    print(f" -- {label}"); print(fw.status_numbered())
    run(fw, [("203.0.113.10", 22), ("203.0.113.5", 22)])

print("\n### DENEME 4: 3 kuralın tüm sıralamaları -> 203.0.113.5:22")
rules = [("allow", 22, "any"), ("deny", None, "203.0.113.5"), ("allow", None, "203.0.113.5")]
for perm in itertools.permutations(rules):
    fw = new()
    for a, p, s in perm: fw.add(a, p, "tcp" if p else None, s)
    res, why = fw.check("203.0.113.5", 22)
    print("  ", " > ".join(f"{a}:{p or 'tüm'}:{s}" for a, p, s in perm), "=>", res, why)
