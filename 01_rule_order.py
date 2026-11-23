"""Deney 01: Lab adımları (yanlış sıra -> doğru sıra -> disable -> reset)."""
import sys, os; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ufwsim import UFW

def probe(fw, label):
    print(f"-- {label}")
    for ip in ["203.0.113.5", "198.51.100.7"]:
        for p in [22, 80, 443]:
            res, why = fw.check(ip, p)
            print(f"   {ip:<14} -> {p:<4} {res:<6} ({why})")

fw = UFW(); fw.reset(); fw.default_in = "deny"
fw.add("allow", 22, "tcp"); fw.add("allow", 80, "tcp")
print("### Adım 4: deny from 203.0.113.5 (YANLIŞ SIRA)")
fw.add("deny", src="203.0.113.5"); fw.enable()
print(fw.status_numbered()); probe(fw, "Yanlış sıra")
print("\n### Adım 5: delete + insert 1")
fw.delete("deny", src="203.0.113.5"); fw.add("deny", src="203.0.113.5", pos=1)
print(fw.status_numbered()); probe(fw, "Doğru sıra")
print("\n### Adım 6: ufw disable")
fw.disable(); print(fw.status_numbered()); probe(fw, "UFW kapalı")
print(f"\ndisable sonrası kural sayısı: {len(fw.rules)} (silinmedi)")
fw.reset(); print(f"reset sonrası kural sayısı: {len(fw.rules)}")
