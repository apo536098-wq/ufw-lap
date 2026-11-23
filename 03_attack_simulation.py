"""Deney 03: Tamamen sahte saldırı (port taraması + brute-force). Gerçek ağ trafiği YOK."""
import random
import sys, os; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ufwsim import UFW

random.seed(1)
ATTACKER = "203.0.113.5"; USERS = ["198.51.100.7", "198.51.100.8", "192.0.2.44"]

def build(correct):
    fw = UFW(); fw.default_in = "deny"
    fw.add("allow", 22, "tcp"); fw.add("allow", 80, "tcp")
    fw.add("deny", src=ATTACKER, pos=1 if correct else None); fw.enable(); return fw

def scenario(fw):
    log = {"attack_ok": 0, "attack_blocked": 0, "user_ok": 0, "user_blocked": 0}
    open_ports = [p for p in range(1, 1025) if fw.check(ATTACKER, p)[0] == "ALLOW"]
    for _ in range(200):
        log["attack_ok" if fw.check(ATTACKER, 22)[0] == "ALLOW" else "attack_blocked"] += 1
    for _ in range(100):
        ip = random.choice(USERS); p = random.choice([22, 80, 443])
        log["user_ok" if fw.check(ip, p)[0] == "ALLOW" else "user_blocked"] += 1
    return open_ports, log

for label, correct in [("YANLIŞ SIRA (deny sonda)", False), ("DOĞRU SIRA (deny başta)", True)]:
    fw = build(correct); ports, log = scenario(fw)
    print(f"=== {label}\n{fw.status_numbered()}")
    print(f"  Port taraması: saldırganın gördüğü açık portlar -> {ports}")
    print(f"  Brute-force 200 deneme: geçen={log['attack_ok']}  engellenen={log['attack_blocked']}")
    print(f"  Meşru kullanıcı 100 istek: geçen={log['user_ok']}  engellenen={log['user_blocked']}")
    print(f"  SONUÇ: {'SALDIRI BAŞARILI' if log['attack_ok'] else 'SALDIRI ENGELLENDİ'}\n")
