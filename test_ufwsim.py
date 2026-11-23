import ipaddress, os, random, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ufwsim import UFW
from ufwsim.core import UFWError

ATT = "203.0.113.5"

def lab_fw():
    fw = UFW(); fw.default_in = "deny"
    fw.add("allow", 22, "tcp"); fw.add("allow", 80, "tcp")
    return fw

class LabBehaviour(unittest.TestCase):
    def test_wrong_order_deny_is_ineffective(self):
        fw = lab_fw(); fw.add("deny", src=ATT); fw.enable()
        self.assertEqual(fw.check(ATT, 22), ("ALLOW", "kural [1]"))
        self.assertEqual(fw.check(ATT, 80), ("ALLOW", "kural [2]"))
        self.assertEqual(fw.check(ATT, 443)[0], "DENY")   # allow olmadığı için

    def test_right_order_blocks_everything(self):
        fw = lab_fw(); fw.add("deny", src=ATT, pos=1); fw.enable()
        for p in (22, 80, 443):
            self.assertEqual(fw.check(ATT, p), ("DENY", "kural [1]"))
        self.assertEqual(fw.check("198.51.100.7", 22)[0], "ALLOW")

    def test_disable_keeps_rules_reset_removes(self):
        fw = lab_fw(); fw.add("deny", src=ATT, pos=1); fw.enable(); fw.disable()
        self.assertEqual(len(fw.rules), 3)
        self.assertEqual(fw.check(ATT, 22)[0], "ALLOW")
        self.assertEqual(fw.status_numbered(), "Status: inactive")
        fw.reset(); self.assertEqual(fw.rules, [])

    def test_exact_status_output_from_lab(self):
        fw = lab_fw(); fw.add("deny", src=ATT); fw.enable()
        s = fw.status_numbered().splitlines()
        self.assertEqual(s[4], "[ 1] 22/tcp                     ALLOW IN    Anywhere")
        self.assertEqual(s[6], "[ 3] Anywhere                   DENY IN     203.0.113.5")
        self.assertEqual(s[-1], "[ 5] 80/tcp (v6)                ALLOW IN    Anywhere (v6)")

class RealUfwSemantics(unittest.TestCase):
    def setUp(self): self.fw = UFW(); self.fw.default_in = "deny"; self.fw.enable()

    def test_allow_without_proto_opens_tcp_and_udp(self):
        self.fw.add("allow", 80)
        self.assertEqual(self.fw.check("198.51.100.7", 80, "tcp")[0], "ALLOW")
        self.assertEqual(self.fw.check("198.51.100.7", 80, "udp")[0], "ALLOW")

    def test_allow_tcp_only_blocks_udp(self):
        self.fw.add("allow", 80, "tcp")
        self.assertEqual(self.fw.check("198.51.100.7", 80, "udp")[0], "DENY")

    def test_port_range(self):
        self.fw.add("allow", "6000:6007", "tcp")
        self.assertEqual(self.fw.check("198.51.100.7", 6003)[0], "ALLOW")
        self.assertEqual(self.fw.check("198.51.100.7", 6008)[0], "DENY")

    def test_subnet(self):
        self.fw.add("deny", src="203.0.113.0/24", pos=1); self.fw.add("allow", 22)
        self.assertEqual(self.fw.check("203.0.113.200", 22)[0], "DENY")
        self.assertEqual(self.fw.check("203.0.114.1", 22)[0], "ALLOW")

    def test_ipv4_deny_does_not_block_ipv6(self):
        self.fw.add("allow", 22); self.fw.add("deny", src=ATT, pos=1)
        self.assertEqual(self.fw.check("2001:db8::5", 22)[0], "ALLOW")

    def test_ipv6_rule(self):
        self.fw.add("allow", 22); self.fw.add("deny", src="2001:db8::/32", pos=1)
        self.assertEqual(self.fw.check("2001:db8::5", 22)[0], "DENY")
        self.assertEqual(self.fw.check("198.51.100.7", 22)[0], "ALLOW")

    def test_established_survives_deny_insert(self):
        self.fw.add("allow", 22, "tcp")
        self.assertEqual(self.fw.connect(ATT, 22)[0], "ALLOW")
        self.fw.add("deny", src=ATT, pos=1)
        self.assertEqual(self.fw.check(ATT, 22), ("ALLOW", "before.rules: conntrack"))
        self.assertEqual(self.fw.check(ATT, 22, state="NEW")[0], "DENY")

    def test_icmp_accepted_before_user_rules(self):
        self.fw.add("deny", src=ATT, pos=1)
        self.assertEqual(self.fw.check(ATT, 0, "icmp"), ("ALLOW", "before.rules: ICMP"))

    def test_loopback_always_allowed(self):
        self.fw.add("deny"); 
        self.assertEqual(self.fw.check("127.0.0.1", 22, iface="lo")[0], "ALLOW")

    def test_reject_verdict(self):
        self.fw.add("reject", 23); self.assertEqual(self.fw.check("198.51.100.7", 23)[0], "REJECT")

    def test_duplicate_rule_skipped(self):
        self.assertTrue(self.fw.add("allow", 80)); self.assertFalse(self.fw.add("allow", 80))
        self.assertEqual(len(self.fw.rules), 1)

    def test_validation_errors(self):
        for bad in (dict(port=0), dict(port=70000), dict(port="abc"), dict(port="9:1"),
                    dict(src="999.1.1.1"), dict(proto="icmp"), dict(action="x")):
            kw = dict(action="allow"); kw.update(bad)
            with self.assertRaises(UFWError, msg=str(bad)): self.fw.add(**kw)
        self.fw.add("allow", 22)
        for pos in (0, -1, 3, 99):
            with self.assertRaises(UFWError, msg=f"pos={pos}"): self.fw.add("deny", src=ATT, pos=pos)
        with self.assertRaises(UFWError): self.fw.check("999.1.1.1", 22)

    def test_insert_of_existing_rule_is_skipped_so_delete_first(self):
        """Aynı kural zaten varsa insert 1 onu YUKARI TAŞIMAZ (atlanır). Lab'da
        'delete' ın 'insert 1' den önce yapılmasının nedeni budur."""
        self.fw.add("allow", 22); self.fw.add("deny", src=ATT)
        self.assertFalse(self.fw.add("deny", src=ATT, pos=1))        # atlandı
        self.assertEqual(self.fw.check(ATT, 22)[0], "ALLOW")          # hâlâ etkisiz
        self.fw.delete("deny", src=ATT); self.fw.add("deny", src=ATT, pos=1)
        self.assertEqual(self.fw.check(ATT, 22)[0], "DENY")           # artık etkili

    def test_delete_nonexistent(self):
        self.assertFalse(self.fw.delete("allow", 1234))

# ---- bağımsız referans uygulama (farklılık / differential testi) ----
def reference(rules, default, ip, port, proto, active=True):
    """ipaddress.in operatörü yerine tamsayı/maske aritmetiği kullanır."""
    if not active: return "ALLOW"
    a = ipaddress.ip_address(ip); ai, av = int(a), a.version
    for action, rport, rproto, rsrc in rules:
        if rsrc != "any":
            n = ipaddress.ip_network(rsrc)
            if n.version != av: continue
            mask = ((1 << n.max_prefixlen) - 1) ^ ((1 << (n.max_prefixlen - n.prefixlen)) - 1)
            if ai & mask != int(n.network_address): continue
        if rport is not None:
            if proto not in ("tcp", "udp"): continue
            if rproto and rproto != proto: continue
            if not (rport[0] <= port <= rport[1]): continue
        elif rproto and rproto != proto: continue
        return action.upper()
    return default.upper()

IPS4 = ["203.0.113.5", "203.0.113.200", "198.51.100.7", "192.0.2.44", "10.0.0.1"]
IPS6 = ["2001:db8::5", "2001:db8:1::9", "fe80::1"]
SRCS = ["any", "203.0.113.5", "203.0.113.0/24", "198.51.100.0/25", "10.0.0.0/8", "2001:db8::/32", "fe80::/10"]

def rand_rule(rng):
    port = rng.choice([None, 22, 80, 443, (6000, 6007)])
    rp = None if port is None else (port if isinstance(port, tuple) else (port, port))
    portarg = None if port is None else (f"{port[0]}:{port[1]}" if isinstance(port, tuple) else port)
    return (rng.choice(["allow", "deny", "reject"]), portarg, rng.choice([None, "tcp", "udp"]), rng.choice(SRCS)), rp

class Fuzz(unittest.TestCase):
    def test_differential_vs_reference(self):
        rng = random.Random(1234); checked = 0
        for _ in range(3000):
            fw = UFW(); fw.default_in = rng.choice(["deny", "allow"]); fw.enable(); refrules = []
            for _ in range(rng.randint(0, 8)):
                (a, p, pr, s), rp = rand_rule(rng)
                if fw.add(a, p, pr, s, pos=rng.choice([None, 1, len(fw.rules) + 1])):
                    pass
            refrules = [(r.action, r.port, r.proto, r.src) for r in fw.rules]
            for _ in range(20):
                ip = rng.choice(IPS4 + IPS6); port = rng.choice([22, 80, 443, 6003, 9999]); proto = rng.choice(["tcp", "udp"])
                got = fw.check(ip, port, proto)[0]
                self.assertEqual(got, reference(refrules, fw.default_in, ip, port, proto), (refrules, ip, port, proto))
                checked += 1
        self.assertGreater(checked, 50000)

    def test_property_deny_on_top_always_wins(self):
        rng = random.Random(99)
        for _ in range(2000):
            fw = UFW(); fw.default_in = rng.choice(["deny", "allow"]); fw.enable()
            for _ in range(rng.randint(0, 8)):
                (a, p, pr, s), _rp = rand_rule(rng); fw.add(a, p, pr, s)
            fw.delete("deny", src=ATT)          # lab iş akışı: önce sil,
            fw.add("deny", src=ATT, pos=1)      # sonra en üste ekle
            for port in (22, 80, 443, 9999):
                for proto in ("tcp", "udp"):
                    self.assertEqual(fw.check(ATT, port, proto)[0], "DENY")

    def test_property_appending_never_changes_earlier_match(self):
        rng = random.Random(7)
        for _ in range(2000):
            fw = UFW(); fw.default_in = "deny"; fw.enable()
            for _ in range(rng.randint(1, 6)):
                (a, p, pr, s), _rp = rand_rule(rng); fw.add(a, p, pr, s)
            ip = rng.choice(IPS4 + IPS6); port = rng.choice([22, 80, 443]); proto = rng.choice(["tcp", "udp"])
            before = fw.check(ip, port, proto)
            if before[1].startswith("kural"):
                (a, p, pr, s), _rp = rand_rule(rng); fw.add(a, p, pr, s)   # sona ekle
                self.assertEqual(fw.check(ip, port, proto), before)

    def test_property_disabled_allows_everything(self):
        rng = random.Random(5)
        for _ in range(500):
            fw = UFW()
            for _ in range(5):
                (a, p, pr, s), _rp = rand_rule(rng); fw.add(a, p, pr, s)
            fw.disable()
            self.assertEqual(fw.check(rng.choice(IPS4 + IPS6), 22)[0], "ALLOW")

if __name__ == "__main__":
    unittest.main(verbosity=2)
