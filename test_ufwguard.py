import io, json, os, random, subprocess, sys, unittest
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
from ufwsim import UFW
from ufwguard.parser import parse_status
from ufwguard.analyzer import analyze, score, covers
from ufwguard.logs import parse_log, analyze_events, suggestions, is_internal

SAMPLES = os.path.join(ROOT, "ufwguard", "samples")
def sample(n):
    with open(os.path.join(SAMPLES, n), encoding="utf-8") as fh:
        return fh.read()
def codes(text): return [f.code for f in analyze(parse_status(text))]
def table(*rows, header="Status: active\n\n     To                         Action      From\n     --                         ------      ----\n"):
    return header + "\n".join(f"[{i:>2}] {to:<27}{act:<12}{frm}" for i, (to, act, frm) in enumerate(rows, 1))

class Parser(unittest.TestCase):
    def test_lab_output(self):
        st = parse_status(sample("status_wrong_order.txt"))
        self.assertTrue(st.active); self.assertEqual(len(st.rules), 5)
        self.assertEqual([r.family for r in st.rules], [4, 4, 4, 6, 6])
        self.assertEqual(st.rules[0].ports, [(22, 22)]); self.assertEqual(st.rules[0].proto, "tcp")
        self.assertEqual(str(st.rules[2].src), "203.0.113.5/32"); self.assertIsNone(st.rules[2].ports)

    def test_verbose_header(self):
        st = parse_status("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
                          "New profiles: skip\n\nTo  Action  From\n--  ------  ----\n22/tcp                     ALLOW IN    Anywhere\n")
        self.assertEqual((st.default_in, st.default_out, st.logging), ("deny", "allow", "on (low)"))

    def test_ranges_lists_iface_comment_and_app(self):
        st = parse_status(table(("6000:6007/tcp", "ALLOW IN", "Anywhere"), ("80,443/tcp", "ALLOW IN", "Anywhere"),
                                ("22/tcp on eth0", "ALLOW IN", "10.0.0.0/8"), ("OpenSSH", "ALLOW IN", "Anywhere    # ssh")))
        self.assertEqual(st.rules[0].ports, [(6000, 6007)]); self.assertEqual(st.rules[1].ports, [(80, 80), (443, 443)])
        self.assertEqual(st.rules[2].iface, "eth0"); self.assertTrue(st.rules[3].complex)

    def test_garbage_input(self):
        st = parse_status("merhaba dünya\n\n???"); self.assertEqual(st.rules, []); self.assertIsNone(st.active)

class Findings(unittest.TestCase):
    def test_lab_wrong_order_flagged_fixed_clean(self):
        self.assertIn("PARTIAL_OVERRIDE", codes(sample("status_wrong_order.txt")))
        good = codes(sample("status_fixed.txt"))
        for bad in ("PARTIAL_OVERRIDE", "SHADOWED_DENY", "REDUNDANT"): self.assertNotIn(bad, good)

    def test_fix_commands_use_rule_text_not_numbers(self):
        f = [x for x in analyze(parse_status(sample("status_wrong_order.txt"))) if x.code == "PARTIAL_OVERRIDE"][0]
        self.assertEqual(f.fix, ["sudo ufw delete deny from 203.0.113.5", "sudo ufw insert 1 deny from 203.0.113.5"])

    def test_fully_shadowed_deny(self):
        c = codes(table(("Anywhere", "ALLOW IN", "Anywhere"), ("22/tcp", "DENY IN", "203.0.113.5")))
        self.assertIn("SHADOWED_DENY", c); self.assertIn("ALLOW_ALL", c)

    def test_admin_lockout_shadowed_allow(self):
        self.assertIn("SHADOWED_ALLOW", codes(table(("Anywhere", "DENY IN", "203.0.113.0/24"), ("Anywhere", "ALLOW IN", "203.0.113.10"))))

    def test_correct_exception_order_is_clean(self):
        c = codes(table(("Anywhere", "ALLOW IN", "203.0.113.10"), ("Anywhere", "DENY IN", "203.0.113.0/24")))
        self.assertNotIn("SHADOWED_ALLOW", c); self.assertNotIn("PARTIAL_OVERRIDE", c)

    def test_redundant(self):
        self.assertIn("REDUNDANT", codes(table(("80/tcp", "ALLOW IN", "Anywhere"), ("80/tcp", "ALLOW IN", "10.0.0.0/8"))))

    def test_risky_ports_and_ranges(self):
        c = analyze(parse_status(table(("3306/tcp", "ALLOW IN", "Anywhere"), ("3380:3400", "ALLOW IN", "Anywhere"),
                                       ("6379/tcp", "ALLOW IN", "192.168.1.0/24"))))
        titles = " ".join(f.title for f in c if f.code == "RISKY_PORT_EXPOSED")
        self.assertIn("MySQL", titles); self.assertIn("RDP", titles); self.assertNotIn("Redis", titles)  # kısıtlı kaynak: sorun değil

    def test_default_allow_and_inactive(self):
        self.assertIn("DEFAULT_ALLOW_INCOMING", codes("Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n\n22/tcp  ALLOW IN  Anywhere"))
        self.assertIn("FIREWALL_INACTIVE", codes("Status: inactive"))

    def test_ssh_open_suggests_limit_but_limit_rule_is_ok(self):
        self.assertIn("SSH_OPEN_ANYWHERE", codes(table(("22/tcp", "ALLOW IN", "Anywhere"))))
        self.assertNotIn("SSH_OPEN_ANYWHERE", codes(table(("22/tcp", "LIMIT IN", "Anywhere"))))

    def test_ipv6_gap_and_app_profile(self):
        c = codes(table(("Anywhere", "DENY IN", "203.0.113.5"), ("22/tcp (v6)", "LIMIT IN", "Anywhere (v6)"), ("OpenSSH", "ALLOW IN", "Anywhere")))
        self.assertIn("IPV6_GAP", c); self.assertIn("UNANALYZED_RULE", c)

    def test_score_monotonic(self):
        self.assertLess(score(analyze(parse_status(sample("status_wrong_order.txt")))), score(analyze(parse_status(sample("status_fixed.txt")))))

# ---- simülatör ile çapraz doğrulama (soundness) ----
SRCS = ["any", "203.0.113.5", "203.0.113.0/24", "198.51.100.0/25", "10.0.0.0/8", "203.0.113.10"]
def rand_sim(rng):
    fw = UFW(); fw.default_in = rng.choice(["deny", "allow"]); fw.enable()
    for _ in range(rng.randint(2, 7)):
        port = rng.choice([None, 22, 80, 443, "6000:6007", "5990:6003"])
        fw.add(rng.choice(["allow", "deny", "reject"]), port, rng.choice([None, "tcp", "udp"]), rng.choice(SRCS),
               pos=rng.choice([None, 1]))
    return fw

def universe(fw):
    import ipaddress
    ips = {"198.51.100.200", "8.8.8.8"}
    ports = {1, 22, 80, 443, 9999, 65535}
    for r in fw.rules:
        if r.src != "any": ips.add(str(ipaddress.ip_network(r.src).network_address))
        if r.port: ports.update(r.port)
    return [(ip, p, pr) for ip in ips for p in ports for pr in ("tcp", "udp")]

class CrossCheck(unittest.TestCase):
    def test_shadow_findings_are_sound_against_simulator(self):
        rng = random.Random(2026); checked = 0
        for _ in range(1500):
            fw = rand_sim(rng); st = parse_status(fw.status_numbered())
            v4 = [r for r in fw.rules if r.version() in (None, 4)]
            uni = universe(fw)
            for f in analyze(st):
                if f.code not in ("SHADOWED_DENY", "SHADOWED_ALLOW", "REDUNDANT"): continue
                if next(r for r in st.rules if r.num == f.rules[0]).family == 6: continue
                simidx = fw.rules.index(v4[f.rules[0] - 1]) + 1
                for ip, p, pr in uni:
                    why = fw.check(ip, p, pr)[1]
                    self.assertNotEqual(why, f"kural [{simidx}]", (fw.status_numbered(), f.code, f.rules, ip, p, pr))
                checked += 1
        self.assertGreater(checked, 300)

    def test_partial_override_claims_have_a_witness_packet(self):
        rng = random.Random(11); checked = 0
        for _ in range(1500):
            fw = rand_sim(rng); st = parse_status(fw.status_numbered())
            v4 = [r for r in fw.rules if r.version() in (None, 4)]; uni = universe(fw)
            for f in analyze(st):
                if f.code != "PARTIAL_OVERRIDE": continue
                if next(r for r in st.rules if r.num == f.rules[0]).family == 6: continue
                i, j = v4[f.rules[0] - 1], v4[f.rules[1] - 1]
                import ipaddress
                self.assertTrue(any(i.matches(ipaddress.ip_address(ip), p, pr) and j.matches(ipaddress.ip_address(ip), p, pr) for ip, p, pr in uni),
                                (fw.status_numbered(), f.rules))
                checked += 1
        self.assertGreater(checked, 100)

    def test_covers_is_reflexive_and_transitive_samples(self):
        st = parse_status(table(("Anywhere", "ALLOW IN", "10.0.0.0/8"), ("80/tcp", "ALLOW IN", "10.1.0.0/16"), ("80/tcp", "ALLOW IN", "10.1.2.3")))
        a, b, c = st.rules
        self.assertTrue(covers(a, a) and covers(a, b) and covers(b, c) and covers(a, c)); self.assertFalse(covers(c, a))

LOG = sample("ufw.log")
class Logs(unittest.TestCase):
    def setUp(self):
        self.ev = parse_log(LOG, 2026); self.rep = analyze_events(self.ev)

    def test_parse_skips_malformed(self):
        self.assertEqual(len(self.ev), 143)

    def test_detects_scan_and_repeat(self):
        self.assertTrue(self.rep["203.0.113.5"].scan); self.assertEqual(self.rep["198.51.100.99"].repeat_port, 22)
        self.assertFalse(self.rep["192.0.2.44"].scan or self.rep["192.0.2.44"].repeat_port)

    def test_suggestions_skip_internal_and_whitelist(self):
        s = {r.src for r in suggestions(self.rep)}
        self.assertEqual(s, {"203.0.113.5", "198.51.100.99", "198.51.100.7"})
        s = {r.src for r in suggestions(self.rep, whitelist=["198.51.100.7"])}
        self.assertEqual(s, {"203.0.113.5", "198.51.100.99"}); self.assertNotIn("192.168.1.5", s)

    def test_iso_timestamps_and_empty(self):
        line = "2026-11-22T10:11:12.123456+00:00 kali kernel: [1.2] [UFW BLOCK] IN=eth0 SRC=203.0.113.9 DST=10.0.0.2 PROTO=TCP SPT=1 DPT=22"
        self.assertEqual(len(parse_log(line)), 1); self.assertEqual(parse_log(""), [])
        self.assertEqual(analyze_events([]), {})

    def test_window_matters(self):
        # 20 farklı port, dakikada 1 tane: 60 sn pencerede tarama sayılmamalı
        evs = parse_log("\n".join(f"Nov 22 {10+i//60:02d}:{i%60:02d}:00 h kernel: [UFW BLOCK] SRC=203.0.113.9 PROTO=TCP DPT={1000+i}" for i in range(20)), 2026)
        self.assertFalse(analyze_events(evs, window=60, scan_ports=15)["203.0.113.9"].scan)   # dakikada 1 port
        self.assertTrue(analyze_events(evs, window=3600, scan_ports=15)["203.0.113.9"].scan)

    def test_internal_detection(self):
        for ip in ("10.1.1.1", "192.168.0.9", "127.0.0.1", "fe80::1", "172.20.0.1"): self.assertTrue(is_internal(ip))
        for ip in ("8.8.8.8", "203.0.113.5", "2001:db8::1", "172.32.0.1"): self.assertFalse(is_internal(ip))

class CLI(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, "-m", "ufwguard", *args], cwd=ROOT, input=stdin, capture_output=True, text=True)

    def test_exit_codes(self):
        self.assertEqual(self.run_cli("audit", os.path.join(SAMPLES, "status_wrong_order.txt")).returncode, 1)
        self.assertEqual(self.run_cli("audit", os.path.join(SAMPLES, "status_fixed.txt")).returncode, 0)
        self.assertEqual(self.run_cli("audit", "yok.txt").returncode, 2)
        self.assertEqual(self.run_cli("audit", "-", stdin="anlamsız").returncode, 2)

    def test_json_and_stdin(self):
        r = self.run_cli("audit", "-", "--json", stdin=sample("status_wrong_order.txt"))
        d = json.loads(r.stdout); self.assertIn("PARTIAL_OVERRIDE", [f["code"] for f in d["findings"]]); self.assertLess(d["score"], 100)

    def test_logs_and_demo(self):
        self.assertEqual(self.run_cli("logs", os.path.join(SAMPLES, "ufw.log"), "--year", "2026", "--whitelist", "198.51.100.7").returncode, 0)
        self.assertEqual(self.run_cli("demo").returncode, 0)
        self.assertEqual(self.run_cli("logs", os.path.join(SAMPLES, "ufw.log"), "--whitelist", "bozuk").returncode, 2)

    def test_no_network_imports(self):
        import glob, re
        for f in glob.glob(os.path.join(ROOT, "ufw*", "*.py")):
            with open(f, encoding="utf-8") as fh:
                src = fh.read()
            self.assertIsNone(re.search(r"^\s*(import|from)\s+(socket|scapy|requests|urllib|http|asyncio|subprocess)\b", src, re.M), f)

if __name__ == "__main__":
    unittest.main(verbosity=2)
