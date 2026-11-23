import argparse
import ipaddress
import os
import sys
from datetime import datetime

from .analyzer import SEV_ORDER, analyze, score, to_json
from .logs import analyze_events, parse_log, suggestions
from .parser import parse_status

HERE = os.path.dirname(__file__)
ICON = {"CRITICAL": "[KRİTİK]", "HIGH": "[YÜKSEK]", "MEDIUM": "[ORTA]", "LOW": "[DÜŞÜK]", "INFO": "[BİLGİ]"}


def _read(path):
    try:
        return sys.stdin.read() if path == "-" else open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        print(f"Hata: {path} okunamadı ({e.strerror})", file=sys.stderr); sys.exit(2)


def cmd_audit(a):
    st = parse_status(_read(a.file))
    if not st.rules and st.active is None:
        print("Hata: `ufw status` çıktısı tanınmadı.", file=sys.stderr); return 2
    fs = analyze(st)
    if a.json:
        print(to_json(st, fs))
    else:
        print(f"UFW denetimi: {len(st.rules)} kural, durum={'aktif' if st.active else 'kapalı/bilinmiyor'}, "
              f"skor={score(fs)}/100 (basit kural tabanlı gösterge)\n")
        if not fs:
            print("Bulgu yok.")
        for f in fs:
            print(f"{ICON[f.severity]} {f.title}\n  {f.detail}")
            for c in f.fix:
                print(f"  $ {c}")
            print()
        if any(f.fix for f in fs):
            print("Uyarı: SSH ile bağlıysan 22/tcp iznini kaybetme. Komutları önce kendi lab'ında dene; "
                  "kural numaraları (v6 dahil) değişebilir, bu yüzden komutlar numara yerine kural metniyle verildi.")
    worst = max((SEV_ORDER[f.severity] for f in fs), default=-1)
    return 1 if worst >= SEV_ORDER[a.fail_on.upper()] else 0


def cmd_logs(a):
    events = parse_log(_read(a.file), a.year)
    reps = analyze_events(events, a.window, a.scan_ports, a.hits)
    print(f"Log analizi: {len(events)} engellenen paket, {len(reps)} farklı kaynak\n")
    if not events:
        print("Analiz edilecek [UFW BLOCK] kaydı bulunamadı (loglama açık mı? `sudo ufw logging low`)."); return 0
    print("En çok engellenen kaynaklar:")
    for r in sorted(reps.values(), key=lambda r: -r.count)[:a.top]:
        flag = " [TARAMA]" if r.scan else ""
        flag += f" [TEKRAR:{r.repeat_port}]" if r.repeat_port else ""
        print(f"  {r.src:<16} {r.count:>5} paket, {len(r.ports):>4} farklı port{flag}")
    wl = [w for w in (a.whitelist or "").split(",") if w]
    for w in wl:
        ipaddress.ip_address(w)
    sug = suggestions(reps, wl, a.top)
    print()
    if not sug:
        print("Engelleme önerisi yok (şüpheli kaynak bulunamadı veya hepsi iç ağ/beyaz listede)."); return 0
    print("Engelleme ÖNERİLERİ (otomatik uygulanmaz, önce kendin incele):")
    for r in sug:
        why = "port taraması" if r.scan else f"{r.repeat_port} portuna tekrarlayan deneme"
        print(f"  # {r.src}: {why}\n  $ sudo ufw delete deny from {r.src}   # zaten varsa\n  $ sudo ufw insert 1 deny from {r.src}")
    print("\nDikkat: Kaynak IP'ler sahte (spoof) olabilir, özellikle UDP ve SYN paketlerinde. Otomatik engelleme, "
          "saldırganın meşru IP'leri engelletmesine yol açabilir. Meşru IP'leri --whitelist ile koru.")
    return 0


def cmd_demo(a):
    for name, label in (("status_wrong_order.txt", "YANLIŞ SIRA (lab Adım 4)"), ("status_fixed.txt", "DÜZELTİLMİŞ (lab Adım 5)")):
        print(f"===== {label} =====")
        cmd_audit(argparse.Namespace(file=os.path.join(HERE, "samples", name), json=False, fail_on="critical"))
        print()
    print("===== LOG ANALİZİ (sentetik örnek log) =====")
    cmd_logs(argparse.Namespace(file=os.path.join(HERE, "samples", "ufw.log"), year=2026, window=60,
                                scan_ports=15, hits=20, top=10, whitelist="198.51.100.7"))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="ufwguard", description="UFW kural denetleyici ve log analizcisi (çevrimdışı, salt-okunur).")
    sub = p.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("audit", help="`ufw status numbered|verbose` çıktısını denetle ('-' = stdin)")
    pa.add_argument("file"); pa.add_argument("--json", action="store_true")
    pa.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info"],
                    help="bu seviye veya üstü bulguda çıkış kodu 1 (CI için)")
    pa.set_defaults(fn=cmd_audit)
    pl = sub.add_parser("logs", help="ufw.log analizi: tarama / tekrarlayan deneme tespiti")
    pl.add_argument("file"); pl.add_argument("--year", type=int, default=datetime.now().year)
    pl.add_argument("--window", type=int, default=60); pl.add_argument("--scan-ports", type=int, default=15)
    pl.add_argument("--hits", type=int, default=20); pl.add_argument("--top", type=int, default=10)
    pl.add_argument("--whitelist", help="virgülle ayrılmış, ASLA önerilmeyecek IP'ler")
    pl.set_defaults(fn=cmd_logs)
    pd = sub.add_parser("demo", help="örnek verilerle çalıştır"); pd.set_defaults(fn=cmd_demo)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except ValueError as e:
        print(f"Hata: {e}", file=sys.stderr); return 2


if __name__ == "__main__":
    sys.exit(main())
