# UFW Lab: Kural Sıralaması ve Kapatma

> **Amaç ve uyarı:** Bu proje **eğitim amaçlı** bir UFW kural simülatörüdür. Ağ trafiği üretmez, hiçbir sisteme bağlanmaz, zararlı kod içermez. "Saldırı" deneyleri bellek içi sentetik olaylardır ve yalnızca dokümantasyon için ayrılmış IP adreslerini kullanır. Gerçek UFW komutlarını sadece **kendi makinende / yetkili olduğun lab ortamında** çalıştır; başkasının sistemine izinsiz tarama veya deneme yapma. Ayrıntı: [docs/LEGAL.md](docs/LEGAL.md) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

UFW (Uncomplicated Firewall) kurallarının nasıl sıralandığını ve bu sıralamanın neden önemli olduğunu gösteren küçük bir lab çalışması. Gerçek UFW komutları (Kali Linux) ve aynı mantığı gösteren, **ağ trafiği üretmeyen** bir Python simülatörü içerir.

- **Sistem:** Kali Linux
- **Tarih:** 16 Ekim 2026
- **Konu:** UFW kural setleri, kural sıralaması, UFW'yi kapatma

## Amaç
UFW kuralları yukarıdan aşağıya değerlendirilir ve **ilk eşleşen kural uygulanır**. Bu lab'da aynı IP için bir `deny` kuralı önce allow kurallarından sonra (yanlış sıra), sonra en üste (doğru sıra) eklenerek fark gösterilir.

Örnek IP olarak dokümantasyon için ayrılmış `203.0.113.5` (TEST-NET-3) kullanıldı. Bu adres gerçek bir sisteme ait değildir.

## Gereksinimler
- Linux (Kali, Debian, Ubuntu vb.) ve `sudo` yetkisi
- UFW: `sudo apt update && sudo apt install ufw -y`
- Simülatör için: Python 3.8+ (ek paket gerekmez)

> **Uyarı:** Komutları sadece kendi makinende veya yetkili olduğun bir lab ortamında çalıştır. SSH ile bağlıysan `22/tcp` kuralını eklemeden UFW'yi açma, yoksa bağlantın kopar. `ufw reset` mevcut tüm kuralları siler (yedeği `/etc/ufw/` altına alır).

## Lab adımları

### 1. Temiz başlangıç
```bash
sudo ufw disable
sudo ufw reset
```

### 2. Varsayılan politikalar
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

### 3. İzin kuralları
```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
```

### 4. Deny kuralı (yanlış sıra)
```bash
sudo ufw deny from 203.0.113.5
sudo ufw enable
sudo ufw status numbered
```
```
[ 1] 22/tcp      ALLOW IN    Anywhere
[ 2] 80/tcp      ALLOW IN    Anywhere
[ 3] Anywhere    DENY IN     203.0.113.5
```
Deny kuralı [3]'te. Paket önce `22/tcp ALLOW` ve `80/tcp ALLOW` kurallarına eşleştiği için 203.0.113.5 yine 22 ve 80'e erişebilir.

### 5. Sırayı düzeltme
```bash
sudo ufw delete deny from 203.0.113.5
sudo ufw insert 1 deny from 203.0.113.5
sudo ufw status numbered
```
```
[ 1] Anywhere    DENY IN     203.0.113.5
[ 2] 22/tcp      ALLOW IN    Anywhere
[ 3] 80/tcp      ALLOW IN    Anywhere
```
Deny kuralı [1]'de: 203.0.113.5 engellenir, diğer herkes için 22 ve 80 açık kalır.

### 6. UFW'yi kapatma
```bash
sudo ufw disable
sudo ufw status      # Status: inactive
```

## Sonuç
- Kurallar yukarıdan aşağıya okunur, ilk eşleşen kural uygulanır.
- Özel (dar) kurallar, genel (geniş) kurallardan önce gelmelidir.
- Önce dar istisnalar, sonra dar deny'lar, en sonda geniş kurallar.
- Kuralı en üste almak için `ufw insert 1 ...` kullanılır.
- `ufw disable` güvenlik duvarını durdurur, kurallar silinmez. Silmek için `ufw reset`.
- Kural dosyaları `/etc/ufw/` altındadır: `user.rules`, `before.rules`, `after.rules` ve IPv6 karşılıkları.

## Faydalı komutlar
| Komut | Ne yapar |
|---|---|
| `sudo ufw status verbose` | Durum ve varsayılan politikaları gösterir |
| `sudo ufw status numbered` | Kuralları numaralı listeler |
| `sudo ufw insert N <kural>` | Kuralı N. sıraya ekler |
| `sudo ufw delete N` | N numaralı kuralı siler |
| `sudo ufw enable / disable` | Güvenlik duvarını açar / kapatır |
| `sudo ufw reset` | Tüm kuralları siler |

## ufwguard: UFW denetleyici ve log analizcisi (savunma aracı)
Gerçek `ufw status` çıktını ve `ufw.log` dosyanı **çevrimdışı ve salt-okunur** analiz eder. Ağ bağlantısı kurmaz, sisteme komut çalıştırmaz, hiçbir şeyi otomatik engellemez; sadece bulgu ve komut **önerir**.

```bash
sudo ufw status verbose | python3 -m ufwguard audit -        # kural denetimi
python3 -m ufwguard audit status.txt --json --fail-on high   # CI/otomasyon için (bulgu varsa çıkış kodu 1)
sudo python3 -m ufwguard logs /var/log/ufw.log --whitelist 198.51.100.7   # tarama / tekrarlayan deneme
python3 -m ufwguard demo                                     # örnek verilerle
```

**Neleri bulur:**
| Bulgu | Seviye |
|---|---|
| Güvenlik duvarı kapalı, varsayılan gelen politika `allow`, her yerden her şeye allow | Kritik |
| Etkisiz veya kısmen etkisiz `deny` (lab'daki yanlış sıra hatası), veritabanı/RDP/Telnet gibi riskli portların herkese açılması | Yüksek |
| Gölgelenen `allow` (yönetici IP'sinin kilitlenmesi), SSH'ın herkese açık olması (`ufw limit` önerir) | Orta |
| Gereksiz kural, IPv4 engelinin IPv6'yı kapsamaması, loglama kapalı | Düşük |

Önerilen düzeltmeler **numara yerine kural metniyle** verilir (`sudo ufw delete deny from ...`), çünkü numaralar v6 kuralları yüzünden kayabilir.

**Log analizi:** pencere içinde çok sayıda farklı porta gelen kaynakları (tarama) ve aynı porta tekrar tekrar gelenleri (brute-force belirtisi) listeler. İç ağ (RFC1918) ve `--whitelist` IP'leri asla önerilmez.

### Sınırlar (dürüst not)
- Bu bir **statik analiz** aracıdır; sızma testi, IDS/IPS veya antivirüs yerine geçmez. "Skor" basit kural tabanlı bir göstergedir, güvenlik garantisi değildir.
- Sadece `ufw status` çıktısına bakar: `before.rules`, ham iptables/nftables kuralları, Docker'ın eklediği kurallar ve uygulama profillerinin ayrıntıları görülmez.
- Kapsama analizi tek kural bazlıdır: birden fazla kuralın birlikte gölgelediği durumları kaçırabilir (yanlış alarm değil, kaçırma yönünde hata). Bulguların **doğruluğu** simülatörle çapraz test edilir.
- Log'daki kaynak IP'ler sahte olabilir; önerileri elle incele. Sistem sertleştirme rehberi: [docs/HARDENING.md](docs/HARDENING.md).

## Simülatör (`ufwsim`)
UFW'nin "ilk eşleşen kural kazanır" mantığını bellek içinde taklit eder. **Gerçek paket, soket veya ağ bağlantısı yoktur**; hiçbir sisteme zarar vermez.

Modellenenler: kural sıralaması, varsayılan politika, IPv4 + IPv6, port aralığı, tcp/udp, alt ağ, `before.rules` (loopback, ESTABLISHED/RELATED, ICMP), geçersiz giriş doğrulaması, aynı kuralı ikinci kez eklemeyi atlama, `ufw status numbered` çıktısı.
Modellenmeyenler: `after.rules`, `ufw limit`, loglama, uygulama profilleri, out/forward kuralları, conntrack zaman aşımı.

`status_numbered()` çıktısı, bu lab'daki gerçek UFW çıktısıyla (Adım 4 ve 5) **birebir** aynıdır; bu bir testle doğrulanır.

```bash
python3 experiments/01_rule_order.py               # lab adımları
python3 experiments/02_port_subnet_exceptions.py   # porta özel deny, /24, istisna, permütasyonlar
python3 experiments/03_attack_simulation.py        # sahte port taraması + brute-force
python3 experiments/04_blind_spots.py              # "doğru sırada deny" yetmediğinde
python3 -m unittest discover -s tests -t . -v      # tüm testler
```

### Örnek sonuç (Deney 03)
| | Yanlış sıra | Doğru sıra |
|---|---|---|
| Port taraması (1-1024) | 22 ve 80 görünür | Açık port görünmez |
| Brute-force (200 deneme) | 200 geçti | 200 engellendi |
| Sonuç | Saldırı başarılı | Saldırı engellendi |

## Kör noktalar (Deney 04)
Deny kuralını doğru sıraya koymak tek başına yetmeyebilir:

| # | Durum | Sonuç | Çözüm |
|---|---|---|---|
| 1 | Saldırgan zaten bağlıyken deny eklenirse | Açık oturum devam eder (`before.rules` conntrack) | Oturumu/conntrack kaydını da sonlandır |
| 2 | Ping (ICMP) | Deny'dan önce kabul edilir | `before.rules` içinde ayrıca DROP |
| 3 | Sadece IPv4 engellenirse | Saldırganın IPv6 adresi geçer | IPv6 adresini de engelle |
| 4 | `allow 80/tcp` ile `allow 80` | İkincisi UDP'yi de açar | Protokolü açıkça yaz |
| 5 | Aynı deny kuralı zaten varsa `insert 1` | Atlanır, kural yukarı taşınmaz | Önce `delete`, sonra `insert 1` |

> Bu davranışlar simülatörde modellenmiştir; kendi Kali makinende gerçek UFW ile doğrula: [docs/real-ufw-commands.md](docs/real-ufw-commands.md).

## Test kalitesi
- **50 test** (simülatör, analizör, log analizi, komut satırı).
- **Çapraz doğrulama:** `ufwguard`'ın "bu kural etkisiz" iddiaları, rastgele kural setlerinde simülatörün gerçek karar mantığıyla sınanır (iddia doğruysa hiçbir paket o kurala ulaşamaz). Bu test sırasında simülatörün `Anywhere/udp` gösterim hatası ve analizörün "dar istisna allow'unu hata sanma" yanlış alarmı bulunup düzeltildi.
- **Farklılık testi:** 60.000 rastgele karar, bağımsız bir referans uygulamayla karşılaştırılır.
- **Mutasyon testi:** simülatöre 6, `ufwguard`'a 9 kasıtlı hata sokuldu; testler hepsini yakaladı (15/15).
- Gerçek UFW ile birebir çıktı karşılaştırması (lab Adım 4 ve 5) testlerde yer alır.

## Yapı
```
ufw-lab/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── .github/workflows/tests.yml   # CI
├── ufwsim/            # kural motoru (simülatör)
├── ufwguard/          # denetleyici + log analizcisi (CLI)
├── experiments/       # 01-04
├── tests/             # unittest + çapraz doğrulama + fuzz
└── docs/              # LEGAL.md, HARDENING.md, gerçek UFW komutları
```

## Lisans
MIT, bkz. [LICENSE](LICENSE).
