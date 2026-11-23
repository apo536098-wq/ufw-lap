# Sistem Koruma Rehberi (savunma katmanları)

UFW tek başına yetmez. Güvenlik **katmanlıdır**: bir katman kırılırsa diğeri devreye girer. `ufwguard` yalnızca güvenlik duvarı katmanını denetler; aşağıdakiler diğer katmanlardır. Hepsi **kendi makinen / yetkili olduğun sistem** içindir.

## 1. Güvenlik duvarı (UFW)
- Varsayılan: `sudo ufw default deny incoming` ve `sudo ufw default allow outgoing`.
- Sadece gerekli portları aç; veritabanı (3306, 5432, 6379, 27017...) ve yönetim portlarını (3389, 5900, 2375) internete açma.
- Yönetim erişimini mümkünse tek güvenilir IP veya VPN'e kısıtla.
- Kural sırasını denetle: dar istisna → dar deny → geniş kurallar. `python3 -m ufwguard audit` bunu otomatik kontrol eder.
- Her kural değişikliğinden sonra `sudo ufw status numbered` ile sonucu doğrula.
- `/etc/ufw/` dizinini düzenli yedekle.

## 2. SSH
- Parola yerine **anahtar** kullan; `PasswordAuthentication no`, `PermitRootLogin no`.
- `sudo ufw limit 22/tcp` ile kaba kuvveti yavaşlat (aynı IP'den kısa sürede çok bağlantıyı sınırlar).
- Gerekirse portu değiştirmek tek başına güvenlik sayılmaz; sadece gürültüyü azaltır.

## 3. Loglama ve izleme
- `sudo ufw logging low` ile engellemeleri kaydet.
- `python3 -m ufwguard logs /var/log/ufw.log` ile tarama ve tekrarlayan denemeleri incele.
- Önerilen engellemeleri **elle** gözden geçir; kaynak IP'ler sahte olabilir (özellikle UDP ve SYN paketleri). Otomatik engelleme, saldırganın meşru IP'leri engelletmesine yol açabilir.
- Otomatik tepki için olgun araçlar (ör. fail2ban) var; kullanırsan beyaz liste tanımla.

## 4. Sistem sertleştirme
- Güncellemeleri düzenli uygula (`apt update && apt upgrade`).
- Kullanılmayan servisleri kapat; dinleyen portları gör: `sudo ss -tulpn`.
- Minimum yetki ilkesi: gereksiz kullanıcı ve `sudo` yetkisini kaldır.
- Düzenli yedek al ve geri yüklemeyi dene.

## 5. Bilinen tuzaklar
| Tuzak | Açıklama |
|---|---|
| Yanlış kural sırası | Üstteki allow, alttaki deny'ı etkisiz bırakır (lab'ın konusu). |
| Kurulmuş bağlantılar | Yeni deny, zaten açık bağlantıyı hemen kesmeyebilir. |
| ICMP (ping) | `before.rules` içinde kabul edilir; `ufw deny` ping'i kesmez. |
| IPv6 | IPv4 engeli IPv6 adresini kapsamaz. |
| Docker | Docker'ın yayınladığı portlar UFW kurallarını atlayabilir (kendi iptables kurallarını ekler). `docker run -p` ile açılan portları ayrıca kontrol et. |
| `ufw disable` | Güvenlik duvarını durdurur, kurallar kalır; açılışta da başlamaz. |

## 6. Uzaktan çalışırken güvenli değişiklik
- 22/tcp iznini kaybetme; SSH ile bağlıyken `ufw enable`/`reset` yapmadan önce izni ekle.
- Riskli bir değişiklikte, ikinci bir oturum açık tut ve gerekirse konsol erişiminin olduğundan emin ol.
