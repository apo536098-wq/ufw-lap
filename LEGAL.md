# Hukuki Notlar

> **Bu belge hukuki danışmanlık değildir.** Bir avukat tarafından hazırlanmamıştır. Kesin görüş için bir avukata veya okulunun (BGT207) ilgili birimine danış.

## Proje ne yapıyor, ne yapmıyor
- **Yapıyor:** UFW kural sıralamasını bellek içinde taklit eden bir Python simülatörü; kullanıcının **kendi** `ufw status` çıktısını ve **kendi** `ufw.log` dosyasını okuyup güvenlik açıklarını ve şüpheli kaynakları raporlayan salt-okunur bir denetleyici (`ufwguard`); testler ve eğitim amaçlı deneyler.
- **Yapmıyor:** (`ufwguard` dahil) Ağ bağlantısı kurmaz, paket göndermez, port taraması yapmaz, hiçbir sisteme girmez, exploit veya zararlı yazılım içermez.
- "Sahte saldırı" deneyleri sadece kural motoruna verilen sentetik olaylardır. Kullanılan IP adresleri (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`, `2001:db8::/32`) dokümantasyon için ayrılmış adreslerdir ve gerçek sistemlere ait değildir.

## Türkiye (TCK) açısından değerlendirme
| Madde | Konusu | Bu proje |
|---|---|---|
| TCK 243 | Bilişim sistemine izinsiz girme / orada kalma | Hiçbir sisteme girmez. **Risk yok.** |
| TCK 244 | Sistemi engelleme, bozma, veri yok etme/değiştirme | Hiçbir sisteme müdahale etmez. **Risk yok.** |
| TCK 245/A | Bilişim suçlarını işlemek **amacıyla** cihaz/program/şifre yapma, bulundurma, yayma | Amaç savunma eğitimidir; saldırı aracı değildir. Madde amaç unsuruna bağlıdır. **Düşük risk.** |

Bu maddeler özetle şunu söyler: izinsiz erişim ve sistemi bozma suçtur, ayrıca bu suçları işlemek için özel olarak araç üretmek de suç olabilir. Projeyi bu çizginin güvenli tarafında tutmak için:

1. **Gerçek tarama/saldırı kodu ekleme** (socket ile port tarama, brute-force aracı, paket üretici vb.). Bunlar projeyi "saldırı aracı" izlenimine sokar.
2. **Gerçek IP veya alan adı kullanma.** Sadece yukarıdaki ayrılmış adresleri kullan.
3. **Gerçek UFW komutlarını yalnızca kendi makinende / yetkili olduğun lab ortamında çalıştır.** Başkasının sistemine izinsiz tarama veya deneme yapmak ayrı bir hukuki risktir. Test için yazılı izin al.
4. README'deki amaç beyanını ve uyarıyı koru.

## GitHub kuralları
GitHub, zarar vermeyen güvenlik araştırması ve "dual-use" (hem savunma hem saldırı için kullanılabilen) içeriği izin verir. Aktif saldırıları destekleyen zararlı içerik yasaktır. GitHub'ın istediği iyi uygulamalar:
- README'de potansiyel olarak zararlı olabilecek içeriği açıkça belirten bir uyarı,
- `SECURITY.md` ile kötüye kullanım bildirimi için iletişim yöntemi.

Bu depoda ikisi de vardır. Bu proje zaten zarar verebilecek bir kod içermez.

## Kaynaklar
- TCK 243, 244, 245/A genel açıklama: https://kadimhukuk.com.tr/makale/bilisim-suclari-cezalari/
- TCK 245/A açıklaması: https://mihci.av.tr/yasak-cihaz-veya-program-sucu/
- GitHub Active Malware or Exploits politikası: https://docs.github.com/en/site-policy/acceptable-use-policies/github-active-malware-or-exploits

Ceza miktarları ve madde metinleri değişebilir; güncel metni Resmî Gazete / mevzuat.gov.tr üzerinden kontrol et.

## Log analizi ve kişisel veri notu
`ufwguard logs`, log dosyalarındaki IP adreslerini okur. IP adresleri bazı hukuk düzenlerinde (ör. KVKK/GDPR) kişisel veri sayılabilir. Bu yüzden: sadece **kendi sistemlerinin** loglarını analiz et, gerçek log dosyalarını GitHub'a **yükleme** (depodaki `ufw.log` tamamen sentetiktir), ve paylaşman gerekirse IP'leri maskele.
