# Katkı Kuralları

Katkılar memnuniyetle karşılanır. Şu kurallara uy:

1. **Gerçek ağ trafiği yok.** Socket, paket üretimi, port tarama, brute-force aracı gibi kod kabul edilmez.
2. **Sadece ayrılmış adresler:** `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`, `2001:db8::/32`. Gerçek IP/alan adı kullanma.
3. `ufwguard` yalnızca dosya okur ve öneri üretir: komut çalıştırma, ağ erişimi veya otomatik engelleme ekleme.
4. **Savunma odaklı kal:** Amaç UFW kural mantığını anlamak.
5. Her değişiklik için test ekle ve `python3 -m unittest discover -s tests -t .` komutunun geçtiğini kontrol et.
6. Gerçek UFW davranışına dair bir iddia ekliyorsan, kaynağını veya kendi Kali makinende nasıl doğruladığını yaz.
