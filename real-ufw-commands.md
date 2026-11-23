# Gerçek UFW karşılıkları ve doğrulama (Kali'de dene)

> Sadece **kendi** makinende / lab ortamında. SSH ile bağlıysan 22/tcp iznini kaybetme.

## Komut karşılıkları
| Simülasyon | Gerçek komut |
|---|---|
| Porta özel deny | `sudo ufw insert 1 deny from 203.0.113.5 to any port 22` |
| /24 alt ağ engeli | `sudo ufw insert 1 deny from 203.0.113.0/24` |
| Dar istisna (yönetici IP) | `sudo ufw insert 1 allow from 203.0.113.10` |
| Sırayı görme | `sudo ufw status numbered` |
| Kuralı silme | `sudo ufw delete N` |

## Kör noktaları gerçek sistemde doğrulama
Simülatör bunları modelledi ama gerçek UFW'nin davranışını sen kendi makinende görmelisin.

1. **Aynı kural varken insert:** `sudo ufw insert 1 deny from 203.0.113.5` komutunu kural zaten varken çalıştır. Çıktıda kuralın atlandığına dair bir mesaj bekleniyor.
2. **Protokolsüz allow:** `sudo ufw allow 80` sonra `sudo ufw status numbered` ile `80/tcp` yerine `80` yazdığını ve `(v6)` karşılığının eklendiğini gör.
3. **IPv6 durumu:** `grep IPV6 /etc/default/ufw` (IPV6=yes ise v6 kuralları da oluşur).
4. **ICMP:** `grep -n icmp /etc/ufw/before.rules` ile ping kurallarının `before.rules` içinde olduğunu gör. Bu dosya kullanıcı kurallarından önce işlenir.
5. **Kurulmuş bağlantı:** `conntrack-tools` kuruluysa `sudo conntrack -L` ile aktif bağlantıları listele. Bunun için kendi iki makinen (ör. iki sanal makine) gerekir.

Dosyalar: `/etc/ufw/before.rules`, `/etc/ufw/user.rules`, `/etc/ufw/user6.rules`.
