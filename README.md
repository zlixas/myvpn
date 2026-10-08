# myvpn

VPS ile Debian masaüstü arasında kişisel VPN. Şifre yok: sunucu iki tane 12 karakterlik kod gösterir, bu kodları masaüstündeki uygulamaya girince eşleşip bağlanırsın.

- **Tünel:** WireGuard (denetlenmiş şifreleme, Linux çekirdeğinde hazır).
- **Eşleştirme:** bu projenin kendi protokolü ([internal/pairing](internal/pairing/pairing.go)).

## Kurulum

Debian / Ubuntu, amd64 ya da arm64. Tek komut:

**VPS (sunucu)**

```sh
curl -fsSL https://raw.githubusercontent.com/zlixas/myvpn/main/install.sh | sudo bash -s server
```

**Masaüstü (istemci + arayüz)**

```sh
curl -fsSL https://raw.githubusercontent.com/zlixas/myvpn/main/install.sh | sudo bash -s client
```

Betik şunları yapar:

1. Gerekli paketleri kurar (`wireguard-tools` vb.).
2. Son sürümü [Releases](https://github.com/zlixas/myvpn/releases) sayfasından indirir ve SHA256 ile doğrular.
3. Sunucuda kurulumu başlatır ve kodları gösterir; masaüstünde eşleşmek isteyip istemediğini sorar.

Aynı komutu tekrar çalıştırmak programı günceller; ayarlar ve eşleşmeler korunur.

| İşlem | Komut |
|---|---|
| Kaldırma | `... \| sudo bash -s uninstall` |
| Kaldırma (anahtarlar ve ayarlar dahil) | `... \| sudo bash -s uninstall --purge` |
| Belirli bir sürümü kurma | `... \| sudo MYVPN_VERSION=v0.1.0 bash -s server` |

Sunucu kurulunca ekranda şunu görürsün:

```
    Sunucu adresi :  203.0.113.10
    Sunucu kodu   :  WHPR-ST7W-D64A
    Eşleşme kodu  :  AB9G-V5HK-PQ15
```

Masaüstünde bunları gir:

- **Arayüz:** menüden *myvpn* ya da `myvpn gui`
- **Terminal:** `sudo myvpn pair` (adres ve kodları sorar)

> VPS sağlayıcının güvenlik duvarında **UDP 51820** (VPN) ve **TCP 51821** (sadece eşleşme sırasında) açık olmalı.

## Komutlar

| Sunucu | |
|---|---|
| `sudo myvpn-server pair` | Yeni cihaz için kod üretir (10 dk, tek kullanımlık) |
| `sudo myvpn-server list` | Eşleşmiş cihazlar ve son bağlantı zamanı |
| `sudo myvpn-server remove <ad\|ip>` | Cihazın erişimini kaldırır |
| `sudo myvpn-server status` | `wg show` çıktısı |

| Masaüstü | |
|---|---|
| `myvpn gui` | Arayüz (bağlan, bağlantıyı kes, eşleş, trafik) |
| `sudo myvpn pair [adres] [kod1] [kod2]` | Eşleş ve bağlan |
| `sudo myvpn up` / `down` | Bağlan / bağlantıyı kes |
| `sudo myvpn status` | Durum, son el sıkışma, trafik |

## Kodlar nasıl çalışıyor

| Kod | Ne işe yarıyor |
|---|---|
| **Sunucu kodu** | Sunucunun eşleştirme anahtarının parmak izi. Uygulama doğru sunucuya bağlandığını bununla doğrular; araya giren biri (MITM) bu anahtarı taklit edemez. Sunucu için sabittir. |
| **Eşleşme kodu** | Her `pair` çalıştırıldığında yeni üretilir, 10 dakika geçerli ve tek kullanımlıktır. Ağa **hiç gönderilmez**: anahtar türetmeye karıştırılır. Kod yanlışsa sunucu mesajı çözemez ve bağlantıyı kapatır. |

Eşleşme sırasında iki taraf geçici X25519 anahtarlarıyla ortak bir anahtar türetir (HKDF-SHA256 ile; içine eşleşme kodu da girer) ve WireGuard açık anahtarlarını AES-GCM ile şifreli olarak değiş tokuş eder. Bundan sonra kodlara bir daha gerek kalmaz; tünel WireGuard ile kurulur.

Koruma önlemleri:

- Kodlar Crockford base32 alfabesindedir; 0/O ve 1/I/L karışmaz, küçük harf ve tire fark etmez.
- Her kod 60 bittir.
- 3 hatalı denemede eşleşme kodu iptal olur.
- Bağlantılar sırayla işlenir ve eşleştirme portu sadece kod geçerliyken açıktır.

Arayüz yalnızca `127.0.0.1`'de, rastgele bir oturum anahtarıyla çalışır. Başka siteler ona istek gönderemez (Host kontrolü, SameSite çerezi ve JSON zorunluluğu var).

## Dosyalar

| Yol | İçerik |
|---|---|
| `/etc/myvpn/server.json` | Sunucu anahtarları ve cihaz listesi (600) |
| `/etc/wireguard/myvpn0.conf` | Sunucu WireGuard ayarı; `server.json`'dan üretilir |
| `/etc/wireguard/myvpn.conf` | Masaüstü WireGuard ayarı (600) |

## Geliştirme

```sh
make test   # protokol testleri: doğru kod, yanlış eşleşme kodu, yanlış sunucu
make dist   # dist/ altında Linux paketleri + SHA256SUMS (Go 1.24+)
```

Yeni sürüm yayınlamak için tag at; GitHub Actions paketleri derleyip Releases'a yükler:

```sh
git tag v0.2.0 && git push origin v0.2.0
```
