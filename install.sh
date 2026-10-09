#!/usr/bin/env bash
# myvpn otomatik kurulum (Debian / Ubuntu)
#
#   Sunucu   : curl -fsSL https://raw.githubusercontent.com/zlixas/myvpn/main/install.sh | sudo bash -s server
#   Masaüstü : curl -fsSL https://raw.githubusercontent.com/zlixas/myvpn/main/install.sh | sudo bash -s client
#   Kaldır   : curl -fsSL https://raw.githubusercontent.com/zlixas/myvpn/main/install.sh | sudo bash -s uninstall
#
# Tekrar çalıştırmak programı son sürüme günceller; ayarlar ve eşleşmeler korunur.
# Belirli bir sürüm için: ... | sudo MYVPN_VERSION=v0.1.0 bash -s server
#
# Tüm betik main içinde: indirme yarıda kesilirse yarım betik çalışmaz.

set -euo pipefail

REPO="${MYVPN_REPO:-zlixas/myvpn}"
VERSION="${MYVPN_VERSION:-latest}"
BIN_DIR=/usr/local/bin

info() { printf '\033[1;34m•\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mhata:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Kullanım: sudo bash install.sh <server|client|uninstall>
  server     VPS'e sunucuyu kurar ve eşleşme kodlarını gösterir
  client     Masaüstüne istemciyi ve arayüzü kurar
  uninstall  myvpn'i kaldırır (ayarları silmek için: uninstall --purge)
EOF
  exit 2
}

detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64)  echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) die "desteklenmeyen işlemci mimarisi: $(uname -m) (amd64 ve arm64 destekleniyor)" ;;
  esac
}

apt_install() {
  command -v apt-get >/dev/null || die "bu kurulum Debian/Ubuntu (apt) içindir"
  info "Paketler kuruluyor: $*"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
}

# fetch_release <hedef-dizin>: programları GitHub sürümünden indirir ve SHA256 ile doğrular.
# Betik açılmış bir sürüm arşivinin içinden çalıştırıldıysa yanındaki dosyaları kullanır.
fetch_release() {
  local dest=$1 src="${BASH_SOURCE[0]:-}"
  if [[ -n $src && -f $src ]]; then
    local here
    here=$(cd "$(dirname "$src")" && pwd)
    if [[ -x $here/myvpn && -x $here/myvpn-server ]]; then
      info "Yerel dosyalar kullanılıyor: $here"
      cp "$here/myvpn" "$here/myvpn-server" "$here/myvpn.desktop" "$dest/"
      return
    fi
  fi

  command -v curl >/dev/null || apt_install curl ca-certificates
  local arch name base
  arch=$(detect_arch)
  name="myvpn-linux-$arch"
  if [[ $VERSION == latest ]]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$VERSION"
  fi

  info "İndiriliyor: $name ($VERSION)"
  curl -fsSL --retry 3 -o "$dest/$name.tar.gz" "$base/$name.tar.gz" || die "indirilemedi: $base/$name.tar.gz"
  curl -fsSL --retry 3 -o "$dest/SHA256SUMS" "$base/SHA256SUMS" || die "SHA256SUMS indirilemedi"
  (cd "$dest" && grep " $name.tar.gz\$" SHA256SUMS | sha256sum -c --quiet -) || die "SHA256 doğrulaması başarısız, dosya bozuk ya da değiştirilmiş"
  tar -xzf "$dest/$name.tar.gz" -C "$dest" --strip-components=1
}

# Geçici dizin global: trap betik bitince çalışır, fonksiyonun yerel değişkeni o an yok olur.
TMP=""
make_tmp() { TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT; }

has_tty() { [[ -r /dev/tty && -w /dev/tty ]] && (: </dev/tty) 2>/dev/null; }

install_server() {
  apt_install wireguard-tools iptables iproute2
  make_tmp
  fetch_release "$TMP"
  install -m 755 "$TMP/myvpn-server" "$BIN_DIR/myvpn-server"
  ok "myvpn-server kuruldu: $BIN_DIR/myvpn-server"

  # ufw açıksa portları aç. Bulut sağlayıcının güvenlik duvarı ayrıca kontrol edilmeli.
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    info "ufw: 51820/udp ve 51821/tcp açılıyor"
    ufw allow 51820/udp >/dev/null
    ufw allow 51821/tcp >/dev/null
  fi

  if [[ -f /etc/myvpn/server.json ]]; then
    ok "Sunucu zaten kuruluydu, program güncellendi. Ayarlar ve cihazlar korundu."
    echo "  Yeni cihaz eklemek için: sudo myvpn-server pair"
  else
    myvpn-server init
  fi
}

install_client() {
  local pkgs=(wireguard-tools iproute2 procps)
  # wg-quick, VPN'in DNS ayarı için resolvconf ister (systemd-resolved varsa zaten vardır).
  command -v resolvconf >/dev/null || pkgs+=(openresolv)
  apt_install "${pkgs[@]}"
  make_tmp
  fetch_release "$TMP"
  install -m 755 "$TMP/myvpn" "$BIN_DIR/myvpn"
  install -D -m 644 "$TMP/myvpn.desktop" /usr/share/applications/myvpn.desktop
  ok "myvpn kuruldu: $BIN_DIR/myvpn"

  if [[ -f /etc/wireguard/myvpn.conf ]]; then
    ok "Daha önce eşleşilmiş, ayarlar korundu. Bağlanmak için: sudo myvpn up"
    return
  fi
  echo
  echo "  Arayüz : uygulama menüsünden 'myvpn' ya da terminalde: myvpn gui"
  echo "  Terminal: sudo myvpn pair"
  echo

  # curl | bash ile çalışırken stdin betiğin kendisidir; soruları doğrudan terminale sor.
  if has_tty; then
    local ans
    read -r -p "Şimdi sunucuyla eşleşmek ister misin? [E/h] " ans </dev/tty || ans=h
    if [[ ! $ans =~ ^[Hh] ]]; then
      myvpn pair </dev/tty || true
    fi
  fi
}

uninstall() {
  local purge=${1:-}
  info "myvpn kaldırılıyor"
  if [[ -x $BIN_DIR/myvpn ]]; then
    "$BIN_DIR/myvpn" down 2>/dev/null || true
  fi
  if systemctl list-unit-files 'wg-quick@myvpn0.service' >/dev/null 2>&1; then
    systemctl disable --now wg-quick@myvpn0 2>/dev/null || true
  fi
  ip link show myvpn0 >/dev/null 2>&1 && wg-quick down myvpn0 2>/dev/null || true
  rm -f "$BIN_DIR/myvpn" "$BIN_DIR/myvpn-server" /usr/share/applications/myvpn.desktop
  if [[ $purge == --purge ]]; then
    rm -rf /etc/myvpn /etc/wireguard/myvpn.conf /etc/wireguard/myvpn0.conf /etc/sysctl.d/99-myvpn.conf
    ok "Kaldırıldı; anahtarlar ve ayarlar silindi."
  else
    ok "Kaldırıldı. Ayarlar duruyor (/etc/myvpn, /etc/wireguard/myvpn*.conf); silmek için: uninstall --purge"
  fi
}

main() {
  [[ $EUID -eq 0 ]] || die "root olarak çalıştır (komutta 'sudo bash' olmalı)"
  case "${1:-}" in
    server)    install_server ;;
    client)    install_client ;;
    uninstall) uninstall "${2:-}" ;;
    *)         usage ;;
  esac
}

main "$@"
