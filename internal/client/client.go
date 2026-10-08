// Package client, masaüstü tarafının eşleşme ve bağlantı işlemlerini yürütür.
// Komut satırı ve arayüz aynı fonksiyonları kullanır.
package client

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"myvpn/internal/codes"
	"myvpn/internal/pairing"
	"myvpn/internal/sysutil"
	"myvpn/internal/wgkey"
)

const (
	Iface           = "myvpn"
	ConfPath        = "/etc/wireguard/" + Iface + ".conf"
	DefaultPairPort = "51821"
)

// Status, arayüzde ve "myvpn status" çıktısında gösterilen durum.
type Status struct {
	Paired        bool   `json:"paired"`
	Connected     bool   `json:"connected"`
	Server        string `json:"server,omitempty"`
	Address       string `json:"address,omitempty"`
	LastHandshake int64  `json:"last_handshake"` // unix saniye, 0 = henüz yok
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
}

func checkTools() error {
	return sysutil.RequireTools("apt install wireguard-tools openresolv", "wg", "wg-quick")
}

// Pair, sunucuyla eşleşir ve WireGuard yapılandırmasını yazar.
func Pair(server, serverCode, pairCode string) error {
	if err := checkTools(); err != nil {
		return err
	}
	c1, err := codes.Normalize(serverCode)
	if err != nil {
		return fmt.Errorf("sunucu kodu: %w", err)
	}
	c2, err := codes.Normalize(pairCode)
	if err != nil {
		return fmt.Errorf("eşleşme kodu: %w", err)
	}
	host, port, err := splitServer(server)
	if err != nil {
		return err
	}

	// Eski tünel açıksa eşleştirme trafiği onun içinden gitmeye çalışmasın.
	if IsUp() {
		if err := Down(); err != nil {
			return err
		}
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return fmt.Errorf("sunucuya ulaşılamadı (sunucuda 'myvpn-server pair' çalışıyor mu, TCP %s açık mı?): %w", port, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	priv, pub, err := wgkey.Generate()
	if err != nil {
		return err
	}
	name, _ := os.Hostname()
	cfg, err := pairing.Client(conn, c1, c2, pairing.ClientHello{Name: name, WGPublicKey: pub})
	if err != nil {
		return err
	}
	return writeConf(priv, host, cfg)
}

// splitServer, "1.2.3.4", "1.2.3.4:51821", "vpn.ornek.com" veya IPv6 adreslerini ayırır.
func splitServer(s string) (host, port string, err error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t\r\n/") {
		return "", "", errors.New("geçersiz sunucu adresi")
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p, nil
	}
	return strings.Trim(s, "[]"), DefaultPairPort, nil
}

func writeConf(priv, host string, cfg *pairing.Config) error {
	addr, err := netip.ParsePrefix(cfg.Address)
	if err != nil || !addr.Addr().Is4() {
		return errors.New("sunucudan geçersiz tünel adresi geldi")
	}
	if cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
		return errors.New("sunucudan geçersiz port geldi")
	}

	var b strings.Builder
	b.WriteString("# myvpn tarafından üretildi. Yeniden eşleşince üzerine yazılır.\n[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\nAddress = %s\n", priv, addr)
	if dns, err := netip.ParseAddr(cfg.DNS); err == nil && hasResolvconf() {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	if cfg.MTU >= 1280 && cfg.MTU <= 1500 {
		fmt.Fprintf(&b, "MTU = %d\n", cfg.MTU)
	}
	// IPv6 açıksa onu da tünele al; yoksa IPv6 trafiği VPN dışından sızardı.
	allowed := "0.0.0.0/0"
	if ipv6Enabled() {
		allowed += ", ::/0"
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n",
		cfg.WGPublicKey, net.JoinHostPort(host, strconv.Itoa(cfg.ListenPort)), allowed)
	return sysutil.WriteFileAtomic(ConfPath, []byte(b.String()), 0o600)
}

func hasResolvconf() bool {
	_, err := exec.LookPath("resolvconf")
	return err == nil
}

func ipv6Enabled() bool {
	b, err := os.ReadFile("/proc/net/if_inet6")
	return err == nil && len(strings.TrimSpace(string(b))) > 0
}

func IsUp() bool {
	_, err := os.Stat("/sys/class/net/" + Iface)
	return err == nil
}

func Up() error {
	if err := checkTools(); err != nil {
		return err
	}
	if _, err := os.Stat(ConfPath); errors.Is(err, fs.ErrNotExist) {
		return errors.New("henüz eşleşilmemiş, önce: sudo myvpn pair")
	}
	if IsUp() {
		return nil
	}
	return sysutil.Run("wg-quick", "up", Iface)
}

func Down() error {
	if !IsUp() {
		return nil
	}
	return sysutil.Run("wg-quick", "down", Iface)
}

func GetStatus() (*Status, error) {
	st := &Status{}
	b, err := os.ReadFile(ConfPath)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	st.Paired = true
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Endpoint":
			st.Server = strings.TrimSpace(v)
		case "Address":
			st.Address = strings.TrimSpace(v)
		}
	}
	if !IsUp() {
		return st, nil
	}
	st.Connected = true
	// dump çıktısı: 1. satır arayüz, 2. satır sunucu:
	// pubkey psk endpoint allowed-ips son-el-sıkışma rx tx keepalive
	out, err := sysutil.Output("wg", "show", Iface, "dump")
	if err != nil {
		return st, nil
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) >= 2 {
		if f := strings.Split(lines[1], "\t"); len(f) >= 7 {
			st.LastHandshake, _ = strconv.ParseInt(f[4], 10, 64)
			st.RxBytes, _ = strconv.ParseInt(f[5], 10, 64)
			st.TxBytes, _ = strconv.ParseInt(f[6], 10, 64)
		}
	}
	return st, nil
}
