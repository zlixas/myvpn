package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"myvpn/internal/sysutil"
)

const (
	iface      = "myvpn0"
	wgConfPath = "/etc/wireguard/" + iface + ".conf"
)

// writeWGConf, wg-quick yapılandırmasını durumdan baştan üretir.
func writeWGConf(st *State) error {
	var b strings.Builder
	b.WriteString("# myvpn-server tarafından üretildi. Elle düzenleme, değişiklikler silinir.\n")
	fmt.Fprintf(&b, "[Interface]\nAddress = %s/%d\nListenPort = %d\nPrivateKey = %s\nMTU = %d\n",
		st.serverAddr(), st.prefix().Bits(), st.ListenPort, st.WGPrivateKey, st.MTU)

	// Tünelden gelen trafiği ilet ve dış arayüzden NAT'la çıkar.
	up := fmt.Sprintf("iptables -I FORWARD -i %%i -j ACCEPT; "+
		"iptables -I FORWARD -o %%i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; "+
		"iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", st.prefix(), st.OutIface)
	down := strings.NewReplacer(" -I ", " -D ", " -A ", " -D ").Replace(up)
	fmt.Fprintf(&b, "PostUp = %s\nPostDown = %s\n", up, down)

	for _, p := range st.Peers {
		fmt.Fprintf(&b, "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n", p.Name, p.PublicKey, p.Address)
	}
	return sysutil.WriteFileAtomic(wgConfPath, []byte(b.String()), 0o600)
}

func hasSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// startInterface, arayüzü açar ve açılışta otomatik başlamasını sağlar.
func startInterface() error {
	if hasSystemd() {
		return sysutil.Run("systemctl", "enable", "--now", "wg-quick@"+iface)
	}
	return sysutil.Run("wg-quick", "up", iface)
}

func addPeerLive(pub, addr string) error {
	return sysutil.Run("wg", "set", iface, "peer", pub, "allowed-ips", addr+"/32")
}

func removePeerLive(pub string) error {
	return sysutil.Run("wg", "set", iface, "peer", pub, "remove")
}

// latestHandshakes, açık anahtar → son el sıkışma (unix saniye) eşlemesi döndürür.
func latestHandshakes() map[string]int64 {
	out, err := sysutil.Output("wg", "show", iface, "latest-handshakes")
	m := map[string]int64{}
	if err != nil {
		return m
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			m[f[0]], _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	return m
}

func enableForwarding() error {
	if err := os.WriteFile("/etc/sysctl.d/99-myvpn.conf", []byte("net.ipv4.ip_forward = 1\n"), 0o644); err != nil {
		return err
	}
	cur, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if strings.TrimSpace(string(cur)) == "1" {
		return nil
	}
	return sysutil.Run("sysctl", "-w", "net.ipv4.ip_forward=1")
}

// defaultIface, internete çıkan arayüzün adını bulur (örn. eth0).
func defaultIface() (string, error) {
	out, err := sysutil.Output("ip", "-4", "route", "show", "default")
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1], nil
		}
	}
	return "", fmt.Errorf("varsayılan ağ arayüzü bulunamadı, -out-iface ile belirt")
}
