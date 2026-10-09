// myvpn-server: VPS'te çalışan kişisel VPN sunucusu.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"myvpn/internal/codes"
	"myvpn/internal/pairing"
	"myvpn/internal/sysutil"
	"myvpn/internal/wgkey"
)

const usageText = `myvpn-server: kişisel VPN sunucusu

Kullanım:
  sudo myvpn-server init [seçenekler]   Sunucuyu kurar ve ilk eşleşme kodlarını gösterir
  sudo myvpn-server pair                Yeni cihaz için eşleşme kodu üretir
  sudo myvpn-server list                Eşleşmiş cihazları listeler
  sudo myvpn-server remove <ad|ip>      Cihazı siler
  sudo myvpn-server status              WireGuard durumunu gösterir

Seçenekler için: myvpn-server <komut> -h
`

// Bir eşleşme kodu için izin verilen hatalı deneme sayısı.
const maxFails = 3

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		fmt.Print(usageText)
		return
	}
	err := sysutil.RequireRoot()
	if err == nil {
		switch cmd {
		case "init":
			err = cmdInit(args)
		case "pair":
			err = cmdPair(args)
		case "list":
			err = cmdList()
		case "remove":
			err = cmdRemove(args)
		case "status":
			c := exec.Command("wg", "show", iface)
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			err = c.Run()
		default:
			fmt.Fprint(os.Stderr, usageText)
			os.Exit(2)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hata:", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	port := fs.Int("port", 51820, "WireGuard UDP portu")
	pairPort := fs.Int("pair-port", 51821, "eşleştirme TCP portu (sadece eşleşme sırasında açık)")
	subnet := fs.String("subnet", "10.66.0.0/24", "VPN iç ağı")
	dns := fs.String("dns", "1.1.1.1", "istemcilere verilecek DNS sunucusu")
	mtu := fs.Int("mtu", 1420, "tünel MTU değeri")
	outIface := fs.String("out-iface", "", "internete çıkan arayüz (boşsa otomatik bulunur)")
	noPair := fs.Bool("no-pair", false, "kurulumdan sonra eşleşme kodunu gösterme")
	timeout := fs.Duration("timeout", 10*time.Minute, "eşleşme kodunun geçerlilik süresi")
	fs.Parse(args)

	if _, err := os.Stat(statePath); err == nil {
		return errors.New("sunucu zaten kurulu. Yeni cihaz eklemek için: sudo myvpn-server pair")
	}
	if err := sysutil.RequireTools("apt install wireguard-tools iptables iproute2", "wg", "wg-quick", "iptables", "ip"); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(*subnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() > 29 {
		return fmt.Errorf("geçersiz alt ağ %q (örnek: 10.66.0.0/24)", *subnet)
	}
	if _, err := netip.ParseAddr(*dns); err != nil {
		return fmt.Errorf("geçersiz DNS adresi %q", *dns)
	}
	if *outIface == "" {
		if *outIface, err = defaultIface(); err != nil {
			return err
		}
	}

	wgPriv, _, err := wgkey.Generate()
	if err != nil {
		return err
	}
	pairKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	st := &State{
		WGPrivateKey:   wgPriv,
		PairPrivateKey: base64.StdEncoding.EncodeToString(pairKey.Bytes()),
		ListenPort:     *port,
		PairPort:       *pairPort,
		Subnet:         prefix.Masked().String(),
		DNS:            *dns,
		MTU:            *mtu,
		OutIface:       *outIface,
	}

	fmt.Println("• IP yönlendirme açılıyor")
	if err := enableForwarding(); err != nil {
		return err
	}
	fmt.Println("• Yapılandırma yazılıyor")
	if err := writeWGConf(st); err != nil {
		return err
	}
	fmt.Printf("• %s arayüzü başlatılıyor\n", iface)
	if err := startInterface(); err != nil {
		return err
	}
	// Durum en son kaydedilir: yarıda kalan kurulum "init" ile baştan denenebilir.
	if err := st.save(); err != nil {
		return err
	}
	fmt.Printf("✓ Sunucu kuruldu. Güvenlik duvarında UDP %d ve TCP %d açık olmalı.\n", st.ListenPort, st.PairPort)

	if *noPair {
		fmt.Println("Cihaz eklemek için: sudo myvpn-server pair")
		return nil
	}
	return pair(st, *timeout)
}

func cmdPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Minute, "eşleşme kodunun geçerlilik süresi")
	fs.Parse(args)
	st, err := loadState()
	if err != nil {
		return err
	}
	return pair(st, *timeout)
}

// pair, eşleştirme portunu sadece kod geçerliyken açar, tek cihaz eşleşince kapatır.
func pair(st *State, window time.Duration) error {
	static, err := st.pairKey()
	if err != nil {
		return err
	}
	serverCode := codes.Fingerprint(static.PublicKey().Bytes())
	pairCode := codes.Random()

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", st.PairPort))
	if err != nil {
		return fmt.Errorf("eşleştirme portu açılamadı: %w", err)
	}
	defer ln.Close()
	deadline := time.Now().Add(window)
	ln.(*net.TCPListener).SetDeadline(deadline)

	printCodes(st, serverCode, pairCode, deadline)

	fails := 0
	for {
		conn, err := ln.Accept()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return errors.New("eşleşme süresi doldu. Yeni kod için: sudo myvpn-server pair")
		}
		if err != nil {
			return err
		}
		remote := conn.RemoteAddr().String()
		peer, err := handlePair(conn, st, static, pairCode)
		switch {
		case err == nil:
			fmt.Printf("✓ %q eşleşti, adresi %s. Eşleşme kodu artık geçersiz.\n", peer.Name, peer.Address)
			return nil
		case errors.Is(err, pairing.ErrBadCode):
			fails++
			fmt.Printf("✗ %s hatalı eşleşme kodu denedi (%d/%d)\n", remote, fails, maxFails)
			if fails >= maxFails {
				return errors.New("çok fazla hatalı deneme, kod iptal edildi. Yeni kod için: sudo myvpn-server pair")
			}
		default:
			fmt.Printf("· %s bağlantısı yok sayıldı: %v\n", remote, err)
		}
	}
}

// handlePair tek bir bağlantıyı işler. Bağlantılar sırayla işlendiği için
// aynı anda birden çok tahmin denenemez.
func handlePair(conn net.Conn, st *State, static *ecdh.PrivateKey, pairCode string) (*Peer, error) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	var peer Peer
	_, err := pairing.Server(conn, static, pairCode, func(h pairing.ClientHello) (*pairing.Config, error) {
		addr, err := st.nextFreeAddr()
		if err != nil {
			return nil, err
		}
		pub, err := st.wgPublicKey()
		if err != nil {
			return nil, err
		}
		if err := addPeerLive(h.WGPublicKey, addr.String()); err != nil {
			return nil, err
		}
		peer = Peer{Name: cleanName(h.Name), PublicKey: h.WGPublicKey, Address: addr.String(), Added: time.Now().UTC()}
		st.Peers = append(st.Peers, peer)
		if err := st.save(); err != nil {
			return nil, err
		}
		if err := writeWGConf(st); err != nil {
			return nil, err
		}
		return &pairing.Config{
			WGPublicKey: pub,
			ListenPort:  st.ListenPort,
			Address:     fmt.Sprintf("%s/%d", addr, st.prefix().Bits()),
			DNS:         st.DNS,
			MTU:         st.MTU,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return &peer, nil
}

func printCodes(st *State, serverCode, pairCode string, until time.Time) {
	line := strings.Repeat("─", 44)
	fmt.Println()
	fmt.Println("  " + line)
	if ip, private := guessAddr(st.OutIface); ip != "" {
		note := ""
		if private {
			note = "  (özel IP, VPS'in genel IP'sini kullan)"
		}
		fmt.Printf("    Sunucu adresi :  %s%s\n", ip, note)
	}
	fmt.Printf("    Sunucu kodu   :  %s\n", codes.Format(serverCode))
	fmt.Printf("    Eşleşme kodu  :  %s\n", codes.Format(pairCode))
	fmt.Println("  " + line)
	fmt.Printf("    Kod %s saatine kadar geçerli ve tek kullanımlık.\n", until.Local().Format("15:04"))
	fmt.Println("    Masaüstünde: sudo myvpn pair   ya da   myvpn gui")
	fmt.Println()
	fmt.Println("  Cihaz bekleniyor... (iptal: Ctrl+C)")
}

// guessAddr, internete çıkan arayüzün IPv4 adresini bulur.
func guessAddr(name string) (ip string, private bool) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return "", false
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsGlobalUnicast() {
			return n.IP.String(), n.IP.IsPrivate()
		}
	}
	return "", false
}

// cleanName, istemciden gelen cihaz adını terminal ve yapılandırma dosyası için güvenli hale getirir.
func cleanName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
		if b.Len() >= 32 {
			break
		}
	}
	if b.Len() == 0 {
		return "cihaz"
	}
	return b.String()
}

func cmdList() error {
	st, err := loadState()
	if err != nil {
		return err
	}
	if len(st.Peers) == 0 {
		fmt.Println("Henüz eşleşmiş cihaz yok. Eklemek için: sudo myvpn-server pair")
		return nil
	}
	hs := latestHandshakes()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "AD\tADRES\tEKLENDİ\tSON BAĞLANTI")
	for _, p := range st.Peers {
		last := "hiç"
		if t := hs[p.PublicKey]; t > 0 {
			last = time.Since(time.Unix(t, 0)).Round(time.Second).String() + " önce"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, p.Address, p.Added.Local().Format("2006-01-02 15:04"), last)
	}
	return w.Flush()
}

func cmdRemove(args []string) error {
	if len(args) != 1 {
		return errors.New("kullanım: sudo myvpn-server remove <ad|ip>")
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	var idx []int
	for i, p := range st.Peers {
		if p.Address == args[0] || p.Name == args[0] {
			idx = append(idx, i)
		}
	}
	switch len(idx) {
	case 0:
		return fmt.Errorf("%q adında ya da adresinde cihaz yok (bkz: myvpn-server list)", args[0])
	case 1:
	default:
		return fmt.Errorf("%q adında birden fazla cihaz var, IP adresiyle sil", args[0])
	}
	p := st.Peers[idx[0]]
	if err := removePeerLive(p.PublicKey); err != nil {
		fmt.Fprintln(os.Stderr, "uyarı: canlı arayüzden silinemedi:", err)
	}
	st.Peers = append(st.Peers[:idx[0]], st.Peers[idx[0]+1:]...)
	if err := st.save(); err != nil {
		return err
	}
	if err := writeWGConf(st); err != nil {
		return err
	}
	fmt.Printf("✓ %s (%s) silindi.\n", p.Name, p.Address)
	return nil
}
