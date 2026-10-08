// myvpn: masaüstünde çalışan kişisel VPN istemcisi (komut satırı + arayüz).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"myvpn/internal/client"
	"myvpn/internal/sysutil"
)

const usageText = `myvpn: kişisel VPN istemcisi

Kullanım:
  sudo myvpn pair [sunucu] [sunucu-kodu] [eşleşme-kodu]   Sunucuyla eşleşir ve bağlanır
  sudo myvpn up                                         Bağlanır
  sudo myvpn down                                       Bağlantıyı keser
  sudo myvpn status                                     Durumu gösterir
  myvpn gui                                             Arayüzü açar

Kodlar verilmezse tek tek sorulur.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return
	case "gui":
		err = cmdGUI(args)
	case "pair", "up", "down", "status":
		if err = sysutil.RequireRoot(); err != nil {
			break
		}
		switch cmd {
		case "pair":
			err = cmdPair(args)
		case "up":
			if err = client.Up(); err == nil {
				fmt.Println("✓ Bağlandı.")
			}
		case "down":
			if err = client.Down(); err == nil {
				fmt.Println("✓ Bağlantı kesildi.")
			}
		case "status":
			err = cmdStatus()
		}
	default:
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hata:", err)
		os.Exit(1)
	}
}

func cmdPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	noConnect := fs.Bool("no-connect", false, "eşleştikten sonra bağlanma")
	fs.Parse(args)

	vals := fs.Args()
	in := bufio.NewReader(os.Stdin)
	ask := func(i int, prompt string) string {
		if i < len(vals) {
			return vals[i]
		}
		fmt.Print(prompt)
		line, _ := in.ReadString('\n')
		return strings.TrimSpace(line)
	}
	server := ask(0, "Sunucu adresi : ")
	serverCode := ask(1, "Sunucu kodu   : ")
	pairCode := ask(2, "Eşleşme kodu  : ")

	fmt.Println("Eşleşiliyor...")
	if err := client.Pair(server, serverCode, pairCode); err != nil {
		return err
	}
	fmt.Println("✓ Eşleşme tamam, ayarlar kaydedildi.")
	if *noConnect {
		fmt.Println("Bağlanmak için: sudo myvpn up")
		return nil
	}
	if err := client.Up(); err != nil {
		return err
	}
	fmt.Println("✓ Bağlandı. Tüm trafik VPN üzerinden gidiyor.")
	return nil
}

func cmdStatus() error {
	st, err := client.GetStatus()
	if err != nil {
		return err
	}
	switch {
	case !st.Paired:
		fmt.Println("Durum   : eşleşmemiş (sudo myvpn pair)")
		return nil
	case !st.Connected:
		fmt.Println("Durum   : bağlı değil")
	case st.LastHandshake == 0 || time.Since(time.Unix(st.LastHandshake, 0)) > 3*time.Minute:
		fmt.Println("Durum   : bağlanıyor (sunucudan yanıt yok)")
	default:
		fmt.Println("Durum   : bağlı")
	}
	fmt.Println("Sunucu  :", st.Server)
	fmt.Println("Adres   :", st.Address)
	if st.Connected {
		last := "henüz yok"
		if st.LastHandshake > 0 {
			last = time.Since(time.Unix(st.LastHandshake, 0)).Round(time.Second).String() + " önce"
		}
		fmt.Println("Son el sıkışma:", last)
		fmt.Printf("Trafik  : ↓ %s  ↑ %s\n", humanBytes(st.RxBytes), humanBytes(st.TxBytes))
	}
	return nil
}

func humanBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}
