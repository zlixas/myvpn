package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"myvpn/internal/client"
)

//go:embed web/index.html
var indexHTML []byte

// Arayüzü sudo altında açarken tarayıcıyı kullanıcının oturumunda başlatabilmek için korunan değişkenler.
var sessionEnv = []string{"DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"}

func cmdGUI(args []string) error {
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	port := fs.Int("port", 0, "yerel port (0 = rastgele)")
	noBrowser := fs.Bool("no-browser", false, "tarayıcıyı otomatik açma")
	fs.Parse(args)

	// WireGuard'ı yönetmek root ister; kullanıcı olarak açıldıysa kendini sudo ile yeniden başlat.
	if os.Geteuid() != 0 {
		return reexecWithSudo()
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return err
	}
	g := &gui{host: ln.Addr().String(), token: rand.Text()}
	url := "http://" + g.host + "/?t=" + g.token
	fmt.Println("myvpn arayüzü:", url)
	fmt.Println("Kapatmak için bu pencerede Ctrl+C.")
	if !*noBrowser {
		openBrowser(url)
	}
	srv := &http.Server{Handler: g, ReadHeaderTimeout: 5 * time.Second}
	return srv.Serve(ln)
}

func reexecWithSudo() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	sudoArgs := append([]string{"--preserve-env=" + strings.Join(sessionEnv, ","), self}, os.Args[1:]...)
	cmd := exec.Command("sudo", sudoArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	return err
}

// openBrowser, tarayıcıyı root olarak değil, sudo'yu çağıran kullanıcı olarak açar.
func openBrowser(url string) {
	var cmd *exec.Cmd
	if user := os.Getenv("SUDO_USER"); user != "" && user != "root" {
		args := []string{"-u", user, "env"}
		for _, k := range sessionEnv {
			if v := os.Getenv(k); v != "" {
				args = append(args, k+"="+v)
			}
		}
		cmd = exec.Command("sudo", append(args, "xdg-open", url)...)
	} else {
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err == nil {
		go cmd.Wait()
	}
}

type gui struct {
	host  string
	token string
	mu    sync.Mutex // eşleşme/bağlanma işlemleri aynı anda çalışmasın
}

func (g *gui) validToken(t string) bool {
	return subtle.ConstantTimeCompare([]byte(t), []byte(g.token)) == 1
}

func (g *gui) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Host kontrolü DNS rebinding saldırılarını engeller.
	if r.Host != g.host {
		http.Error(w, "geçersiz host", http.StatusForbidden)
		return
	}
	// Terminaldeki bağlantı açıldığında token çereze taşınır.
	if r.URL.Path == "/" && r.URL.Query().Has("t") {
		if !g.validToken(r.URL.Query().Get("t")) {
			http.Error(w, "geçersiz oturum", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "myvpn", Value: g.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if c, err := r.Cookie("myvpn"); err != nil || !g.validToken(c.Value) {
		http.Error(w, "Oturum geçersiz. Terminalde yazan bağlantıyı aç.", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "geçersiz istek", http.StatusBadRequest)
		return
	}

	switch r.Method + " " + r.URL.Path {
	case "GET /":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
		w.Write(indexHTML)
	case "GET /api/status":
		g.do(w, nil)
	case "POST /api/up":
		g.do(w, client.Up)
	case "POST /api/down":
		g.do(w, client.Down)
	case "POST /api/pair":
		var req struct {
			Server     string `json:"server"`
			ServerCode string `json:"server_code"`
			PairCode   string `json:"pair_code"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "geçersiz istek"})
			return
		}
		g.do(w, func() error {
			if err := client.Pair(req.Server, req.ServerCode, req.PairCode); err != nil {
				return err
			}
			return client.Up()
		})
	default:
		http.NotFound(w, r)
	}
}

// do, işlemi çalıştırır ve sonuçta güncel durumu döndürür.
func (g *gui) do(w http.ResponseWriter, fn func() error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if fn != nil {
		if err := fn(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	st, err := client.GetStatus()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
