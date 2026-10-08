package pairing

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"myvpn/internal/codes"
	"myvpn/internal/wgkey"
)

type result struct {
	hello *ClientHello
	err   error
}

// run, istemci ve sunucuyu bellek içi bir bağlantı üzerinden konuşturur.
func run(t *testing.T, serverCode, clientPairCode string) (*Config, error, result) {
	t.Helper()
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if serverCode == "" {
		serverCode = codes.Fingerprint(static.PublicKey().Bytes())
	}
	const pairCode = "ABCDEFGHJKMN"
	if clientPairCode == "" {
		clientPairCode = pairCode
	}
	_, srvPub, _ := wgkey.Generate()
	_, cliPub, _ := wgkey.Generate()

	c, s := net.Pipe()
	done := make(chan result, 1)
	go func() {
		defer s.Close()
		h, err := Server(s, static, pairCode, func(h ClientHello) (*Config, error) {
			if h.WGPublicKey != cliPub {
				t.Errorf("sunucu yanlış anahtar aldı")
			}
			return &Config{WGPublicKey: srvPub, ListenPort: 51820, Address: "10.66.0.2/24"}, nil
		})
		done <- result{h, err}
	}()
	cfg, err := Client(c, serverCode, clientPairCode, ClientHello{Name: "masaustu", WGPublicKey: cliPub})
	c.Close()
	res := <-done
	if err == nil && cfg.WGPublicKey != srvPub {
		t.Errorf("istemci yanlış anahtar aldı")
	}
	return cfg, err, res
}

func TestPairSuccess(t *testing.T) {
	cfg, err, res := run(t, "", "")
	if err != nil || res.err != nil {
		t.Fatalf("istemci: %v, sunucu: %v", err, res.err)
	}
	if cfg.Address != "10.66.0.2/24" || res.hello.Name != "masaustu" {
		t.Fatalf("beklenmeyen sonuç: %+v %+v", cfg, res.hello)
	}
}

func TestWrongPairCode(t *testing.T) {
	_, err, res := run(t, "", "ZZZZZZZZZZZZ")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("istemci hatası ErrRejected olmalı, gelen: %v", err)
	}
	if !errors.Is(res.err, ErrBadCode) {
		t.Fatalf("sunucu hatası ErrBadCode olmalı, gelen: %v", res.err)
	}
}

func TestWrongServerCode(t *testing.T) {
	_, err, res := run(t, "000000000000", "")
	if !errors.Is(err, ErrWrongServer) {
		t.Fatalf("istemci hatası ErrWrongServer olmalı, gelen: %v", err)
	}
	if res.err == nil {
		t.Fatal("sunucu eşleşmeyi kabul etmemeliydi")
	}
}

func TestNormalize(t *testing.T) {
	got, err := codes.Normalize("abcd-efgh-ijko")
	if err != nil || got != "ABCDEFGH1JK0" {
		t.Fatalf("Normalize: %q %v", got, err)
	}
	if _, err := codes.Normalize("ABCD-EFGH-JKU0"); err == nil {
		t.Fatal("U harfi reddedilmeliydi")
	}
	if _, err := codes.Normalize("ABC"); err == nil {
		t.Fatal("kısa kod reddedilmeliydi")
	}
}
