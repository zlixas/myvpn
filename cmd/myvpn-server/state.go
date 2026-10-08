package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"time"

	"myvpn/internal/sysutil"
	"myvpn/internal/wgkey"
)

const (
	stateDir  = "/etc/myvpn"
	statePath = stateDir + "/server.json"
)

type Peer struct {
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	Address   string    `json:"address"`
	Added     time.Time `json:"added"`
}

// State, sunucunun kalıcı durumu. WireGuard yapılandırması her seferinde bundan üretilir.
type State struct {
	WGPrivateKey   string `json:"wg_private_key"`
	PairPrivateKey string `json:"pair_private_key"`
	ListenPort     int    `json:"listen_port"`
	PairPort       int    `json:"pair_port"`
	Subnet         string `json:"subnet"`
	DNS            string `json:"dns"`
	MTU            int    `json:"mtu"`
	OutIface       string `json:"out_iface"`
	Peers          []Peer `json:"peers"`
}

func loadState() (*State, error) {
	b, err := os.ReadFile(statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("sunucu henüz kurulmamış, önce: sudo myvpn-server init")
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *State) save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return sysutil.WriteFileAtomic(statePath, append(b, '\n'), 0o600)
}

func (s *State) prefix() netip.Prefix {
	p, _ := netip.ParsePrefix(s.Subnet)
	return p.Masked()
}

// serverAddr, alt ağın ilk adresi (örn. 10.66.0.1).
func (s *State) serverAddr() netip.Addr {
	return s.prefix().Addr().Next()
}

// nextFreeAddr, yeni cihaza verilecek ilk boş adresi bulur (yayın adresi hariç).
func (s *State) nextFreeAddr() (netip.Addr, error) {
	used := map[string]bool{}
	for _, p := range s.Peers {
		used[p.Address] = true
	}
	p := s.prefix()
	for a := s.serverAddr().Next(); p.Contains(a.Next()); a = a.Next() {
		if !used[a.String()] {
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("alt ağda boş adres kalmadı")
}

func (s *State) pairKey() (*ecdh.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s.PairPrivateKey)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

func (s *State) wgPublicKey() (string, error) {
	return wgkey.Public(s.WGPrivateKey)
}
