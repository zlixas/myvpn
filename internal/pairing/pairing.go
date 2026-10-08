// Package pairing, iki 12 karakterlik kodla istemci ile sunucuyu eşleştiren protokoldür.
//
// Sunucu kodu, sunucunun sabit eşleştirme anahtarının parmak izidir; istemci bununla
// doğru sunucuya bağlandığını doğrular (araya giren biri bu anahtarı taklit edemez).
// Eşleşme kodu ağa hiç gönderilmez; anahtar türetmeye karıştırılır, yanlışsa sunucu
// istemcinin mesajını çözemez ve bağlantıyı kapatır.
//
// Akış (her mesaj 2 bayt uzunluk + içerik):
//
//	İ → S : magic || e_i                       (istemcinin geçici X25519 anahtarı)
//	S → İ : s_s || e_s                         (sunucunun sabit ve geçici anahtarı)
//	        th  = SHA256(magic || e_i || s_s || e_s)
//	        k   = HKDF(DH(e_i,s_s) || DH(e_i,e_s) || eşleşme kodu, salt=th)
//	İ → S : AES-GCM(k_i→s, ClientHello)        (istemcinin WireGuard açık anahtarı)
//	S → İ : AES-GCM(k_s→i, Config)             (sunucunun WireGuard bilgileri, atanan IP)
package pairing

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"myvpn/internal/codes"
	"myvpn/internal/wgkey"
)

const (
	magic    = "MYVPN/1\x00"
	maxFrame = 4096
)

var (
	ErrWrongServer = errors.New("sunucu kodu tutmuyor: yanlış sunucuya bağlanıyor olabilirsin")
	ErrRejected    = errors.New("sunucu eşleşmeyi reddetti: eşleşme kodu yanlış ya da süresi dolmuş")
	ErrBadCode     = errors.New("eşleşme kodu hatalı")
	ErrProtocol    = errors.New("geçersiz eşleştirme mesajı")
)

// ClientHello, istemcinin sunucuya gönderdiği bilgiler.
type ClientHello struct {
	Name        string `json:"name"`
	WGPublicKey string `json:"wg_public_key"`
}

// Config, sunucunun istemciye verdiği WireGuard ayarları.
type Config struct {
	WGPublicKey string `json:"wg_public_key"`
	ListenPort  int    `json:"listen_port"`
	Address     string `json:"address"` // istemcinin tünel adresi, örn. 10.66.0.2/24
	DNS         string `json:"dns,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
}

// Her yönde tek mesaj gidip anahtarlar her oturumda yeni olduğu için sabit nonce güvenli.
var nonce = make([]byte, 12)

type session struct {
	c2s, s2c cipher.AEAD
	th       []byte
}

func newSession(dh1, dh2 []byte, pairCode string, th []byte) (*session, error) {
	secret := bytes.Join([][]byte{dh1, dh2, []byte(pairCode)}, nil)
	okm, err := hkdf.Key(sha256.New, secret, th, "myvpn pairing v1", 64)
	if err != nil {
		return nil, err
	}
	c2s, err := newGCM(okm[:32])
	if err != nil {
		return nil, err
	}
	s2c, err := newGCM(okm[32:])
	if err != nil {
		return nil, err
	}
	return &session{c2s: c2s, s2c: s2c, th: th}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func transcript(parts ...[]byte) []byte {
	h := sha256.New()
	h.Write([]byte(magic))
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// Client, eşleştirmenin istemci tarafını yürütür. Kodların Normalize edilmiş olması gerekir.
func Client(rw io.ReadWriter, serverCode, pairCode string, hello ClientHello) (*Config, error) {
	curve := ecdh.X25519()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ePub := eph.PublicKey().Bytes()
	if err := writeFrame(rw, append([]byte(magic), ePub...)); err != nil {
		return nil, err
	}

	msg, err := readFrame(rw)
	if err != nil {
		return nil, fmt.Errorf("sunucudan yanıt alınamadı: %w", err)
	}
	if len(msg) != 64 {
		return nil, ErrProtocol
	}
	sStatic, sEph := msg[:32], msg[32:]
	if codes.Fingerprint(sStatic) != serverCode {
		return nil, ErrWrongServer
	}
	sStaticPub, err := curve.NewPublicKey(sStatic)
	if err != nil {
		return nil, ErrProtocol
	}
	sEphPub, err := curve.NewPublicKey(sEph)
	if err != nil {
		return nil, ErrProtocol
	}
	dh1, err := eph.ECDH(sStaticPub)
	if err != nil {
		return nil, ErrProtocol
	}
	dh2, err := eph.ECDH(sEphPub)
	if err != nil {
		return nil, ErrProtocol
	}
	s, err := newSession(dh1, dh2, pairCode, transcript(ePub, sStatic, sEph))
	if err != nil {
		return nil, err
	}

	pt, err := json.Marshal(hello)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(rw, s.c2s.Seal(nil, nonce, pt, s.th)); err != nil {
		return nil, err
	}

	ct, err := readFrame(rw)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, ErrRejected
	}
	if err != nil {
		return nil, fmt.Errorf("sunucudan yanıt alınamadı: %w", err)
	}
	pt, err = s.s2c.Open(nil, nonce, ct, s.th)
	if err != nil {
		return nil, ErrRejected
	}
	var cfg Config
	if err := json.Unmarshal(pt, &cfg); err != nil || !wgkey.Valid(cfg.WGPublicKey) {
		return nil, ErrProtocol
	}
	return &cfg, nil
}

// Server, eşleştirmenin sunucu tarafını yürütür. accept yalnızca istemci doğru
// eşleşme kodunu kanıtladıktan sonra çağrılır ve istemciye gidecek ayarları döndürür.
func Server(rw io.ReadWriter, static *ecdh.PrivateKey, pairCode string, accept func(ClientHello) (*Config, error)) (*ClientHello, error) {
	curve := ecdh.X25519()
	msg, err := readFrame(rw)
	if err != nil {
		return nil, err
	}
	if len(msg) != len(magic)+32 || string(msg[:len(magic)]) != magic {
		return nil, ErrProtocol
	}
	cEph := msg[len(magic):]
	cEphPub, err := curve.NewPublicKey(cEph)
	if err != nil {
		return nil, ErrProtocol
	}

	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sStatic, sEph := static.PublicKey().Bytes(), eph.PublicKey().Bytes()
	if err := writeFrame(rw, bytes.Join([][]byte{sStatic, sEph}, nil)); err != nil {
		return nil, err
	}
	dh1, err := static.ECDH(cEphPub)
	if err != nil {
		return nil, ErrProtocol
	}
	dh2, err := eph.ECDH(cEphPub)
	if err != nil {
		return nil, ErrProtocol
	}
	s, err := newSession(dh1, dh2, pairCode, transcript(cEph, sStatic, sEph))
	if err != nil {
		return nil, err
	}

	ct, err := readFrame(rw)
	if err != nil {
		return nil, err
	}
	pt, err := s.c2s.Open(nil, nonce, ct, s.th)
	if err != nil {
		return nil, ErrBadCode
	}
	var hello ClientHello
	if err := json.Unmarshal(pt, &hello); err != nil || !wgkey.Valid(hello.WGPublicKey) {
		return nil, ErrProtocol
	}

	cfg, err := accept(hello)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(rw, s.s2c.Seal(nil, nonce, out, s.th)); err != nil {
		return nil, err
	}
	return &hello, nil
}

func writeFrame(w io.Writer, b []byte) error {
	if len(b) > maxFrame {
		return ErrProtocol
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n > maxFrame {
		return nil, ErrProtocol
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}
