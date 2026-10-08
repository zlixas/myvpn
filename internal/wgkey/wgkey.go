// Package wgkey, WireGuard (X25519) anahtarlarını üretir ve doğrular.
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

var errInvalid = errors.New("geçersiz WireGuard anahtarı")

// Generate, base64 kodlu yeni bir özel/açık anahtar çifti üretir.
func Generate() (priv, pub string, err error) {
	var k [32]byte
	rand.Read(k[:])
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	sk, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return "", "", err
	}
	enc := base64.StdEncoding.EncodeToString
	return enc(k[:]), enc(sk.PublicKey().Bytes()), nil
}

// Public, özel anahtardan açık anahtarı hesaplar.
func Public(priv string) (string, error) {
	raw, ok := decode(priv)
	if !ok {
		return "", errInvalid
	}
	sk, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes()), nil
}

// Valid, k'nin tam olarak 32 baytlık kanonik base64 anahtar olduğunu doğrular.
// Yapılandırma dosyasına yazılan değerler buradan geçtiği için katıdır.
func Valid(k string) bool {
	_, ok := decode(k)
	return ok
}

func decode(k string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != k {
		return nil, false
	}
	return raw, true
}
