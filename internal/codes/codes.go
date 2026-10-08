// Package codes, kullanıcıya gösterilen 12 karakterlik kodları üretir ve doğrular.
package codes

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
)

// Crockford base32: 0/O ve 1/I/L birbirine karışmaz, U yok.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Length, bir kodun karakter sayısı. 12 × 5 bit = 60 bit.
const Length = 12

var ErrInvalid = errors.New("kod 12 karakter olmalı (rakamlar ve I, L, O, U dışındaki harfler)")

// encode, v'nin alt 60 bitini 12 karaktere çevirir.
func encode(v uint64) string {
	var b [Length]byte
	for i := Length - 1; i >= 0; i-- {
		b[i] = alphabet[v&31]
		v >>= 5
	}
	return string(b[:])
}

// Random, tek kullanımlık eşleşme kodu üretir.
func Random() string {
	var b [8]byte
	rand.Read(b[:])
	return encode(binary.BigEndian.Uint64(b[:]))
}

// Fingerprint, sunucunun eşleştirme açık anahtarından sunucu kodunu türetir.
func Fingerprint(pub []byte) string {
	h := sha256.New()
	h.Write([]byte("myvpn-server-id-v1"))
	h.Write(pub)
	return encode(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
}

// Normalize, kullanıcının girdiği kodu temizler: tire/boşluk atılır,
// küçük harf büyütülür, O→0 ve I/L→1 düzeltilir.
func Normalize(s string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(alphabet, r) {
			return "", ErrInvalid
		}
		b.WriteRune(r)
	}
	if b.Len() != Length {
		return "", ErrInvalid
	}
	return b.String(), nil
}

// Format, kodu okunması kolay XXXX-XXXX-XXXX biçimine getirir.
func Format(c string) string {
	if len(c) != Length {
		return c
	}
	return c[:4] + "-" + c[4:8] + "-" + c[8:]
}
