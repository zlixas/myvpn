// Package sysutil, sunucu ve istemcinin ortak sistem yardımcılarını içerir.
package sysutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Run, komutu çalıştırır; başarısız olursa komutun çıktısını hataya ekler.
func Run(name string, args ...string) error {
	_, err := Output(name, args...)
	return err
}

// Output, komutu çalıştırıp standart çıktısını döndürür.
func Output(name string, args ...string) (string, error) {
	var stderr strings.Builder
	cmd := exec.Command(name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(string(out))
		}
		if msg == "" {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		return "", fmt.Errorf("%s: %w: %s", name, err, msg)
	}
	return string(out), nil
}

// WriteFileAtomic, dosyayı yarım kalmayacak şekilde (geçici dosya + rename) yazar.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RequireRoot, root değilsek anlaşılır bir hata döndürür.
func RequireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("bu komut root yetkisi istiyor, başına sudo ekle")
	}
	return nil
}

// RequireTools, gerekli komutların kurulu olduğunu kontrol eder.
func RequireTools(hint string, tools ...string) error {
	var missing []string
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("eksik araç: %s (kurmak için: %s)", strings.Join(missing, ", "), hint)
	}
	return nil
}
