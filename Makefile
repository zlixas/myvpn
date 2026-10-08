ARCHES  := amd64 arm64
LDFLAGS := -s -w

.PHONY: all test dist clean

all: dist

test:
	go vet ./...
	go test ./...

# dist/myvpn-linux-<arch>.tar.gz: iki program + kurulum betikleri.
dist: test
	@for a in $(ARCHES); do \
		d=dist/myvpn-linux-$$a; mkdir -p $$d; \
		GOOS=linux GOARCH=$$a CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $$d/myvpn ./cmd/myvpn || exit 1; \
		GOOS=linux GOARCH=$$a CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $$d/myvpn-server ./cmd/myvpn-server || exit 1; \
		cp install.sh packaging/myvpn.desktop $$d/; \
		tar -C dist -czf $$d.tar.gz myvpn-linux-$$a; \
		echo "  $$d.tar.gz"; \
	done; \
	cd dist && (command -v sha256sum >/dev/null && sha256sum *.tar.gz || shasum -a 256 *.tar.gz) > SHA256SUMS

clean:
	rm -rf dist
