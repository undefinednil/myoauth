package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/zenpk/my-oauth/util"
)

// A missing key file must be generated on the spot as a PKCS#1 PEM, and a
// second Init must reuse the persisted key rather than minting a new one.
func TestInitGeneratesKeyWhenMissing(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "auto.pem")
	conf := &util.Configuration{OidcIssuer: "https://issuer.example.com", RsaPrivateKeyPath: keyPath}
	logger := newTestLogger(t)

	tk := new(Token)
	if err := tk.Init(conf, logger); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if tk.rsaPrivateKey == nil {
		t.Fatal("rsaPrivateKey = nil, want a generated key")
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read generated key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("generated key is not a PKCS#1 PEM block: %+v", block)
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatalf("generated key does not parse as PKCS#1: %v", err)
	}
	first := tk.rsaPrivateKey

	tk2 := new(Token)
	if err := tk2.Init(conf, logger); err != nil {
		t.Fatalf("second Init: %v", err)
	}
	if tk2.rsaPrivateKey.N.Cmp(first.N) != 0 {
		t.Error("second Init minted a different key, want the persisted key reused")
	}
}

// A missing parent directory must fail clearly instead of being created.
func TestInitMissingKeyDirectoryFails(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "missing", "auto.pem")
	conf := &util.Configuration{OidcIssuer: "https://issuer.example.com", RsaPrivateKeyPath: keyPath}
	logger := newTestLogger(t)

	tk := new(Token)
	if err := tk.Init(conf, logger); err == nil {
		t.Fatal("Init succeeded, want an error for a missing key directory")
	}
}

// Concurrent first-boot Inits against the same absent path must agree on a
// single generated key: exactly one writer wins, every Init loads that same
// key, and none error or overwrite it.
func TestInitConcurrentGenerationSingleKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "concurrent.pem")
	conf := &util.Configuration{OidcIssuer: "https://issuer.example.com", RsaPrivateKeyPath: keyPath}
	logger := newTestLogger(t)

	const workers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	keys := make([]*rsa.PrivateKey, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tk := new(Token)
			<-start
			if err := tk.Init(conf, logger); err != nil {
				errs[i] = err
				return
			}
			keys[i] = tk.rsaPrivateKey
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d Init: %v", i, errs[i])
		}
		if keys[i] == nil {
			t.Fatalf("worker %d loaded no key", i)
		}
		if keys[i].N.Cmp(keys[0].N) != 0 {
			t.Fatalf("worker %d loaded a different key than worker 0", i)
		}
	}

	// Exactly one key exists on disk and it matches what everyone loaded.
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("on-disk key is not a PEM block")
	}
	onDisk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse on-disk key: %v", err)
	}
	if onDisk.N.Cmp(keys[0].N) != 0 {
		t.Fatal("on-disk key differs from the key loaded in memory")
	}
}

// An existing but malformed key must fail without being overwritten.
func TestInitMalformedKeyFailsWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(keyPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write malformed key: %v", err)
	}
	conf := &util.Configuration{OidcIssuer: "https://issuer.example.com", RsaPrivateKeyPath: keyPath}
	logger := newTestLogger(t)

	tk := new(Token)
	if err := tk.Init(conf, logger); err == nil {
		t.Fatal("Init succeeded, want a parse error")
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(data) != "not a pem" {
		t.Error("malformed key was overwritten, want it left untouched")
	}
}
