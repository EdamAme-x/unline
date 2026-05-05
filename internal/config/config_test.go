package config

import "testing"

func TestHostAllowedNormalizesPortsAndIPv6(t *testing.T) {
	cfg := DefaultServerConfig()
	if err := cfg.Finalize(); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"localhost:8080", "127.0.0.1:8080", "[::1]:8080", "::1"} {
		if !cfg.HostAllowed(host) {
			t.Fatalf("expected host %q to be allowed", host)
		}
	}
	if cfg.HostAllowed("example.com") {
		t.Fatal("example.com should not be allowed by default")
	}
}

func TestOriginAllowed(t *testing.T) {
	cfg := DefaultServerConfig()
	if err := cfg.Finalize(); err != nil {
		t.Fatal(err)
	}
	if !cfg.OriginAllowed("http://127.0.0.1:8080") {
		t.Fatal("localhost origin should be allowed")
	}
	if cfg.OriginAllowed("https://example.com") {
		t.Fatal("unexpected external origin allowed")
	}
}
