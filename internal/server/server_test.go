package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EdamAme-x/unline/internal/config"
)

func TestStaticHeadersAndHostGuard(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultServerConfig()
	cfg.AssetsDir = dir
	if err := cfg.Finalize(); err != nil {
		t.Fatal(err)
	}
	handler, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "connect-src 'self'") {
		t.Fatalf("missing strict CSP: %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "http://evil.example/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("expected host guard, got status=%d", rec.Code)
	}
}

func TestProxyPreflightRejectsExternalOrigin(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultServerConfig()
	cfg.AssetsDir = dir
	if err := cfg.Finalize(); err != nil {
		t.Fatal(err)
	}
	handler, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodOptions, "http://127.0.0.1:8080/_proxy/R4", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden origin, got status=%d", rec.Code)
	}
}
