package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EdamAme-x/unline/internal/auth"
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
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "connect-src 'self' https://profile.line-scdn.net https://shop.line-scdn.net https://stickershop.line-scdn.net") || !strings.Contains(got, "img-src 'self' data: blob: https://profile.line-scdn.net https://shop.line-scdn.net https://stickershop.line-scdn.net") || !strings.Contains(got, "media-src 'self' data: blob: https://stickershop.line-scdn.net") || !strings.Contains(got, "frame-ancestors 'self'") {
		t.Fatalf("missing strict CSP: %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("unexpected X-Frame-Options: %q", got)
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

func TestProxySuffixAllowedRejectsTraversal(t *testing.T) {
	if !proxySuffixAllowed("/stickershop/v1/sticker/1/android/sticker.png") {
		t.Fatal("expected normal sticker path to be allowed")
	}
	for _, suffix := range []string{"/../api", "/stickershop/../api", `/stickershop\api`} {
		if proxySuffixAllowed(suffix) {
			t.Fatalf("expected suffix to be rejected: %q", suffix)
		}
	}
}

func TestChromeGWCookieRewrite(t *testing.T) {
	src := []*http.Cookie{
		{Name: "lct", Value: "token", Domain: ".line-apps.com", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode},
		{Name: "other", Value: "drop"},
	}
	header := http.Header{}
	copyChromeGWSetCookies(header, src, false)
	got := header.Values("Set-Cookie")
	if len(got) != 1 {
		t.Fatalf("expected one Set-Cookie, got %d: %#v", len(got), got)
	}
	if !strings.Contains(got[0], "lct=token") || !strings.Contains(got[0], "Path=/_proxy/CHROME_GW") || !strings.Contains(got[0], "HttpOnly") || !strings.Contains(got[0], "SameSite=Lax") {
		t.Fatalf("unexpected rewritten cookie: %q", got[0])
	}
	if strings.Contains(got[0], "Domain=") || strings.Contains(got[0], "Secure") || strings.Contains(got[0], "other=") {
		t.Fatalf("cookie kept unsafe attributes: %q", got[0])
	}

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/_proxy/CHROME_GW/api", nil)
	req.AddCookie(&http.Cookie{Name: "lct", Value: "token"})
	req.AddCookie(&http.Cookie{Name: "other", Value: "drop"})
	header = http.Header{}
	copyChromeGWCookies(header, req.Cookies())
	if got := header.Get("Cookie"); got != "lct=token" {
		t.Fatalf("unexpected forwarded Cookie: %q", got)
	}
}

func TestBasicAuthIgnoresUsername(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashSecret([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultServerConfig()
	cfg.AssetsDir = dir
	cfg.BasicAuthPasswordHash = hash
	cfg.BasicAuthUsername = "unline"
	if err := cfg.Finalize(); err != nil {
		t.Fatal(err)
	}
	handler, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	req.SetBasicAuth("anything", "secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	req.SetBasicAuth("anything", "wrong")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized for wrong password, got status=%d", rec.Code)
	}
}
