package server

import (
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/EdamAme-x/unline/internal/auth"
	"github.com/EdamAme-x/unline/internal/config"
	"github.com/EdamAme-x/unline/internal/security"
)

const (
	r4BaseURL       = "https://ci.line-apps.com/R4"
	chromeGWBaseURL = "https://line-chrome-gw.line-apps.com"
)

type Handler struct {
	cfg        config.ServerConfig
	httpClient *http.Client
}

type proxyOptions struct {
	chromeGW bool
}

func New(cfg config.ServerConfig) (http.Handler, error) {
	if _, err := os.Stat(cfg.AssetsDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	h := &Handler{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.ProxyTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.healthz)
	mux.HandleFunc("/_proxy/R4", h.proxyR4)
	mux.HandleFunc("/_proxy/CHROME_GW/", h.proxyChromeGW)
	mux.HandleFunc("/", h.static)
	return h.wrap(mux), nil
}

func (h *Handler) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if !h.cfg.HostAllowed(r.Host) {
			http.Error(w, "host not allowed", http.StatusMisdirectedRequest)
			log.Printf("blocked host=%q path=%q", r.Host, r.URL.Path)
			return
		}
		if h.cfg.BasicAuthEnabled() && r.URL.Path != "/healthz" && !h.basicAuthOK(w, r) {
			log.Printf("blocked auth path=%q", r.URL.Path)
			return
		}
		security.ApplyHeaders(w.Header())
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

func (h *Handler) basicAuthOK(w http.ResponseWriter, r *http.Request) bool {
	_, password, ok := r.BasicAuth()
	if !ok || !auth.VerifySecret(h.cfg.BasicAuthPasswordHash, []byte(password)) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q, charset="UTF-8"`, h.cfg.BasicAuthRealm))
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	return true
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (h *Handler) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	assetPath := cleanAssetPath(r.URL.Path)
	fullPath := filepath.Join(h.cfg.AssetsDir, filepath.FromSlash(assetPath))
	info, err := os.Stat(fullPath)
	if err != nil || info.IsDir() {
		if r.URL.Path == "/" || shouldFallbackToIndex(r.URL.Path) {
			h.serveFile(w, r, filepath.Join(h.cfg.AssetsDir, "index.html"))
			return
		}
		http.NotFound(w, r)
		return
	}
	h.serveFile(w, r, fullPath)
}

func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, fullPath string) {
	if _, err := os.Stat(fullPath); err != nil {
		h.missingAssets(w)
		return
	}
	if ctype := mime.TypeByExtension(filepath.Ext(fullPath)); ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	http.ServeFile(w, r, fullPath)
}

func (h *Handler) missingAssets(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>unline not generated</title></head><body><main><h1>unline assets are not generated</h1><p>Run <code>unline generate --out ./www</code> before serving this host.</p><p>Powered by <a href="https://github.com/EdamAme-x/unline" rel="noreferrer">unline</a></p></main></body></html>`)
}

func (h *Handler) proxyR4(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r4BaseURL)
	u.RawQuery = r.URL.RawQuery
	h.proxy(w, r, u.String(), proxyOptions{})
}

func (h *Handler) proxyChromeGW(w http.ResponseWriter, r *http.Request) {
	suffix := strings.TrimPrefix(r.URL.Path, "/_proxy/CHROME_GW")
	if suffix == "" {
		suffix = "/"
	}
	if strings.Contains(suffix, "\\") || strings.Contains(path.Clean("/"+suffix), "..") {
		http.Error(w, "bad upstream path", http.StatusBadRequest)
		return
	}
	u, _ := url.Parse(chromeGWBaseURL)
	u.Path = suffix
	u.RawQuery = r.URL.RawQuery
	h.proxy(w, r, u.String(), proxyOptions{chromeGW: true})
}

func (h *Handler) proxy(w http.ResponseWriter, r *http.Request, target string, opts proxyOptions) {
	if !methodAllowed(r.Method) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	origin := r.Header.Get("Origin")
	if !h.cfg.OriginAllowed(origin) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", allowedCORSHeaders(r.Header.Get("Access-Control-Request-Headers")))
		w.WriteHeader(http.StatusNoContent)
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes)
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if err != nil {
		http.Error(w, "bad upstream request", http.StatusInternalServerError)
		return
	}
	copyProxyHeaders(upstreamReq.Header, r, h.cfg, opts)
	upstreamReq.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36 unline/"+serverVersion())

	resp, err := h.httpClient.Do(upstreamReq)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)
	if opts.chromeGW {
		copyChromeGWSetCookies(w.Header(), resp.Cookies(), isSecureRequest(r))
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func cleanAssetPath(raw string) string {
	value := path.Clean("/" + strings.TrimPrefix(raw, "/"))
	value = strings.TrimPrefix(value, "/")
	if value == "." || value == "" {
		return "index.html"
	}
	return value
}

func shouldFallbackToIndex(raw string) bool {
	base := path.Base(raw)
	return !strings.Contains(base, ".")
}

func methodAllowed(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

func copyProxyHeaders(dst http.Header, src *http.Request, cfg config.ServerConfig, opts proxyOptions) {
	for key, values := range src.Header {
		if opts.chromeGW && strings.EqualFold(key, "cookie") {
			continue
		}
		if proxyRequestHeaderBlocked(key, cfg) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	if opts.chromeGW {
		copyChromeGWCookies(dst, src.Cookies())
	}
}

func proxyRequestHeaderBlocked(key string, cfg config.ServerConfig) bool {
	k := strings.ToLower(key)
	if strings.HasPrefix(k, "proxy-") || strings.HasPrefix(k, "x-forwarded-") || strings.HasPrefix(k, "cf-") || strings.HasPrefix(k, "sec-fetch-") || strings.HasPrefix(k, "sec-ch-") {
		return true
	}
	switch k {
	case "host", "connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "referer", "origin", "forwarded", "x-real-ip", "user-agent", "accept-encoding":
		return true
	case "cookie":
		return !cfg.ForwardCookies
	case "authorization":
		return cfg.BasicAuthEnabled() || !cfg.ForwardAuthorization
	default:
		return false
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		if proxyResponseHeaderBlocked(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func proxyResponseHeaderBlocked(key string) bool {
	k := strings.ToLower(key)
	if strings.HasPrefix(k, "access-control-") {
		return true
	}
	switch k {
	case "set-cookie", "server", "report-to", "nel", "content-security-policy", "content-security-policy-report-only":
		return true
	default:
		return false
	}
}

func copyChromeGWCookies(dst http.Header, cookies []*http.Cookie) {
	var parts []string
	for _, cookie := range cookies {
		if chromeGWCookieAllowed(cookie.Name) {
			parts = append(parts, cookie.Name+"="+cookie.Value)
		}
	}
	if len(parts) > 0 {
		dst.Set("Cookie", strings.Join(parts, "; "))
	}
}

func copyChromeGWSetCookies(dst http.Header, cookies []*http.Cookie, secure bool) {
	for _, cookie := range cookies {
		if !chromeGWCookieAllowed(cookie.Name) {
			continue
		}
		copied := *cookie
		copied.Domain = ""
		copied.Path = "/_proxy/CHROME_GW"
		copied.Secure = secure
		copied.HttpOnly = true
		copied.SameSite = http.SameSiteLaxMode
		dst.Add("Set-Cookie", copied.String())
	}
}

func chromeGWCookieAllowed(name string) bool {
	return name == "lct"
}

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func allowedCORSHeaders(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "Content-Type, X-Line-Access, X-Line-Application, X-Line-ChannelId"
	}
	var allowed []string
	for _, item := range strings.Split(raw, ",") {
		header := textHeader(strings.TrimSpace(item))
		if header == "" || proxyRequestHeaderBlocked(header, config.ServerConfig{}) {
			continue
		}
		allowed = append(allowed, header)
	}
	if len(allowed) == 0 {
		return "Content-Type"
	}
	return strings.Join(allowed, ", ")
}

func textHeader(value string) string {
	if value == "" {
		return ""
	}
	for _, r := range value {
		if r <= 31 || r >= 127 || r == ':' {
			return ""
		}
	}
	return http.CanonicalHeaderKey(value)
}

func serverVersion() string {
	return strings.TrimPrefix(fmt.Sprintf("%s", "0.1.0"), "v")
}
