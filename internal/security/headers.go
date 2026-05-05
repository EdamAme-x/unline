package security

import "net/http"

const ContentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; form-action 'none'; frame-ancestors 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; img-src 'self' data: blob:; media-src 'self' data: blob:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-src 'self'"

func ApplyHeaders(h http.Header) {
	h.Set("Content-Security-Policy", ContentSecurityPolicy)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), browsing-topics=()")
	h.Set("Cache-Control", "no-store")
}
