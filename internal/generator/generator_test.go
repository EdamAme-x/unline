package generator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPatchAndVerifyAssets(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "index.html"), `<!doctype html><html><head></head><body><div id="root"></div></body></html>`)
	mustWrite(t, filepath.Join(dir, "manifest.json"), `{"host_permissions":["*://*/*"],"key":"secret","update_url":"https://clients2.google.com/service/update2/crx","name":"LINE"}`)
	mustWrite(t, filepath.Join(dir, "static/js/main.js"), `const r="https://ci.line-apps.com/R4";const h="line-chrome-gw.line-apps.com";S({dsn:"https://abc@sentry-uit.line-apps.com/12",sampleRate:.5,tracesSampleRate:.2});`)
	mustWrite(t, filepath.Join(dir, "static/js/ltsmSandbox.js"), `const a=window.location.origin;const b=window.origin;const c= location.origin;const r="https://ci.line-apps.com/R4";const h="line-chrome-gw.line-apps.com";`)

	if report, err := PatchAssets(dir); err != nil {
		t.Fatalf("PatchAssets failed: %v\n%v", err, report.Lines)
	}
	if report, err := VerifyAssets(dir); err != nil {
		t.Fatalf("VerifyAssets failed: %v\n%v", err, report.Lines)
	}

	index, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(index), "Powered by", "https://github.com/EdamAme-x/unline") {
		t.Fatalf("powered link not injected: %s", index)
	}
}

func mustWrite(t *testing.T, filename, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func containsAll(content string, needles ...string) bool {
	for _, needle := range needles {
		if !stringsContains(content, needle) {
			return false
		}
	}
	return true
}

func stringsContains(content, needle string) bool {
	return len(needle) == 0 || len(content) >= len(needle) && (content == needle || stringsIndex(content, needle) >= 0)
}

func stringsIndex(content, needle string) int {
	for i := 0; i+len(needle) <= len(content); i++ {
		if content[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
