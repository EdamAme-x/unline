package generator

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const officialExtensionID = "ophjlpahpchlmihnnnihgmmeilfjmjjc"

type Options struct {
	OutDir      string
	CacheDir    string
	ExtensionID string
	ProdVersion string
	FromCRX     string
	Clean       bool
}

type Report struct {
	Lines []string
}

func DefaultOptions() Options {
	return Options{
		OutDir:      "./www",
		CacheDir:    "./.cache/unline",
		ExtensionID: officialExtensionID,
		ProdVersion: "120.0.6099.109",
		Clean:       true,
	}
}

func Generate(ctx context.Context, opts Options) (Report, error) {
	var report Report
	if opts.ExtensionID == "" {
		opts.ExtensionID = officialExtensionID
	}
	data, source, err := loadPackage(ctx, opts)
	if err != nil {
		return report, err
	}
	sum := sha256.Sum256(data)
	report.Lines = append(report.Lines, "source="+source)
	report.Lines = append(report.Lines, "sha256="+hex.EncodeToString(sum[:]))

	zipData, err := crxZipData(data)
	if err != nil {
		return report, err
	}
	if opts.Clean {
		if err := os.RemoveAll(opts.OutDir); err != nil {
			return report, err
		}
	}
	if err := unzip(zipData, opts.OutDir); err != nil {
		return report, err
	}
	patchReport, err := PatchAssets(opts.OutDir)
	report.Lines = append(report.Lines, patchReport.Lines...)
	if err != nil {
		return report, err
	}
	verifyReport, err := VerifyAssets(opts.OutDir)
	report.Lines = append(report.Lines, verifyReport.Lines...)
	if err != nil {
		return report, err
	}
	report.Lines = append(report.Lines, "generated="+opts.OutDir)
	return report, nil
}

func loadPackage(ctx context.Context, opts Options) ([]byte, string, error) {
	if opts.FromCRX != "" {
		data, err := os.ReadFile(opts.FromCRX)
		return data, opts.FromCRX, err
	}
	if err := os.MkdirAll(opts.CacheDir, 0o755); err != nil {
		return nil, "", err
	}
	u := fmt.Sprintf("https://clients2.google.com/service/update2/crx?response=redirect&prodversion=%s&acceptformat=crx3&x=id%%3D%s%%26installsource%%3Dondemand%%26uc", opts.ProdVersion, opts.ExtensionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 unline-generator")
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "", fmt.Errorf("download failed: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, "", err
	}
	cachePath := filepath.Join(opts.CacheDir, opts.ExtensionID+".crx")
	if err := os.WriteFile(cachePath, data, 0o644); err != nil {
		return nil, "", err
	}
	return data, cachePath, nil
}

func crxZipData(data []byte) ([]byte, error) {
	if len(data) >= 4 && string(data[:4]) != "Cr24" {
		return data, nil
	}
	if len(data) < 12 {
		return nil, errors.New("CRX data too short")
	}
	if string(data[:4]) != "Cr24" {
		return nil, errors.New("invalid CRX magic")
	}
	headerSize := int(binary.LittleEndian.Uint32(data[8:12]))
	offset := 12 + headerSize
	if offset < 12 || offset >= len(data) {
		return nil, errors.New("invalid CRX header size")
	}
	return data[offset:], nil
}

func unzip(data []byte, outDir string) error {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, file := range reader.File {
		cleanName, err := cleanZipName(file.Name)
		if err != nil {
			return err
		}
		target := filepath.Join(outDir, filepath.FromSlash(cleanName))
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		err = writeExtractedFile(target, rc, file.Mode())
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func cleanZipName(name string) (string, error) {
	if strings.Contains(name, "\\") {
		return "", fmt.Errorf("unsafe zip path %q", name)
	}
	clean := path.Clean("/" + name)
	clean = strings.TrimPrefix(clean, "/")
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe zip path %q", name)
	}
	return clean, nil
}

func writeExtractedFile(target string, src io.Reader, mode os.FileMode) error {
	perm := mode.Perm()
	if perm == 0 {
		perm = 0o644
	}
	tmp := target + ".tmp"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dst, io.LimitReader(src, 128<<20))
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, target)
}

type patchOp struct {
	File        string
	Pattern     *regexp.Regexp
	Replacement string
	Required    bool
	Name        string
}

func PatchAssets(dir string) (Report, error) {
	var report Report
	ops := []patchOp{
		{File: "static/js/ltsmSandbox.js", Pattern: regexp.MustCompile(`window\.location\.origin`), Replacement: `"chrome-extension://` + officialExtensionID + `"`, Required: true, Name: "origin window.location"},
		{File: "static/js/ltsmSandbox.js", Pattern: regexp.MustCompile(`window\.origin`), Replacement: `"chrome-extension://` + officialExtensionID + `"`, Required: true, Name: "origin window"},
		{File: "static/js/ltsmSandbox.js", Pattern: regexp.MustCompile(`(?m)([^.\w])location\.origin`), Replacement: `${1}"chrome-extension://` + officialExtensionID + `"`, Required: true, Name: "origin location"},
		{File: "static/js/main.js", Pattern: regexp.MustCompile(`"https://ci\.line-apps\.com/R4"`), Replacement: "`${location.origin}/_proxy/R4`", Required: true, Name: "main R4 proxy"},
		{File: "static/js/ltsmSandbox.js", Pattern: regexp.MustCompile(`"https://ci\.line-apps\.com/R4"`), Replacement: "`${location.origin}/_proxy/R4`", Required: true, Name: "ltsm R4 proxy"},
		{File: "static/js/main.js", Pattern: regexp.MustCompile(`"line-chrome-gw\.line-apps\.com"`), Replacement: "`${location.host}/_proxy/CHROME_GW`", Required: true, Name: "main chrome gateway proxy"},
		{File: "static/js/ltsmSandbox.js", Pattern: regexp.MustCompile(`"line-chrome-gw\.line-apps\.com"`), Replacement: "`${location.host}/_proxy/CHROME_GW`", Required: true, Name: "ltsm chrome gateway proxy"},
		{File: "static/js/main.js", Pattern: regexp.MustCompile("host:`\\$\\{location\\.host\\}/_proxy/CHROME_GW`,protocol:\"http\",port:443"), Replacement: "host:`${location.host}/_proxy/CHROME_GW`,protocol:\"http\",port:80", Required: true, Name: "main chrome gateway http port"},
		{File: "static/js/ltsmSandbox.js", Pattern: regexp.MustCompile("host:`\\$\\{location\\.host\\}/_proxy/CHROME_GW`,protocol:\"http\",port:443"), Replacement: "host:`${location.host}/_proxy/CHROME_GW`,protocol:\"http\",port:80", Required: true, Name: "ltsm chrome gateway http port"},
		{File: "static/js/main.js", Pattern: regexp.MustCompile(`"stickershop\.line-scdn\.net"`), Replacement: "`${location.host}/_proxy/CDN_STICKER`", Required: true, Name: "main sticker cdn proxy"},
		{File: "static/js/ltsmSandbox.js", Pattern: regexp.MustCompile(`"stickershop\.line-scdn\.net"`), Replacement: "`${location.host}/_proxy/CDN_STICKER`", Required: true, Name: "ltsm sticker cdn proxy"},
		{File: "static/js/main.js", Pattern: regexp.MustCompile("host:`\\$\\{location\\.host\\}/_proxy/CDN_STICKER`,protocol:\"http\",port:443"), Replacement: "host:`${location.host}/_proxy/CDN_STICKER`,protocol:\"http\",port:80", Required: true, Name: "main sticker cdn http port"},
		{File: "static/js/ltsmSandbox.js", Pattern: regexp.MustCompile("host:`\\$\\{location\\.host\\}/_proxy/CDN_STICKER`,protocol:\"http\",port:443"), Replacement: "host:`${location.host}/_proxy/CDN_STICKER`,protocol:\"http\",port:80", Required: true, Name: "ltsm sticker cdn http port"},
		{File: "static/js/main.js", Pattern: regexp.MustCompile(`dsn:"https://[^"]*@sentry-uit\.line-apps\.com/\d+"`), Replacement: "dsn:void 0", Required: false, Name: "disable sentry dsn"},
		{File: "static/js/main.js", Pattern: regexp.MustCompile(`sampleRate:\.?5`), Replacement: "sampleRate:0", Required: false, Name: "disable sentry sample"},
		{File: "static/js/main.js", Pattern: regexp.MustCompile(`tracesSampleRate:\.?2`), Replacement: "tracesSampleRate:0", Required: false, Name: "disable sentry traces"},
		{File: "static/js/main.js", Pattern: regexp.MustCompile(`sentry-uit\.line-apps\.com`), Replacement: "127.0.0.1.invalid", Required: false, Name: "neutralize sentry host"},
	}

	for _, op := range ops {
		count, err := applyPatchOp(filepath.Join(dir, op.File), op)
		if err != nil {
			return report, err
		}
		if op.Required && count == 0 {
			return report, fmt.Errorf("required patch did not match: %s", op.Name)
		}
		report.Lines = append(report.Lines, fmt.Sprintf("patch %s count=%d", op.Name, count))
	}
	residualCount, err := patchResidualJS(dir)
	if err != nil {
		return report, err
	}
	report.Lines = append(report.Lines, fmt.Sprintf("patch residual js endpoint/telemetry count=%d", residualCount))
	if err := patchIndex(dir); err != nil {
		return report, err
	}
	report.Lines = append(report.Lines, "patch powered-by count=1")
	if err := patchOGPImagePatcher(dir); err != nil {
		return report, err
	}
	report.Lines = append(report.Lines, "patch ogp image proxy=1")
	if err := patchCallMessagePatcher(dir); err != nil {
		return report, err
	}
	report.Lines = append(report.Lines, "patch call message svg=1")
	if err := patchCacheWorker(dir); err != nil {
		return report, err
	}
	report.Lines = append(report.Lines, "patch service worker disabled=1")
	if err := patchManifest(dir); err != nil {
		return report, err
	}
	report.Lines = append(report.Lines, "patch manifest hardened=1")
	return report, nil
}

func applyPatchOp(filename string, op patchOp) (int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	matches := op.Pattern.FindAllIndex(data, -1)
	if len(matches) == 0 {
		return 0, nil
	}
	patched := op.Pattern.ReplaceAll(data, []byte(op.Replacement))
	return len(matches), os.WriteFile(filename, patched, 0o644)
}

func patchResidualJS(dir string) (int, error) {
	replacements := []struct {
		pattern     *regexp.Regexp
		replacement string
	}{
		{regexp.MustCompile(`"https://ci\.line-apps\.com/R4"`), "`${location.origin}/_proxy/R4`"},
		{regexp.MustCompile(`"line-chrome-gw\.line-apps\.com"`), "`${location.host}/_proxy/CHROME_GW`"},
		{regexp.MustCompile("host:`\\$\\{location\\.host\\}/_proxy/CHROME_GW`,protocol:\"http\",port:443"), "host:`${location.host}/_proxy/CHROME_GW`,protocol:\"http\",port:80"},
		{regexp.MustCompile(`"stickershop\.line-scdn\.net"`), "`${location.host}/_proxy/CDN_STICKER`"},
		{regexp.MustCompile("host:`\\$\\{location\\.host\\}/_proxy/CDN_STICKER`,protocol:\"http\",port:443"), "host:`${location.host}/_proxy/CDN_STICKER`,protocol:\"http\",port:80"},
		{regexp.MustCompile(`navigator\.serviceWorker\.register\("/cache\.js"\)\.catch\(\(function\(\)\{\}\)\)`), `navigator.serviceWorker.getRegistrations().then((e=>e.forEach((e=>e.unregister())))).catch((function(){}))`},
		{regexp.MustCompile(`dsn:"https://[^"]*@sentry-uit\.line-apps\.com/\d+"`), "dsn:void 0"},
		{regexp.MustCompile(`sentry-uit\.line-apps\.com`), "127.0.0.1.invalid"},
	}
	total := 0
	root := filepath.Join(dir, "static/js")
	err := filepath.WalkDir(root, func(filename string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(filename) != ".js" {
			return nil
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		patched := data
		changed := false
		for _, replacement := range replacements {
			matches := replacement.pattern.FindAllIndex(patched, -1)
			if len(matches) == 0 {
				continue
			}
			total += len(matches)
			patched = replacement.pattern.ReplaceAll(patched, []byte(replacement.replacement))
			changed = true
		}
		if changed {
			return os.WriteFile(filename, patched, 0o644)
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return total, nil
	}
	return total, err
}

func patchIndex(dir string) error {
	filename := filepath.Join(dir, "index.html")
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	content := string(data)
	if !strings.Contains(content, "unline-cleanup.js") {
		content = strings.Replace(content, "<head>", `<head><script defer="defer" src="/unline-cleanup.js"></script>`, 1)
	}
	if !strings.Contains(content, "unline-call-message-patch.js") {
		content = strings.Replace(content, "<head>", `<head><script defer="defer" src="/unline-call-message-patch.js"></script>`, 1)
	}
	if !strings.Contains(content, "unline-ogp-image-patch.js") {
		content = strings.Replace(content, "<head>", `<head><script defer="defer" src="/unline-ogp-image-patch.js"></script>`, 1)
	}
	if !strings.Contains(content, "unline-powered.css") {
		content = strings.Replace(content, "</head>", `<link rel="stylesheet" href="/unline-powered.css"></head>`, 1)
	}
	if !strings.Contains(content, "https://github.com/EdamAme-x/unline") {
		badge := `<div class="unline-powered" aria-label="Powered by unline">Powered by <a href="https://github.com/EdamAme-x/unline" rel="noreferrer" target="_blank">unline</a></div>`
		content = strings.Replace(content, "</body>", badge+"</body>", 1)
	}
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		return err
	}
	css := `.unline-powered{display:none;position:fixed;right:12px;bottom:10px;z-index:2147483647;padding:4px 7px;border-radius:6px;background:rgba(255,255,255,.88);color:#111;font:12px/1.3 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;box-shadow:0 1px 5px rgba(0,0,0,.18);pointer-events:auto}body:has([class*=loginPage-module__page_login]) .unline-powered{display:block}.unline-powered a{color:#06c755;text-decoration:none;font-weight:600}.unline-powered a:focus,.unline-powered a:hover{text-decoration:underline}`
	if err := os.WriteFile(filepath.Join(dir, "unline-powered.css"), []byte(css), 0o644); err != nil {
		return err
	}
	cleanup := `(function(){if("serviceWorker"in navigator){navigator.serviceWorker.getRegistrations().then(function(registrations){registrations.forEach(function(registration){registration.unregister();});}).catch(function(){});}if("caches"in window){caches.keys().then(function(keys){return Promise.all(keys.map(function(key){return caches.delete(key);}));}).catch(function(){});}})();`
	return os.WriteFile(filepath.Join(dir, "unline-cleanup.js"), []byte(cleanup), 0o644)
}

func patchOGPImagePatcher(dir string) error {
	script := `(function(){var proxyPath="/_proxy/OGP_IMAGE?url=";var passthroughHosts={"profile.line-scdn.net":1,"shop.line-scdn.net":1,"obs.line-scdn.net":1,"static.line-scdn.net":1,"emojipack.landpress.line.me":1};function proxyURL(raw){if(!raw){return"";}try{var u=new URL(raw,location.href);if(u.origin===location.origin){return"";}if(u.protocol!=="https:"&&u.protocol!=="http:"){return"";}if(passthroughHosts[u.hostname]){return"";}return proxyPath+encodeURIComponent(u.href);}catch(e){return"";}}function patchImage(img){if(!img||img.nodeType!==Node.ELEMENT_NODE||img.tagName!=="IMG"){return;}var raw=img.getAttribute("src");var next=proxyURL(raw);if(!next){return;}img.dataset.unlineOriginalSrc=raw;img.setAttribute("src",next);if(img.hasAttribute("srcset")){img.dataset.unlineOriginalSrcset=img.getAttribute("srcset")||"";img.removeAttribute("srcset");}}function scan(root){if(!root){return;}if(root.nodeType===Node.ELEMENT_NODE&&root.tagName==="IMG"){patchImage(root);return;}if(root.querySelectorAll){root.querySelectorAll("img").forEach(patchImage);}}function start(){scan(document);var observer=new MutationObserver(function(records){for(var i=0;i<records.length;i++){var record=records[i];if(record.type==="attributes"){patchImage(record.target);continue;}for(var j=0;j<record.addedNodes.length;j++){scan(record.addedNodes[j]);}}});observer.observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:["src","srcset"]});}if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",start,{once:true});}else{start();}})();`
	return os.WriteFile(filepath.Join(dir, "unline-ogp-image-patch.js"), []byte(script), 0o644)
}

func patchCallMessagePatcher(dir string) error {
	svgPath, err := callMessageSVGPath(dir)
	if err != nil {
		return err
	}
	script := fmt.Sprintf(`(function(){var target="\u3053\u306e\u6a5f\u80fd\u306f\u304a\u4f7f\u3044\u306eOS\u30d0\u30fc\u30b8\u30e7\u30f3\u306b\u306f\u5bfe\u5fdc\u3057\u3066\u3044\u307e\u305b\u3093";var patchedClass="unline-call-svg-message";var styleId="unline-call-svg-message-style";var svg=%q;function installStyle(){if(document.getElementById(styleId)){return;}var style=document.createElement("style");style.id=styleId;style.textContent="."+patchedClass+"{font-size:0!important;line-height:0!important;display:inline-flex!important;align-items:center!important;justify-content:center!important;min-width:20px!important;min-height:20px!important;vertical-align:middle!important}."+patchedClass+"::before{content:\"\";display:inline-block;width:20px;height:20px;background:url(\""+svg+"\") center/contain no-repeat;vertical-align:middle}";document.head.appendChild(style);}function patchText(node){if(!node||!node.nodeValue||node.nodeValue.indexOf(target)<0){return;}var parent=node.parentElement;if(!parent||parent.classList.contains(patchedClass)){return;}installStyle();parent.classList.add(patchedClass);parent.setAttribute("aria-label","call");}function scan(root){if(!root){return;}if(root.nodeType===Node.TEXT_NODE){patchText(root);return;}if(root.nodeType!==Node.ELEMENT_NODE&&root.nodeType!==Node.DOCUMENT_NODE&&root.nodeType!==Node.DOCUMENT_FRAGMENT_NODE){return;}var walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);var nodes=[];while(walker.nextNode()){nodes.push(walker.currentNode);}for(var i=0;i<nodes.length;i++){patchText(nodes[i]);}}function start(){scan(document.body);var observer=new MutationObserver(function(records){for(var i=0;i<records.length;i++){var record=records[i];if(record.type==="characterData"){patchText(record.target);continue;}for(var j=0;j<record.addedNodes.length;j++){scan(record.addedNodes[j]);}}});observer.observe(document.body,{childList:true,subtree:true,characterData:true});}if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",start,{once:true});}else{start();}})();`, svgPath)
	return os.WriteFile(filepath.Join(dir, "unline-call-message-patch.js"), []byte(script), 0o644)
}

func callMessageSVGPath(dir string) (string, error) {
	manifestPath := filepath.Join(dir, "asset-manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err == nil {
		var manifest struct {
			Files map[string]string `json:"files"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return "", err
		}
		if path, ok := manifest.Files["static/media/icon_video.svg"]; ok && path != "" {
			return path, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	matches, err := filepath.Glob(filepath.Join(dir, "static/media/icon_video*.svg"))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("call message svg not found")
	}
	rel, err := filepath.Rel(dir, matches[0])
	if err != nil {
		return "", err
	}
	return "/" + filepath.ToSlash(rel), nil
}

func patchCacheWorker(dir string) error {
	filename := filepath.Join(dir, "cache.js")
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	worker := `self.addEventListener("install",function(event){self.skipWaiting();});self.addEventListener("activate",function(event){event.waitUntil((async function(){const names=await caches.keys();await Promise.all(names.map(function(name){return caches.delete(name);}));await self.registration.unregister();await self.clients.claim();})());});self.addEventListener("fetch",function(){});`
	return os.WriteFile(filename, []byte(worker), 0o644)
}

func patchManifest(dir string) error {
	filename := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	delete(manifest, "update_url")
	delete(manifest, "key")
	manifest["name"] = "unline"
	manifest["short_name"] = "unline"
	manifest["description"] = "Self-hosted LINE web client assets prepared by unline"
	manifest["host_permissions"] = []string{
		"https://ci.line-apps.com/*",
		"https://line-chrome-gw.line-apps.com/*",
	}
	patched, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	patched = append(patched, '\n')
	return os.WriteFile(filename, patched, 0o644)
}

func VerifyAssets(dir string) (Report, error) {
	var report Report
	checks := []struct {
		name string
		fn   func() error
	}{
		{"required files", func() error {
			for _, file := range []string{"index.html", "unline-call-message-patch.js", "unline-cleanup.js", "unline-ogp-image-patch.js", "unline-powered.css", "static/js/main.js", "static/js/ltsmSandbox.js"} {
				if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
					return err
				}
			}
			return nil
		}},
		{"powered link", func() error {
			if err := fileContains(filepath.Join(dir, "index.html"), "Powered by", "https://github.com/EdamAme-x/unline"); err != nil {
				return err
			}
			return fileContains(filepath.Join(dir, "unline-powered.css"), "display:none", "body:has([class*=loginPage-module__page_login])")
		}},
		{"service worker disabled", func() error {
			if err := fileContains(filepath.Join(dir, "index.html"), "/unline-cleanup.js"); err != nil {
				return err
			}
			if err := fileContains(filepath.Join(dir, "unline-cleanup.js"), "serviceWorker", "unregister", "caches.delete"); err != nil {
				return err
			}
			return walkNoContains(filepath.Join(dir, "static/js"), []string{`serviceWorker.register("/cache.js")`})
		}},
		{"call message patcher", func() error {
			if err := fileContains(filepath.Join(dir, "index.html"), "/unline-call-message-patch.js"); err != nil {
				return err
			}
			return fileContains(filepath.Join(dir, "unline-call-message-patch.js"), "unline-call-svg-message", "icon_video", `\u3053\u306e\u6a5f\u80fd`)
		}},
		{"ogp image patcher", func() error {
			if err := fileContains(filepath.Join(dir, "index.html"), "/unline-ogp-image-patch.js"); err != nil {
				return err
			}
			return fileContains(filepath.Join(dir, "unline-ogp-image-patch.js"), "/_proxy/OGP_IMAGE?url=", "MutationObserver", "unlineOriginalSrc")
		}},
		{"proxy patches", func() error {
			if err := fileContains(filepath.Join(dir, "static/js/main.js"), "/_proxy/R4", "/_proxy/CHROME_GW", "/_proxy/CDN_STICKER", "host:`${location.host}/_proxy/CHROME_GW`,protocol:\"http\",port:80", "host:`${location.host}/_proxy/CDN_STICKER`,protocol:\"http\",port:80"); err != nil {
				return err
			}
			return fileContains(filepath.Join(dir, "static/js/ltsmSandbox.js"), "/_proxy/R4", "/_proxy/CHROME_GW", "/_proxy/CDN_STICKER", "host:`${location.host}/_proxy/CHROME_GW`,protocol:\"http\",port:80", "host:`${location.host}/_proxy/CDN_STICKER`,protocol:\"http\",port:80", "chrome-extension://"+officialExtensionID)
		}},
		{"no direct telemetry/upstream literals", func() error {
			return walkNoContains(dir, []string{"sentry-uit.line-apps.com", `"https://ci.line-apps.com/R4"`, `"line-chrome-gw.line-apps.com"`, `"stickershop.line-scdn.net"`, "host:`${location.host}/_proxy/CHROME_GW`,protocol:\"http\",port:443", "host:`${location.host}/_proxy/CDN_STICKER`,protocol:\"http\",port:443", `"*://*/*"`})
		}},
	}
	var failed []string
	for _, check := range checks {
		if err := check.fn(); err != nil {
			report.Lines = append(report.Lines, "verify "+check.name+"=fail: "+err.Error())
			failed = append(failed, check.name)
			continue
		}
		report.Lines = append(report.Lines, "verify "+check.name+"=ok")
	}
	if len(failed) > 0 {
		return report, fmt.Errorf("asset verification failed: %s", strings.Join(failed, ", "))
	}
	return report, nil
}

func fileContains(filename string, needles ...string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	content := string(data)
	for _, needle := range needles {
		if !strings.Contains(content, needle) {
			return fmt.Errorf("%s missing %q", filename, needle)
		}
	}
	return nil
}

func walkNoContains(root string, needles []string) error {
	return filepath.WalkDir(root, func(filename string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		content := string(data)
		for _, needle := range needles {
			if strings.Contains(content, needle) {
				return fmt.Errorf("%s contains blocked literal %q", filename, needle)
			}
		}
		return nil
	})
}
