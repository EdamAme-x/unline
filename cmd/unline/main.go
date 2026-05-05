package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/EdamAme-x/unline/internal/auth"
	"github.com/EdamAme-x/unline/internal/config"
	"github.com/EdamAme-x/unline/internal/generator"
	"github.com/EdamAme-x/unline/internal/server"
)

const version = "0.1.0"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if err := run(context.Background(), os.Args[1:]); err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return flag.ErrHelp
	}

	switch args[0] {
	case "setup":
		return setup(args[1:])
	case "serve":
		return serve(ctx, args[1:])
	case "generate":
		return generate(ctx, args[1:])
	case "verify":
		return verify(args[1:])
	case "version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfg := config.DefaultServerConfig()
	fs.StringVar(&cfg.Addr, "addr", envString("UNLINE_ADDR", cfg.Addr), "listen address")
	fs.StringVar(&cfg.AssetsDir, "assets", envString("UNLINE_ASSETS_DIR", cfg.AssetsDir), "patched web asset directory")
	fs.StringVar(&cfg.AllowedHostsRaw, "allowed-hosts", envString("UNLINE_ALLOWED_HOSTS", cfg.AllowedHostsRaw), "comma-separated Host allowlist; use the public host name in production")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert", envString("UNLINE_TLS_CERT", ""), "optional TLS certificate path")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key", envString("UNLINE_TLS_KEY", ""), "optional TLS key path")
	fs.DurationVar(&cfg.ProxyTimeout, "proxy-timeout", envDuration("UNLINE_PROXY_TIMEOUT", cfg.ProxyTimeout), "upstream proxy timeout")
	fs.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", envInt64("UNLINE_MAX_BODY_BYTES", cfg.MaxBodyBytes), "maximum proxied request body size")
	fs.BoolVar(&cfg.ForwardCookies, "forward-cookies", envBool("UNLINE_FORWARD_COOKIES", false), "forward Cookie headers to LINE upstreams")
	fs.BoolVar(&cfg.ForwardAuthorization, "forward-authorization", envBool("UNLINE_FORWARD_AUTHORIZATION", false), "forward Authorization headers to LINE upstreams")
	fs.StringVar(&cfg.BasicAuthUsername, "basic-auth-user", envString("UNLINE_BASIC_AUTH_USERNAME", ""), "optional Basic auth username")
	fs.StringVar(&cfg.BasicAuthPasswordHash, "basic-auth-password-hash", envString("UNLINE_BASIC_AUTH_PASSWORD_HASH", ""), "PBKDF2 password hash from unline setup")
	fs.StringVar(&cfg.BasicAuthRealm, "basic-auth-realm", envString("UNLINE_BASIC_AUTH_REALM", cfg.BasicAuthRealm), "Basic auth realm")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := cfg.Finalize(); err != nil {
		return err
	}

	handler, err := server.New(cfg)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("unline serving assets=%s addr=%s allowed_hosts=%s", cfg.AssetsDir, cfg.Addr, cfg.AllowedHostsRaw)
		if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
			errCh <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	out := ".env"
	username := "unline"
	realm := "unline"
	force := false
	fs.StringVar(&out, "out", out, "environment file to write")
	fs.StringVar(&username, "username", username, "Basic auth username")
	fs.StringVar(&realm, "realm", realm, "Basic auth realm")
	fs.BoolVar(&force, "force", false, "overwrite an existing output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(out); err == nil && !force {
		return fmt.Errorf("%s already exists; pass --force to overwrite", out)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	reader := bufio.NewReader(os.Stdin)
	enableAuth, err := readYesNo(reader, "Enable access authentication? (y/n) => ")
	if err != nil {
		return err
	}
	hash := ""
	if enableAuth {
		if strings.TrimSpace(username) == "" {
			return fmt.Errorf("username must not be empty")
		}
		first, err := readSecret(reader, "Access key: ")
		if err != nil {
			return err
		}
		second, err := readSecret(reader, "Confirm access key: ")
		if err != nil {
			return err
		}
		if first != second {
			return fmt.Errorf("access key confirmation did not match")
		}
		hash, err = auth.HashSecret([]byte(first))
		if err != nil {
			return err
		}
	} else {
		username = ""
	}
	content := strings.Join([]string{
		"UNLINE_ADDR=127.0.0.1:8080",
		"UNLINE_ASSETS_DIR=./www",
		"UNLINE_ALLOWED_HOSTS=localhost,127.0.0.1,::1",
		"UNLINE_FORWARD_COOKIES=false",
		"UNLINE_FORWARD_AUTHORIZATION=false",
		"UNLINE_BASIC_AUTH_USERNAME=" + shellValue(username),
		"UNLINE_BASIC_AUTH_PASSWORD_HASH=" + shellValue(hash),
		"UNLINE_BASIC_AUTH_REALM=" + shellValue(realm),
		"",
	}, "\n")
	if err := os.WriteFile(out, []byte(content), 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", out)
	if enableAuth {
		fmt.Println("access authentication enabled")
	} else {
		fmt.Println("access authentication disabled")
	}
	return nil
}

func generate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	opts := generator.DefaultOptions()
	fs.StringVar(&opts.OutDir, "out", opts.OutDir, "output web asset directory")
	fs.StringVar(&opts.CacheDir, "cache", opts.CacheDir, "download cache directory")
	fs.StringVar(&opts.ExtensionID, "extension-id", opts.ExtensionID, "Chrome extension id to fetch")
	fs.StringVar(&opts.ProdVersion, "prod-version", opts.ProdVersion, "Chrome prodversion used for the update endpoint")
	fs.StringVar(&opts.FromCRX, "from-crx", "", "use a local CRX/ZIP file instead of downloading")
	fs.BoolVar(&opts.Clean, "clean", opts.Clean, "delete output directory before extracting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report, err := generator.Generate(ctx, opts)
	if err != nil {
		return err
	}
	for _, line := range report.Lines {
		fmt.Println(line)
	}
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	assets := "./www"
	fs.StringVar(&assets, "assets", envString("UNLINE_ASSETS_DIR", assets), "patched web asset directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report, err := generator.VerifyAssets(assets)
	for _, line := range report.Lines {
		fmt.Println(line)
	}
	return err
}

func usage() {
	fmt.Fprintf(os.Stderr, `unline %s

Usage:
  unline setup [--out .env]
  unline generate [--out ./www]
  unline verify [--assets ./www]
  unline serve [--assets ./www] [--addr 127.0.0.1:8080]

`, version)
}

func readYesNo(reader *bufio.Reader, prompt string) (bool, error) {
	for {
		fmt.Fprint(os.Stderr, prompt)
		value, err := reader.ReadString('\n')
		if err != nil && !(errors.Is(err, io.EOF) && value != "") {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(os.Stderr, "Please answer y or n.")
			if errors.Is(err, io.EOF) {
				return false, io.EOF
			}
		}
	}
}

func readSecret(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	var oldState syscall.Termios
	hasTermios := ioctl(fd, syscall.TCGETS, uintptr(unsafe.Pointer(&oldState))) == nil
	if hasTermios {
		newState := oldState
		newState.Lflag &^= syscall.ECHO
		if err := ioctl(fd, syscall.TCSETS, uintptr(unsafe.Pointer(&newState))); err != nil {
			return "", err
		}
		defer func() {
			_ = ioctl(fd, syscall.TCSETS, uintptr(unsafe.Pointer(&oldState)))
			fmt.Fprintln(os.Stderr)
		}()
	}
	value, err := reader.ReadString('\n')
	if !hasTermios {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil && !(errors.Is(err, io.EOF) && value != "") {
		return "", err
	}
	value = strings.TrimRight(value, "\r\n")
	if value == "" {
		return "", fmt.Errorf("access key must not be empty")
	}
	return value, nil
}

func ioctl(fd int, request, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, argp)
	if errno != 0 {
		return errno
	}
	return nil
}

func shellValue(value string) string {
	if value == "" {
		return ""
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || r == ':' || r == '/' || r == '+' || r == '=' || r == '@' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func envString(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envInt64(name string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	var value int64
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil {
		return fallback
	}
	return value
}
