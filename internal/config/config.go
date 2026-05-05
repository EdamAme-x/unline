package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

type ServerConfig struct {
	Addr                  string
	AssetsDir             string
	AllowedHostsRaw       string
	TLSCertFile           string
	TLSKeyFile            string
	ProxyTimeout          time.Duration
	MaxBodyBytes          int64
	ForwardCookies        bool
	ForwardAuthorization  bool
	BasicAuthUsername     string
	BasicAuthPasswordHash string
	BasicAuthRealm        string

	allowedHosts map[string]struct{}
	allowAnyHost bool
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:            "127.0.0.1:8080",
		AssetsDir:       "./www",
		AllowedHostsRaw: "localhost,127.0.0.1,::1",
		ProxyTimeout:    180 * time.Second,
		MaxBodyBytes:    32 << 20,
		BasicAuthRealm:  "unline",
	}
}

func (c *ServerConfig) Finalize() error {
	if c.TLSCertFile == "" && c.TLSKeyFile != "" || c.TLSCertFile != "" && c.TLSKeyFile == "" {
		return fmt.Errorf("both --tls-cert and --tls-key must be set together")
	}
	if c.ProxyTimeout <= 0 {
		return fmt.Errorf("proxy timeout must be positive")
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("max body bytes must be positive")
	}
	if c.BasicAuthRealm == "" {
		c.BasicAuthRealm = "unline"
	}

	c.allowedHosts = map[string]struct{}{}
	for _, item := range strings.Split(c.AllowedHostsRaw, ",") {
		host := normalizeHost(item)
		if host == "" {
			continue
		}
		if host == "*" {
			c.allowAnyHost = true
			continue
		}
		c.allowedHosts[host] = struct{}{}
	}
	if !c.allowAnyHost && len(c.allowedHosts) == 0 {
		return fmt.Errorf("allowed host list is empty")
	}
	return nil
}

func (c ServerConfig) BasicAuthEnabled() bool {
	return strings.TrimSpace(c.BasicAuthPasswordHash) != ""
}

func (c ServerConfig) HostAllowed(hostport string) bool {
	if c.allowAnyHost {
		return true
	}
	host := normalizeHost(hostport)
	_, ok := c.allowedHosts[host]
	return ok
}

func (c ServerConfig) OriginAllowed(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return c.HostAllowed(u.Host)
}

func normalizeHost(hostport string) string {
	value := strings.TrimSpace(strings.ToLower(hostport))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "[") {
		host, _, err := net.SplitHostPort(value)
		if err == nil {
			return strings.Trim(host, "[]")
		}
		return strings.Trim(value, "[]")
	}
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.Count(value, ":") > 1 {
		return strings.Trim(value, "[]")
	}
	return value
}
