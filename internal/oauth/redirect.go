package oauth

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// DefaultRedirectHosts are the built-in OAuth callback hosts from
// docs/reference/01-oauth-endpoints-spec.md.
var DefaultRedirectHosts = []string{
	"chatgpt.com",
	"platform.openai.com",
	"claude.ai",
	"claude.com",
	"oauth-redirect.googleusercontent.com",
	"oauth-redirect-sandbox.googleusercontent.com",
	"oauth-redirect-test.googleusercontent.com",
	"localhost",
	"127.0.0.1",
	"::1",
}

// RedirectHostAllowlist returns the default hosts plus configured extras.
func RedirectHostAllowlist(extra []string) map[string]bool {
	hosts := make(map[string]bool, len(DefaultRedirectHosts)+len(extra))
	for _, h := range DefaultRedirectHosts {
		hosts[h] = true
	}
	for _, h := range extra {
		h = strings.ToLower(strings.TrimSpace(h))
		h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
		if h != "" {
			hosts[h] = true
		}
	}
	return hosts
}

// ValidateRedirectURI applies the DCR redirect_uri policy: absolute HTTPS, or
// HTTP only for loopback callbacks, with a hostname in the allowlist and no
// fragment or userinfo.
func ValidateRedirectURI(raw string, allowed map[string]bool) error {
	if raw == "" || len(raw) > 2048 {
		return fmt.Errorf("redirect_uri must be 1-2048 characters")
	}
	if strings.ContainsAny(raw, "\\ \t\r\n") {
		return fmt.Errorf("redirect_uri contains forbidden characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri is not a valid URI")
	}
	if !u.IsAbs() || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("redirect_uri must be absolute with a host")
	}
	if u.User != nil {
		return fmt.Errorf("redirect_uri must not contain userinfo")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("redirect_uri must not contain a fragment")
	}
	host := strings.ToLower(u.Hostname())
	if !allowed[host] {
		return fmt.Errorf("redirect_uri host %q is not allowed", host)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if !isLoopbackHost(host) {
			return fmt.Errorf("redirect_uri must use https unless the host is loopback")
		}
		return nil
	default:
		return fmt.Errorf("redirect_uri must use https or loopback http")
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// appendOAuthParams adds code/state/iss (or error/state/iss) to a validated
// redirect URI without disturbing its existing query.
func appendOAuthParams(redirectURI string, values url.Values) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect_uri: %w", err)
	}
	q := u.Query()
	for k, vals := range values {
		for _, v := range vals {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
