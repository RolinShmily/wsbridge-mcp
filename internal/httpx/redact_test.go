package httpx_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/RolinShmily/wsbridge-mcp/internal/httpx"
)

func TestRedactHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{"bearer token", "Authorization", "Bearer abc.def.ghi", "Bearer [REDACTED]"},
		{"bearer lowercase", "authorization", "bearer abc", "bearer [REDACTED]"},
		{"basic auth", "Authorization", "Basic dXNlcjpwYXNz", "[REDACTED]"},
		{"cookie", "Cookie", "session=secret", "[REDACTED]"},
		{"proxy authorization", "Proxy-Authorization", "Bearer xyz", "[REDACTED]"},
		{"set cookie", "Set-Cookie", "sid=secret; HttpOnly", "[REDACTED]"},
		{"content type untouched", "Content-Type", "application/json", "application/json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpx.RedactHeaderValue(tt.key, tt.value); got != tt.want {
				t.Errorf("RedactHeaderValue(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.want)
			}
		})
	}
}

func TestRedactHeadersDoesNotMutateInput(t *testing.T) {
	h := http.Header{
		"Authorization": {"Bearer secret"},
		"Cookie":        {"a=b", "c=d"},
		"X-Test":        {"visible"},
	}
	out := httpx.RedactHeaders(h)
	if got := h.Get("Authorization"); got != "Bearer secret" {
		t.Errorf("input Authorization mutated: %q", got)
	}
	if got := out.Get("Authorization"); got != "Bearer [REDACTED]" {
		t.Errorf("output Authorization = %q", got)
	}
	if got := out.Values("Cookie"); len(got) != 2 || got[0] != "[REDACTED]" || got[1] != "[REDACTED]" {
		t.Errorf("output Cookie = %v", got)
	}
	if got := out.Get("X-Test"); got != "visible" {
		t.Errorf("output X-Test = %q", got)
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantSub    []string
		wantAbsent []string
	}{
		{
			name:       "sensitive query values",
			in:         "https://bridge.example.com/oauth/authorize?code=AUTHCODE&state=STATE&access_token=ACCESSTOKEN&password=PASSWORD",
			wantSub:    []string{"code=[REDACTED]", "state=STATE", "access_token=[REDACTED]", "password=[REDACTED]"},
			wantAbsent: []string{"AUTHCODE", "ACCESSTOKEN", "PASSWORD"},
		},
		{
			name:    "no query",
			in:      "https://bridge.example.com/mcp",
			wantSub: []string{"https://bridge.example.com/mcp"},
		},
		{
			name:       "malformed query semicolon fails closed",
			in:         "https://bridge.example.com/?code=MALFORMEDSECRET;x=1",
			wantSub:    []string{"[REDACTED]"},
			wantAbsent: []string{"MALFORMEDSECRET"},
		},
		{
			name:       "malformed query escape fails closed",
			in:         "https://bridge.example.com/?code=MALFORMEDSECRET%zz",
			wantSub:    []string{"[REDACTED]"},
			wantAbsent: []string{"MALFORMEDSECRET"},
		},
		{
			name:    "unparseable url",
			in:      "http://[::1",
			wantSub: []string{"[REDACTED]"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpx.RedactURL(tt.in)
			for _, sub := range tt.wantSub {
				if !strings.Contains(got, sub) {
					t.Errorf("RedactURL(%q) = %q, want substring %q", tt.in, got, sub)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("RedactURL(%q) = %q, contains secret %q", tt.in, got, absent)
				}
			}
		})
	}
}

func TestRedactJSON(t *testing.T) {
	in := []byte(`{
		"grant_type": "authorization_code",
		"code": "AUTHCODE",
		"password": "PASSWORD",
		"nested": {"access_token": "ACCESS", "refresh_token": "REFRESH", "keep": "ok"},
		"items": [{"csrf_token": "CSRF", "value": 1}],
		"big": 12345678901234567890,
		"Password": "CASED"
	}`)
	out, err := httpx.RedactJSON(in)
	if err != nil {
		t.Fatalf("RedactJSON: %v", err)
	}
	s := string(out)
	for _, secret := range []string{"AUTHCODE", "PASSWORD", "ACCESS", "REFRESH", "CSRF", "CASED"} {
		if strings.Contains(s, secret) {
			t.Errorf("output contains secret %q: %s", secret, s)
		}
	}
	if !strings.Contains(s, `"code":"[REDACTED]"`) {
		t.Errorf("output missing masked code: %s", s)
	}
	if !strings.Contains(s, `"keep":"ok"`) {
		t.Errorf("output lost non-sensitive field: %s", s)
	}
	if !strings.Contains(s, `12345678901234567890`) {
		t.Errorf("output mangled big number: %s", s)
	}

	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Errorf("output is not valid JSON: %v", err)
	}
}

func TestRedactJSONInvalidInput(t *testing.T) {
	if _, err := httpx.RedactJSON([]byte("{not json")); err == nil {
		t.Fatal("RedactJSON accepted invalid JSON")
	}
}

func TestRedactFormDoesNotMutateInput(t *testing.T) {
	v := url.Values{
		"code":            {"AUTHCODE"},
		"refresh_token":   {"REFRESH"},
		"client_id":       {"client"},
		"code_verifier":   {"VERIFIER"},
		"grant_type":      {"authorization_code"},
		"csrf_token":      {"CSRF"},
		"password":        {"PASSWORD"},
		"passphrase":      {"PASSPHRASE"},
		"unrelated_field": {"keep"},
	}
	out := httpx.RedactForm(v)
	if got := v.Get("code"); got != "AUTHCODE" {
		t.Errorf("input mutated: code = %q", got)
	}
	for _, key := range []string{"code", "refresh_token", "code_verifier", "csrf_token", "password", "passphrase"} {
		if got := out.Get(key); got != "[REDACTED]" {
			t.Errorf("%s = %q, want [REDACTED]", key, got)
		}
	}
	if got := out.Get("client_id"); got != "client" {
		t.Errorf("client_id = %q", got)
	}
	if got := out.Get("unrelated_field"); got != "keep" {
		t.Errorf("unrelated_field = %q", got)
	}
}
