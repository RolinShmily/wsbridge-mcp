package httpx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Redacted is the replacement marker for all sensitive values in logs.
const Redacted = "[REDACTED]"

var sensitiveFields = map[string]struct{}{
	"password":      {},
	"passphrase":    {},
	"code":          {},
	"access_token":  {},
	"refresh_token": {},
	"code_verifier": {},
	"csrf_token":    {},
}

func isSensitiveField(name string) bool {
	_, ok := sensitiveFields[strings.ToLower(name)]
	return ok
}

// RedactHeaderValue masks authentication-bearing HTTP header values.
// A Bearer prefix is preserved so logs remain diagnosable.
func RedactHeaderValue(name, value string) string {
	switch http.CanonicalHeaderKey(name) {
	case "Authorization":
		if len(value) >= len("bearer ") && strings.EqualFold(value[:len("bearer ")], "bearer ") {
			return value[:len("bearer ")] + Redacted
		}
		return Redacted
	case "Proxy-Authorization", "Cookie", "Set-Cookie":
		return Redacted
	default:
		return value
	}
}

// RedactHeaders returns a deep copy of h with sensitive header values masked.
func RedactHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for name, values := range h {
		masked := make([]string, len(values))
		for i, value := range values {
			masked[i] = RedactHeaderValue(name, value)
		}
		out[name] = masked
	}
	return out
}

// RedactURL masks sensitive query parameters (for example code and tokens)
// and userinfo passwords while keeping the rest of the URL readable.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return Redacted
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(u.User.Username(), Redacted)
		}
	}
	if u.RawQuery != "" {
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			// Fail closed: a malformed query can hide sensitive pairs that
			// ParseQuery silently drops, so never echo it back to logs.
			u.RawQuery = Redacted
			u.ForceQuery = false
			return u.String()
		}
		changed := false
		for name := range query {
			if isSensitiveField(name) {
				query.Set(name, Redacted)
				changed = true
			}
		}
		if changed {
			// url.Values.Encode escapes the brackets; keep the readable marker.
			u.RawQuery = strings.ReplaceAll(query.Encode(), url.QueryEscape(Redacted), Redacted)
		}
	}
	return u.String()
}

// RedactForm returns a copy of v with sensitive form values masked.
func RedactForm(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for name, values := range v {
		if isSensitiveField(name) {
			out[name] = []string{Redacted}
			continue
		}
		out[name] = append([]string(nil), values...)
	}
	return out
}

// RedactJSON masks sensitive keys in a JSON document, recursively.
// It returns an error if data is not a single valid JSON value.
func RedactJSON(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("redact JSON: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return nil, err
	}
	masked, err := json.Marshal(redactJSONValue(value))
	if err != nil {
		return nil, fmt.Errorf("redact JSON: %w", err)
	}
	return masked, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("redact JSON: trailing data after JSON value")
	}
	return fmt.Errorf("redact JSON: trailing data: %w", err)
}

func redactJSONValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if isSensitiveField(key) {
				v[key] = Redacted
			} else {
				v[key] = redactJSONValue(item)
			}
		}
		return v
	case []any:
		for i, item := range v {
			v[i] = redactJSONValue(item)
		}
		return v
	default:
		return v
	}
}
