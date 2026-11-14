package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// ValidPKCEChallenge reports whether a code_challenge is 43-128 characters of
// unpadded Base64URL, the only S256 challenge shape we accept.
func ValidPKCEChallenge(challenge string) bool {
	return validBase64URL(challenge, 43, 128)
}

// ValidPKCEVerifier reports whether a code_verifier is 43-128 characters of
// unpadded Base64URL.
func ValidPKCEVerifier(verifier string) bool {
	return validBase64URL(verifier, 43, 128)
}

// VerifyPKCE constant-time compares BASE64URL(SHA256(verifier)) with challenge.
func VerifyPKCE(verifier, challenge string) bool {
	if !ValidPKCEVerifier(verifier) || !ValidPKCEChallenge(challenge) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func validBase64URL(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
