package oauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params controls argon2id password hashing.
type Argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// DefaultArgon2Params follows the OWASP argon2id baseline: 64 MiB, 3 passes,
// 2 lanes.
var DefaultArgon2Params = Argon2Params{
	Memory:  64 * 1024,
	Time:    3,
	Threads: 2,
	SaltLen: 16,
	KeyLen:  32,
}

const argon2Version = 19

// HashAdminPassphrase returns a PHC-formatted argon2id hash.
func HashAdminPassphrase(passphrase string, params Argon2Params) (string, error) {
	if passphrase == "" {
		return "", fmt.Errorf("oauth: passphrase must not be empty")
	}
	if params.Memory == 0 || params.Time == 0 || params.Threads == 0 || params.SaltLen == 0 || params.KeyLen == 0 {
		params = DefaultArgon2Params
	}
	salt := make([]byte, params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("oauth: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(passphrase), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version, params.Memory, params.Time, params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyAdminPassphrase reports whether passphrase matches encoded. A malformed
// encoded hash is an error; a mismatch is (false, nil). Comparison is constant
// time.
func VerifyAdminPassphrase(encoded, passphrase string) (bool, error) {
	params, salt, want, err := parseArgon2Hash(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(passphrase), salt, params.Time, params.Memory, params.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func parseArgon2Hash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(strings.TrimSpace(encoded), "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Argon2Params{}, nil, nil, ErrInvalidSecret
	}
	var p Argon2Params
	for _, item := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			return Argon2Params{}, nil, nil, ErrInvalidSecret
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return Argon2Params{}, nil, nil, ErrInvalidSecret
		}
		switch k {
		case "m":
			p.Memory = uint32(n)
		case "t":
			p.Time = uint32(n)
		case "p":
			if n > 255 {
				return Argon2Params{}, nil, nil, ErrInvalidSecret
			}
			p.Threads = uint8(n)
		default:
			return Argon2Params{}, nil, nil, ErrInvalidSecret
		}
	}
	if p.Memory == 0 || p.Time == 0 || p.Threads == 0 {
		return Argon2Params{}, nil, nil, ErrInvalidSecret
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return Argon2Params{}, nil, nil, ErrInvalidSecret
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 {
		return Argon2Params{}, nil, nil, ErrInvalidSecret
	}
	p.SaltLen = uint32(len(salt))
	p.KeyLen = uint32(len(key))
	return p, salt, key, nil
}
