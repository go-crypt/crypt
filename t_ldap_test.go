package crypt

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var rePrefix = regexp.MustCompile(`^\{(\w+)}(.*)$`)

func matchLDAPX(password, digest string) bool {
	parts := rePrefix.FindStringSubmatch(digest)

	alg, encodedKey := parts[1], parts[2]

	var (
		salted   bool
		hashfunc hash.Hash
	)

	switch alg {
	case "MD5":
		hashfunc = md5.New()
	case "SSHA":
		salted = true

		fallthrough
	case "SHA":
		hashfunc = sha1.New()
	case "SSHA256":
		salted = true

		fallthrough
	case "SHA256":
		hashfunc = sha256.New()
	case "SSHA512":
		salted = true

		fallthrough
	case "SHA512":
		hashfunc = sha512.New()
	}

	if hashfunc == nil {
		panic("invalid algorithm")
	}

	var (
		key []byte
		err error
	)

	if key, err = base64.StdEncoding.DecodeString(encodedKey); err != nil {
		panic(err)
	}

	return matchLDAPHashFunc(password, key, salted, hashfunc)
}

func matchLDAPHashFunc(password string, key []byte, salted bool, hashfunc hash.Hash) bool {
	var salt []byte

	if salted {
		salt = key[hashfunc.Size():]
		key = key[:hashfunc.Size()]
	}

	hashfunc.Write([]byte(password))
	hashfunc.Write(salt)

	sum := hashfunc.Sum(nil)

	return subtle.ConstantTimeCompare(sum, key) == 1
}

func TestLDAPSHACRYPT(t *testing.T) {
	testcCases := []struct {
		name string
		have string
	}{
		{
			"ShouldValidatePasswordAI",
			"{SSHA}Yzg4ZTljNjcwNDFhNzRlMDM1N2JlZmRmZjkzZjg3ZGRlMDkwNDIxNHNhbHQ=",
		},
		{
			"ShouldValidatePasswordSHAWithoutSalt",
			"{SHA}w0mcJylzCn+AfvuGdqkty2+KP48=",
		},
		{
			"ShouldValidatePasswordSHAWithSalt",
			"{SSHA}zUmI4pewiNEHgqohjFzObVbD7VYM0mYT",
		},
		{
			"ShouldValidatePasswordSHA256WithoutSalt",
			"{SHA256}UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=",
		},
		{
			"ShouldValidatePasswordSHA256WithSalt",
			"{SSHA256}BAX6mgsQ+Dg4kKsyURsrlngPhqBoG6NB/1hswAHkZeIdCc9AXXABwg==",
		},
		{
			"ShouldValidatePasswordSHA512WithoutSalt",
			"{SHA512}O7Eu2jwpjbXeJVl/VNkk8uF+eKJq2JU+2CGO5oLwu76QIeLzAJ0VLJEb8fJexoOpAnFBZnZ6+9jlvQ+wEk7Lig==",
		},
		{
			"ShouldValidatePasswordSHA512WithSalt",
			"{SSHA512}FXFpO1AxW+S7GAv+Ig07TTf5wbPH+pqnRWeBn0u76P62aLK8aeLltqnSnmz6GYS8ks2n1CRKQCXRlbuqHGq1HvXdYKIYz9Ee",
		},
	}

	for _, tc := range testcCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := Verify([]byte("password"), tc.have)
			assert.NoError(t, err)
			assert.True(t, ok)

			assert.Equal(t, true, matchLDAPX("example", tc.have))
			assert.Equal(t, false, matchLDAPX("password", tc.have))
		})
	}
}

type Scheme string

const (
	MD5     Scheme = "{MD5}"     // MD5 over password, base64(digest)
	SHA     Scheme = "{SHA}"     // SHA-1 over password, base64(digest)
	SSHA    Scheme = "{SSHA}"    // SHA-1 over password||salt, base64(digest||salt)
	SHA256  Scheme = "{SHA256}"  // SHA-256 over password, base64(digest)
	SSHA256 Scheme = "{SSHA256}" // SHA-256 over password||salt, base64(digest||salt)
	SHA512  Scheme = "{SHA512}"  // SHA-512 over password, base64(digest)
	SSHA512 Scheme = "{SSHA512}" // SHA-512 over password||salt, base64(digest||salt)
)

// Generate returns an LDAP-style hash string for the given scheme.
// For salted schemes (SSHA*, SSHA512), provide saltLen > 0 (e.g., 8–16 bytes).
// For unsalted schemes (SHA*, SHA512), saltLen is ignored.
func Generate(scheme Scheme, password []byte, saltLen int) (string, error) {
	normalized, err := normalizeScheme(scheme)
	if err != nil {
		return "", err
	}

	var salt []byte
	if isSalted(normalized) {
		if saltLen <= 0 {
			saltLen = 8 // sensible default for LDAP SSHA
		}
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return "", fmt.Errorf("generate salt: %w", err)
		}
	}

	digest, err := hashWithScheme(normalized, password, salt)
	if err != nil {
		return "", err
	}

	blob := append(digest, salt...)
	enc := base64.StdEncoding.EncodeToString(blob)
	return string(normalized) + enc, nil
}

// Verify compares the plaintext password with the stored LDAP-style hash string.
// Returns true if they match.
func Verify(password []byte, stored string) (bool, error) {
	if len(stored) == 0 {
		return false, errors.New("empty stored hash")
	}

	// Split scheme prefix and payload
	i := strings.IndexByte(stored, '}')
	if i <= 0 || stored[0] != '{' {
		return false, errors.New("invalid format: missing scheme braces")
	}
	schemeStr := stored[:i+1]
	payload := strings.TrimSpace(stored[i+1:])

	scheme, err := normalizeScheme(Scheme(schemeStr))
	if err != nil {
		return false, err
	}

	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return false, fmt.Errorf("base64 decode: %w", err)
	}

	dLen, ok := digestLen(scheme)
	if !ok {
		return false, fmt.Errorf("unsupported scheme: %s", scheme)
	}
	if len(raw) < dLen {
		return false, errors.New("payload shorter than digest length")
	}

	digest := raw[:dLen]
	salt := raw[dLen:]

	// Recompute digest with extracted salt (if any)
	computed, err := hashWithScheme(scheme, password, salt)
	if err != nil {
		return false, err
	}

	// Constant-time comparison
	if subtle.ConstantTimeCompare(computed, digest) == 1 {
		return true, nil
	}
	return false, nil
}

// ----- internals -----

func normalizeScheme(s Scheme) (Scheme, error) {
	up := strings.ToUpper(string(s))
	switch up {
	case string(MD5), string(SHA), string(SSHA), string(SHA256), string(SSHA256), string(SHA512), string(SSHA512):
		return Scheme(up), nil
	default:
		return "", fmt.Errorf("unsupported scheme: %s", s)
	}
}

func isSalted(s Scheme) bool {
	switch s {
	case SSHA, SSHA256, SSHA512:
		return true
	default:
		return false
	}
}

func digestLen(s Scheme) (int, bool) {
	switch s {
	case MD5:
		return md5.Size, true
	case SHA, SSHA:
		return sha1.Size, true // 20
	case SHA256, SSHA256:
		return sha256.Size, true // 32
	case SHA512, SSHA512:
		return sha512.Size, true // 64
	default:
		return 0, false
	}
}

func hashWithScheme(s Scheme, password, salt []byte) ([]byte, error) {
	switch s {
	case MD5:
		h := md5.New()
		h.Write(password)
		h.Write(salt)
		return h.Sum(nil), nil
	case SHA, SSHA:
		h := sha1.New()
		h.Write(password)
		h.Write(salt)
		return h.Sum(nil), nil

	case SHA256, SSHA256:
		h := sha256.New()
		h.Write(password)
		h.Write(salt)
		return h.Sum(nil), nil

	case SHA512, SSHA512:
		h := sha512.New()
		h.Write(password)
		h.Write(salt)
		return h.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", s)
	}
}

// ----- example usage (remove or adapt in your codebase) -----

// Example:
// func main() {
// 	pass := []byte("correct horse battery staple")
//
// 	h1, _ := Generate(SSHA, pass, 8)
// 	fmt.Println("SSHA:", h1)
// 	ok, _ := Verify(pass, h1)
// 	fmt.Println("verify SSHA:", ok)
//
// 	h2, _ := Generate(SHA256, pass, 0)
// 	fmt.Println("SHA256:", h2)
// 	ok, _ = Verify(pass, h2)
// 	fmt.Println("verify SHA256:", ok)
//
// 	// Checking mismatch:
// 	ok, _ = Verify([]byte("wrong"), h1)
// 	fmt.Println("verify wrong:", ok)
// }

// ----- helpers for decoding if you ever need raw salt back -----
