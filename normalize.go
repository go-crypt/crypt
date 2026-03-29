package crypt

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-crypt/crypt/internal/encoding"
)

var (
	reAlgorithmPrefixPBKDF2 = regexp.MustCompile(`^\{(?P<identifier>PBKDF2(-SHA\d+)?)}(?P<remainder>\d+\$.*)$`)
)

// Normalize performs normalization on an encoded digest. This removes prefixes which are not necessary and performs
// minimal modification to the encoded digest to make it possible for decoding.
func Normalize(encodedDigest string) string {
	if strings.HasPrefix(encodedDigest, StorageFormatPrefixLDAPCrypt) {
		return encodedDigest[7:]
	}

	if strings.HasPrefix(encodedDigest, StorageFormatPrefixLDAPArgon2) {
		return encodedDigest[8:]
	}

	matchesPBKDF2 := reAlgorithmPrefixPBKDF2.FindStringSubmatch(encodedDigest)

	if len(matchesPBKDF2) != 0 {
		var identifier, remainder string

		for g, group := range reAlgorithmPrefixPBKDF2.SubexpNames() {
			switch group {
			case "identifier":
				identifier = matchesPBKDF2[g]
			case "remainder":
				remainder = matchesPBKDF2[g]
			}
		}

		return fmt.Sprintf("$%s$%s", strings.ToLower(identifier), remainder)
	}

	if normalized, ok := normalizeCisco(encodedDigest); ok {
		return normalized
	}

	return encodedDigest
}

// normalizeCisco converts Cisco IOS Type 8, 9, and 10 password hashes into the standard modular crypt formats
// understood by this library's decoders.
//
// Type 5 ($1$) is standard md5crypt and requires no conversion.
//
// Type 8 ($8$salt$hash) is PBKDF2-SHA256 with 20,000 iterations. The salt and hash use standard base64 encoding.
// It is normalized to $pbkdf2-sha256$20000$<adapted-b64-salt>$<adapted-b64-hash>.
//
// Type 9 ($9$salt$hash) is scrypt with N=16384 (ln=14), r=1, p=1. The salt and hash use standard base64 encoding.
// It is normalized to $scrypt$ln=14,r=1,p=1$<std-b64-salt>$<std-b64-hash>.
//
// Type 10 uses the identifier $sha512$ and is PBKDF2-SHA512. The salt and hash use standard base64 with padding.
// It is normalized to $pbkdf2-sha512$<iterations>$<adapted-b64-salt>$<adapted-b64-hash>.
func normalizeCisco(encodedDigest string) (string, bool) {
	switch {
	case strings.HasPrefix(encodedDigest, StorageFormatPrefixCiscoType8):
		return normalizeCiscoType8(encodedDigest)
	case strings.HasPrefix(encodedDigest, StorageFormatPrefixCiscoType9):
		return normalizeCiscoType9(encodedDigest)
	case strings.HasPrefix(encodedDigest, StorageFormatPrefixCiscoType10):
		return normalizeCiscoType10(encodedDigest)
	default:
		return "", false
	}
}

// normalizeCiscoType8 converts $8$salt$hash to $pbkdf2-sha256$20000$salt$hash.
// Cisco Type 8 already uses the crypt adapted base64 alphabet, so no re-encoding is needed.
func normalizeCiscoType8(digest string) (string, bool) {
	parts := strings.SplitN(digest, "$", 4)
	if len(parts) != 4 || parts[1] != "8" {
		return "", false
	}

	return fmt.Sprintf("$pbkdf2-sha256$%d$%s$%s", CiscoType8Iterations, parts[2], parts[3]), true
}

// normalizeCiscoType9 converts $9$salt$hash to $scrypt$ln=14,r=1,p=1$salt$hash.
func normalizeCiscoType9(digest string) (string, bool) {
	parts := strings.SplitN(digest, "$", 4)
	if len(parts) != 4 || parts[1] != "9" {
		return "", false
	}

	return fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s",
		CiscoType9LN, CiscoType9R, CiscoType9P, parts[2], parts[3]), true
}

// normalizeCiscoType10 converts $sha512$iterations$salt$hash to $pbkdf2-sha512$iterations$salt$hash with adapted base64.
func normalizeCiscoType10(digest string) (string, bool) {
	parts := strings.SplitN(digest, "$", 5)
	if len(parts) != 5 || parts[1] != "sha512" {
		return "", false
	}

	salt, ok := paddedBase64ToAdapted(parts[3])
	if !ok {
		return "", false
	}

	key, ok := paddedBase64ToAdapted(parts[4])
	if !ok {
		return "", false
	}

	return fmt.Sprintf("$pbkdf2-sha512$%s$%s$%s", parts[2], salt, key), true
}

// paddedBase64ToAdapted converts a padded standard base64 string to the adapted base64 encoding
// used by pbkdf2 digests in this library.
func paddedBase64ToAdapted(s string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", false
	}

	return encoding.Base64RawAdaptedEncoding.EncodeToString(raw), true
}