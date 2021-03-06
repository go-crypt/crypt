package crypt

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
)

// NormalizeEncodedDigest helps normalize encoded digest strings from sources which don't use the same format as this
// library.
func NormalizeEncodedDigest(encodedDigest string) (out string) {
	if strings.HasPrefix(encodedDigest, StorageFormatPrefixLDAPCrypt) {
		encodedDigest = encodedDigest[7:]
	}

	switch {
	case strings.HasPrefix(encodedDigest, StorageFormatPrefixLDAPArgon2):
		encodedDigest = encodedDigest[8:]
	case strings.HasPrefix(encodedDigest, algorithmPrefixBcrypt):
		encodedDigest = strings.Replace(encodedDigest, algorithmPrefixBcrypt, algorithmPrefixBcryptNormalized, 1)
	case strings.HasPrefix(encodedDigest, algorithmPrefixBcryptA):
		encodedDigest = strings.Replace(encodedDigest, algorithmPrefixBcryptA, algorithmPrefixBcryptNormalized, 1)
	case strings.HasPrefix(encodedDigest, algorithmPrefixBcryptX):
		encodedDigest = strings.Replace(encodedDigest, algorithmPrefixBcryptX, algorithmPrefixBcryptNormalized, 1)
	case strings.HasPrefix(encodedDigest, algorithmPrefixBcryptY):
		encodedDigest = strings.Replace(encodedDigest, algorithmPrefixBcryptY, algorithmPrefixBcryptNormalized, 1)
	}

	matchesPBKDF2 := reAlgorithmPrefixPBKDF2.FindStringSubmatch(encodedDigest)

	if len(matchesPBKDF2) >= 3 {
		encodedDigest = fmt.Sprintf("$%s$%s", strings.ToLower(matchesPBKDF2[1]), matchesPBKDF2[3])
	}

	return encodedDigest
}

func splitDigest(encodedDigest, delimiter string) (parts []string) {
	encodedDigest = NormalizeEncodedDigest(encodedDigest)

	return strings.Split(encodedDigest, delimiter)
}

func randomBytes(length uint32) (bytes []byte, err error) {
	bytes = make([]byte, length)

	if _, err = io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, err
	}

	return bytes, nil
}

func roundDownToNearestMultiple(value, multiple uint32) uint32 {
	return (value / multiple) * multiple
}
