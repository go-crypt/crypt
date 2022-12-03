package crypt

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	reAlgorithmPrefixPBKDF2 = regexp.MustCompile(`^\{(?P<identifier>PBKDF2(-SHA\d+)?)}(?P<remainder>\d+\$.*)$`)
)

// Normalize performs normalization on an encoded digest. This removes prefixes which are not necessary and performs
// minimal modification to the encoded digest to make it possible for decoding.
func Normalize(encodedDigest string) string {
	if strings.HasPrefix(encodedDigest, StorageFormatPrefixLDAPCrypt) {
		encodedDigest = encodedDigest[7:]
	}

	if strings.HasPrefix(encodedDigest, StorageFormatPrefixLDAPArgon2) {
		encodedDigest = encodedDigest[8:]
	}

	matchesPBKDF2 := reAlgorithmPrefixPBKDF2.FindStringSubmatch(encodedDigest)

	if len(matchesPBKDF2) != 0 {
		var identifier, remainder string

		for g, group := range reAlgorithmPrefixPBKDF2.SubexpNames() {
			switch group {
			case "identifier":
				identifier = matchesPBKDF2[g]
			case "remainder":
				identifier = matchesPBKDF2[g]
			}
		}

		encodedDigest = fmt.Sprintf("$%s$%s", strings.ToLower(identifier), remainder)
	}

	return encodedDigest
}
