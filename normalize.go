package crypt

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	reAlgorithmPrefixLDAPPBKDF2 = regexp.MustCompile(`^\{(?P<identifier>PBKDF2(-SHA\d+)?)}(?P<remainder>\d+\$.*)$`)
	reAlgorithmPrefixLDAP       = regexp.MustCompile(`^\{(?P<identifier>\w+)}(?P<remainder>\d+\$.*)$`)
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

	if strings.HasPrefix(encodedDigest, StorageFormatPrefixLDAPClearText) {
		return fmt.Sprintf("$plaintext$%s", encodedDigest[11:])
	}

	var matches []string

	matches = reAlgorithmPrefixLDAPPBKDF2.FindStringSubmatch(encodedDigest)

	if len(matches) != 0 {
		identifier, remainder := getIdentifierRemainderGroups(reAlgorithmPrefixLDAPPBKDF2, matches)

		encodedDigest = fmt.Sprintf("$%s$%s", strings.ToLower(identifier), remainder)
	}

	matches = reAlgorithmPrefixLDAP.FindStringSubmatch(encodedDigest)

	if len(matches) != 0 {
		identifier, remainder := getIdentifierRemainderGroups(reAlgorithmPrefixLDAPPBKDF2, matches)

		encodedDigest = fmt.Sprintf("$%s$%s", strings.ToLower(identifier), remainder)
	}

	return encodedDigest
}

func getIdentifierRemainderGroups(pattern *regexp.Regexp, matches []string) (identifier, remainder string) {
	for g, group := range pattern.SubexpNames() {
		switch group {
		case "identifier":
			identifier = matches[g]
		case "remainder":
			remainder = matches[g]
		}
	}

	return identifier, remainder
}
