package crypt

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	xcrypt "github.com/go-crypt/x/crypt"
)

// SHA2CryptDigest is a digest which handles SHA2 Crypt hashes like SHA256 or SHA512.
type SHA2CryptDigest struct {
	variant SHA2CryptVariant

	rounds    uint32
	salt, key []byte
}

// Match returns true if the string password matches the current Digest.
func (d SHA2CryptDigest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current Digest.
func (d SHA2CryptDigest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d SHA2CryptDigest) MatchAdvanced(password string) (match bool, err error) {
	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d SHA2CryptDigest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	return subtle.ConstantTimeCompare(d.key, xcrypt.Key(d.variant.HashFunc(), passwordBytes, d.salt, int(d.rounds))) == 1, nil
}

// Decode a password hash into this SHA2CryptDigest. Returns an error if the supplied encoded hash string cannot be
// decoded as a SHA2CryptDigest.
func (d *SHA2CryptDigest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := strings.Split(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 5 {
		return fmt.Errorf("encoded digest does not have the correct number of parts: should be 4 but has %d", len(encodedDigestParts)-1)
	}

	variant, options, salt, key := NewSHA2CryptVariant(encodedDigestParts[1]), encodedDigestParts[2], encodedDigestParts[3], encodedDigestParts[4]

	d.variant = variant

	for _, opt := range strings.Split(options, ",") {
		pair := strings.SplitN(opt, "=", 2)

		if len(pair) != 2 {
			return fmt.Errorf("sha2crypt hash invalid option '%s'", opt)
		}

		k, v := pair[0], pair[1]

		switch k {
		case "rounds":
			var rounds uint64

			if rounds, err = strconv.ParseUint(v, 10, 32); err != nil {
				return fmt.Errorf("sha2crypt option '%s' has invalid value '%s': %w", k, v, err)
			}

			d.rounds = uint32(rounds)
		default:
			return fmt.Errorf("sha2crypt option '%s' with value '%s' is unknown", k, v)
		}
	}

	d.salt, d.key = []byte(salt), []byte(key)

	return nil
}

// Encode this SHA2CryptDigest as a string for storage.
func (d *SHA2CryptDigest) Encode() (hash string) {

	return strings.ReplaceAll(fmt.Sprintf(StorageFormatSHACrypt,
		d.variant.String(), d.rounds,
		d.salt, d.key,
	), "\n", "")
}

// String returns the storable format of the SHA2CryptDigest hash utilizing fmt.Sprintf and StorageFormatSHACrypt.
func (d SHA2CryptDigest) String() string {
	return d.Encode()
}
