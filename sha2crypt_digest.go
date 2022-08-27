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

	rounds    int
	salt, key []byte
}

// Match returns true if the string password matches the current Digest.
func (d *SHA2CryptDigest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current Digest.
func (d *SHA2CryptDigest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d *SHA2CryptDigest) MatchAdvanced(password string) (match bool, err error) {
	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d *SHA2CryptDigest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf("sha2crypt match error: %w: key has 0 bytes", ErrPasswordInvalid)
	}

	return subtle.ConstantTimeCompare(d.key, xcrypt.Key(d.variant.HashFunc(), passwordBytes, d.salt, d.rounds)) == 1, nil
}

// Decode a password hash into this SHA2CryptDigest. Returns an error if the supplied encoded hash string cannot be
// decoded as a SHA2CryptDigest.
func (d *SHA2CryptDigest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := strings.Split(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 5 {
		return fmt.Errorf("sha2crypt decode error: %w", ErrEncodedHashInvalidFormat)
	}

	variant, options, salt, key := NewSHA2CryptVariant(encodedDigestParts[1]), encodedDigestParts[2], encodedDigestParts[3], encodedDigestParts[4]

	d.variant = variant

	for _, opt := range strings.Split(options, ",") {
		pair := strings.SplitN(opt, "=", 2)

		if len(pair) != 2 {
			return fmt.Errorf("sha2crypt decode error: %w: option '%s' is invalid", ErrEncodedHashInvalidOption, opt)
		}

		k, v := pair[0], pair[1]

		switch k {
		case "rounds":
			var rounds uint64

			if rounds, err = strconv.ParseUint(v, 10, 32); err != nil {
				return fmt.Errorf("sha2crypt decode error: %w: option '%s' has invalid value '%s': %v", ErrEncodedHashInvalidOptionValue, k, v, err)
			}

			d.rounds = int(rounds)
		default:
			return fmt.Errorf("sha2crypt decode error: %w: option '%s' with value '%s' is unknown", ErrEncodedHashInvalidOptionKey, k, v)
		}
	}

	if d.salt, err = b64rs.DecodeString(salt); err != nil {
		return fmt.Errorf("sha2crypt decode error: %w: %+v", ErrEncodedHashSaltEncoding, err)
	}

	d.key = []byte(key)

	return nil
}

// Encode this SHA2CryptDigest as a string for storage.
func (d *SHA2CryptDigest) Encode() (hash string) {
	salt := make([]byte, b64rs.EncodedLen(len(d.salt)))

	b64rs.Encode(salt, d.salt)

	return strings.ReplaceAll(fmt.Sprintf(StorageFormatSHACrypt,
		d.variant.Prefix(), d.rounds,
		salt, d.key,
	), "\n", "")
}

// String returns the storable format of the SHA2CryptDigest hash utilizing fmt.Sprintf and StorageFormatSHACrypt.
func (d *SHA2CryptDigest) String() string {
	return d.Encode()
}
