package shacrypt

import (
	"crypto/subtle"
	"fmt"
	"strings"

	xcrypt "github.com/go-crypt/x/crypt"

	"github.com/go-crypt/crypt/algorithm"
)

// Digest is a digest which handles SHA2 Crypt hashes like SHA256 or SHA512.
type Digest struct {
	variant Variant

	rounds    int
	salt, key []byte
}

// Match returns true if the string password matches the current Digest.
func (d *Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current Digest.
func (d *Digest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d *Digest) MatchAdvanced(password string) (match bool, err error) {
	if match, err = d.MatchBytesAdvanced([]byte(password)); err != nil {
		return match, fmt.Errorf(algorithm.ErrFmtDigestMatch, AlgName, err)
	}

	return match, nil
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d *Digest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrPasswordInvalid)
	}

	return subtle.ConstantTimeCompare(d.key, xcrypt.KeySHACrypt(d.variant.HashFunc(), passwordBytes, d.salt, d.rounds)) == 1, nil
}

// Encode this Digest as a string for storage.
func (d *Digest) Encode() (hash string) {
	return strings.ReplaceAll(fmt.Sprintf(EncodingFmt,
		d.variant.Prefix(), d.rounds,
		d.salt, d.key,
	), "\n", "")
}

// String returns the storable format of the Digest hash utilizing fmt.Sprintf and EncodingFmt.
func (d *Digest) String() string {
	return d.Encode()
}
