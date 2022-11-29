package argon2

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-crypt/x/argon2"

	"github.com/go-crypt/crypt/algorithm"
)

// Digest is a digest which handles Argon2 hashes like Argon2id, Argon2i, and Argon2d.
type Digest struct {
	variant Variant

	v uint8

	m, t, p uint32

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
	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d *Digest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf(algorithm.ErrFmtDigestMatch, AlgName, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrPasswordInvalid))
	}

	return subtle.ConstantTimeCompare(d.key, d.variant.KeyFunc()(passwordBytes, d.salt, d.t, d.m, d.p, uint32(len(d.key)))) == 1, nil
}

// Encode returns the encoded form of this Digest.
func (d *Digest) Encode() (encodedHash string) {
	return strings.ReplaceAll(fmt.Sprintf(EncodingFmt,
		d.variant.Prefix(), argon2.Version,
		d.m, d.t, d.p,
		base64.RawStdEncoding.EncodeToString(d.salt), base64.RawStdEncoding.EncodeToString(d.key),
	), "\n", "")
}

// String returns the storable format of the Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}
