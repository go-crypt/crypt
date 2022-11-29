package pbkdf2

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-crypt/x/pbkdf2"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// Digest is a pbkdf2.Digest which handles PBKDF2 hashes.
type Digest struct {
	variant Variant

	iterations int
	t          int
	salt, key  []byte
}

// Match returns true if the string password matches the current pbkdf2.Digest.
func (d *Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current pbkdf2.Digest.
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

	return subtle.ConstantTimeCompare(d.key, pbkdf2.Key(passwordBytes, d.salt, d.iterations, d.t, d.variant.HashFunc())) == 1, nil
}

// Encode returns the encoded form of this pbkdf2.Digest.
func (d *Digest) Encode() string {
	return fmt.Sprintf(EncodingFmt,
		d.variant.Prefix(),
		d.iterations,
		encoding.Base64RawAdaptedEncoding.EncodeToString(d.salt), encoding.Base64RawAdaptedEncoding.EncodeToString(d.key),
	)
}

// String returns the storable format of the pbkdf2.Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}
