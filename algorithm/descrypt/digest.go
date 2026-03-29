package descrypt

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/descrypt"
)

// Digest is a algorithm.Digest which handles descrypt hashes.
type Digest struct {
	salt, key []byte
}

// Match returns true if the string password matches the current descrypt.Digest.
func (d *Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current descrypt.Digest.
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

	return subtle.ConstantTimeCompare(d.key, descrypt.Key(passwordBytes, d.salt)) == 1, nil
}

// Encode returns the encoded form of this descrypt.Digest.
func (d *Digest) Encode() string {
	return fmt.Sprintf(EncodingFmt, d.salt, d.key)
}

// String returns the storable format of the descrypt.Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}
