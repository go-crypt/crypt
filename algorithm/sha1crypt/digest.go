package sha1crypt

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-crypt/x/crypt"

	"github.com/go-crypt/crypt/algorithm"
)

// Digest is a algorithm.Digest which handles sha1crypt hashes.
type Digest struct {
	iterations uint32

	i bool

	salt, key []byte
}

// Match returns true if the string password matches the current sha1crypt.Digest.
func (d *Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current sha1crypt.Digest.
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

	return subtle.ConstantTimeCompare(d.key, crypt.KeySHA1Crypt(passwordBytes, d.salt, d.iterations)) == 1, nil
}

// Encode returns the encoded form of this sha1crypt.Digest.
func (d *Digest) Encode() string {
	return fmt.Sprintf(EncodingFmt,
		d.iterations, d.salt, d.key,
	)
}

// String returns the storable format of the sha1crypt.Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}

func (d *Digest) defaults() {
	if !d.i {
		d.iterations = IterationsDefault
	}
}
