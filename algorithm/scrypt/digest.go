package scrypt

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/go-crypt/x/scrypt"

	"github.com/go-crypt/crypt/algorithm"
)

// Digest is a Digest which handles scrypt hashes.
type Digest struct {
	ln, r, p int

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

	var key []byte

	if key, err = scrypt.Key(passwordBytes, d.salt, d.n(), d.r, d.p, len(d.key)); err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(d.key, key) == 1, nil
}

// Encode returns the encoded form of this Digest.
func (d *Digest) Encode() string {
	return fmt.Sprintf(EncodingFormat, AlgName,
		d.ln, d.r, d.p, base64.RawStdEncoding.EncodeToString(d.salt), base64.RawStdEncoding.EncodeToString(d.key),
	)
}

// String returns the storable format of the Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}

// n returns 2 to the power of log N i.e d.ln.
func (d *Digest) n() (n int) {
	return 1 << d.ln
}
