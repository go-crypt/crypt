package bcrypt

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-crypt/x/bcrypt"

	"github.com/go-crypt/crypt/algorithm"
)

// Digest is a digest which handles bcrypt hashes.
type Digest struct {
	variant Variant

	iterations int

	salt, key []byte
}

// Match returns true if the string password matches the current bcrypt.Digest.
func (d *Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current bcrypt.Digest.
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

	input := d.variant.EncodeInput(passwordBytes, d.salt)

	var key []byte

	if key, err = bcrypt.Key(input, d.salt, d.iterations); err != nil {
		return false, fmt.Errorf(algorithm.ErrFmtDigestMatch, AlgName, fmt.Errorf("%w: %v", algorithm.ErrKeyDerivation, err))
	}

	return subtle.ConstantTimeCompare(d.key, key) == 1, nil
}

// Encode returns the encoded form of this bcrypt.Digest.
func (d *Digest) Encode() string {
	return d.variant.Encode(d.iterations, AlgIdentifier, bcrypt.Base64Encode(d.salt), d.key)
}

// String returns the storable format of the bcrypt.Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}

func (d *Digest) defaults() {
	switch d.variant {
	case VariantNone:
		d.variant = VariantStandard
	case VariantStandard, VariantSHA256:
		break
	default:
		d.variant = variantDefault
	}

	if d.iterations < IterationsMin {
		d.iterations = IterationsDefault
	}
}
