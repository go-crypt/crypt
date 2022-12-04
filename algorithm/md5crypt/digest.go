package md5crypt

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-crypt/x/crypt"

	"github.com/go-crypt/crypt/algorithm"
)

// Digest is a algorithm.Digest which handles md5crypt hashes.
type Digest struct {
	variant Variant

	iterations int
	salt, key  []byte
}

// Match returns true if the string password matches the current md5crypt.Digest.
func (d *Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current md5crypt.Digest.
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

	switch d.variant {
	case VariantSun:
		return subtle.ConstantTimeCompare(d.key, crypt.KeyMD5CryptSun(passwordBytes, d.salt, d.iterations)) == 1, nil
	default:
		return subtle.ConstantTimeCompare(d.key, crypt.KeyMD5Crypt(passwordBytes, d.salt)) == 1, nil
	}
}

// Encode returns the encoded form of this md5crypt.Digest.
func (d *Digest) Encode() string {
	switch {
	case d.variant == VariantSun && d.iterations > 0:
		return fmt.Sprintf(EncodingFmtSunIterations,
			d.iterations, d.salt, d.key,
		)
	case d.variant == VariantSun:
		return fmt.Sprintf(EncodingFmtSun,
			d.salt, d.key,
		)
	default:
		return fmt.Sprintf(EncodingFmt,
			d.salt, d.key,
		)
	}
}

// String returns the storable format of the md5crypt.Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}

func (d *Digest) defaults() {
	switch d.variant {
	case VariantStandard, VariantSun:
		break
	default:
		d.variant = variantDefault
	}

	if d.iterations < IterationsMin {
		d.iterations = IterationsDefault
	}
}
