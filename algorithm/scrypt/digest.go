package scrypt

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// Digest is a scrypt.Digest which handles scrypt hashes.
type Digest struct {
	variant Variant

	ln, r, p int

	salt, key []byte
}

// Match returns true if the string password matches the current scrypt.Digest.
func (d *Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current scrypt.Digest.
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

	if key, err = d.variant.KeyFunc()(passwordBytes, d.salt, d.n(), d.r, d.p, len(d.key)); err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(d.key, key) == 1, nil
}

// Encode returns the encoded form of this scrypt.Digest.
func (d *Digest) Encode() string {
	return d.variant.Encode(d.ln, d.r, d.p, d.salt, d.key)
}

// String returns the storable format of the scrypt.Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}

// n returns 2 to the power of log N i.e d.ln.
func (d *Digest) n() (n int) {
	return 1 << d.ln
}

func (d *Digest) defaults() {
	switch d.variant {
	case VariantScrypt, VariantYescrypt:
		break
	default:
		d.variant = variantDefault
	}

	if d.ln < IterationsMin {
		d.ln = IterationsDefault
	}

	if d.r < BlockSizeMin {
		d.r = BlockSizeDefault
	}

	if d.p < ParallelismMin {
		d.p = ParallelismDefault
	}
}
