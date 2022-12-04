package argon2

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-crypt/x/argon2"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/math"
)

// Digest is a digest which handles Argon2 hashes like Argon2id, Argon2i, and Argon2d.
type Digest struct {
	variant Variant

	v uint8

	m, t, p uint32

	salt, key []byte
}

// Match returns true if the string password matches the current argon2.Digest.
func (d *Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current argon2.Digest.
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

// Encode returns the encoded form of this argon2.Digest.
func (d *Digest) Encode() (encodedHash string) {
	return strings.ReplaceAll(fmt.Sprintf(EncodingFmt,
		d.variant.Prefix(), argon2.Version,
		d.m, d.t, d.p,
		base64.RawStdEncoding.EncodeToString(d.salt), base64.RawStdEncoding.EncodeToString(d.key),
	), "\n", "")
}

// String returns the storable format of the argon2.Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}

func (d *Digest) defaults() {
	switch d.variant {
	case VariantID, VariantI, VariantD:
		break
	default:
		d.variant = variantDefault
	}

	if d.t < IterationsMin {
		d.t = IterationsDefault
	}

	if d.p < ParallelismMin {
		d.p = ParallelismDefault
	}

	if d.m < MemoryMin {
		d.m = MemoryDefault
	}

	/*
	   Memory size m MUST be an integer number of kibibytes from 8*p to
	   2^(32)-1.  The actual number of blocks is m', which is m rounded
	   down to the nearest multiple of 4*p.
	*/

	pM := d.p * MemoryRoundingParallelismMultiplier

	d.m = math.Uint32RoundDownToNearestMultiple(d.m, pM)
}
