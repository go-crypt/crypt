package plaintext

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// NewDigest creates a new plaintext.Digest using the plaintext.Variant.
func NewDigest(password string) (digest Digest) {
	digest = Digest{
		variant: VariantPlainText,
		key:     []byte(password),
	}

	return digest
}

// NewBase64Digest creates a new plaintext.Digest using the Base64 plaintext.Variant.
func NewBase64Digest(password string) (digest Digest) {
	digest = Digest{
		variant: VariantBase64,
		key:     []byte(password),
	}

	return digest
}

// Digest is an algorithm.Digest which handles plaintext matching.
type Digest struct {
	variant Variant

	key []byte
}

// Match returns true if the string password matches the current plaintext.Digest.
func (d *Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current plaintext.Digest.
func (d *Digest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d *Digest) MatchAdvanced(password string) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf(algorithm.ErrFmtDigestMatch, AlgName, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrPasswordInvalid))
	}

	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d *Digest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf(algorithm.ErrFmtDigestMatch, AlgName, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrPasswordInvalid))
	}

	return subtle.ConstantTimeCompare(d.key, passwordBytes) == 1, nil
}

// Encode returns the encoded form of this plaintext.Digest.
func (d *Digest) Encode() string {
	return fmt.Sprintf(EncodingFmt, d.variant.Prefix(), d.variant.Encode(d.key))
}

// String returns the storable format of the plaintext.Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}

func (d *Digest) defaults() {
	switch d.variant {
	case VariantPlainText, VariantBase64:
		break
	default:
		d.variant = VariantPlainText
	}
}

// Key returns the raw plaintext key which can be used in situations where the plaintext value is required such as
// validating JWT's signed by HMAC-SHA256.
func (d *Digest) Key() []byte {
	return d.key
}
