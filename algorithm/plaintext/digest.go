package plaintext

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-crypt/crypt"
)

// NewDigest creates a new plaintext.Digest using the PlainText Variant.
func NewDigest(password string) (digest Digest) {
	digest = Digest{
		variant: VariantPlainText,
		key:     []byte(password),
	}

	return digest
}

// NewBase64Digest creates a new Digest using the Base64 Variant.
func NewBase64Digest(password string) (digest Digest) {
	digest = Digest{
		variant: VariantBase64,
		key:     []byte(password),
	}

	return digest
}

// Digest is a Digest which handles plain text matching.
type Digest struct {
	variant Variant

	key []byte
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
	if len(d.key) == 0 {
		return false, fmt.Errorf("plaintext match error: %w: key has 0 bytes", crypt.ErrPasswordInvalid)
	}

	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d *Digest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf("plaintext match error: key has 0 bytes")
	}

	return subtle.ConstantTimeCompare(d.key, passwordBytes) == 1, nil
}

// Encode returns the encoded form of this digest.
func (d *Digest) Encode() string {
	return fmt.Sprintf(EncodingFmt, d.variant.Prefix(), d.variant.Encode(d.key))
}

// String returns the storable format of the Digest encoded hash.
func (d *Digest) String() string {
	return d.Encode()
}
