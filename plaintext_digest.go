package crypt

import (
	"crypto/subtle"
	"fmt"
	"strings"
)

// PlainTextDigest is a digest which handles plain text matching.
type PlainTextDigest struct {
	variant PlainTextVariant

	key []byte
}

// Match returns true if the string password matches the current Digest.
func (d PlainTextDigest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current Digest.
func (d PlainTextDigest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d PlainTextDigest) MatchAdvanced(password string) (match bool, err error) {
	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d PlainTextDigest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf("plaintext match error: key has 0 bytes")
	}

	return subtle.ConstantTimeCompare(d.key, passwordBytes) == 1, nil
}

// Encode returns the encoded form of this digest.
func (d *PlainTextDigest) Encode() string {
	return fmt.Sprintf(StorageFormatSimple, d.variant.String(), d.variant.Encode(d.key))
}

// Decode takes an encodedDigest string and parses it into this Digest.
func (d *PlainTextDigest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := strings.Split(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 3 {
		return fmt.Errorf("plaintext decode error: %w", ErrEncodedHashInvalidFormat)
	}

	variant, key := NewPlainTextVariant(encodedDigestParts[1]), encodedDigestParts[2]

	if variant == PlainTextVariantNone {
		return fmt.Errorf("plaintext decode error: %w: the '%s' identifier is not a plaintext encoded hash", ErrEncodedHashInvalidIdentifier, encodedDigestParts[1])
	}

	if d.key, err = variant.Decode(key); err != nil {
		return fmt.Errorf("plaintext decode error: %w: %v", ErrEncodedHashKeyEncoding, err)
	}

	return nil
}

// String returns the storable format of the Digest encoded hash.
func (d PlainTextDigest) String() string {
	return d.Encode()
}
