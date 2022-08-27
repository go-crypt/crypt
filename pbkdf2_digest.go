package crypt

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/pbkdf2"
)

// PBKDF2Digest is a Digest which handles PBKDF2 hashes.
type PBKDF2Digest struct {
	variant PBKDF2Variant

	iterations int
	k          int
	salt, key  []byte
}

// Match returns true if the string password matches the current Digest.
func (d *PBKDF2Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current Digest.
func (d *PBKDF2Digest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d *PBKDF2Digest) MatchAdvanced(password string) (match bool, err error) {
	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d *PBKDF2Digest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf("pbkdf2 match error: %w: key has 0 bytes", ErrPasswordInvalid)
	}

	return subtle.ConstantTimeCompare(d.key, pbkdf2.Key(passwordBytes, d.salt, d.iterations, d.k, d.variant.HashFunc())) == 1, nil
}

// Encode returns the encoded form of this digest.
func (d *PBKDF2Digest) Encode() string {
	return fmt.Sprintf(StorageFormatPBKDF2,
		d.variant.Prefix(),
		d.iterations,
		b64ra.EncodeToString(d.salt), b64ra.EncodeToString(d.key),
	)
}

// Decode takes an encodedDigest string and parses it into this Digest.
func (d *PBKDF2Digest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := strings.Split(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 5 {
		return fmt.Errorf("pbkdf2 decode error: %w", ErrEncodedHashInvalidFormat)
	}

	variant, iterations, salt, key := NewPBKDF2Variant(encodedDigestParts[1]), encodedDigestParts[2], encodedDigestParts[3], encodedDigestParts[4]

	if variant == PBKDF2VariantNone {
		return fmt.Errorf("pbkdf2 decode error: %w: the '%s' identifier is not a pbkdf2 encoded hash", ErrEncodedHashInvalidIdentifier, encodedDigestParts[1])
	}

	d.variant = variant

	if d.iterations, err = strconv.Atoi(iterations); err != nil {
		return fmt.Errorf("pbkdf2 decode error: %w: iterations could not be parsed: %v", ErrEncodedHashInvalidOptionValue, err)
	}

	if d.salt, err = b64ra.DecodeString(salt); err != nil {
		return fmt.Errorf("pbkdf2 decode error: %w: %+v", ErrEncodedHashSaltEncoding, err)
	}

	if d.key, err = b64ra.DecodeString(key); err != nil {
		return fmt.Errorf("pbkdf2 decode error: %w: %v", ErrEncodedHashKeyEncoding, err)
	}

	d.k = len(d.key)

	return nil
}

// String returns the storable format of the Digest encoded hash.
func (d *PBKDF2Digest) String() string {
	return d.Encode()
}
