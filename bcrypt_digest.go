package crypt

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/bcrypt"
)

// BcryptDigest is a digest which handles bcrypt hashes.
type BcryptDigest struct {
	variant BcryptVariant

	cost int

	salt, key []byte
}

// Match returns true if the string password matches the current Digest.
func (d BcryptDigest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current Digest.
func (d BcryptDigest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d BcryptDigest) MatchAdvanced(password string) (match bool, err error) {
	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d BcryptDigest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf("bcrypt match error: %w: key has 0 bytes", ErrPasswordInvalid)
	}

	var key []byte

	password := d.variant.EncodeInput(passwordBytes, d.salt)

	if key, err = bcrypt.Key(password, d.salt, d.cost); err != nil {
		return false, fmt.Errorf("bcrypt match error: %w: %v", ErrKeyDerivation, err)
	}

	return subtle.ConstantTimeCompare(d.key, key) == 1, nil
}

// Encode returns the encoded form of this digest.
func (d *BcryptDigest) Encode() string {
	return d.variant.Encode(d.cost, AlgorithmPrefixBcrypt, bcrypt.Base64Encode(d.salt), d.key)
}

// Decode takes an encodedDigest string and parses it into this Digest.
func (d *BcryptDigest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := splitDigest(encodedDigest, StorageDelimiter)

	countParts := len(encodedDigestParts)

	if countParts < 2 {
		return fmt.Errorf("bcrypt decode error: %w", ErrEncodedHashInvalidFormat)
	}

	var (
		salt, key []byte
	)

	d.variant = NewBcryptVariant(encodedDigestParts[1])

	switch d.variant {
	case BcryptVariantNone:
		return fmt.Errorf("bcrypt decode error: %w: the '%s' identifier is not valid for a bcrypt encoded hash", ErrEncodedHashInvalidIdentifier, encodedDigestParts[1])
	case BcryptVariantStandard:
		if countParts != 4 {
			return fmt.Errorf("bcrypt decode error: %w", ErrEncodedHashInvalidFormat)
		}

		if d.cost, err = strconv.Atoi(encodedDigestParts[2]); err != nil {
			return fmt.Errorf("bcrypt decode error: %w: cost could not be parsed: %v", ErrEncodedHashInvalidOptionValue, err)
		}

		salt, key = bcrypt.DecodeSecret([]byte(encodedDigestParts[3]))
	case BcryptVariantSHA256:
		if countParts != 5 {
			return fmt.Errorf("bcrypt decode error: %w", ErrEncodedHashInvalidFormat)
		}

		var options string

		options, salt, key = encodedDigestParts[2], []byte(encodedDigestParts[3]), []byte(encodedDigestParts[4])

		for _, opt := range strings.Split(options, ",") {
			pair := strings.SplitN(opt, "=", 2)

			if len(pair) != 2 {
				return fmt.Errorf("bcrypt decode error: %w: option '%s' is invalid", ErrEncodedHashInvalidOption, opt)
			}

			k, v := pair[0], pair[1]

			switch k {
			case oV, oT:
				break
			case oR:
				d.cost, err = strconv.Atoi(v)
			default:
				return fmt.Errorf("bcrypt decode error: %w: option '%s' with value '%s' is unknown", ErrEncodedHashInvalidOptionKey, k, v)
			}

			if err != nil {
				return fmt.Errorf("bcrypt decode error: %w: option '%s' has invalid value '%s': %v", ErrEncodedHashInvalidOptionValue, k, v, err)
			}
		}
	}

	if d.salt, err = bcrypt.Base64Decode(salt); err != nil {
		return fmt.Errorf("bcrypt decode error: %w: %+v", ErrEncodedHashSaltEncoding, err)
	}

	d.key = key

	return nil
}

// String returns the storable format of the Digest encoded hash.
func (d BcryptDigest) String() string {
	return d.Encode()
}
