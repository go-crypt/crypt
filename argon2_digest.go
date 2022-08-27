package crypt

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/argon2"
)

// Argon2Digest is a digest which handles Argon2 hashes like Argon2id, Argon2i, and Argon2d.
type Argon2Digest struct {
	variant Argon2Variant

	v uint8

	m, t, p uint32

	salt, key []byte
}

// Match returns true if the string password matches the current Digest.
func (d *Argon2Digest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current Digest.
func (d *Argon2Digest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d *Argon2Digest) MatchAdvanced(password string) (match bool, err error) {
	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d *Argon2Digest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf("argon2 match error: %w: key has 0 bytes", ErrPasswordInvalid)
	}

	return subtle.ConstantTimeCompare(d.key, d.variant.KeyFunc()(passwordBytes, d.salt, d.t, d.m, d.p, uint32(len(d.key)))) == 1, nil
}

// Encode returns the encoded form of this Digest.
func (d *Argon2Digest) Encode() (encodedHash string) {
	return strings.ReplaceAll(fmt.Sprintf(StorageFormatArgon2,
		d.variant.Prefix(), argon2.Version,
		d.m, d.t, d.p,
		b64rs.EncodeToString(d.salt), b64rs.EncodeToString(d.key),
	), "\n", "")
}

// Decode takes an encodedDigest string and parses it into this Digest.
//
//nolint:gocyclo
func (d *Argon2Digest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := splitDigest(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 6 {
		return fmt.Errorf("argon2 decode error: %w", ErrEncodedHashInvalidFormat)
	}

	variant, version, options, salt, key := NewArgon2Variant(encodedDigestParts[1]), encodedDigestParts[2], encodedDigestParts[3], encodedDigestParts[4], encodedDigestParts[5]

	options += "," + version

	if variant == Argon2VariantNone {
		return fmt.Errorf("argon2 decode error: %w: the '%s' identifier is not an argon2 encoded hash", ErrEncodedHashInvalidIdentifier, encodedDigestParts[1])
	}

	d.variant = variant

	var (
		value   uint64
		bitSize int
	)

	for _, opt := range strings.Split(options, ",") {
		pair := strings.SplitN(opt, "=", 2)

		if len(pair) != 2 {
			return fmt.Errorf("argon2 decode error: %w: option '%s' is invalid", ErrEncodedHashInvalidOption, opt)
		}

		k, v := pair[0], pair[1]

		switch k {
		case oV:
			bitSize = 8
		default:
			bitSize = 32
		}

		if value, err = strconv.ParseUint(v, 10, bitSize); err != nil {
			return fmt.Errorf("argon2 decode error: %w: option '%s' has invalid value '%s': %v", ErrEncodedHashInvalidOptionValue, k, v, err)
		}

		switch k {
		case oV:
			d.v = uint8(value)

			if d.v != argon2.Version {
				return fmt.Errorf("argon2 decode error: %w: version %d is supported but encoded hash is version %d", ErrEncodedHashInvalidVersion, argon2.Version, d.v)
			}
		case oK:
			break
		case oM:
			d.m = uint32(value)
		case oT:
			d.t = uint32(value)
		case oP:
			d.p = uint32(value)
		default:
			return fmt.Errorf("argon2 decode error: %w: option '%s' with value '%s' is unknown", ErrEncodedHashInvalidOptionKey, k, v)
		}
	}

	if d.salt, err = b64rs.DecodeString(salt); err != nil {
		return fmt.Errorf("argon2 decode error: %w: %+v", ErrEncodedHashSaltEncoding, err)
	}

	if d.key, err = b64rs.DecodeString(key); err != nil {
		return fmt.Errorf("argon2 decode error: %w: %v", ErrEncodedHashKeyEncoding, err)
	}

	if d.t == 0 {
		d.t = 1
	}

	if d.p == 0 {
		d.p = 4
	}

	if d.m == 0 {
		d.m = 32 * 1024
	}

	return nil
}

// String returns the storable format of the Digest encoded hash.
func (d *Argon2Digest) String() string {
	return d.Encode()
}
