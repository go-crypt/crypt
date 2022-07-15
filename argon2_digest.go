package crypt

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/argon2"
)

type Argon2Digest struct {
	variant Argon2Variant

	v uint8

	k, m, t, p uint32

	salt, key []byte
}

func (d Argon2Digest) Match(password string) (match bool) {
	if len(d.key) == 0 {
		return false
	}

	return subtle.ConstantTimeCompare(d.key, d.variant.KeyFunc()([]byte(password), d.salt, d.t, d.m, d.p, d.k)) == 1
}

func (d Argon2Digest) Encode() (hash string) {
	prefix := AlgorithmPrefixArgon2id
	switch d.variant {
	case Argon2VariantI:
		prefix = AlgorithmPrefixArgon2i
	case Argon2VariantD:
		prefix = AlgorithmPrefixArgon2d
	}

	return strings.ReplaceAll(fmt.Sprintf(StorageFormatArgon2,
		prefix, argon2.Version,
		d.m, d.t, d.p, d.k,
		b64rs.EncodeToString(d.salt), b64rs.EncodeToString(d.key),
	), "\n", "")
}

var (
	ErrDigestWithIncorrectFormat  = errors.New("provided hash has an invalid format")
	ErrDigestWithIncorrectVariant = errors.New("provided hash has an invalid variant")
)

func (d *Argon2Digest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := splitDigest(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 6 {
		return fmt.Errorf("argon2 error: %w", ErrDigestWithIncorrectFormat)
	}

	variant, version, options, salt, key := NewArgon2Variant(encodedDigestParts[1]), encodedDigestParts[2], encodedDigestParts[3], encodedDigestParts[4], encodedDigestParts[5]

	options += "," + version

	if variant == Argon2VariantNone {
		return fmt.Errorf("argon2 error: %w: %s", ErrDigestWithIncorrectVariant, encodedDigestParts[1])
	}

	d.variant = variant
	d.k = defaultKeySize

	var (
		value   uint64
		bitSize int
	)

	for _, opt := range strings.Split(options, ",") {
		pair := strings.SplitN(opt, "=", 2)

		if len(pair) != 2 {
			return fmt.Errorf("argon2 hash invalid option '%s'", opt)
		}

		k, v := pair[0], pair[1]

		switch k {
		case "v":
			bitSize = 8
		default:
			bitSize = 32
		}

		if value, err = strconv.ParseUint(v, 10, bitSize); err != nil {
			return fmt.Errorf("argon2 option '%s' has invalid value '%s': %w", k, v, err)
		}

		switch k {
		case "v":
			d.v = uint8(value)
		case "k":
			d.k = uint32(value)
		case "m":
			d.m = uint32(value)
		case "t":
			d.t = uint32(value)
		case "p":
			d.p = uint32(value)
		default:
			return fmt.Errorf("argon2 option '%s' with value '%d' is unknown", k, value)
		}
	}

	if d.salt, err = b64rs.DecodeString(salt); err != nil {
		return fmt.Errorf("argon2 salt '%s' could not be decoded: %w", salt, err)
	}

	if d.key, err = b64rs.DecodeString(key); err != nil {
		return fmt.Errorf("argon2 key '%s' could not be decoded: %w", key, err)
	}

	return nil
}

// String returns the storable format of the Argon2Digest hash utilizing fmt.Sprintf and StorageFormatArgon2.
func (d Argon2Digest) String() string {
	return d.Encode()
}
