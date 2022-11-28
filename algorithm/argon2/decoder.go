package argon2

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/argon2"

	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/internal/encoding"
)

// Register the decoder with the crypt.DecoderRegister.
func Register(r crypt.DecoderRegister) (err error) {
	if err = r.Register(AlgIdentifierVariantID, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierVariantI, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierVariantD, Decode); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into a crypt.Digest.
func Decode(encodedDigest string) (digest crypt.Digest, err error) {
	var (
		parts   []string
		variant Variant
	)

	if variant, parts, err = decoderParts(encodedDigest); err != nil {
		return nil, fmt.Errorf(crypt.ErrFmtDigestDecode, AlgName, err)
	}

	if digest, err = decode(variant, parts); err != nil {
		return nil, fmt.Errorf(crypt.ErrFmtDigestDecode, AlgName, err)
	}

	return digest, nil
}

func decoderParts(encodedDigest string) (variant Variant, parts []string, err error) {
	parts = encoding.Split(encodedDigest, -1)

	if len(parts) != 6 {
		return VariantNone, nil, crypt.ErrEncodedHashInvalidFormat
	}

	variant = NewVariant(parts[1])

	if variant == VariantNone {
		return variant, nil, fmt.Errorf("%w: identifier '%s' is not an encoded %s digest", crypt.ErrEncodedHashInvalidIdentifier, parts[1], AlgName)
	}

	return variant, parts[2:], nil
}

func decode(variant Variant, parts []string) (digest crypt.Digest, err error) {
	version, options, salt, key := parts[0], parts[1], parts[2], parts[3]

	options += "," + version

	decoded := &Digest{
		variant: variant,
	}

	var (
		value   uint64
		bitSize int
	)

	for _, opt := range strings.Split(options, ",") {
		pair := strings.SplitN(opt, "=", 2)

		if len(pair) != 2 {
			return nil, fmt.Errorf("%w: option '%s' is invalid", crypt.ErrEncodedHashInvalidOption, opt)
		}

		k, v := pair[0], pair[1]

		switch k {
		case oV:
			bitSize = 8
		default:
			bitSize = 32
		}

		if value, err = strconv.ParseUint(v, 10, bitSize); err != nil {
			return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", crypt.ErrEncodedHashInvalidOptionValue, k, v, err)
		}

		switch k {
		case oV:
			decoded.v = uint8(value)

			if decoded.v != argon2.Version {
				return nil, fmt.Errorf("%w: version %d is supported but encoded hash is version %d", crypt.ErrEncodedHashInvalidVersion, argon2.Version, decoded.v)
			}
		case oK:
			break
		case oM:
			decoded.m = uint32(value)
		case oT:
			decoded.t = uint32(value)
		case oP:
			decoded.p = uint32(value)
		default:
			return nil, fmt.Errorf("%w: option '%s' with value '%s' is unknown", crypt.ErrEncodedHashInvalidOptionKey, k, v)
		}
	}

	if decoded.salt, err = base64.RawStdEncoding.DecodeString(salt); err != nil {
		return nil, fmt.Errorf("%w: %v", crypt.ErrEncodedHashSaltEncoding, err)
	}

	if decoded.key, err = base64.RawStdEncoding.DecodeString(key); err != nil {
		return nil, fmt.Errorf("%w: %v", crypt.ErrEncodedHashKeyEncoding, err)
	}

	if decoded.t == 0 {
		decoded.t = 1
	}

	if decoded.p == 0 {
		decoded.p = 4
	}

	if decoded.m == 0 {
		decoded.m = 32 * 1024
	}

	return decoded, nil
}
