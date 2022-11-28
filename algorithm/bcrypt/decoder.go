package bcrypt

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/bcrypt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// Register the decoder with the algorithm.DecoderRegister.
func Register(r algorithm.DecoderRegister) (err error) {
	if err = r.Register(AlgIdentifier, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierVariantSHA256, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierVerA, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierVerX, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierVerY, Decode); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into a algorithm.Digest.
func Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	var (
		parts   []string
		variant Variant
	)

	if variant, parts, err = decoderParts(encodedDigest); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, err)
	}

	if digest, err = decode(variant, parts); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, err)
	}

	return digest, nil
}

func decoderParts(encodedDigest string) (variant Variant, parts []string, err error) {
	parts = encoding.Split(encodedDigest, -1)

	if len(parts) < 4 {
		return VariantNone, nil, algorithm.ErrEncodedHashInvalidFormat
	}

	variant = NewVariant(parts[1])

	if variant == VariantNone {
		return variant, nil, fmt.Errorf("%w: identifier '%s' is not an encoded %s digest", algorithm.ErrEncodedHashInvalidIdentifier, parts[1], AlgName)
	}

	return variant, parts[2:], nil
}

func decode(variant Variant, parts []string) (digest algorithm.Digest, err error) {
	countParts := len(parts)

	var (
		salt, key []byte
	)

	decoded := &Digest{
		variant: variant,
	}

	switch decoded.variant {
	case VariantStandard:
		if countParts != 2 {
			return nil, algorithm.ErrEncodedHashInvalidFormat
		}

		if decoded.cost, err = strconv.Atoi(parts[0]); err != nil {
			return nil, fmt.Errorf("%w: cost could not be parsed: %v", algorithm.ErrEncodedHashInvalidOptionValue, err)
		}

		salt, key = bcrypt.DecodeSecret([]byte(parts[1]))
	case VariantSHA256:
		if countParts != 3 {
			return nil, algorithm.ErrEncodedHashInvalidFormat
		}

		var options string

		options, salt, key = parts[0], []byte(parts[1]), []byte(parts[2])

		for _, opt := range strings.Split(options, ",") {
			pair := strings.SplitN(opt, "=", 2)

			if len(pair) != 2 {
				return nil, fmt.Errorf("%w: option '%s' is invalid", algorithm.ErrEncodedHashInvalidOption, opt)
			}

			k, v := pair[0], pair[1]

			switch k {
			case oV, oT:
				break
			case oR:
				decoded.cost, err = strconv.Atoi(v)
			default:
				return nil, fmt.Errorf("%w: option '%s' with value '%s' is unknown", algorithm.ErrEncodedHashInvalidOptionKey, k, v)
			}

			if err != nil {
				return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", algorithm.ErrEncodedHashInvalidOptionValue, k, v, err)
			}
		}
	}

	if decoded.salt, err = bcrypt.Base64Decode(salt); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrEncodedHashSaltEncoding, err)
	}

	decoded.key = key

	return decoded, nil
}
