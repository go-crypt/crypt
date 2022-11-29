package sha2crypt

import (
	"fmt"
	"strconv"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// Register the decoder with the algorithm.DecoderRegister.
func Register(reg algorithm.DecoderRegister) (err error) {
	if err = reg.Register(AlgIdentifierSHA256, Decode); err != nil {
		return err
	}

	if err = reg.Register(AlgIdentifierSHA512, Decode); err != nil {
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

	if len(parts) != 5 {
		return VariantNone, nil, algorithm.ErrEncodedHashInvalidFormat
	}

	variant = NewVariant(parts[1])

	if variant == VariantNone {
		return variant, nil, fmt.Errorf("%w: identifier '%s' is not an encoded %s digest", algorithm.ErrEncodedHashInvalidIdentifier, parts[1], AlgName)
	}

	return variant, parts[2:], nil
}

func decode(variant Variant, parts []string) (digest algorithm.Digest, err error) {
	decoded := &Digest{
		variant: variant,
	}

	if len(parts[2]) == 0 {
		return nil, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrEncodedHashKeyEncoding)
	}

	var params []encoding.Parameter

	if params, err = encoding.DecodeParameterStr(parts[0]); err != nil {
		return nil, err
	}

	for _, param := range params {
		switch param.Key {
		case "rounds":
			var rounds uint64

			if rounds, err = strconv.ParseUint(param.Value, 10, 32); err != nil {
				return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", algorithm.ErrEncodedHashInvalidOptionValue, param.Key, param.Value, err)
			}

			decoded.rounds = int(rounds)
		default:
			return nil, fmt.Errorf("%w: option '%s' with value '%s' is unknown", algorithm.ErrEncodedHashInvalidOptionKey, param.Key, param.Value)
		}
	}

	decoded.salt, decoded.key = []byte(parts[1]), []byte(parts[2])

	return decoded, nil
}
