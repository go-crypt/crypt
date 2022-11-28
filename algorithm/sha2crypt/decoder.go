package sha2crypt

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/internal/encoding"
)

// Register the decoder with the crypt.DecoderRegister.
func Register(reg crypt.DecoderRegister) (err error) {
	if err = reg.Register(AlgIdentifierSHA256, Decode); err != nil {
		return err
	}

	if err = reg.Register(AlgIdentifierSHA512, Decode); err != nil {
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

	if len(parts) != 5 {
		return VariantNone, nil, crypt.ErrEncodedHashInvalidFormat
	}

	variant = NewVariant(parts[1])

	if variant == VariantNone {
		return variant, nil, fmt.Errorf("%w: identifier '%s' is not an encoded %s digest", crypt.ErrEncodedHashInvalidIdentifier, parts[1], AlgName)
	}

	return variant, parts[2:], nil
}

func decode(variant Variant, parts []string) (digest crypt.Digest, err error) {
	decoded := &Digest{
		variant: variant,
	}

	options, salt, key := parts[0], parts[1], parts[2]

	for _, opt := range strings.Split(options, ",") {
		pair := strings.SplitN(opt, "=", 2)

		if len(pair) != 2 {
			return nil, fmt.Errorf("%w: option '%s' is invalid", crypt.ErrEncodedHashInvalidOption, opt)
		}

		k, v := pair[0], pair[1]

		switch k {
		case "rounds":
			var rounds uint64

			if rounds, err = strconv.ParseUint(v, 10, 32); err != nil {
				return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", crypt.ErrEncodedHashInvalidOptionValue, k, v, err)
			}

			decoded.rounds = int(rounds)
		default:
			return nil, fmt.Errorf("%w: option '%s' with value '%s' is unknown", crypt.ErrEncodedHashInvalidOptionKey, k, v)
		}
	}

	decoded.salt, decoded.key = []byte(salt), []byte(key)

	return decoded, nil
}
