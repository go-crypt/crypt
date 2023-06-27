package bcrypt

import (
	"fmt"
	"strconv"

	"github.com/go-crypt/x/bcrypt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// RegisterDecoder the decoder with the algorithm.DecoderRegister.
func RegisterDecoder(r algorithm.DecoderRegister) (err error) {
	if err = RegisterDecoderStandard(r); err != nil {
		return err
	}

	if err = RegisterDecoderSHA256(r); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderStandard registers specifically the standard decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderStandard(r algorithm.DecoderRegister) (err error) {
	decodefunc := DecodeVariant(VariantStandard)

	if err = r.RegisterDecodeFunc(VariantStandard.Prefix(), decodefunc); err != nil {
		return err
	}

	if err = r.RegisterDecodeFunc(AlgIdentifierVerA, decodefunc); err != nil {
		return err
	}

	if err = r.RegisterDecodeFunc(AlgIdentifierVerX, decodefunc); err != nil {
		return err
	}

	if err = r.RegisterDecodeFunc(AlgIdentifierVerY, decodefunc); err != nil {
		return err
	}

	if err = r.RegisterDecodeFunc(AlgIdentifierUnversioned, decodefunc); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderSHA256 registers specifically the sha256 decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderSHA256(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantSHA256.Prefix(), DecodeVariant(VariantSHA256)); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into a algorithm.Digest.
func Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	return DecodeVariant(VariantNone)(encodedDigest)
}

// DecodeVariant the encoded digest into a algorithm.Digest provided it matches the provided bcrypt.Variant. If
// bcrypt.VariantNone is used all variants can be decoded.
func DecodeVariant(v Variant) func(encodedDigest string) (digest algorithm.Digest, err error) {
	return func(encodedDigest string) (digest algorithm.Digest, err error) {
		var (
			parts   []string
			variant Variant
		)

		if variant, parts, err = decoderParts(encodedDigest); err != nil {
			return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, err)
		}

		if v != VariantNone && v != variant {
			return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, fmt.Errorf("the '%s' variant cannot be decoded only the '%s' variant can be", variant.String(), v.String()))
		}

		if digest, err = decode(variant, parts); err != nil {
			return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, err)
		}

		return digest, nil
	}
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

		if decoded.iterations, err = strconv.Atoi(parts[0]); err != nil {
			return nil, fmt.Errorf("%w: iterations could not be parsed: %v", algorithm.ErrEncodedHashInvalidOptionValue, err)
		}

		switch n, i := len(parts[1]), bcrypt.EncodedSaltSize+bcrypt.EncodedHashSize; n {
		case i:
			break
		case 0:
			return nil, fmt.Errorf("%w: key is expected to be %d bytes but it was empty", algorithm.ErrEncodedHashKeyEncoding, i)
		default:
			return nil, fmt.Errorf("%w: key is expected to be %d bytes but it has %d bytes", algorithm.ErrEncodedHashKeyEncoding, i, n)
		}

		salt, key = bcrypt.DecodeSecret([]byte(parts[1]))
	case VariantSHA256:
		if countParts != 3 {
			return nil, algorithm.ErrEncodedHashInvalidFormat
		}

		salt, key = []byte(parts[1]), []byte(parts[2])

		switch n := len(salt); n {
		case bcrypt.EncodedSaltSize:
			break
		case 0:
			return nil, fmt.Errorf("%w: salt is expected to be %d bytes but it was empty", algorithm.ErrEncodedHashSaltEncoding, bcrypt.EncodedSaltSize)
		default:
			return nil, fmt.Errorf("%w: salt is expected to be %d bytes but it has %d bytes", algorithm.ErrEncodedHashSaltEncoding, bcrypt.EncodedSaltSize, n)
		}

		switch n := len(key); n {
		case bcrypt.EncodedHashSize:
			break
		case 0:
			return nil, fmt.Errorf("%w: key is expected to be %d bytes but it was empty", algorithm.ErrEncodedHashKeyEncoding, bcrypt.EncodedHashSize)
		default:
			return nil, fmt.Errorf("%w: key is expected to be %d bytes but it has %d bytes", algorithm.ErrEncodedHashKeyEncoding, bcrypt.EncodedHashSize, n)
		}

		var params []encoding.Parameter

		if params, err = encoding.DecodeParameterStr(parts[0]); err != nil {
			return nil, err
		}

		for _, param := range params {
			switch param.Key {
			case oV, oT:
				break
			case oR:
				decoded.iterations, err = param.Int()
			default:
				return nil, fmt.Errorf("%w: option '%s' with value '%s' is unknown", algorithm.ErrEncodedHashInvalidOptionKey, param.Key, param.Value)
			}

			if err != nil {
				return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", algorithm.ErrEncodedHashInvalidOptionValue, param.Key, param.Value, err)
			}
		}
	}

	if decoded.salt, err = bcrypt.Base64Decode(salt); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrEncodedHashSaltEncoding, err)
	}

	if len(key) == 0 {
		return nil, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrEncodedHashKeyEncoding)
	}

	decoded.key = key

	return decoded, nil
}
