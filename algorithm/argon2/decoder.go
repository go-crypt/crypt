package argon2

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/go-crypt/x/argon2"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// RegisterDecoder the decoder with the algorithm.DecoderRegister.
func RegisterDecoder(r algorithm.DecoderRegister) (err error) {
	if err = RegisterDecoderArgon2id(r); err != nil {
		return err
	}

	if err = RegisterDecoderArgon2i(r); err != nil {
		return err
	}

	if err = RegisterDecoderArgon2d(r); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderArgon2id registers specifically the argon2id decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderArgon2id(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantID.Prefix(), DecodeVariant(VariantID)); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderArgon2i registers specifically the argon2i decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderArgon2i(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantI.Prefix(), DecodeVariant(VariantI)); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderArgon2d registers specifically the argon2d decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderArgon2d(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantD.Prefix(), DecodeVariant(VariantD)); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into a algorithm.Digest.
func Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	return DecodeVariant(VariantNone)(encodedDigest)
}

// DecodeVariant the encoded digest into a algorithm.Digest provided it matches the provided argon2.Variant. If
// argon2.VariantNone is used all variants can be decoded.
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

	if len(parts) != 6 {
		return VariantNone, nil, algorithm.ErrEncodedHashInvalidFormat
	}

	variant = NewVariant(parts[1])

	if variant == VariantNone {
		return variant, nil, fmt.Errorf("%w: identifier '%s' is not an encoded %s digest", algorithm.ErrEncodedHashInvalidIdentifier, parts[1], AlgName)
	}

	return variant, parts[2:], nil
}

//nolint:gocyclo
func decode(variant Variant, parts []string) (digest algorithm.Digest, err error) {
	decoded := &Digest{
		variant: variant,
	}

	var (
		value   uint64
		bitSize int
	)

	var params []encoding.Parameter

	if params, err = encoding.DecodeParameterStr(parts[1] + "," + parts[0]); err != nil {
		return nil, err
	}

	for _, param := range params {
		switch param.Key {
		case oV:
			bitSize = 8
		default:
			bitSize = 32
		}

		if value, err = strconv.ParseUint(param.Value, 10, bitSize); err != nil {
			return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", algorithm.ErrEncodedHashInvalidOptionValue, param.Key, param.Value, err)
		}

		switch param.Key {
		case oV:
			decoded.v = uint8(value)

			if decoded.v != argon2.Version {
				return nil, fmt.Errorf("%w: version %d is supported but encoded hash is version %d", algorithm.ErrEncodedHashInvalidVersion, argon2.Version, decoded.v)
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
			return nil, fmt.Errorf("%w: option '%s' with value '%s' is unknown", algorithm.ErrEncodedHashInvalidOptionKey, param.Key, param.Value)
		}
	}

	if decoded.salt, err = base64.RawStdEncoding.DecodeString(parts[2]); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrEncodedHashSaltEncoding, err)
	}

	if decoded.key, err = base64.RawStdEncoding.DecodeString(parts[3]); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrEncodedHashKeyEncoding, err)
	}

	if len(decoded.key) == 0 {
		return nil, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrEncodedHashKeyEncoding)
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
