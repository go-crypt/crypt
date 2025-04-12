package scrypt

import (
	"encoding/base64"
	"fmt"

	"github.com/go-crypt/x/yescrypt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// RegisterDecoder the decoder with the algorithm.DecoderRegister.
func RegisterDecoder(r algorithm.DecoderRegister) (err error) {
	if err = RegisterDecoderScrypt(r); err != nil {
		return err
	}

	if err = RegisterDecoderYescrypt(r); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderScrypt the scrypt decoder with the algorithm.DecoderRegister.
func RegisterDecoderScrypt(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantScrypt.Prefix(), Decode); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderYescrypt the yescrypt decoder with the algorithm.DecoderRegister.
func RegisterDecoderYescrypt(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantYescrypt.Prefix(), Decode); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into a algorithm.Digest.
func Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	return DecodeVariant(VariantNone)(encodedDigest)
}

// DecodeVariant the encoded digest into a algorithm.Digest provided it matches the provided scrypt.Variant. If
// scrypt.VariantNone is used all variants can be decoded.
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
		ln:      IterationsDefault,
		r:       BlockSizeDefault,
		p:       ParallelismDefault,
	}

	switch variant {
	case VariantYescrypt:
		if _, decoded.ln, decoded.r, err = yescrypt.DecodeSetting([]byte(parts[0])); err != nil {
			return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, err)
		}

		decoded.salt, decoded.key = yescrypt.Decode64([]byte(parts[1])), yescrypt.Decode64([]byte(parts[2]))
	default:
		var params []encoding.Parameter

		if params, err = encoding.DecodeParameterStr(parts[0]); err != nil {
			return nil, err
		}

		for _, param := range params {
			switch param.Key {
			case oLN:
				decoded.ln, err = param.Int()
			case oR:
				decoded.r, err = param.Int()
			case oP:
				decoded.p, err = param.Int()
			default:
				return nil, fmt.Errorf("%w: option '%s' with value '%s' is unknown", algorithm.ErrEncodedHashInvalidOptionKey, param.Key, param.Value)
			}

			if err != nil {
				return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", algorithm.ErrEncodedHashInvalidOptionValue, param.Key, param.Value, err)
			}
		}

		if decoded.salt, err = base64.RawStdEncoding.DecodeString(parts[1]); err != nil {
			return nil, fmt.Errorf("%w: %v", algorithm.ErrEncodedHashSaltEncoding, err)
		}

		if decoded.key, err = base64.RawStdEncoding.DecodeString(parts[2]); err != nil {
			return nil, fmt.Errorf("%w: %v", algorithm.ErrEncodedHashKeyEncoding, err)
		}
	}

	if len(decoded.key) == 0 {
		return nil, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrEncodedHashKeyEncoding)
	}

	return decoded, nil
}
