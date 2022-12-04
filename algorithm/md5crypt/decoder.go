package md5crypt

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// RegisterDecoder the decoder with the algorithm.DecoderRegister.
func RegisterDecoder(r algorithm.DecoderRegister) (err error) {
	if err = RegisterDecoderCommon(r); err != nil {
		return err
	}

	if err = RegisterDecoderSun(r); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderCommon registers specifically the common decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderCommon(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantStandard.Prefix(), DecodeVariant(VariantStandard)); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderSun registers specifically the sun decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderSun(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantSun.Prefix(), DecodeVariant(VariantSun)); err != nil {
		return err
	}

	if err = r.RegisterDecodePrefix("$md5,", VariantSun.Prefix()); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into a algorithm.Digest.
func Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	return DecodeVariant(VariantNone)(encodedDigest)
}

// DecodeVariant the encoded digest into a algorithm.Digest provided it matches the provided Variant. If VariantNone is
// used all variants can be decoded.
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
	partsTemp := encoding.Split(encodedDigest, -1)

	p := len(partsTemp)

	if p != 4 && p != 5 {
		return VariantNone, nil, algorithm.ErrEncodedHashInvalidFormat
	}

	switch partsTemp[1] {
	case AlgIdentifier:
		if p != 4 {
			return VariantNone, nil, algorithm.ErrEncodedHashInvalidFormat
		}
	default:
		if p != 5 {
			return VariantNone, nil, algorithm.ErrEncodedHashInvalidFormat
		}
	}

	if strings.HasPrefix(partsTemp[1], "md5,") {
		parts = append([]string{strings.SplitN(partsTemp[1], ",", 2)[1]}, partsTemp[2:]...)

		variant = VariantSun
	} else {
		switch variant = NewVariant(partsTemp[1]); variant {
		case VariantNone:
			return variant, nil, fmt.Errorf("%w: identifier '%s' is not an encoded %s digest", algorithm.ErrEncodedHashInvalidIdentifier, partsTemp[1], AlgName)
		default:
			parts = append([]string{""}, partsTemp[2:]...)
		}
	}

	return variant, parts, nil
}

func decode(variant Variant, parts []string) (digest algorithm.Digest, err error) {
	decoded := &Digest{
		variant: variant,
	}

	decoded.variant = variant

	var params []encoding.Parameter

	if parts[0] != "" {
		if variant != VariantSun {
			return nil, fmt.Errorf("%w: parameters are only valid for the %s variant but the %s variant was decoded", algorithm.ErrParameterInvalid, VariantSun.String(), variant.String())
		}

		if params, err = encoding.DecodeParameterStr(parts[0]); err != nil {
			return nil, err
		}

		for _, param := range params {
			switch param.Key {
			case "rounds":
				var value uint64

				if value, err = strconv.ParseUint(param.Value, 10, 32); err != nil {
					return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", algorithm.ErrEncodedHashInvalidOptionValue, param.Key, param.Value, err)
				}

				decoded.iterations = uint32(value)
			default:
				return nil, fmt.Errorf("%w: option '%s' with value '%s' is unknown", algorithm.ErrEncodedHashInvalidOptionKey, param.Key, param.Value)
			}
		}
	}

	switch variant {
	case VariantSun:
		decoded.salt, decoded.key = []byte(parts[1]), []byte(parts[3])
	default:
		decoded.salt, decoded.key = []byte(parts[1]), []byte(parts[2])
	}

	return decoded, nil
}
