package pbkdf2

import (
	"fmt"
	"strconv"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// RegisterDecoder the decoder with the algorithm.DecoderRegister.
func RegisterDecoder(r algorithm.DecoderRegister) (err error) {
	if err = RegisterDecoderSHA1(r); err != nil {
		return err
	}

	if err = RegisterDecoderSHA224(r); err != nil {
		return err
	}

	if err = RegisterDecoderSHA256(r); err != nil {
		return err
	}

	if err = RegisterDecoderSHA384(r); err != nil {
		return err
	}

	if err = RegisterDecoderSHA512(r); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderSHA1 registers specifically the sha1 decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderSHA1(r algorithm.DecoderRegister) (err error) {
	decodefunc := DecodeVariant(VariantSHA1)

	if err = r.RegisterDecodeFunc(VariantSHA1.Prefix(), decodefunc); err != nil {
		return err
	}

	if err = r.RegisterDecodeFunc(AlgIdentifierSHA1, decodefunc); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderSHA224 registers specifically the sha224 decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderSHA224(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantSHA224.Prefix(), DecodeVariant(VariantSHA224)); err != nil {
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

// RegisterDecoderSHA384 registers specifically the sha384 decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderSHA384(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantSHA384.Prefix(), DecodeVariant(VariantSHA384)); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderSHA512 registers specifically the sha512 decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderSHA512(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(VariantSHA512.Prefix(), DecodeVariant(VariantSHA512)); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into a algorithm.Digest.
func Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	return DecodeVariant(VariantNone)(encodedDigest)
}

// DecodeVariant the encoded digest into a algorithm.Digest provided it matches the provided pbkdf2.Variant. If
// pbkdf2.VariantNone is used all variants can be decoded.
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
	}

	decoded.variant = variant

	if decoded.iterations, err = strconv.Atoi(parts[0]); err != nil {
		return nil, fmt.Errorf("%w: iterations could not be parsed: %v", algorithm.ErrEncodedHashInvalidOptionValue, err)
	}

	if decoded.salt, err = encoding.Base64RawAdaptedEncoding.DecodeString(parts[1]); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrEncodedHashSaltEncoding, err)
	}

	if decoded.key, err = encoding.Base64RawAdaptedEncoding.DecodeString(parts[2]); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrEncodedHashKeyEncoding, err)
	}

	decoded.t = len(decoded.key)

	if decoded.t == 0 {
		return nil, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrEncodedHashKeyEncoding)
	}

	return decoded, nil
}
