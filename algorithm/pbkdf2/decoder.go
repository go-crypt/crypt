package pbkdf2

import (
	"fmt"
	"strconv"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// Register the decoder with the algorithm.DecoderRegister.
func Register(r algorithm.DecoderRegister) (err error) {
	if err = r.Register(AlgIdentifier, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierSHA1, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierSHA224, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierSHA256, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierSHA384, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierSHA512, Decode); err != nil {
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
