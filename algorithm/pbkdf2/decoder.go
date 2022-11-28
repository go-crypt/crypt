package pbkdf2

import (
	"fmt"
	"strconv"

	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/internal/encoding"
)

// Register the decoder with the crypt.DecoderRegister.
func Register(r crypt.DecoderRegister) (err error) {
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
	iterations, salt, key := parts[0], parts[1], parts[2]

	decoded := &Digest{
		variant: variant,
	}

	decoded.variant = variant

	if decoded.iterations, err = strconv.Atoi(iterations); err != nil {
		return nil, fmt.Errorf("%w: iterations could not be parsed: %v", crypt.ErrEncodedHashInvalidOptionValue, err)
	}

	if decoded.salt, err = encoding.Base64RawAdaptedEncoding.DecodeString(salt); err != nil {
		return nil, fmt.Errorf("%w: %v", crypt.ErrEncodedHashSaltEncoding, err)
	}

	if decoded.key, err = encoding.Base64RawAdaptedEncoding.DecodeString(key); err != nil {
		return nil, fmt.Errorf("%w: %v", crypt.ErrEncodedHashKeyEncoding, err)
	}

	decoded.k = len(decoded.key)

	return decoded, nil
}
