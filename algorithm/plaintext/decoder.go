package plaintext

import (
	"fmt"

	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/internal/encoding"
)

// Register the decoder with the crypt.DecoderRegister.
func Register(r crypt.DecoderRegister) (err error) {
	if err = r.Register(AlgIdentifierPlainText, Decode); err != nil {
		return err
	}

	if err = r.Register(AlgIdentifierBase64, Decode); err != nil {
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
	parts = encoding.Split(encodedDigest, 3)

	if len(parts) != 3 {
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

	if decoded.key, err = decoded.variant.Decode(parts[0]); err != nil {
		return nil, fmt.Errorf("%w: %v", crypt.ErrEncodedHashKeyEncoding, err)
	}

	return decoded, nil
}
