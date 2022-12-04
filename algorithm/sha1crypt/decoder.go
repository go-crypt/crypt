package sha1crypt

import (
	"fmt"
	"strconv"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// RegisterDecoder the decoder with the algorithm.DecoderRegister.
func RegisterDecoder(r algorithm.DecoderRegister) (err error) {
	if err = RegisterDecoderCommon(r); err != nil {
		return err
	}

	return nil
}

// RegisterDecoderCommon registers specifically the common decoder variant with the algorithm.DecoderRegister.
func RegisterDecoderCommon(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(AlgIdentifier, Decode); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into a algorithm.Digest.
func Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	var (
		parts []string
	)

	if parts, err = decoderParts(encodedDigest); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, err)
	}

	if digest, err = decode(parts); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, err)
	}

	return digest, nil
}

func decoderParts(encodedDigest string) (parts []string, err error) {
	parts = encoding.Split(encodedDigest, -1)

	if len(parts) != 5 {
		return nil, algorithm.ErrEncodedHashInvalidFormat
	}

	if parts[1] != AlgIdentifier {
		return nil, fmt.Errorf("%w: identifier '%s' is not an encoded %s digest", algorithm.ErrEncodedHashInvalidIdentifier, parts[1], AlgName)
	}

	return parts[2:], nil
}

func decode(parts []string) (digest algorithm.Digest, err error) {
	decoded := &Digest{}

	if parts[0] != "" {
		var iterations uint64

		if iterations, err = strconv.ParseUint(parts[0], 10, 32); err != nil {
			return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", algorithm.ErrEncodedHashInvalidOptionValue, "rounds", parts[0], err)
		}

		decoded.iterations = uint32(iterations)
	}

	decoded.salt, decoded.key = []byte(parts[1]), []byte(parts[2])

	return decoded, nil
}
