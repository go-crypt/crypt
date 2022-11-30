package scrypt

import (
	"encoding/base64"
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/encoding"
)

// RegisterDecoder the decoder with the algorithm.DecoderRegister.
func RegisterDecoder(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(AlgName, Decode); err != nil {
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

	if parts[1] != AlgName {
		return nil, fmt.Errorf("%w: identifier '%s' is not an encoded %s digest", algorithm.ErrEncodedHashInvalidIdentifier, parts[1], AlgName)
	}

	return parts[2:], nil
}

func decode(parts []string) (digest algorithm.Digest, err error) {
	decoded := &Digest{
		ln: IterationsDefault,
		r:  BlockSizeDefault,
		p:  ParallelismDefault,
	}

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

	if len(decoded.key) == 0 {
		return nil, fmt.Errorf("%w: key has 0 bytes", algorithm.ErrEncodedHashKeyEncoding)
	}

	return decoded, nil
}
