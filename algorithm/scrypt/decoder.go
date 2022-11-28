package scrypt

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/internal/encoding"
)

// Register the decoder with the crypt.DecoderRegister.
func Register(r crypt.DecoderRegister) (err error) {
	if err = r.Register(AlgName, Decode); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into a crypt.Digest.
func Decode(encodedDigest string) (digest crypt.Digest, err error) {
	var (
		parts []string
	)

	if parts, err = decoderParts(encodedDigest); err != nil {
		return nil, fmt.Errorf(crypt.ErrFmtDigestDecode, AlgName, err)
	}

	if digest, err = decode(parts); err != nil {
		return nil, fmt.Errorf(crypt.ErrFmtDigestDecode, AlgName, err)
	}

	return digest, nil
}

func decoderParts(encodedDigest string) (parts []string, err error) {
	parts = encoding.Split(encodedDigest, -1)

	if len(parts) != 5 {
		return nil, crypt.ErrEncodedHashInvalidFormat
	}

	if parts[1] != AlgName {
		return nil, fmt.Errorf("%w: identifier '%s' is not an encoded %s digest", crypt.ErrEncodedHashInvalidIdentifier, parts[1], AlgName)
	}

	return parts[2:], nil
}

func decode(parts []string) (digest crypt.Digest, err error) {
	decoded := &Digest{
		ln: IterationsDefault,
		r:  BlockSizeDefault,
		p:  ParallelismDefault,
	}

	options, salt, key := parts[0], parts[1], parts[2]

	for _, opt := range strings.Split(options, ",") {
		pair := strings.SplitN(opt, "=", 2)

		if len(pair) != 2 {
			return nil, fmt.Errorf("%w: option '%s' is invalid", crypt.ErrEncodedHashInvalidOption, opt)
		}

		k, v := pair[0], pair[1]

		switch k {
		case oLN:
			decoded.ln, err = strconv.Atoi(v)
		case oR:
			decoded.r, err = strconv.Atoi(v)
		case oP:
			decoded.p, err = strconv.Atoi(v)
		default:
			return nil, fmt.Errorf("%w: option '%s' with value '%s' is unknown", crypt.ErrEncodedHashInvalidOptionKey, k, v)
		}

		if err != nil {
			return nil, fmt.Errorf("%w: option '%s' has invalid value '%s': %v", crypt.ErrEncodedHashInvalidOptionValue, k, v, err)
		}
	}

	if decoded.salt, err = base64.RawStdEncoding.DecodeString(salt); err != nil {
		return nil, fmt.Errorf("%w: %v", crypt.ErrEncodedHashSaltEncoding, err)
	}

	if decoded.key, err = base64.RawStdEncoding.DecodeString(key); err != nil {
		return nil, fmt.Errorf("%w: %v", crypt.ErrEncodedHashKeyEncoding, err)
	}

	return decoded, nil
}
