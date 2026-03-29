package descrypt

import (
	"fmt"
	"strings"

	"github.com/go-crypt/crypt/algorithm"
)

// RegisterDecoder registers the descrypt decoder with the algorithm.DecoderRegister.
func RegisterDecoder(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc(AlgName, Decode); err != nil {
		return err
	}

	return nil
}

// Decode the encoded digest into an algorithm.Digest.
func Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	if len(encodedDigest) != DigestLength {
		return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, fmt.Errorf("%w: digest must be exactly %d characters but has %d", algorithm.ErrEncodedHashInvalidFormat, DigestLength, len(encodedDigest)))
	}

	for i, c := range encodedDigest {
		if !strings.ContainsRune(SaltCharSet, c) {
			return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, fmt.Errorf("%w: invalid character at position %d", algorithm.ErrEncodedHashInvalidFormat, i))
		}
	}

	salt := []byte(encodedDigest[:SaltLength])
	key := []byte(encodedDigest[SaltLength:])

	d := &Digest{
		salt: salt,
		key:  key,
	}

	return d, nil
}
