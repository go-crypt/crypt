package crypt

import (
	"github.com/go-crypt/crypt/algorithm"
)

// The global Decoder. This is utilized by the Decode function.
var gdecoder *Decoder

// Decode is a convenience function which wraps the Decoder functionality. It's recommended to create your own decoder
// instead via NewDecoder or NewDefaultDecoder.
//
// CRITICAL STABILITY NOTE: the decoders loaded via this function are not guaranteed to remain the same. It is strongly
// recommended that users implementing this library use the NewDecoder function and explicitly register each decoder
// which they wish to support.
func Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	if digest, err = decode(encodedDigest); err != nil {
		return nil, err
	}

	return digest, nil
}

func decode(encodedDigest string) (digest algorithm.Digest, err error) {
	if gdecoder == nil {
		if gdecoder, err = NewDefaultDecoder(); err != nil {
			return nil, err
		}
	}

	return gdecoder.Decode(encodedDigest)
}
