package crypt

import (
	"github.com/go-crypt/crypt/algorithm"
)

// CheckPassword takes the string password and an encoded digest. It decodes the Digest, then performs the
// MatchAdvanced() function on the Digest. If any process returns an error it returns false with the error, otherwise
// it returns the result of MatchAdvanced(). This is just a helper function and implementers can manually invoke this
// process themselves in situations where they may want to store the Digest to perform matches at a later date to avoid
// decoding multiple times for example.
//
// CRITICAL STABILITY NOTE: the decoders loaded via this function are not guaranteed to remain the same. It is strongly
// recommended that users implementing this library use the NewDecoder function and explicitly register each decoder
// which they wish to support.
func CheckPassword(password, encodedDigest string) (valid bool, err error) {
	var digest algorithm.Digest

	if digest, err = Decode(encodedDigest); err != nil {
		return false, err
	}

	return digest.MatchAdvanced(password)
}

// CheckPasswordWithPlainText is the same as CheckPassword however it also allows the plaintext passwords.
//
// CRITICAL STABILITY NOTE: the decoders loaded via this function are not guaranteed to remain the same. It is strongly
// recommended that users implementing this library use the NewDecoder function and explicitly register each decoder
// which they wish to support.
func CheckPasswordWithPlainText(password, encodedDigest string) (valid bool, err error) {
	var (
		digest  algorithm.Digest
		decoder algorithm.Decoder
	)

	if decoder, err = NewDecoderAll(); err != nil {
		return false, err
	}

	if digest, err = decoder.Decode(encodedDigest); err != nil {
		return false, err
	}

	return digest.MatchAdvanced(password)
}
