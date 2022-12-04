// Package crypt provides helpful abstractions for github.com/go-crypt/x. These abstractions allow generating password
// hashes, encoding them in a common storage format, and comparing them to ensure they are valid.
//
// It's recommended that you either use crypt.NewDefaultDecoder for decoding existing encoded digests into the
// algorithm.Digest. The Match function on the algorithm.Digest as well as the other methods described by
// algorithm.Matcher can be utilized to validate passwords.
//
// The algorithm.Digest implementations include an Encode method which encodes the algorithm.Digest in the PHC String Format.
//
// To create new algorithm.Digest results you can utilize the algorithm.Hash implementations which exist for each algorithm.
// The implementations utilize the functional options pattern where all options methods have the pattern With* or
// Without*.
package crypt
