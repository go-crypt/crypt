package sha1crypt

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// Opt describes the functional option pattern for the sha1crypt.Hasher.
type Opt func(h *Hasher) (err error)

// WithIterations sets the iterations parameter of the resulting sha1crypt.Digest.
// Minimum is 0, Maximum is 4294967295. Default is 480000.
func WithIterations(iterations uint32) Opt {
	return func(h *Hasher) (err error) {
		if iterations < IterationsMin || iterations > IterationsMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "iterations", IterationsMin, "", IterationsMax, iterations))
		}

		h.i = true
		h.iterations = iterations

		return nil
	}
}

// WithRounds is an alias for sha1crypt.WithIterations.
func WithRounds(rounds uint32) Opt {
	return WithIterations(rounds)
}

// WithSaltLength adjusts the salt size (in bytes) of the resulting sha1crypt.Digest.
// Minimum is 1, Maximum is 64. Default is 8.
func WithSaltLength(bytes int) Opt {
	return func(h *Hasher) (err error) {
		if bytes < SaltLengthMin || bytes > SaltLengthMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "salt length", SaltLengthMin, "", SaltLengthMax, bytes))
		}

		h.bytesSalt = bytes

		return nil
	}
}
