package argon2

import (
	"github.com/go-crypt/crypt/algorithm"
)

// Profile represents a hashing profile for Argon2Hash.
type Profile int

const (
	// ProfileRFC9106LowMemory is the RFC9106 low memory profile.
	ProfileRFC9106LowMemory Profile = iota

	// ProfileRFC9106Recommended is the RFC9106 recommended profile.
	ProfileRFC9106Recommended
)

// Hasher returns the argon2.Profile parameters as an argon2.Hasher.
func (p Profile) Hasher() *Hasher {
	switch p {
	case ProfileRFC9106LowMemory:
		return &Hasher{variant: VariantID, t: 3, p: 4, m: 64 * 1024, k: KeyLengthDefault, s: algorithm.SaltLengthDefault}
	case ProfileRFC9106Recommended:
		return &Hasher{variant: VariantID, t: IterationsDefault, p: ParallelismDefault, m: MemoryDefault, k: KeyLengthDefault, s: algorithm.SaltLengthDefault}
	default:
		return ProfileRFC9106Recommended.Hasher()
	}
}
