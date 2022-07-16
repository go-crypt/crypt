package crypt

// Argon2Profile represents a hashing profile for Argon2Hash.
type Argon2Profile int

const (
	// Argon2ProfileRFC9106LowMemory is the RFC9106 low memory profile.
	Argon2ProfileRFC9106LowMemory Argon2Profile = iota

	// Argon2ProfileRFC9106Recommended is the RFC9106 recommended profile.
	Argon2ProfileRFC9106Recommended
)

// Params returns the Argon2Profile parameters as a Argon2Hash.
func (p Argon2Profile) Params() Argon2Hash {
	switch p {
	case Argon2ProfileRFC9106LowMemory:
		return Argon2Hash{t: 3, p: 4, m: 64 * 1024, k: 32, s: 16}
	case Argon2ProfileRFC9106Recommended:
		return Argon2Hash{t: 1, p: 4, m: 2 * 1024 * 1024, k: 32, s: 16}
	default:
		return Argon2Hash{t: 1, p: 4, m: 2 * 1024 * 1024, k: 32, s: 16}
	}
}
