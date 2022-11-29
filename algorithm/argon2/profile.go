package argon2

// Profile represents a hashing profile for Argon2Hash.
type Profile int

const (
	// ProfileRFC9106LowMemory is the RFC9106 low memory profile.
	ProfileRFC9106LowMemory Profile = iota

	// ProfileRFC9106Recommended is the RFC9106 recommended profile.
	ProfileRFC9106Recommended
)

// Hasher returns the Argon2Profile parameters as a Argon2Hash.
func (p Profile) Hasher() *Hasher {
	switch p {
	case ProfileRFC9106LowMemory:
		return &Hasher{variant: VariantID, t: 3, p: 4, m: 64 * 1024, k: 32, s: 16}
	case ProfileRFC9106Recommended:
		return &Hasher{variant: VariantID, t: 1, p: 4, m: 2 * 1024 * 1024, k: 32, s: 16}
	default:
		return ProfileRFC9106Recommended.Hasher()
	}
}
