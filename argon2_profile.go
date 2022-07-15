package crypt

type Argon2Profile int

const (
	Argon2ProfileRFC9106LowMemory Argon2Profile = iota
	Argon2ProfileRFC9106Recommended
)

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
