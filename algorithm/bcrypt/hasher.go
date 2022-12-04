package bcrypt

import (
	"fmt"

	"github.com/go-crypt/x/bcrypt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/random"
)

// New returns a new bcrypt.Hasher with the provided functional options applied.
func New(opts ...Opt) (hasher *Hasher, err error) {
	hasher = &Hasher{}

	if err = hasher.WithOptions(
		WithVariant(VariantStandard),
		WithIterations(IterationsDefault),
	); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(opts...); err != nil {
		return nil, err
	}

	if err = hasher.Validate(); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA256 returns a new bcrypt.Hasher with the provided functional options applied as well as the bcrypt.VariantSHA256
// applied via the bcrypt.WithVariant bcrypt.Opt.
func NewSHA256(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA256)); err != nil {
		return nil, err
	}

	return hasher, nil
}

// Hasher is a crypt.Hash for bcrypt which can be initialized via bcrypt.New using a functional options pattern.
type Hasher struct {
	variant Variant

	iterations int
}

// WithOptions applies the provided functional options provided as an bcrypt.Opt to the bcrypt.Hasher.
func (h *Hasher) WithOptions(opts ...Opt) (err error) {
	for _, opt := range opts {
		if err = opt(h); err != nil {
			return err
		}
	}

	return nil
}

// Hash performs the hashing operation and returns either an algorithm.Digest or an error.
func (h *Hasher) Hash(password string) (digest algorithm.Digest, err error) {
	if digest, err = h.hash(password); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hash(password string) (digest algorithm.Digest, err error) {
	var salt []byte

	if salt, err = random.Bytes(algorithm.SaltLengthDefault); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt. It's recommended instead to configure the
// salt size and let this be a random value generated using crypto/rand.
func (h *Hasher) HashWithSalt(password string, salt []byte) (digest algorithm.Digest, err error) {
	if digest, err = h.hashWithSalt(password, salt); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hashWithSalt(password string, salt []byte) (digest algorithm.Digest, err error) {
	if len(salt) != algorithm.SaltLengthDefault {
		return nil, fmt.Errorf("%w: salt size must be 16 bytes but it's %d bytes", algorithm.ErrSaltInvalid, len(salt))
	}

	d := &Digest{
		variant:    h.variant,
		iterations: h.iterations,
		salt:       salt,
	}

	d.defaults()

	passwordMaxLen := d.variant.PasswordMaxLength()

	if passwordMaxLen != -1 && len(password) > passwordMaxLen {
		return nil, fmt.Errorf("%w: password must be %d bytes or less but it's %d bytes", algorithm.ErrPasswordInvalid, passwordMaxLen, len(password))
	}

	if d.key, err = bcrypt.Key(d.variant.EncodeInput([]byte(password), salt), salt, d.iterations); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrKeyDerivation, err)
	}

	return d, nil
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *Hasher) MustHash(password string) (digest algorithm.Digest) {
	var err error

	if digest, err = h.Hash(password); err != nil {
		panic(err)
	}

	return digest
}

// Validate checks the settings/parameters for this bcrypt.Hasher and returns an error.
func (h *Hasher) Validate() (err error) {
	if err = h.validate(); err != nil {
		return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, err)
	}

	return nil
}

func (h *Hasher) validate() (err error) {
	return nil
}
