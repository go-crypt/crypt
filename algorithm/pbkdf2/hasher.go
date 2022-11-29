package pbkdf2

import (
	"fmt"

	"github.com/go-crypt/x/pbkdf2"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/random"
)

// New returns a *Hasher without any settings configured.
func New(opts ...Opt) (hasher *Hasher, err error) {
	hasher = &Hasher{}

	if err = hasher.WithOptions(opts...); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA1 returns a SHA1 variant *Hasher without any settings configured.
func NewSHA1(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA1), WithTagLength(VariantSHA1.HashFunc()().Size())); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA224 returns a SHA224 variant *Hasher without any settings configured.
func NewSHA224(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA224), WithTagLength(VariantSHA224.HashFunc()().Size())); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA256 returns a SHA256 variant *Hasher without any settings configured.
func NewSHA256(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA256), WithTagLength(VariantSHA256.HashFunc()().Size())); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA384 returns a SHA384 variant *Hasher without any settings configured.
func NewSHA384(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA384), WithTagLength(VariantSHA384.HashFunc()().Size())); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA512 returns a SHA512 variant *Hasher without any settings configured.
func NewSHA512(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA512), WithTagLength(VariantSHA512.HashFunc()().Size())); err != nil {
		return nil, err
	}

	return hasher, nil
}

// Hasher is a crypt.Hash for PBKDF2 which can be initialized via New using a functional options pattern.
type Hasher struct {
	variant Variant

	iterations, bytesTag, bytesSalt int

	defaults bool
}

// WithOptions applies the provided functional options provided as an Opt to the pbkdf2.Hasher.
func (h *Hasher) WithOptions(opts ...Opt) (err error) {
	for _, opt := range opts {
		if err = opt(h); err != nil {
			return err
		}
	}

	return nil
}

// Hash performs the hashing operation and returns either a algorithm.Digest or an error.
func (h *Hasher) Hash(password string) (digest algorithm.Digest, err error) {
	if digest, err = h.hash(password); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hash(password string) (digest algorithm.Digest, err error) {
	h.setDefaults()

	var salt []byte

	if salt, err = random.Bytes(h.bytesSalt); err != nil {
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
	d := &Digest{
		variant:    h.variant,
		iterations: h.iterations,
		t:          h.bytesTag,
		salt:       salt,
	}

	hf := d.variant.HashFunc()

	d.key = pbkdf2.Key([]byte(password), d.salt, h.iterations, d.t, hf)

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

// Validate checks the settings/parameters for this Hash and returns an error.
func (h *Hasher) Validate() (err error) {
	if err = h.validate(); err != nil {
		return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, err)
	}

	return nil
}

func (h *Hasher) validate() (err error) {
	h.setDefaults()

	tagSizeMin := h.variant.HashFunc()().Size()

	if h.bytesTag < tagSizeMin || h.bytesTag > TagSizeMax {
		return fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "tag size", tagSizeMin, "", TagSizeMax, h.bytesTag)
	}

	return nil
}

func (h *Hasher) setDefaults() {
	if h.defaults {
		return
	}

	h.defaults = true

	switch h.variant {
	case VariantNone:
		h.variant = variantDefault
	case VariantSHA1, VariantSHA224, VariantSHA256, VariantSHA384, VariantSHA512:
		break
	default:
		h.variant = variantDefault
	}

	if h.bytesTag == 0 {
		h.bytesTag = h.variant.HashFunc()().Size()
	}

	if h.bytesSalt == 0 {
		h.bytesSalt = algorithm.SaltSizeDefault
	}

	if h.iterations == 0 {
		h.iterations = h.variant.DefaultIterations()
	}
}
