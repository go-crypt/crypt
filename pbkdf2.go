package crypt

import (
	"fmt"

	"github.com/go-crypt/x/pbkdf2"
)

// NewPBKDF2Hash returns a *PBKDF2Hash without any settings configured.
func NewPBKDF2Hash() *PBKDF2Hash {
	return &PBKDF2Hash{}
}

// NewPBKDF2SHA1Hash returns a SHA1 variant *PBKDF2Hash without any settings configured.
func NewPBKDF2SHA1Hash() *PBKDF2Hash {
	return NewPBKDF2Hash().WithVariant(PBKDF2VariantSHA1)
}

// NewPBKDF2SHA224Hash returns a SHA224 variant *PBKDF2Hash without any settings configured.
func NewPBKDF2SHA224Hash() *PBKDF2Hash {
	return NewPBKDF2Hash().WithVariant(PBKDF2VariantSHA224)
}

// NewPBKDF2SHA256Hash returns a SHA256 variant *PBKDF2Hash without any settings configured.
func NewPBKDF2SHA256Hash() *PBKDF2Hash {
	return NewPBKDF2Hash().WithVariant(PBKDF2VariantSHA256)
}

// NewPBKDF2SHA384Hash returns a SHA384 variant *PBKDF2Hash without any settings configured.
func NewPBKDF2SHA384Hash() *PBKDF2Hash {
	return NewPBKDF2Hash().WithVariant(PBKDF2VariantSHA384)
}

// NewPBKDF2SHA512Hash returns a SHA512 variant *PBKDF2Hash without any settings configured.
func NewPBKDF2SHA512Hash() *PBKDF2Hash {
	return NewPBKDF2Hash().WithVariant(PBKDF2VariantSHA512)
}

// PBKDF2Hash is a Hash for PBKDF2 which provides a builder design pattern.
type PBKDF2Hash struct {
	variant PBKDF2Variant

	iterations, bytesKey, bytesSalt int

	defaults, unsafe bool
}

// WithVariant configures the PBKDF2Variant.
func (h *PBKDF2Hash) WithVariant(variant PBKDF2Variant) *PBKDF2Hash {
	h.variant = variant

	return h
}

// WithoutValidation disables the validation and allows potentially unsafe values. Use at your own risk.
func (h *PBKDF2Hash) WithoutValidation() *PBKDF2Hash {
	h.unsafe = true

	return h
}

// WithIterations sets the iterations parameter of the resulting PBKDF2Digest. Default is 29000.
func (h *PBKDF2Hash) WithIterations(iterations int) *PBKDF2Hash {
	h.iterations = iterations

	return h
}

// WithKeyLength adjusts the key size (in bytes) of the resulting PBKDF2Digest. Default is the output length of the
// HMAC digest. Generally it's NOT recommended to change this value at all and let the default values be applied.
// Longer key lengths technically reduce security by forcing a longer hash calculation for legitimate users but not
// requiring this for an attacker. In addition most implementations expect the key length to match the output length of
// the HMAC digest.
func (h *PBKDF2Hash) WithKeyLength(bytes int) *PBKDF2Hash {
	h.bytesKey = bytes

	return h
}

// WithSaltLength adjusts the salt size (in bytes) of the resulting PBKDF2Digest. Default is 16.
func (h *PBKDF2Hash) WithSaltLength(bytes int) *PBKDF2Hash {
	h.bytesSalt = bytes

	return h
}

// Hash performs the hashing operation and returns either a Digest or an error.
func (h *PBKDF2Hash) Hash(password string) (digest Digest, err error) {
	h.setDefaults()

	var salt []byte

	if salt, err = randomBytes(h.bytesSalt); err != nil {
		return nil, fmt.Errorf("pbkdf2 hashing error: %w: %v", ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt. It's recommended instead to configure the
// salt size and let this be a random value generated using crypto/rand.
func (h *PBKDF2Hash) HashWithSalt(password string, salt []byte) (digest Digest, err error) {
	return h.hashWithSalt(password, salt)
}

func (h *PBKDF2Hash) hashWithSalt(password string, salt []byte) (digest Digest, err error) {
	if err = h.validate(); err != nil {
		return nil, err
	}

	d := &PBKDF2Digest{
		variant:    h.variant,
		iterations: h.iterations,
		k:          h.bytesKey,
		salt:       salt,
	}

	hf := d.variant.HashFunc()

	if d.k == 0 {
		d.k = hf().Size()
	}

	d.key = pbkdf2.Key([]byte(password), d.salt, h.iterations, d.k, hf)

	return d, nil
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *PBKDF2Hash) MustHash(password string) (digest Digest) {
	var err error

	if digest, err = h.Hash(password); err != nil {
		panic(err)
	}

	return digest
}

// Validate checks the settings/parameters for this Hash and returns an error.
func (h *PBKDF2Hash) Validate() (err error) {
	return h.validate()
}

func (h *PBKDF2Hash) validate() (err error) {
	h.setDefaults()

	if h.unsafe {
		return nil
	}

	if h.bytesKey != 0 {
		keySizeMin := h.variant.HashFunc()().Size()

		if h.bytesKey < keySizeMin || h.bytesKey > PBKDF2KeySizeMax {
			return fmt.Errorf(errFmtInvalidIntParameter, algorithmNamePBKDF2, ErrParameterInvalid, "key size", keySizeMin, "", PBKDF2KeySizeMax, h.bytesKey)
		}
	}

	if h.bytesSalt < PBKDF2SaltSizeMin || h.bytesSalt > PBKDF2SaltSizeMax {
		return fmt.Errorf(errFmtInvalidIntParameter, algorithmNamePBKDF2, ErrParameterInvalid, "salt size", PBKDF2SaltSizeMin, "", PBKDF2SaltSizeMax, h.bytesSalt)
	}

	if h.iterations < PBKDF2IterationsMin || h.iterations > PBKDF2IterationsMax {
		return fmt.Errorf(errFmtInvalidIntParameter, algorithmNamePBKDF2, ErrParameterInvalid, "iterations", PBKDF2IterationsMin, "", PBKDF2IterationsMax, h.iterations)
	}

	return nil
}

func (h *PBKDF2Hash) setDefaults() {
	if h.defaults {
		return
	}

	h.defaults = true

	switch h.variant {
	case PBKDF2VariantNone:
		h.variant = variantPBKDF2Default
	case PBKDF2VariantSHA1, PBKDF2VariantSHA224, PBKDF2VariantSHA256, PBKDF2VariantSHA384, PBKDF2VariantSHA512:
		break
	default:
		h.variant = variantPBKDF2Default
	}

	if h.bytesSalt == 0 {
		h.bytesSalt = SaltSizeDefault
	}

	if h.iterations == 0 {
		switch h.variant {
		case PBKDF2VariantSHA1, PBKDF2VariantSHA224:
			h.iterations = PBKDF2SHA1IterationsDefault
		case PBKDF2VariantSHA256, PBKDF2VariantSHA384:
			h.iterations = PBKDF2SHA256IterationsDefault
		case PBKDF2VariantSHA512:
			h.iterations = PBKDF2SHA512IterationsDefault
		}
	}
}
