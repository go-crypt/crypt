package crypt

import (
	"encoding"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/argon2"
	"github.com/go-crypt/crypt/algorithm/bcrypt"
	"github.com/go-crypt/crypt/algorithm/md5crypt"
	"github.com/go-crypt/crypt/algorithm/pbkdf2"
	"github.com/go-crypt/crypt/algorithm/plaintext"
	"github.com/go-crypt/crypt/algorithm/scrypt"
	"github.com/go-crypt/crypt/algorithm/sha1crypt"
	"github.com/go-crypt/crypt/algorithm/shacrypt"
)

// newHasherFuncs returns a hasher per supported algorithm and variant, configured with the cheapest parameters each
// one accepts so the round trip assertions stay fast.
func newHasherFuncs() map[string]func() (algorithm.Hash, error) {
	return map[string]func() (algorithm.Hash, error){
		"Argon2id": func() (algorithm.Hash, error) {
			return argon2.New(argon2.WithVariantID(), argon2.WithProfileRFC9106LowMemory())
		},
		"Argon2i": func() (algorithm.Hash, error) {
			return argon2.New(argon2.WithVariantI(), argon2.WithProfileRFC9106LowMemory())
		},
		"Argon2d": func() (algorithm.Hash, error) {
			return argon2.New(argon2.WithVariantD(), argon2.WithProfileRFC9106LowMemory())
		},
		"Bcrypt": func() (algorithm.Hash, error) {
			return bcrypt.New(bcrypt.WithCost(bcrypt.IterationsMin))
		},
		"BcryptSHA256": func() (algorithm.Hash, error) {
			return bcrypt.NewSHA256(bcrypt.WithCost(bcrypt.IterationsMin))
		},
		"PBKDF2SHA1": func() (algorithm.Hash, error) {
			return pbkdf2.NewSHA1(pbkdf2.WithIterations(pbkdf2.IterationsMin))
		},
		"PBKDF2SHA224": func() (algorithm.Hash, error) {
			return pbkdf2.NewSHA224(pbkdf2.WithIterations(pbkdf2.IterationsMin))
		},
		"PBKDF2SHA256": func() (algorithm.Hash, error) {
			return pbkdf2.NewSHA256(pbkdf2.WithIterations(pbkdf2.IterationsMin))
		},
		"PBKDF2SHA384": func() (algorithm.Hash, error) {
			return pbkdf2.NewSHA384(pbkdf2.WithIterations(pbkdf2.IterationsMin))
		},
		"PBKDF2SHA512": func() (algorithm.Hash, error) {
			return pbkdf2.NewSHA512(pbkdf2.WithIterations(pbkdf2.IterationsMin))
		},
		"Scrypt": func() (algorithm.Hash, error) {
			return scrypt.NewScrypt(scrypt.WithLN(10))
		},
		"Yescrypt": func() (algorithm.Hash, error) {
			return scrypt.NewYescrypt(scrypt.WithLN(10))
		},
		"SHACryptSHA256": func() (algorithm.Hash, error) {
			return shacrypt.New(shacrypt.WithSHA256(), shacrypt.WithIterations(shacrypt.IterationsMin))
		},
		"SHACryptSHA512": func() (algorithm.Hash, error) {
			return shacrypt.New(shacrypt.WithSHA512(), shacrypt.WithIterations(shacrypt.IterationsMin))
		},
		"MD5CryptStandard": func() (algorithm.Hash, error) {
			return md5crypt.New(md5crypt.WithVariant(md5crypt.VariantStandard))
		},
		"MD5CryptSun": func() (algorithm.Hash, error) {
			return md5crypt.New(md5crypt.WithVariant(md5crypt.VariantSun), md5crypt.WithIterations(1000))
		},
		"SHA1Crypt": func() (algorithm.Hash, error) {
			return sha1crypt.New(sha1crypt.WithIterations(1000))
		},
		"PlainText": func() (algorithm.Hash, error) {
			return plaintext.New(plaintext.WithVariant(plaintext.VariantPlainText))
		},
		"Base64": func() (algorithm.Hash, error) {
			return plaintext.New(plaintext.WithVariant(plaintext.VariantBase64))
		},
	}
}

// TestHashEncodeDecodeRoundTrip asserts every hasher produces an encoded digest which the decoder accepts, which
// re-encodes to the identical string, and which still matches the password it was created from. A digest this library
// writes but cannot read back is unusable, so this closes the loop each algorithm depends on.
func TestHashEncodeDecodeRoundTrip(t *testing.T) {
	decoder, err := NewDecoderAll()
	require.NoError(t, err)

	for name, newHasher := range newHasherFuncs() {
		t.Run(name, func(t *testing.T) {
			hasher, err := newHasher()
			require.NoError(t, err)
			require.NoError(t, hasher.Validate())

			digest, err := hasher.Hash(password)
			require.NoError(t, err)

			encoded := digest.Encode()

			t.Run("DecodesToTheSameEncoding", func(t *testing.T) {
				decoded, err := decoder.Decode(encoded)
				require.NoError(t, err, "encoded digest %q could not be decoded", encoded)

				assert.Equal(t, encoded, decoded.Encode())
			})

			t.Run("MatchesTheOriginalPassword", func(t *testing.T) {
				decoded, err := decoder.Decode(encoded)
				require.NoError(t, err)

				match, err := decoded.MatchAdvanced(password)
				require.NoError(t, err)
				assert.True(t, match)
			})

			t.Run("RejectsTheWrongPassword", func(t *testing.T) {
				decoded, err := decoder.Decode(encoded)
				require.NoError(t, err)

				match, err := decoded.MatchAdvanced(wrongPassword)
				require.NoError(t, err)
				assert.False(t, match)
			})

			t.Run("DecodingIsIdempotent", func(t *testing.T) {
				first, err := decoder.Decode(encoded)
				require.NoError(t, err)

				second, err := decoder.Decode(first.Encode())
				require.NoError(t, err)

				assert.Equal(t, first.Encode(), second.Encode())
				assert.Equal(t, first.Key(), second.Key())
				assert.Equal(t, first.Salt(), second.Salt())
			})
		})
	}
}

// TestHashWithSaltIsDeterministic asserts hashing the same password with the same salt twice produces the same digest.
func TestHashWithSaltIsDeterministic(t *testing.T) {
	// Salts are constrained differently per algorithm, so the salt of a first hash is reused rather than invented.
	for name, newHasher := range newHasherFuncs() {
		t.Run(name, func(t *testing.T) {
			hasher, err := newHasher()
			require.NoError(t, err)

			first, err := hasher.Hash(password)
			require.NoError(t, err)

			salt := first.Salt()

			if len(salt) == 0 {
				t.Skip("algorithm does not use a salt")
			}

			second, err := hasher.HashWithSalt(password, salt)
			require.NoError(t, err)

			third, err := hasher.HashWithSalt(password, salt)
			require.NoError(t, err)

			assert.Equal(t, second.Encode(), third.Encode())
			assert.True(t, second.Match(password))
		})
	}
}

// TestDigestWrapperRoundTrip asserts the crypt.Digest and crypt.NullDigest decorators preserve an encoded digest
// across every serialisation interface they implement.
func TestDigestWrapperRoundTrip(t *testing.T) {
	hasher, err := argon2.New(argon2.WithProfileRFC9106LowMemory())
	require.NoError(t, err)

	algDigest, err := hasher.Hash(password)
	require.NoError(t, err)

	encoded := algDigest.Encode()

	t.Run("Digest", func(t *testing.T) {
		digest, err := NewDigest(algDigest)
		require.NoError(t, err)

		assertSerialisationRoundTrip(t, digest, &Digest{}, encoded)

		value, err := digest.Value()
		require.NoError(t, err)
		assert.Equal(t, encoded, value)
	})

	t.Run("NullDigest", func(t *testing.T) {
		digest := NewNullDigest(algDigest)

		assertSerialisationRoundTrip(t, digest, &NullDigest{}, encoded)

		value, err := digest.Value()
		require.NoError(t, err)
		assert.Equal(t, encoded, value)
	})
}

type digestSerialiser interface {
	encoding.TextMarshaler
	encoding.BinaryMarshaler
	Encode() string
}

type digestDeserialiser interface {
	encoding.TextUnmarshaler
	encoding.BinaryUnmarshaler
	Encode() string
}

func assertSerialisationRoundTrip(t *testing.T, src digestSerialiser, dst digestDeserialiser, encoded string) {
	t.Helper()

	t.Run("Text", func(t *testing.T) {
		data, err := src.MarshalText()
		require.NoError(t, err)
		assert.Equal(t, encoded, string(data))

		require.NoError(t, dst.UnmarshalText(data))
		assert.Equal(t, encoded, dst.Encode())
	})

	t.Run("Binary", func(t *testing.T) {
		data, err := src.MarshalBinary()
		require.NoError(t, err)

		require.NoError(t, dst.UnmarshalBinary(data))
		assert.Equal(t, encoded, dst.Encode())
	})
}
