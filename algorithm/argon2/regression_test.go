package argon2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeRejectsParametersItCannotHonour(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{"ZeroIterations", "$argon2id$v=19$m=8,t=0,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"},
		{"ZeroParallelism", "$argon2id$v=19$m=8,t=1,p=0$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"},
		{"ZeroMemory", "$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"},
		{"MemoryBelowMinimum", "$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"},
		{"MemoryBelowParallelismMinimum", "$argon2id$v=19$m=8,t=1,p=2$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"},
		{"ParallelismAboveMaximum", "$argon2id$v=19$m=8,t=1,p=16777216$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)

			assert.Nil(t, digest)
			assert.Error(t, err)
		})
	}
}

func TestDecodePreservesParameters(t *testing.T) {
	testCases := []string{
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5",
		"$argon2d$v=19$m=2097152,t=1,p=4$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5",
	}

	for _, encoded := range testCases {
		t.Run(encoded, func(t *testing.T) {
			digest, err := Decode(encoded)

			require.NoError(t, err)
			assert.Equal(t, encoded, digest.Encode())
		})
	}
}

func TestHashedDigestsRoundTrip(t *testing.T) {
	for _, variant := range []Variant{VariantID, VariantI, VariantD} {
		t.Run(variant.String(), func(t *testing.T) {
			hasher, err := New(WithVariant(variant), WithProfileRFC9106LowMemory())
			require.NoError(t, err)
			require.NoError(t, hasher.Validate())

			digest, err := hasher.Hash("password")
			require.NoError(t, err)

			encoded := digest.Encode()

			decoded, err := Decode(encoded)
			require.NoError(t, err, "encoded digest %q could not be decoded", encoded)

			assert.Equal(t, encoded, decoded.Encode())
			assert.True(t, decoded.Match("password"))
			assert.False(t, decoded.Match("incorrect"))
		})
	}
}

func TestDecodeVariantRejectsOtherVariants(t *testing.T) {
	const encoded = "$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"

	digest, err := DecodeVariant(VariantID)(encoded)

	assert.Nil(t, digest)
	assert.Error(t, err)

	digest, err = DecodeVariant(VariantI)(encoded)

	require.NoError(t, err)
	assert.Equal(t, encoded, digest.Encode())
}

func TestNewRejectsMemoryBelowDefaultParallelismMinimum(t *testing.T) {
	hasher, err := New(WithM(30))

	assert.Nil(t, hasher)
	assert.EqualError(t, err, "argon2 validation error: parameter is invalid: parameter 'm' must be between 32 (p * 8) and 4294967295 but is set to '30'")
}

func TestHashRejectsMemoryBelowParallelismMinimumWithoutValidate(t *testing.T) {
	hasher := &Hasher{}

	require.NoError(t, hasher.WithOptions(WithM(30)))

	digest, err := hasher.Hash("password")

	assert.Nil(t, digest)
	assert.EqualError(t, err, "argon2 hashing error: parameter is invalid: parameter 'm' must be between 32 (p * 8) and 4294967295 but is set to '30'")

	digest, err = hasher.HashWithSalt("password", []byte("saltsaltsaltsalt"))

	assert.Nil(t, digest)
	assert.EqualError(t, err, "argon2 hashing error: parameter is invalid: parameter 'm' must be between 32 (p * 8) and 4294967295 but is set to '30'")
}

func TestHashedDigestsWithDefaultParallelismRoundTrip(t *testing.T) {
	for _, m := range []uint32{32, 33, 47, 48, 64} {
		t.Run(fmt.Sprintf("m=%d", m), func(t *testing.T) {
			hasher, err := New(WithM(m))
			require.NoError(t, err)

			digest, err := hasher.Hash("password")
			require.NoError(t, err)

			encoded := digest.Encode()

			decoded, err := Decode(encoded)
			require.NoError(t, err, "encoded digest %q could not be decoded", encoded)

			assert.True(t, decoded.Match("password"))
		})
	}
}
