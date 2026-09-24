package scrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-crypt/crypt/algorithm"
)

func TestDecodeRejectsParametersThatCannotBeUsed(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{"NegativeLN", "$scrypt$ln=-1,r=8,p=1$c2FsdHNhbHQ$a2V5"},
		{"ZeroLN", "$scrypt$ln=0,r=8,p=1$c2FsdHNhbHQ$a2V5"},
		{"OversizedLN", "$scrypt$ln=59,r=8,p=1$c2FsdHNhbHQ$a2V5"},
		{"NegativeR", "$scrypt$ln=16,r=-8,p=1$c2FsdHNhbHQ$a2V5"},
		{"ZeroR", "$scrypt$ln=16,r=0,p=1$c2FsdHNhbHQ$a2V5"},
		{"NegativeP", "$scrypt$ln=16,r=8,p=-1$c2FsdHNhbHQ$a2V5"},
		{"ZeroP", "$scrypt$ln=16,r=8,p=0$c2FsdHNhbHQ$a2V5"},
		{"JointlyOversizedRP", "$scrypt$ln=16,r=32768,p=32768$c2FsdHNhbHQ$a2V5"},
		{"JointlyOversizedNR", "$scrypt$ln=58,r=8,p=1$c2FsdHNhbHQ$a2V5"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)

			assert.Nil(t, digest)
			require.Error(t, err)
		})
	}
}

func TestMatchingNeverPanicsForAcceptedDigests(t *testing.T) {
	testCases := []string{
		"$scrypt$ln=1,r=1,p=1$c2FsdHNhbHQ$a2V5",
		"$scrypt$ln=10,r=8,p=1$c2FsdHNhbHQ$a2V5",
		"$scrypt$ln=12,r=16,p=2$c2FsdHNhbHQ$a2V5",
	}

	for _, encoded := range testCases {
		t.Run(encoded, func(t *testing.T) {
			digest, err := Decode(encoded)
			require.NoError(t, err)

			assert.NotPanics(t, func() {
				_, _ = digest.MatchAdvanced("password")
			})
		})
	}
}

func TestDecodePreservesParameters(t *testing.T) {
	const encoded = "$scrypt$ln=16,r=8,p=1$YmxhaGJsYWhibGFoYmxhaA$Vt4rHrEcdEJ+A9FBAOtqE21NX2NDaCyR3xr0PJmg+dU"

	digest, err := Decode(encoded)

	require.NoError(t, err)
	assert.Equal(t, encoded, digest.Encode())
}

func TestHashedDigestsRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		new  func() (*Hasher, error)
	}{
		{"Scrypt", func() (*Hasher, error) { return NewScrypt(WithLN(10)) }},
		{"Yescrypt", func() (*Hasher, error) { return NewYescrypt(WithLN(10)) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := tc.new()
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

func TestNewYescryptRejectsParallelismOtherThanOne(t *testing.T) {
	testCases := []struct {
		name string
		opts []Opt
	}{
		{"NewYescrypt", []Opt{WithP(2)}},
		{"VariantAfterParallelism", []Opt{WithP(2), WithVariant(VariantYescrypt)}},
		{"VariantName", []Opt{WithVariantName("yescrypt"), WithP(4)}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := NewYescrypt(tc.opts...)

			assert.Nil(t, hasher)
			assert.ErrorIs(t, err, algorithm.ErrParameterInvalid)
			assert.ErrorContains(t, err, "scrypt validation error: parameter is invalid: parameter 'p' must be 1 for the yescrypt variant but is set to '")
		})
	}
}

func TestNewScryptAllowsParallelismOtherThanOne(t *testing.T) {
	hasher, err := NewScrypt(WithLN(4), WithR(1), WithP(2))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	decoded, err := Decode(digest.Encode())
	require.NoError(t, err)

	assert.True(t, decoded.Match("password"))
}

func TestNewYescryptAllowsParallelismOfOne(t *testing.T) {
	hasher, err := NewYescrypt(WithLN(4), WithP(1))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	decoded, err := Decode(digest.Encode())
	require.NoError(t, err)

	assert.True(t, decoded.Match("password"))
}
