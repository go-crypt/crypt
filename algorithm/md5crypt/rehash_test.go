package md5crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasherNeedsRehash(t *testing.T) {
	testCases := []struct {
		name     string
		hasher   []Opt
		digest   []Opt
		expected bool
	}{
		{"ShouldNotNeedRehashSameParameters", []Opt{WithVariant(VariantStandard)}, []Opt{WithVariant(VariantStandard)}, false},
		{"ShouldNotNeedRehashDefaults", nil, []Opt{WithVariant(VariantStandard), WithSaltLength(SaltLengthDefault)}, false},
		{"ShouldNotNeedRehashStandardIterations", []Opt{WithVariant(VariantStandard)}, []Opt{WithVariant(VariantStandard), WithIterations(5000)}, false},
		{"ShouldNeedRehashVariant", []Opt{WithVariant(VariantStandard)}, []Opt{WithVariant(VariantSun)}, true},
		{"ShouldNeedRehashSaltLength", []Opt{WithVariant(VariantStandard)}, []Opt{WithVariant(VariantStandard), WithSaltLength(4)}, true},
		{"ShouldNotNeedRehashSunSameIterations", []Opt{WithVariant(VariantSun), WithIterations(1000)}, []Opt{WithVariant(VariantSun), WithIterations(1000)}, false},
		{"ShouldNeedRehashSunIterations", []Opt{WithVariant(VariantSun), WithIterations(1000)}, []Opt{WithVariant(VariantSun), WithIterations(2000)}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New(tc.hasher...)
			require.NoError(t, err)

			other, err := New(tc.digest...)
			require.NoError(t, err)

			digest, err := other.Hash("password")
			require.NoError(t, err)

			assert.Equal(t, tc.expected, hasher.NeedsRehash(digest))

			decoded, err := Decode(digest.Encode())
			require.NoError(t, err)

			assert.Equal(t, tc.expected, hasher.NeedsRehash(decoded))
		})
	}
}

func TestHasherNeedsRehashSpecial(t *testing.T) {
	sun, err := New(WithVariant(VariantSun))
	require.NoError(t, err)

	assert.True(t, sun.NeedsRehash(nil))
	assert.True(t, sun.NeedsRehash((*Digest)(nil)))
	assert.True(t, sun.NeedsRehash(&Digest{variant: VariantSun, salt: make([]byte, SaltLengthDefault)}))
	assert.False(t, sun.NeedsRehash(&Digest{variant: VariantSun, iterations: IterationsDefault, salt: make([]byte, SaltLengthDefault)}))
}
