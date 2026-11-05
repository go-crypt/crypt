package bcrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasherNeedsRehash(t *testing.T) {
	base := []Opt{WithVariant(VariantStandard), WithIterations(10)}

	testCases := []struct {
		name     string
		have     []Opt
		expected bool
	}{
		{"ShouldNotNeedRehashSameParameters", nil, false},
		{"ShouldNeedRehashVariant", []Opt{WithVariant(VariantSHA256)}, true},
		{"ShouldNeedRehashCost", []Opt{WithIterations(11)}, true},
	}

	hasher, err := New(base...)
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			other, err := New(append(append([]Opt{}, base...), tc.have...)...)
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

func TestHasherNeedsRehashVersion(t *testing.T) {
	testCases := []struct {
		name     string
		variant  Variant
		version  string
		expected bool
	}{
		{"ShouldNotNeedRehashUnset", VariantStandard, "", false},
		{"ShouldNotNeedRehash2b", VariantStandard, AlgIdentifier, false},
		{"ShouldNotNeedRehash2a", VariantStandard, AlgIdentifierVerA, false},
		{"ShouldNotNeedRehash2y", VariantStandard, AlgIdentifierVerY, false},
		{"ShouldNeedRehash2x", VariantStandard, AlgIdentifierVerX, true},
		{"ShouldNeedRehashUnversioned", VariantStandard, AlgIdentifierUnversioned, true},
		{"ShouldNotNeedRehashSHA256", VariantSHA256, "2", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New(WithVariant(tc.variant), WithIterations(10))
			require.NoError(t, err)

			assert.Equal(t, tc.expected, hasher.NeedsRehash(&Digest{variant: tc.variant, version: tc.version, iterations: 10}))
		})
	}
}

func TestHasherNeedsRehashSpecial(t *testing.T) {
	defaults, err := New()
	require.NoError(t, err)

	assert.True(t, defaults.NeedsRehash(nil))
	assert.True(t, defaults.NeedsRehash((*Digest)(nil)))
	assert.False(t, defaults.NeedsRehash(&Digest{variant: VariantStandard, iterations: IterationsDefault}))
}
