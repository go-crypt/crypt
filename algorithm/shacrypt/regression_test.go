package shacrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeRejectsUnusableRounds(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{"Zero", "$6$rounds=0$saltsalt$keykeykey"},
		{"AboveMaximum", "$6$rounds=4294967295$saltsalt$keykeykey"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)

			assert.Nil(t, digest)
			assert.Error(t, err)
		})
	}
}

func TestDecodeAcceptsRoundsWithinRange(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{"Minimum", "$6$rounds=1000$saltsalt$keykeykey"},
		{"Maximum", "$6$rounds=999999999$saltsalt$keykeykey"},
		{"BelowSpecMinimumButUsable", "$6$rounds=100$saltsalt$keykeykey"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)

			require.NoError(t, err)
			assert.Equal(t, tc.digest, digest.Encode())
		})
	}
}

func TestHashedDigestsRoundTrip(t *testing.T) {
	for _, variant := range []Variant{VariantSHA256, VariantSHA512} {
		t.Run(variant.String(), func(t *testing.T) {
			hasher, err := New(WithVariant(variant), WithIterations(1000))
			require.NoError(t, err)

			digest, err := hasher.Hash("password")
			require.NoError(t, err)

			encoded := digest.Encode()

			decoded, err := Decode(encoded)
			require.NoError(t, err)

			assert.Equal(t, encoded, decoded.Encode())
			assert.True(t, decoded.Match("password"))
			assert.False(t, decoded.Match("incorrect"))
		})
	}
}
