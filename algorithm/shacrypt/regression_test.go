package shacrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeClampsOutOfRangeRounds(t *testing.T) {
	testCases := []struct {
		name     string
		digest   string
		expected string
	}{
		{"Zero", "$6$rounds=0$saltsalt$keykeykey", "$6$rounds=1000$saltsalt$keykeykey"},
		{"BelowMinimum", "$6$rounds=100$saltsalt$keykeykey", "$6$rounds=1000$saltsalt$keykeykey"},
		{"JustBelowMinimum", "$6$rounds=999$saltsalt$keykeykey", "$6$rounds=1000$saltsalt$keykeykey"},
		{"JustAboveMaximum", "$6$rounds=1000000000$saltsalt$keykeykey", "$6$rounds=999999999$saltsalt$keykeykey"},
		{"AboveMaximum", "$6$rounds=4294967295$saltsalt$keykeykey", "$6$rounds=999999999$saltsalt$keykeykey"},
		{"AboveUint32", "$6$rounds=4294967296$saltsalt$keykeykey", "$6$rounds=999999999$saltsalt$keykeykey"},
		{"AboveUint64", "$6$rounds=99999999999999999999$saltsalt$keykeykey", "$6$rounds=999999999$saltsalt$keykeykey"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, digest.Encode())
		})
	}
}

func TestDecodeRejectsInvalidRounds(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{"Empty", "$6$rounds=$saltsalt$keykeykey"},
		{"Negative", "$6$rounds=-1$saltsalt$keykeykey"},
		{"NotNumeric", "$6$rounds=abc$saltsalt$keykeykey"},
		{"AboveUint64NotNumericSuffix", "$6$rounds=99999999999999999999x$saltsalt$keykeykey"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)

			assert.Nil(t, digest)
			assert.Error(t, err)
		})
	}
}

func TestDecodeRoundsTooLowSpecVectors(t *testing.T) {
	testCases := []struct {
		name     string
		digest   string
		expected string
	}{
		{
			"SHA256",
			"$5$rounds=10$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC",
			"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC",
		},
		{
			"SHA512",
			"$6$rounds=10$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
			"$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)
			require.NoError(t, err)

			match, err := digest.MatchAdvanced("the minimum number is still observed")

			require.NoError(t, err)
			assert.True(t, match)
			assert.Equal(t, tc.expected, digest.Encode())
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
