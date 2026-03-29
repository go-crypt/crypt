package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiscoOutputs(t *testing.T) {
	testcCases := []struct {
		name string
		have string
	}{
		{
			"ShouldHandleCiscoType5",
			"$1$UO2cR4YH$u7ovm1C0WgdQ4o3f28hhC.",
		},
		{
			"ShouldHandleCiscoType8",
			"$8$GICO4nJa$RWCgiZB3Co/3TTIFTB8FrcAOR10k0CcqB6yVSoAUnc8",
		},
		{
			"ShouldHandleCiscoType9",
			"$9$lGFcBDZN$SGG7ZmWFlp/eO8FLjw/GPDjj3OBq95KPE4D8G7xQ3vk",
		},
		{
			"ShouldHandleCiscoType10",
			"$6$64MsWNLowRm4UqgS$OHIO/S6sZqHHw4H6puPWJqAYZ8KOfIKzHaQJNgjXFU9.1AEPRGPOyk5MtogrzBzh.9KcVsTJo4wSSYsucF.U7/",
		},
	}

	decoder, err := NewDecoderAll()
	require.NoError(t, err)

	for _, tc := range testcCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("CorrectPassword", func(t *testing.T) {
				digest, err := decoder.Decode(tc.have)
				require.NoError(t, err)

				valid, err := digest.MatchAdvanced(password)

				assert.NoError(t, err)
				assert.True(t, valid)
			})

			t.Run("IncorrectPassword", func(t *testing.T) {
				digest, err := decoder.Decode(tc.have)
				require.NoError(t, err)

				valid, err := digest.MatchAdvanced(password)

				assert.NoError(t, err)
				assert.False(t, valid)
			})
		})

	}
}
