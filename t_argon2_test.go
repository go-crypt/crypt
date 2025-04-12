package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2Outputs(t *testing.T) {
	testcCases := []struct {
		name string
		have string
	}{
		{
			"ShouldValidatePasswordArgon2id",
			"$argon2id$v=19$m=65536,t=3,p=4$QmkpoTw3W72fzd7RrWofuw$r0xig+VVj7ynnE2S1jrE5us7dPKv2S2ff6Z6ts4mVuU",
		},
		{
			"ShouldValidatePasswordArgon2i",
			"$argon2i$v=19$m=65536,t=3,p=4$ScGiEq8Low5K7B7/IwYxgA$q6Zo0u/aDtZk404ZNmBi33WXkC5g0y60QdOQQ3oziyU",
		},
		{
			"ShouldValidatePasswordArgon2d",
			"$argon2d$v=19$m=65536,t=3,p=4$HV/RIiFSYEMoRYqBcFnqfg$eGNckPZjkL2xOIHZv8Q4ROg5xbcdD8ijIJOgPwVAPmA",
		},
	}

	for _, tc := range testcCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("CorrectPassword", func(t *testing.T) {
				valid, err := CheckPassword(password, tc.have)

				require.NoError(t, err)
				assert.True(t, valid)
			})

			t.Run("IncorrectPassword", func(t *testing.T) {
				valid, err := CheckPassword(wrongPassword, tc.have)

				require.NoError(t, err)
				assert.False(t, valid)
			})
		})

	}
}
