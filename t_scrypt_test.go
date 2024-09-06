package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScryptOutputs(t *testing.T) {
	testcCases := []struct {
		name string
		have string
	}{
		{
			"ShouldValidatePassword",
			"$scrypt$ln=4,r=8,p=1$ySYknWRq9On6wWfpsOUQQg$C28LpWaXQ3P0/dcbN0njxJx4VL/UCQIAWlnYAJgT/mY",
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
