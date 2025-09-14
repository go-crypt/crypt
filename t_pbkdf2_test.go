package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPBKDF2Outputs(t *testing.T) {
	testcCases := []struct {
		name string
		have string
	}{
		{
			"ShouldValidatePasswordSHA1",
			"$pbkdf2$100000$atrXFCWdBlpmzIi/nXwJOw$20Lsx44nZwmh09bjGHFJ//oRZh8",
		},
		{
			"ShouldValidatePasswordSHA224",
			"$pbkdf2-sha224$100000$qRzrfXPp6ilID9bO89rJkA$akPivgY3p3gLDj8Kd7agycHkM5b0xlTxeLEsqg",
		},
		{
			"ShouldValidatePasswordSHA256",
			"$pbkdf2-sha256$100000$aoWHXwyz0im1Hqg93.N.tA$bO5LsjmnnPle2Xm9RE6W1PMWdJTy1TnEia1TLzynuIQ",
		},
		{
			"ShouldValidatePasswordSHA384",
			"$pbkdf2-sha384$100000$GIZt3eMjZrEs0ycxed3zHg$o8IZWpxd.shbcATBSk9nHqktuvLTv1YeLYowxZM7mO5hhWLa3s4tVFejl9NH9jSO",
		},
		{
			"ShouldValidatePasswordSHA512",
			"$pbkdf2-sha512$100000$bHfSOIyj0UDoCo1Q4Bz49w$v/olF/T/R6On84NuHlNCiI/sUwsdyOC7J4cO8Cz7feNtLHHEKNjayeEZj0b/Js/cgkMK6zLFw2vynLo2el028Q",
		},
		{
			"ShouldValidatePasswordLDAPSHA1",
			"{PBKDF2}100000$atrXFCWdBlpmzIi/nXwJOw$20Lsx44nZwmh09bjGHFJ//oRZh8",
		},
		{
			"ShouldValidatePasswordLDAPSHA224",
			"{PBKDF2-SHA224}100000$qRzrfXPp6ilID9bO89rJkA$akPivgY3p3gLDj8Kd7agycHkM5b0xlTxeLEsqg",
		},
		{
			"ShouldValidatePasswordLDAPSHA256",
			"{PBKDF2-SHA256}100000$aoWHXwyz0im1Hqg93.N.tA$bO5LsjmnnPle2Xm9RE6W1PMWdJTy1TnEia1TLzynuIQ",
		},
		{
			"ShouldValidatePasswordLDAPSHA384",
			"{PBKDF2-SHA384}100000$GIZt3eMjZrEs0ycxed3zHg$o8IZWpxd.shbcATBSk9nHqktuvLTv1YeLYowxZM7mO5hhWLa3s4tVFejl9NH9jSO",
		},
		{
			"ShouldValidatePasswordLDAPSHA512",
			"{PBKDF2-SHA512}100000$bHfSOIyj0UDoCo1Q4Bz49w$v/olF/T/R6On84NuHlNCiI/sUwsdyOC7J4cO8Cz7feNtLHHEKNjayeEZj0b/Js/cgkMK6zLFw2vynLo2el028Q",
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
