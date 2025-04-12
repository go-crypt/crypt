package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-crypt/crypt/algorithm/scrypt"
)

func TestScryptOutputs(t *testing.T) {
	testcCases := []struct {
		name     string
		have     string
		expected string
	}{
		{
			"ShouldValidateScrypt",
			"$scrypt$ln=4,r=8,p=1$ySYknWRq9On6wWfpsOUQQg$C28LpWaXQ3P0/dcbN0njxJx4VL/UCQIAWlnYAJgT/mY",
			password,
		},
		{
			"ShouldValidateYeScrpytNative",
			"$y$j75$z7ztFz2FayrKI79/jEwlL.$u5x/j193MQ09wbFaRGYr0AH/A/jh3kunjuhYRVRNkmC",
			"test1",
		},
	}

	for _, tc := range testcCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("CorrectPassword", func(t *testing.T) {
				valid, err := CheckPassword(tc.expected, tc.have)

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

func TestScryptOutputsNative(t *testing.T) {
	testcCases := []struct {
		name     string
		have     string
		expected string
	}{
		{
			"ShouldValidateYeScrpytExample",
			"$y$j75$z7ztFz2FayrKI79/jEwlL.$u5x/j193MQ09wbFaRGYr0AH/A/jh3kunjuhYRVRNkmC",
			"test1",
		},
		{
			"ShouldValidateYesCryptOutput",
			"$y$jD5$K3wjJ.n1W9g1TfLeI0ESC0$SAt46wIbyewhlHlKVQcelosVETYUGOaV6mC1qjurql9",
			"password",
		},
	}

	for _, tc := range testcCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := CheckPassword(tc.expected, tc.have)

			require.NoError(t, err)
			assert.True(t, valid)
		})
	}
}

func TestScryptEncodeDecode(t *testing.T) {
	hash, err := scrypt.NewYeScrypt()
	require.NoError(t, err)

	digest, err := hash.HashWithSalt("password", []byte("aa131311"))
	require.NoError(t, err)

	raw := digest.Encode()

	assert.Equal(t, "$y$jD5$V3KAn2nAl21$2f0mscSRW3Z0u.oHoVtRAfYwQ3ZbWUIbi4SB04ztMSB", raw)
}
