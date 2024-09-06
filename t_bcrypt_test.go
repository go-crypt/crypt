package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBcryptOutputs(t *testing.T) {
	testcCases := []struct {
		name string
		have string
	}{
		{
			"ShouldValidatePasswordStandardVariantB",
			"$2b$10$3o9IF74Phgdz4Q6j7K7s0unovt.v.7YBLKFyV73pGTd2.tfdz/F8e",
		},
		{
			"ShouldValidatePasswordStandardVariantA",
			"$2a$10$3o9IF74Phgdz4Q6j7K7s0unovt.v.7YBLKFyV73pGTd2.tfdz/F8e",
		},
		{
			"ShouldValidatePasswordStandardVariantX",
			"$2x$10$3o9IF74Phgdz4Q6j7K7s0unovt.v.7YBLKFyV73pGTd2.tfdz/F8e",
		},
		{
			"ShouldValidatePasswordStandardVariantY",
			"$2y$10$3o9IF74Phgdz4Q6j7K7s0unovt.v.7YBLKFyV73pGTd2.tfdz/F8e",
		},
		{
			"ShouldValidatePasswordSHA256VariantB",
			"$bcrypt-sha256$v=2,t=2b,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC",
		},
		{
			"ShouldValidatePasswordSHA256VariantA",
			"$bcrypt-sha256$v=2,t=2a,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC",
		},
		{
			"ShouldValidatePasswordSHA256VariantX",
			"$bcrypt-sha256$v=2,t=2x,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC",
		},
		{
			"ShouldValidatePasswordSHA256VariantY",
			"$bcrypt-sha256$v=2,t=2y,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC",
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
