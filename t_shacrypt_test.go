package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSHACRYPTOutputsMKPASSWD(t *testing.T) {
	testcCases := []struct {
		name     string
		have     string
		expected string
		valid    bool
		err      string
	}{
		{
			"ShouldValidatePasswordWithOmittedRoundsSHA256",
			"$5$4X/QmdRP6q7Ilhpc$2sperIXN6jawEYd8a8arineQHqYIEGURjZGdD4H4xs8",
			password,
			true,
			"",
		},
		{
			"ShouldNotValidatePasswordWithOmittedRoundsSHA256",
			"$5$4X/QmdRP6q7Ilhpc$2sperIXN6jawEYd8a8arineQHqYIEGURjZGdD4H4xs8",
			wrongPassword,
			false,
			"",
		},
		{
			"ShouldValidatePasswordWithOmittedRoundsSHA512",
			"$6$rB2PL49BuajVczWm$sA.XUPEt/j6k4kFnO58EDKsEU8rXau47.eSH6lpqc/tgC9Y0BbYcG7H3.KmMMpthWMcip/xmDn83nTUXK5Vp90",
			password,
			true,
			"",
		},
		{
			"ShouldNotValidatePasswordWithOmittedRoundsSHA512",
			"$6$rB2PL49BuajVczWm$sA.XUPEt/j6k4kFnO58EDKsEU8rXau47.eSH6lpqc/tgC9Y0BbYcG7H3.KmMMpthWMcip/xmDn83nTUXK5Vp90",
			wrongPassword,
			false,
			"",
		},
		{
			"ShouldNotValidatePasswordWithRoundsSHA512",
			"$6$rounds=1000$rB2PL49BuajVczWm$sA.XUPEt/j6k4kFnO58EDKsEU8rXau47.eSH6lpqc/tgC9Y0BbYcG7H3.KmMMpthWMcip/xmDn83nTUXK5Vp90",
			wrongPassword,
			false,
			"",
		},
		{
			"ShouldValidatePasswordWithRoundsSHA512",
			"$6$rounds=1000$eG49klxUKySvBpju$.1paw1pj51FdmvNAnsNoX8lyHMdH/S74DfkZnWWTOnGI9keTp/DXjR9ro5kJrncPSF5fc.krAwdkBxc4C8kSU1",
			password,
			true,
			"",
		},
	}

	for _, tc := range testcCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := CheckPassword(tc.expected, tc.have)

			assert.Equal(t, tc.valid, valid)
			if len(tc.err) == 0 {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}
