package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewArgon2Hash(t *testing.T) {
	testCases := []struct {
		name     string
		have     Argon2Hash
		password string
		salt     string
		expected string
	}{
		{name: "ShouldHashPassword/argon2d/apple123", have: Argon2Hash{variant: Argon2VariantD, m: 65536, t: 4, p: 4}, password: "apple123", salt: "PUfIWctZa611rpXSOicEAA", expected: "$argon2d$v=19$m=65536,t=4,p=4$PUfIWctZa611rpXSOicEAA$eUtgGpyO1+ylLPGhN8gvRXBXF+Zd97kQIZA7OgX4VIM"},
		{name: "ShouldHashPassword/argon2d/another", have: Argon2Hash{variant: Argon2VariantD, m: 65536, t: 4, p: 4}, password: "another", salt: "j5GyNoaQsvYeA8D4Pyek9A", expected: "$argon2d$v=19$m=65536,t=4,p=4$j5GyNoaQsvYeA8D4Pyek9A$O1LC/BW/nF2/PkgSR2/O62q5ERTXxvIVvBFgeN4REUw"},
		{name: "ShouldHashPassword/argon2d/th15isalongandcomplexpassw0rd@", have: Argon2Hash{variant: Argon2VariantD, m: 65536, t: 4, p: 4}, password: "th15isalongandcomplexpassw0rd@", salt: "+j8H4BzjvPeeEwKglDLGWA", expected: "$argon2d$v=19$m=65536,t=4,p=4$+j8H4BzjvPeeEwKglDLGWA$6OmSgnEaAi+HrvMiMmHhuCMK/9s8zg0KJepXUP8QKFo"},
		{name: "ShouldHashPassword/argon2d/password123", have: Argon2Hash{variant: Argon2VariantD, m: 65536, t: 4, p: 4}, password: "password123", salt: "QMi5VwrhvBeiVCplDKEUAg", expected: "$argon2d$v=19$m=65536,t=4,p=4$QMi5VwrhvBeiVCplDKEUAg$BbFZ3C+ptJO7DhzBIxit9e1ZI7uk9KG5n1kpTZf6ZwQ"},
		{name: "ShouldHashPassword/argon2d/p@ssw0rd", have: Argon2Hash{variant: Argon2VariantD, m: 65536, t: 4, p: 4}, password: "p@ssw0rd", salt: "25tzbs1ZCwEAAGCMEYJQyg", expected: "$argon2d$v=19$m=65536,t=4,p=4$25tzbs1ZCwEAAGCMEYJQyg$OlkYC6K4I/X4UJmMC0qecqUwVwLvkT05eje92iumf8E"},

		{name: "ShouldHashPassword/argon2i/apple123", have: Argon2Hash{variant: Argon2VariantI, m: 65536, t: 4, p: 4}, password: "apple123", salt: "cU6JsTZGCEEoxRjD+L/3/g", expected: "$argon2i$v=19$m=65536,t=4,p=4$cU6JsTZGCEEoxRjD+L/3/g$RyLxXgYks/RplDoRKaxvZDJBvrS7R6vGeusKrfXP0Pg"},
		{name: "ShouldHashPassword/argon2i/another", have: Argon2Hash{variant: Argon2VariantI, m: 65536, t: 4, p: 4}, password: "another", salt: "DCHk/B+DcI7xHsP4/7/XWg", expected: "$argon2i$v=19$m=65536,t=4,p=4$DCHk/B+DcI7xHsP4/7/XWg$6luPgx9bGrYQR0oJdNVfsE85zr0AECdD6RHHgRKHG3M"},
		{name: "ShouldHashPassword/argon2i/th15isalongandcomplexpassw0rd@", have: Argon2Hash{variant: Argon2VariantI, m: 65536, t: 4, p: 4}, password: "th15isalongandcomplexpassw0rd@", salt: "D6H0HmOs1ZpzDkHoXQvh/A", expected: "$argon2i$v=19$m=65536,t=4,p=4$D6H0HmOs1ZpzDkHoXQvh/A$xQK6H91LeP5ZLv7PHFMpVYHbAgEKB3gnh/0z0ScJRow"},
		{name: "ShouldHashPassword/argon2i/password123", have: Argon2Hash{variant: Argon2VariantI, m: 65536, t: 4, p: 4}, password: "password123", salt: "NcaYs3bufQ8BwPhfSyklBA", expected: "$argon2i$v=19$m=65536,t=4,p=4$NcaYs3bufQ8BwPhfSyklBA$Iuz9GZw5AUrXQ32Z4poJ3COUTp4w0amWRA6XtMnB5pw"},
		{name: "ShouldHashPassword/argon2i/p@ssw0rd", have: Argon2Hash{variant: Argon2VariantI, m: 65536, t: 4, p: 4}, password: "p@ssw0rd", salt: "t7a2lhKCsBYC4HxPCcH4nw", expected: "$argon2i$v=19$m=65536,t=4,p=4$t7a2lhKCsBYC4HxPCcH4nw$zhSHktwftzV0aL6MgsN2eiZTa7gq8yFiHxJaomEeNfo"},

		{name: "ShouldHashPassword/argon2id/apple123", have: Argon2Hash{variant: Argon2VariantID, m: 65536, t: 4, p: 4}, password: "apple123", salt: "jfE+JyTE2DtnDCHknJOSsg", expected: "$argon2id$v=19$m=65536,t=4,p=4$jfE+JyTE2DtnDCHknJOSsg$+BPKo7PFUjKycwSpEK0Z1ciUPKp05uJvSfC7C+QAvAk"},
		{name: "ShouldHashPassword/argon2id/another", have: Argon2Hash{variant: Argon2VariantID, m: 65536, t: 4, p: 4}, password: "another", salt: "FGJszRlDyDmntJbyHoNQag", expected: "$argon2id$v=19$m=65536,t=4,p=4$FGJszRlDyDmntJbyHoNQag$iGKvD7Oso+PcRhSVT/q/QCRb/mNZL0cwbtCKMzW/NPw"},
		{name: "ShouldHashPassword/argon2id/th15isalongandcomplexpassw0rd@", have: Argon2Hash{variant: Argon2VariantID, m: 65536, t: 4, p: 4}, password: "th15isalongandcomplexpassw0rd@", salt: "qvU+J6Q0xnivdS5FSMm5Fw", expected: "$argon2id$v=19$m=65536,t=4,p=4$qvU+J6Q0xnivdS5FSMm5Fw$SpP3dXG6xTUcSxGrj+GTtWCFzekltzUodkIcPuX0KhY"},
		{name: "ShouldHashPassword/argon2id/password123", have: Argon2Hash{variant: Argon2VariantID, m: 65536, t: 4, p: 4}, password: "password123", salt: "NcaYs3bufQ8BwPhfSyklBA", expected: "$argon2id$v=19$m=65536,t=4,p=4$NcaYs3bufQ8BwPhfSyklBA$2rePx1Br3YqXPROcvo6Ze9fdMRAMLzvm2eFiX+j4Ct4"},
		{name: "ShouldHashPassword/argon2id/p@ssw0rd", have: Argon2Hash{variant: Argon2VariantID, m: 65536, t: 4, p: 4}, password: "p@ssw0rd", salt: "t7a2lhKCsBYC4HxPCcH4nw", expected: "$argon2id$v=19$m=65536,t=4,p=4$t7a2lhKCsBYC4HxPCcH4nw$62nblX1UlyusrAsH8rrXYvq0z7wpWJVGC4+7Xooy8ss"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewArgon2Hash().WithVariant(tc.have.variant).WithP(tc.have.p).WithM(tc.have.m).WithT(tc.have.t)

			salt, err := b64rs.DecodeString(tc.salt)

			require.NoError(t, err)

			actual, err := h.HashWithSalt(tc.password, salt)

			assert.NoError(t, err)

			require.NotNil(t, actual)

			assert.Equal(t, tc.expected, actual.Encode())
		})
	}
}
