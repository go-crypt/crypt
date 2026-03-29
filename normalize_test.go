package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalize(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected string
	}{
		{
			"ShouldStripCRYPTPrefix",
			"{CRYPT}$6$salt$key",
			"$6$salt$key",
		},
		{
			"ShouldStripARGON2Prefix",
			"{ARGON2}$argon2id$v=19$m=65536,t=3,p=4$salt$key",
			"$argon2id$v=19$m=65536,t=3,p=4$salt$key",
		},
		{
			"ShouldRewritePBKDF2Prefix",
			"{PBKDF2-SHA256}310000$salt$key",
			"$pbkdf2-sha256$310000$salt$key",
		},
		{
			"ShouldRewritePBKDF2PrefixWithoutSHAVariant",
			"{PBKDF2}120000$salt$key",
			"$pbkdf2$120000$salt$key",
		},
		{
			"ShouldNotModifyNormalDigest",
			"$6$salt$key",
			"$6$salt$key",
		},
		{
			"ShouldHandleEmptyString",
			"",
			"",
		},
		{
			"ShouldNormalizeCiscoType8",
			"$8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs",
			"$pbkdf2-sha256$20000$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs",
		},
		{
			"ShouldNormalizeCiscoType9",
			"$9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM",
			"$scrypt$ln=14,r=1,p=1$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM",
		},
		{
			"ShouldNormalizeCiscoType10",
			"$sha512$5000$zJZ/+1K9lmgpmVlRXjPEYQ==$9VOAeH+g4QIPkUyWfdq79w==",
			"$pbkdf2-sha512$5000$zJZ/.1K9lmgpmVlRXjPEYQ$9VOAeH.g4QIPkUyWfdq79w",
		},
		{
			"ShouldNotModifyType5",
			"$1$GgghHhJ7$3LxDSE8US1E",
			"$1$GgghHhJ7$3LxDSE8US1E",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, Normalize(tc.have))
		})
	}
}
