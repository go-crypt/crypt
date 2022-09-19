//go:build amd64 && !purego

package crypt

const (
	ScryptKeySizeMax = (1<<32 - 1) * 32
)
