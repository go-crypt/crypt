//go:build !amd64 || purego

package crypt

const (
	ScryptKeySizeMax = maxSigned32BitInteger
)
