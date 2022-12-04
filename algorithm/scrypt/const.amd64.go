//go:build amd64 && !purego

package scrypt

import (
	"math"
)

const (
	// KeyLengthMax is the maximum key size accepted.
	KeyLengthMax = math.MaxUint32 * 32
)
