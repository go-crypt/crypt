//go:build amd64 && !purego

package scrypt

import (
	"math"
)

const (
	// KeySizeMax is the maximum key size accepted.
	KeySizeMax = math.MaxUint32 * 32
)
