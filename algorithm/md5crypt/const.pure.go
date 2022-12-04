//go:build !amd64 || purego

package md5crypt

import (
	"math"
)

const (
	// IterationsMax is the maximum iterations accepted.
	IterationsMax = math.MaxInt32
)
