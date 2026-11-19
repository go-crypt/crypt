package validate

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/math"
)

// Range returns an error wrapping sentinel if value is less than minimum or greater than maximum, otherwise it returns
// nil. The name is used to describe the parameter in the error.
func Range[T math.Integer](sentinel error, name string, value, minimum, maximum T) (err error) {
	if value < minimum || value > maximum {
		return fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, sentinel, name, minimum, "", maximum, value)
	}

	return nil
}
