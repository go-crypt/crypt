package math

// RoundDownToNearestMultiple returns the nearest multiple of value.
func RoundDownToNearestMultiple(value, multiple int) int {
	return (value / multiple) * multiple
}
