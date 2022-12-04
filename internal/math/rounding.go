package math

// RoundDownToNearestMultiple returns the nearest multiple of value.
func RoundDownToNearestMultiple(value, multiple int) int {
	return (value / multiple) * multiple
}

// Uint32RoundDownToNearestMultiple returns the nearest multiple of value (uint32 version).
func Uint32RoundDownToNearestMultiple(value, multiple uint32) uint32 {
	return (value / multiple) * multiple
}
