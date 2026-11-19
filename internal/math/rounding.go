package math

// Integer is a constraint which permits any integer type.
type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// RoundDownToNearestMultiple returns value rounded down to the nearest multiple of multiple.
func RoundDownToNearestMultiple[T Integer](value, multiple T) T {
	return (value / multiple) * multiple
}
