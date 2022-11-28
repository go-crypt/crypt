package scrypt

// Opt describes the functional option pattern for the scrypt.Hasher.
type Opt func(h *Hasher) (err error)

// WithKeySize adjusts the key size of the resulting Scrypt hash. Default is 32.
func WithKeySize(size int) Opt {
	return func(h *Hasher) (err error) {
		h.k = size

		return nil
	}
}

// WithSaltSize adjusts the salt size of the resulting Scrypt hash. Default is 16.
func WithSaltSize(size int) Opt {
	return func(h *Hasher) (err error) {
		h.bytesSalt = size

		return nil
	}
}

// WithLN sets the ln parameter (logN) of the resulting Scrypt hash. Default is 16.
func WithLN(rounds int) Opt {
	return func(h *Hasher) (err error) {
		h.ln = rounds

		return nil
	}
}

// WithR sets the r parameter (block size) of the resulting Scrypt hash. Default is 8.
func WithR(blockSize int) Opt {
	return func(h *Hasher) (err error) {
		h.r = blockSize

		return nil
	}
}

// WithP sets the p parameter (parallelism) of the resulting Scrypt hash. Default is 1.
func WithP(parallelism int) Opt {
	return func(h *Hasher) (err error) {
		h.p = parallelism

		return nil
	}
}
