package descrypt

// Opt describes the functional option pattern for the descrypt.Hasher.
// DES crypt has no configurable parameters, but the type is retained for
// API consistency with other algorithm packages.
type Opt func(h *Hasher) (err error)
