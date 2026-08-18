//go:build linux

package confedit

// One setting at one value is the unit everything else is generated from.
//
// The sudo grant needs a line per pair, because a wildcard in a sudoers argument
// matches `/` as well and a regex needs sudo 1.9.10 — measured, see
// internal-doc/solve-explicit-sudoers-design.md. The shipped drop-in files need a
// file per pair, because a grant can only pin content that exists before the
// command runs. And the app needs to know which values it may offer.
//
// All three come from here, so they cannot disagree with what Check accepts.

// Change is one setting at one value ghostpsy is allowed to write.
type Change struct {
	Setting Setting
	Value   string
}

// Changes lists every setting-and-value pair, in a stable order.
//
// A setting with no allowed values contributes nothing: it is explained, never
// written, and a grant line for it would claim a power we do not have.
func Changes() []Change {
	var out []Change
	for _, s := range All() {
		for _, value := range s.Allow {
			out = append(out, Change{Setting: s, Value: value})
		}
	}
	return out
}
