//go:build linux

package shared

// TruncateRunes truncates to at most max runes.
func TruncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	rs := []rune(s)
	if len(rs) <= max {
		return s
	}
	return string(rs[:max])
}
