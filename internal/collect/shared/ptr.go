package shared

// StringPtr returns a pointer to a copy of s.
func StringPtr(s string) *string {
	return &s
}

// BoolPtr returns a pointer to b.
func BoolPtr(b bool) *bool {
	return &b
}

// IntPtr returns a pointer to n.
func IntPtr(n int) *int {
	return &n
}
