//go:build linux

package core

// Status represents one core subcomponent collection result.
type Status struct {
	Collected bool   `json:"collected"`
	Error     string `json:"error,omitempty"`
}
