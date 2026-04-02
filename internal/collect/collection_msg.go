//go:build linux

package collect

const collectionNoInfoPrefix = "No information extracted."

// collectionNote returns a stable human-readable reason (max ~512 chars for schema).
func collectionNote(detail string) string {
	if len(detail) > 400 {
		detail = detail[:400]
	}
	return collectionNoInfoPrefix + " " + detail
}
