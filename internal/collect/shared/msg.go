//go:build linux

package shared

const collectionNoInfoPrefix = "No information extracted."

// CollectionNote returns a stable human-readable reason (max ~512 chars for schema).
func CollectionNote(detail string) string {
	if len(detail) > 400 {
		detail = detail[:400]
	}
	return collectionNoInfoPrefix + " " + detail
}
