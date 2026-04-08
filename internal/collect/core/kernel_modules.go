//go:build linux

package core

// CollectKernelModules starts #102 core/kernel-modules module placeholder.
func CollectKernelModules() Status {
	return Status{Collected: false, Error: "not implemented"}
}
