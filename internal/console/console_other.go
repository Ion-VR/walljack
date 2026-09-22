//go:build !windows

package console

// OwnsWindow is always false away from Windows. A terminal that was already
// open stays open after the program exits, and nothing launches a CLI binary
// by double-clicking it.
func OwnsWindow() bool { return false }
