//go:build windows

package console

import (
	"syscall"
	"unsafe"
)

// OwnsWindow reports whether this process is the only one attached to the
// console. On Windows that means the exe was double-clicked rather than run
// from an already-open terminal, so the window (and everything printed to it)
// vanishes the instant the program returns.
//
// GetConsoleProcessList returns the number of processes sharing the console.
// Started from PowerShell or cmd, the shell is in that list too, so the count
// is at least two.
func OwnsWindow() bool {
	getConsoleProcessList := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	if err := getConsoleProcessList.Find(); err != nil {
		// Very old Windows, or no console at all. Assume a terminal we did not
		// create, which is the safe answer: worst case the user sees no pause.
		return false
	}

	var pids [4]uint32
	n, _, _ := getConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)
	return n == 1
}
