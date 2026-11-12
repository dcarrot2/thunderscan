//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")

// enableVT turns on ANSI color support in cmd.exe / PowerShell (Windows 10+).
func enableVT() bool {
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	if r, _, _ := kernel32.NewProc("GetConsoleMode").Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return false // not a console (redirected to a file/pipe)
	}
	const enableVirtualTerminalProcessing = 0x0004
	r, _, _ := kernel32.NewProc("SetConsoleMode").Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
	return r != 0
}

// shouldPause is true when the console window belongs only to us, i.e. the
// exe was double-clicked or had a file dragged onto it, so the window would
// otherwise vanish before the user can read the results.
func shouldPause() bool {
	var pids [4]uint32
	n, _, _ := kernel32.NewProc("GetConsoleProcessList").Call(uintptr(unsafe.Pointer(&pids[0])), 4)
	return n == 1
}

func openBrowser(url string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}
