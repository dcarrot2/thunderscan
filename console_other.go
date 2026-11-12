//go:build !windows

package main

import (
	"os"
	"os/exec"
	"runtime"
)

func enableVT() bool {
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func shouldPause() bool { return false }

func openBrowser(url string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", url).Start()
	}
	return exec.Command("xdg-open", url).Start()
}
