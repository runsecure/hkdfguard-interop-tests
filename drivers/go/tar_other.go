//go:build !windows

package main

import "os/exec"

// tarPath is the tar on PATH: GNU tar or bsdtar.
func tarPath() (string, error) {
	return exec.LookPath("tar")
}
