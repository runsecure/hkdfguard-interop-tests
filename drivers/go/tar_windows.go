package main

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// tarPath is Windows' own bsdtar, in the system folder: never one found on PATH.
func tarPath() (string, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(system, "tar.exe"), nil
}
