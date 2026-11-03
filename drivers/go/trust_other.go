//go:build !windows

package main

import (
	"os"

	"github.com/runsecure/hkdfguard-go/securefile"
)

// keyFileTrust trusts this account to have written the key files it reads, as well as root: the
// matrix writes and reads every key file as one account. Never trust an application's own account
// outside a test or developer host.
func keyFileTrust() (securefile.KeyFileTrust, error) {
	return securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{UnixUserIDs: []uint32{uint32(os.Geteuid())}}), nil
}
