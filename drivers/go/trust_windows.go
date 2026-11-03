package main

import (
	"syscall"

	"github.com/runsecure/hkdfguard-go/securefile"
)

// keyFileTrust trusts this account to have written the key files it reads, as well as
// Administrators: the matrix writes and reads every key file as one account. Never trust an
// application's own account outside a test or developer host.
func keyFileTrust() (securefile.KeyFileTrust, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return securefile.KeyFileTrust{}, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return securefile.KeyFileTrust{}, err
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return securefile.KeyFileTrust{}, err
	}
	return securefile.NewKeyFileTrust(securefile.KeyFileTrustOptions{WindowsPrincipals: []string{sid}}), nil
}
