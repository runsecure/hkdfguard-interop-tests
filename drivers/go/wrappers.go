package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	googlekmsapi "cloud.google.com/go/kms/apiv1"
	"github.com/hashicorp/vault/api"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/keywrapping/awskms"
	"github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault"
	"github.com/runsecure/hkdfguard-go/keywrapping/googlekms"
	"github.com/runsecure/hkdfguard-go/keywrapping/hashicorpvault"
	"github.com/runsecure/hkdfguard-go/keywrapping/nativev1"
)

const (
	native = "native"

	// wrapContext is the context every port's integration tests bind their key files to, so the
	// matrix runs under the IAM, key and token policies already written for those tests.
	wrapContext = "hkdfguard.integrationtest"
	// otherContext is the one those tests check a key file is refused under.
	otherContext = "hkdfguard.integrationtest.other"

	defaultVaultAddress = "http://127.0.0.1:8200"
)

// closableWrapper is a key wrapper and whatever client it was built over, released by Close.
type closableWrapper interface {
	hkdfguard.KeyWrapper
	Close()
}

type withClose struct {
	hkdfguard.KeyWrapper
	close func()
}

func (w withClose) Close() {
	if w.close != nil {
		w.close()
	}
}

// newWrapper is this port's wrapper named name, over the KEK the HKDFGUARD_TEST_* settings name and
// bound to context; the native one is over the service's KEK on this host. A network wrapper reads
// key files only from where this account is trusted to have written them, since the matrix writes
// and reads them as one account (see keyFileTrust).
func newWrapper(name, service, context string) (closableWrapper, error) {
	if name == native {
		w, err := nativev1.New(service)
		return withClose{KeyWrapper: w}, err
	}
	trust, err := keyFileTrust()
	if err != nil {
		return nil, err
	}
	switch name {
	case "awskms":
		key, err := setting("HKDFGUARD_TEST_AWS_KMS_KEY_ID")
		if err != nil {
			return nil, err
		}
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}
		w, err := awskms.New(kms.NewFromConfig(cfg), key, awskms.Options{
			EncryptionContext: map[string]string{"purpose": context},
			KeyFileTrust:      trust,
		})
		return withClose{KeyWrapper: w}, err
	case "azurekeyvault":
		wrapKey, err := setting("HKDFGUARD_TEST_AZURE_WRAP_KEY_ID")
		if err != nil {
			return nil, err
		}
		signKey, err := setting("HKDFGUARD_TEST_AZURE_SIGN_KEY_ID")
		if err != nil {
			return nil, err
		}
		credential, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, err
		}
		w, err := azurekeyvault.New(wrapKey, signKey, credential, azurekeyvault.Options{Context: context, KeyFileTrust: trust})
		return withClose{KeyWrapper: w}, err
	case "googlekms":
		key, err := setting("HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME")
		if err != nil {
			return nil, err
		}
		client, err := googlekmsapi.NewKeyManagementClient(ctx)
		if err != nil {
			return nil, err
		}
		w, err := googlekms.New(client, key, googlekms.Options{Context: context, KeyFileTrust: trust})
		if err != nil {
			client.Close()
			return nil, err
		}
		return withClose{w, func() { client.Close() }}, nil
	case "hashicorpvault":
		key, err := setting("HKDFGUARD_TEST_VAULT_TRANSIT_KEY")
		if err != nil {
			return nil, err
		}
		client, err := vaultClient(defaultVaultAddress, false)
		if err != nil {
			return nil, err
		}
		w, err := hashicorpvault.New(client, key, hashicorpvault.Options{
			MountPath:    os.Getenv("HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT"),
			Context:      context,
			KeyFileTrust: trust,
		})
		return withClose{KeyWrapper: w}, err
	}
	return nil, fmt.Errorf("unknown wrapper %q", name)
}

// vaultClient is a client for the Vault server HKDFGUARD_TEST_VAULT_ADDR names (else
// defaultAddress), trusting the CA HKDFGUARD_TEST_VAULT_CACERT names, if any, and authenticated with
// HKDFGUARD_TEST_VAULT_TOKEN. VAULT_* variables are ignored: the client is configured from these alone.
func vaultClient(defaultAddress string, disableRedirects bool) (*api.Client, error) {
	token, err := setting("HKDFGUARD_TEST_VAULT_TOKEN")
	if err != nil {
		return nil, err
	}
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	cfg.Address = defaultAddress
	if address := os.Getenv("HKDFGUARD_TEST_VAULT_ADDR"); address != "" {
		cfg.Address = address
	}
	cfg.DisableRedirects = disableRedirects
	if ca := os.Getenv("HKDFGUARD_TEST_VAULT_CACERT"); ca != "" {
		if err := cfg.ConfigureTLS(&api.TLSConfig{CACert: ca}); err != nil {
			return nil, err
		}
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}

func setting(name string) (string, error) {
	if value := os.Getenv(name); value != "" {
		return value, nil
	}
	return "", errors.New(name + " is not set")
}
