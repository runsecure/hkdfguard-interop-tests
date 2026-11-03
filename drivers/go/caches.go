package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache/awssecretsmanager"
	azurecache "github.com/runsecure/hkdfguard-go/cache/azurekeyvault"
	"github.com/runsecure/hkdfguard-go/cache/googlesecretmanager"
	vaultcache "github.com/runsecure/hkdfguard-go/cache/hashicorpvault"
)

// missingKey is a key no test secret holds.
const missingKey = "hkdfguard-interop-missing"

var integer = regexp.MustCompile(`^-?[0-9]{1,15}$`)

// readStore reads the secret the HKDFGUARD_TEST_* settings name for store through this port's cache
// over the release's key ring, and compares what it reads with the JSON object the settings say the
// secret holds. No value read is ever printed: a failure says only which check failed.
func readStore(store, wrapperName, service, dir string) error {
	r, w, ring, err := openRelease(wrapperName, service, dir)
	if err != nil {
		return err
	}
	defer w.Close()
	defer ring.Close()

	c := &checker{}
	switch store {
	case "awssecretsmanager":
		name, expected, err := secretSettings("HKDFGUARD_TEST_AWS_SECRET_NAME", "HKDFGUARD_TEST_AWS_SECRET_JSON")
		if err != nil {
			return err
		}
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return err
		}
		secrets, err := awssecretsmanager.New(secretsmanager.NewFromConfig(cfg), ring, awssecretsmanager.Options{})
		if err != nil {
			return err
		}
		checkJSONSecret(c, secrets, name, expected)
	case "azurekeyvault":
		id, expected, err := secretSettings("HKDFGUARD_TEST_AZURE_SECRET_ID", "HKDFGUARD_TEST_AZURE_SECRET_JSON")
		if err != nil {
			return err
		}
		vault, name, err := azureSecretID(id)
		if err != nil {
			return err
		}
		credential, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return err
		}
		secrets, err := azurecache.New(vault, credential, ring, azurecache.Options{})
		if err != nil {
			return err
		}
		checkJSONSecret(c, secrets, name, expected)
		// Key Vault matches secret names ignoring case, and so does its cache.
		got, err := readCache(secrets, strings.ToUpper(name))
		c.check(err == nil && holds(got, expected), "%s: the secret's name in upper case reads the same secret: got %d bytes, %v", store, len(got), err)
		if os.Getenv("HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS") == "true" {
			for _, key := range sortedKeys(expected) {
				if want, ok := asCached(expected[key]); ok {
					got, err := readCache(secrets, key)
					c.check(err == nil && got == want, "%s: the secret %s reads as expected: got %d bytes, %v", store, key, len(got), err)
				}
			}
		}
	case "googlesecretmanager":
		resource, expected, err := secretSettings("HKDFGUARD_TEST_GOOGLE_SECRET_NAME", "HKDFGUARD_TEST_GOOGLE_SECRET_JSON")
		if err != nil {
			return err
		}
		parts := strings.Split(resource, "/")
		if len(parts) != 4 || parts[0] != "projects" || parts[2] != "secrets" {
			return fmt.Errorf("HKDFGUARD_TEST_GOOGLE_SECRET_NAME isn't projects/{project}/secrets/{secret}")
		}
		client, err := secretmanager.NewClient(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		secrets, err := googlesecretmanager.New(client, parts[1], ring, googlesecretmanager.Options{})
		if err != nil {
			return err
		}
		checkJSONSecret(c, secrets, parts[3], expected)
	case "hashicorpvault":
		name, expected, err := secretSettings("HKDFGUARD_TEST_VAULT_SECRET_NAME", "HKDFGUARD_TEST_VAULT_SECRET_JSON")
		if err != nil {
			return err
		}
		// The cache refuses a client that follows redirects: one could send the token elsewhere.
		client, err := vaultClient("https://127.0.0.1:8200", true)
		if err != nil {
			return err
		}
		secrets, err := vaultcache.New(client, ring, vaultcache.Options{})
		if err != nil {
			return err
		}
		path, _, _ := strings.Cut(name, "#")
		checkKeys(c, secrets, path, expected)
	default:
		return fmt.Errorf("unknown store %q", store)
	}
	return c.result(fmt.Sprintf("%s through the %s %s release's ring", store, r.Producer, r.Wrapper))
}

// checkJSONSecret checks a secret holding a JSON object: read whole, it holds the expected members,
// and each member reads as "name#key".
func checkJSONSecret(c *checker, secrets hkdfguard.ProtectedReadOnlyCache, name string, expected map[string]json.RawMessage) {
	got, err := readCache(secrets, name)
	c.check(err == nil && holds(got, expected), "the whole secret holds the expected members: got %d bytes, %v", len(got), err)
	checkKeys(c, secrets, name, expected)
}

// checkKeys checks each expected member reads as "name#key", and that a key matches only exactly.
func checkKeys(c *checker, secrets hkdfguard.ProtectedReadOnlyCache, name string, expected map[string]json.RawMessage) {
	keys := sortedKeys(expected)
	for _, key := range keys {
		if want, ok := asCached(expected[key]); ok {
			got, err := readCache(secrets, name+"#"+key)
			c.check(err == nil && got == want, "#%s reads as expected: got %d bytes, %v", key, len(got), err)
		}
	}
	for _, key := range keys {
		if swapped := swapASCIICase(key); swapped != key && expected[swapped] == nil {
			got, err := readCache(secrets, name+"#"+swapped)
			c.check(err == nil && got == "", "#%s, in another ASCII case, is missing: got %d bytes, %v", key, len(got), err)
			break
		}
	}
	got, err := readCache(secrets, name+"#"+missingKey)
	c.check(err == nil && got == "", "#%s is missing: got %d bytes, %v", missingKey, len(got), err)
}

// asCached is a member as every port's cache caches it: a string as its text, true or false as its
// JSON text. An integer is compared as its JSON text too; any other number, null, an object or an
// array isn't compared, since not every port's JSON reader keeps a number's exact text.
func asCached(raw json.RawMessage) (string, bool) {
	trimmed := string(bytes.TrimSpace(raw))
	// Unmarshalling null into a string succeeds, leaving it empty; null isn't cached.
	var text string
	if trimmed != "null" && json.Unmarshal(raw, &text) == nil {
		return text, true
	}
	if trimmed == "true" || trimmed == "false" || integer.MatchString(trimmed) {
		return trimmed, true
	}
	return "", false
}

// holds reports whether value is a JSON object with exactly the expected member names, each
// comparable member holding what's expected.
func holds(value string, expected map[string]json.RawMessage) bool {
	var got map[string]json.RawMessage
	if json.Unmarshal([]byte(value), &got) != nil || got == nil || len(got) != len(expected) {
		return false
	}
	for key, raw := range expected {
		member, ok := got[key]
		if !ok {
			return false
		}
		want, comparable := asCached(raw)
		if have, _ := asCached(member); comparable && have != want {
			return false
		}
	}
	return true
}

func secretSettings(nameVariable, jsonVariable string) (string, map[string]json.RawMessage, error) {
	name, err := setting(nameVariable)
	if err != nil {
		return "", nil, err
	}
	text, err := setting(jsonVariable)
	if err != nil {
		return "", nil, err
	}
	var expected map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &expected); err != nil || expected == nil {
		return "", nil, fmt.Errorf("%s isn't a JSON object", jsonVariable)
	}
	return name, expected, nil
}

// azureSecretID splits https://{vault}.vault.azure.net/secrets/{name} into the vault's URL and the
// secret's name.
func azureSecretID(id string) (string, string, error) {
	invalid := fmt.Errorf("HKDFGUARD_TEST_AZURE_SECRET_ID isn't https://{vault}.vault.azure.net/secrets/{name}")
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" {
		return "", "", invalid
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(parts) != 2 || parts[0] != "secrets" {
		return "", "", invalid
	}
	return "https://" + u.Host + "/", parts[1], nil
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func swapASCIICase(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case 'a' <= c && c <= 'z':
			b[i] = c - 32
		case 'A' <= c && c <= 'Z':
			b[i] = c + 32
		}
	}
	return string(b)
}
