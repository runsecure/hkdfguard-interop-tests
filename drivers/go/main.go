// Command interop is the Go driver for the HkdfGuard interop matrix: it produces a release (pipeline
// encryption plus a key file wrapped by the native hkdfguard tool) and consumes any driver's release.
// See the repository README for the contract every driver follows.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/keywrapping/nativev1"
)

const (
	releaseFile  = "release.json"
	keyFile      = "dek.wrapped"
	formatPrefix = "enc::v"
)

type secret struct {
	Identifier    string   `json:"identifier"`
	Plaintext     string   `json:"plaintext"`
	AlsoReadAs    []string `json:"alsoReadAs,omitempty"`
	MustNotReadAs []string `json:"mustNotReadAs,omitempty"`
}

type fixtures struct {
	KeyVersion int      `json:"keyVersion"`
	Secrets    []secret `json:"secrets"`
}

type release struct {
	Producer   string            `json:"producer"`
	Service    string            `json:"service"`
	KeyVersion int               `json:"keyVersion"`
	DekSha256  string            `json:"dekSha256"`
	Values     map[string]string `json:"values"`
}

var ctx = context.Background()

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	service := flags.String("service", "", "the provisioned service name")
	fixturesPath := flags.String("fixtures", "", "the shared fixtures file")
	dir := flags.String("dir", "", "the release directory to write (produce) or read (consume)")
	cli := flags.String("cli", "", "the native hkdfguard tool (produce only)")
	_ = flags.Parse(os.Args[2:])
	if *service == "" || *fixturesPath == "" || *dir == "" {
		usage()
	}

	f, err := readFixtures(*fixturesPath)
	if err != nil {
		fatal(err)
	}
	switch os.Args[1] {
	case "produce":
		if *cli == "" {
			usage()
		}
		err = produce(*service, f, *dir, *cli)
	case "consume":
		err = consume(*service, f, *dir)
	default:
		usage()
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: interop produce --service S --fixtures F --dir D --cli PATH")
	fmt.Fprintln(os.Stderr, "       interop consume --service S --fixtures F --dir D")
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "FAIL", err)
	os.Exit(1)
}

func readFixtures(path string) (fixtures, error) {
	var f fixtures
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &f)
	}
	return f, err
}

// produce does what a release pipeline does: encrypts every fixture under a fresh pipeline key,
// writes the values, and hands the key to the native tool on standard input to wrap into the key file.
func produce(service string, f fixtures, dir, cli string) error {
	pipeline, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), f.KeyVersion)
	if err != nil {
		return err
	}
	defer pipeline.Close()

	values := make(map[string]string, len(f.Secrets))
	for _, s := range f.Secrets {
		if values[s.Identifier], err = pipeline.Encrypt(ctx, []byte(s.Plaintext), s.Identifier); err != nil {
			return fmt.Errorf("encrypting %s: %w", s.Identifier, err)
		}
	}

	// Test only: a hash of the DEK, so every consumer can prove it unwrapped this same key. Never
	// record anything derived from a DEK beside its key file in a real pipeline.
	raw := make([]byte, aesgcm256.KeySize)
	defer hkdfguard.Wipe(raw)
	if n, err := base64.StdEncoding.Decode(raw, pipeline.KeyBase64()); err != nil || n != aesgcm256.KeySize {
		return fmt.Errorf("decoding the pipeline key: %d bytes, %v", n, err)
	}
	digest := sha256.Sum256(raw)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	wrap := exec.Command(cli, "wrap", "-kf", filepath.Join(dir, keyFile), "-sn", service, "--dek-stdin")
	wrap.Stdin = bytes.NewReader(pipeline.KeyBase64())
	if output, err := wrap.CombinedOutput(); err != nil {
		return fmt.Errorf("hkdfguard wrap: %w: %s", err, strings.TrimSpace(string(output)))
	}

	data, err := json.MarshalIndent(release{"go", service, f.KeyVersion, hex.EncodeToString(digest[:]), values}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, releaseFile), data, 0o600); err != nil {
		return err
	}
	fmt.Printf("OK produced %d secrets in %s\n", len(values), dir)
	return nil
}

// consume reads a release as an application would: builds a ring over the native KEK with the key
// file, then reveals every value through the configuration purpose of its key.
func consume(service string, f fixtures, dir string) error {
	var r release
	data, err := os.ReadFile(filepath.Join(dir, releaseFile))
	if err == nil {
		err = json.Unmarshal(data, &r)
	}
	if err != nil {
		return err
	}

	wrapper, err := nativev1.New(service)
	if err != nil {
		return err
	}
	ring, err := dek.Build(ctx, dek.Config{
		KeyWrapper:            wrapper,
		CryptoProviderFactory: aesgcm256.NewFactory(),
		KeyRefreshInterval:    time.Minute,
		KeyFiles:              map[int]string{r.KeyVersion: filepath.Join(dir, keyFile)},
	})
	if err != nil {
		return fmt.Errorf("building the key ring: %w", err)
	}
	defer ring.Close()

	c := &checker{}
	for _, s := range f.Secrets {
		value, ok := r.Values[s.Identifier]
		if !ok {
			c.fail("%s: missing from the release", s.Identifier)
			continue
		}
		for _, name := range append([]string{s.Identifier}, s.AlsoReadAs...) {
			got, err := reveal(ring, name, value)
			c.check(err == nil && got == s.Plaintext, "%s reads as %s: got %d bytes, %v", s.Identifier, name, len(got), err)
		}
		for _, name := range s.MustNotReadAs {
			_, err := reveal(ring, name, value)
			c.check(err != nil, "%s must not read as %s", s.Identifier, name)
		}
	}

	first, second := f.Secrets[0], f.Secrets[1]
	_, err = reveal(ring, second.Identifier, r.Values[first.Identifier])
	c.check(err != nil, "%s moved under %s fails authentication", first.Identifier, second.Identifier)

	tampered, err := tamper(r.Values[first.Identifier])
	if err == nil {
		_, err = reveal(ring, first.Identifier, tampered)
		c.check(err != nil, "%s with a flipped tag bit fails authentication", first.Identifier)
	} else {
		c.fail("tampering %s: %v", first.Identifier, err)
	}

	digest, err := unwrappedDigest(wrapper, filepath.Join(dir, keyFile))
	c.check(err == nil && digest == r.DekSha256, "the key file unwraps to the producer's DEK: %v", err)

	return c.result(r.Producer)
}

func reveal(ring *dek.KeyRing, name, value string) (string, error) {
	purpose, err := hkdfguard.ConfigurationPurpose(name)
	if err != nil {
		return "", err
	}
	protector, err := ring.CreateProtector(purpose)
	if err != nil {
		return "", err
	}
	size, err := protector.MaxDecryptedLength(ctx, value)
	if err != nil {
		return "", err
	}
	result := make([]byte, size)
	defer hkdfguard.Wipe(result)
	n, err := protector.Decrypt(ctx, value, result)
	if err != nil {
		return "", err
	}
	return string(result[:n]), nil
}

// tamper flips one bit in the last byte (the GCM tag) of a formatted value.
func tamper(value string) (string, error) {
	if !strings.HasPrefix(value, formatPrefix) {
		return "", errors.New("not an enc::v<version>::<base64> value")
	}
	cut := strings.Index(value[len(formatPrefix):], "::")
	if cut < 0 {
		return "", errors.New("not an enc::v<version>::<base64> value")
	}
	head := value[:len(formatPrefix)+cut+2]
	body, err := base64.StdEncoding.DecodeString(value[len(head):])
	if err != nil {
		return "", err
	}
	body[len(body)-1] ^= 0x01
	return head + base64.StdEncoding.EncodeToString(body), nil
}

func unwrappedDigest(wrapper *nativev1.KeyWrapper, path string) (string, error) {
	wrapped, err := wrapper.ReadKeyFile(ctx, path)
	if err != nil {
		return "", err
	}
	raw := make([]byte, aesgcm256.KeySize)
	defer hkdfguard.Wipe(raw)
	n, err := wrapper.Unwrap(ctx, wrapped, raw)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw[:n])
	return hex.EncodeToString(digest[:]), nil
}

type checker struct{ passed, failed int }

func (c *checker) check(ok bool, format string, args ...any) {
	if ok {
		c.passed++
		return
	}
	c.fail(format, args...)
}

func (c *checker) fail(format string, args ...any) {
	c.failed++
	fmt.Printf("FAIL "+format+"\n", args...)
}

func (c *checker) result(producer string) error {
	if c.failed > 0 {
		return fmt.Errorf("%d of %d checks failed reading the %s release", c.failed, c.passed+c.failed, producer)
	}
	fmt.Printf("OK %d checks passed reading the %s release\n", c.passed, producer)
	return nil
}
