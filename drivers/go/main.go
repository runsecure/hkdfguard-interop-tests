// Command interop is the Go driver for the HkdfGuard interop matrix: it produces a release (pipeline
// encryption plus a key file wrapped by one key wrapper), consumes any driver's release with its own
// port of the same wrapper, and reads a remote secret store through its cache over that release's key
// ring. See the repository README for the contract every driver follows.
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
	"github.com/runsecure/hkdfguard-go/cache"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
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
	Wrapper    string            `json:"wrapper"`
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
	wrapperName := flags.String("wrapper", native, "the key wrapper: native, awskms, azurekeyvault, googlekms or hashicorpvault")
	store := flags.String("store", "", "the remote secret store to read (cache only)")
	service := flags.String("service", "", "the provisioned service name")
	fixturesPath := flags.String("fixtures", "", "the shared fixtures file")
	dir := flags.String("dir", "", "the release directory to write (produce) or read (consume, cache)")
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
		err = produce(*wrapperName, *service, f, *dir, *cli)
	case "consume":
		err = consume(*wrapperName, *service, f, *dir)
	case "cache":
		if *store == "" {
			usage()
		}
		err = readStore(*store, *wrapperName, *service, *dir)
	default:
		usage()
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: interop produce [--wrapper W] --service S --fixtures F --dir D --cli PATH")
	fmt.Fprintln(os.Stderr, "       interop consume [--wrapper W] --service S --fixtures F --dir D")
	fmt.Fprintln(os.Stderr, "       interop cache --store C [--wrapper W] --service S --fixtures F --dir D")
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
// writes the values, and wraps the key into the key file - by handing it to the native tool on
// standard input, or through a network key wrapper in this process.
func produce(wrapperName, service string, f fixtures, dir, cli string) error {
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
	path := filepath.Join(dir, keyFile)
	if wrapperName == native {
		wrap := exec.Command(cli, "wrap", "-kf", path, "-sn", service, "--dek-stdin")
		wrap.Stdin = bytes.NewReader(pipeline.KeyBase64())
		if output, err := wrap.CombinedOutput(); err != nil {
			return fmt.Errorf("hkdfguard wrap: %w: %s", err, strings.TrimSpace(string(output)))
		}
	} else {
		w, err := newWrapper(wrapperName, service, wrapContext)
		if err != nil {
			return err
		}
		defer w.Close()
		wrapped := make([]byte, hkdfguard.MaxWrappedKeyBytes)
		n, err := w.Wrap(ctx, raw, wrapped)
		if err != nil {
			return fmt.Errorf("wrapping the pipeline key: %w", err)
		}
		if err := os.WriteFile(path, wrapped[:n], 0o600); err != nil {
			return err
		}
	}

	data, err := json.MarshalIndent(release{"go", wrapperName, service, f.KeyVersion, hex.EncodeToString(digest[:]), values}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, releaseFile), data, 0o600); err != nil {
		return err
	}
	fmt.Printf("OK produced %d secrets in %s\n", len(values), dir)
	return nil
}

// consume reads a release as an application would: builds a ring over the wrapper's KEK with the
// key file, then reveals every value through the configuration purpose of its key, and caches it.
func consume(wrapperName, service string, f fixtures, dir string) error {
	r, w, ring, err := openRelease(wrapperName, service, dir)
	if err != nil {
		return err
	}
	defer w.Close()
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

	path := filepath.Join(dir, keyFile)
	digest, err := unwrappedDigest(w, path)
	c.check(err == nil && digest == r.DekSha256, "the key file unwraps to the producer's DEK: %v", err)

	// A network KEK is shared by every application that may use it, so the context is what keeps
	// one application's key files from another's.
	if wrapperName != native {
		other, err := newWrapper(wrapperName, service, otherContext)
		if err == nil {
			_, err = unwrappedDigest(other, path)
			other.Close()
			c.check(err != nil, "the key file is refused under another context")
		} else {
			c.fail("creating a wrapper with another context: %v", err)
		}
	}

	checkCache(c, cache.New(ring), f)
	return c.result(fmt.Sprintf("the %s %s release", r.Producer, r.Wrapper))
}

// openRelease reads dir's release and builds a ring over its key file with this port of the
// release's wrapper.
func openRelease(wrapperName, service, dir string) (release, closableWrapper, *dek.KeyRing, error) {
	var r release
	data, err := os.ReadFile(filepath.Join(dir, releaseFile))
	if err == nil {
		err = json.Unmarshal(data, &r)
	}
	if err != nil {
		return r, nil, nil, err
	}
	if r.Wrapper != wrapperName {
		return r, nil, nil, fmt.Errorf("the release was wrapped with %q, not %q", r.Wrapper, wrapperName)
	}
	w, err := newWrapper(wrapperName, service, wrapContext)
	if err != nil {
		return r, nil, nil, err
	}
	ring, err := dek.Build(ctx, dek.Config{
		KeyWrapper:            w,
		CryptoProviderFactory: aesgcm256.NewFactory(),
		KeyRefreshInterval:    time.Minute,
		KeyFiles:              map[int]string{r.KeyVersion: filepath.Join(dir, keyFile)},
	})
	if err != nil {
		w.Close()
		return r, nil, nil, fmt.Errorf("building the key ring: %w", err)
	}
	return r, w, ring, nil
}

// checkCache stores every fixture in a protected cache over the release's ring and reads it back:
// names that differ in ASCII case share an entry, names that differ in non-ASCII case don't, and an
// empty value, or a second value under an existing name, is refused.
func checkCache(c *checker, protected hkdfguard.ProtectedCache, f fixtures) {
	for _, s := range f.Secrets {
		err := protected.Add(ctx, s.Identifier, []byte(s.Plaintext))
		if s.Plaintext == "" {
			c.check(errors.Is(err, cache.ErrEmptyValue), "cache: an empty %s is refused: %v", s.Identifier, err)
			continue
		}
		if err != nil {
			c.fail("cache: adding %s: %v", s.Identifier, err)
			continue
		}
		for _, name := range append([]string{s.Identifier}, s.AlsoReadAs...) {
			got, err := readCache(protected, name)
			c.check(err == nil && got == s.Plaintext, "cache: %s reads as %s: got %d bytes, %v", s.Identifier, name, len(got), err)
		}
		for _, name := range s.MustNotReadAs {
			got, err := readCache(protected, name)
			c.check(err == nil && got == "", "cache: %s is missing as %s: got %d bytes, %v", s.Identifier, name, len(got), err)
		}
		if len(s.AlsoReadAs) > 0 {
			err := protected.Add(ctx, s.AlsoReadAs[0], []byte("again"))
			c.check(errors.Is(err, hkdfguard.ErrAlreadyExists), "cache: adding %s again as %s is refused: %v", s.Identifier, s.AlsoReadAs[0], err)
		}
	}
}

// readCache is the value cached under name, or "" if there is none.
func readCache(protected hkdfguard.ProtectedReadOnlyCache, name string) (string, error) {
	size, ok, err := protected.MaxDecryptedLength(ctx, name)
	if err != nil || !ok {
		return "", err
	}
	result := make([]byte, size)
	defer hkdfguard.Wipe(result)
	n, err := protected.Decrypt(ctx, name, result)
	if err != nil {
		return "", err
	}
	return string(result[:n]), nil
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

func unwrappedDigest(wrapper hkdfguard.KeyWrapper, path string) (string, error) {
	wrapped, err := wrapper.ReadKeyFile(ctx, path)
	if err != nil {
		return "", err
	}
	raw := make([]byte, hkdfguard.MaxWrappedKeyBytes)
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

func (c *checker) result(what string) error {
	if c.failed > 0 {
		return fmt.Errorf("%d of %d checks failed reading %s", c.failed, c.passed+c.failed, what)
	}
	fmt.Printf("OK %d checks passed reading %s\n", c.passed, what)
	return nil
}
