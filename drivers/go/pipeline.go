package main

// The secrets pipeline half of a release: every fixture in the fixtures' pipeline section is pulled
// through the port's real pipeline.Writer, over an in-memory store, and written in each of the
// writer's layouts to D/pipeline. A consumer reads them back with its own port's caches over the
// release's key ring. See the README's driver contract.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cache/filepersecret"
	"github.com/runsecure/hkdfguard-go/cache/jsonsecretsfile"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/pipeline"
	"github.com/runsecure/hkdfguard-go/securefile"
)

const (
	pipelineDir           = "pipeline"
	jsonSecretsFile       = "secrets.json"
	streamJSONSecretsFile = "secrets.stream.json"
	emptyJSONSecretsFile  = "secrets.empty.json"
	secretsTar            = "secrets.tar"
	pipelineFilesDir      = "files"
	pipelineUnpackedDir   = "unpacked"
	consumerDir           = "consumed-by-go"

	// The base64 of a 32-byte key: 44 ASCII characters, no line ending.
	keyBase64Length = 44
)

// pipelineSecret and pipelineFixtures are the fixtures' pipeline section: see fixtures/secrets.json
// and the README.
type pipelineSecret struct {
	Name       string   `json:"name"`
	FileName   string   `json:"fileName"`
	Plaintext  string   `json:"plaintext"`
	AlsoReadAs []string `json:"alsoReadAs,omitempty"`
}

type pipelineFixtures struct {
	Store          map[string]string `json:"store"`
	Secrets        []pipelineSecret  `json:"secrets"`
	Missing        []string          `json:"missing"`
	Refused        [][]string        `json:"refused"`
	MissingLookups []string          `json:"missingLookups"`
	InvalidLookups []string          `json:"invalidLookups"`
}

func (f pipelineFixtures) fileNames() []string {
	names := make([]string, len(f.Secrets))
	for i, s := range f.Secrets {
		names[i] = s.FileName
	}
	return names
}

// memoryStore is a pipeline.SecretStore over an in-memory store: each store name maps to its value's
// exact text, handed to the writer as UTF-8 and zeroed after. Names match exactly, and a store name
// is 1 or more ASCII letters, digits, '/', '_', '.' and '-'.
type memoryStore map[string]string

var storeName = regexp.MustCompile(`^[A-Za-z0-9/_.\-]+$`)

func (memoryStore) IsValidName(name string) bool { return storeName.MatchString(name) }

func (m memoryStore) ReadSecret(ctx context.Context, name string, secret *pipeline.Secret) error {
	text, ok := m[name]
	if !ok {
		return nil
	}
	value := []byte(text)
	defer hkdfguard.Wipe(value)
	return secret.ProtectSecret(ctx, value)
}

// writePipeline writes the release's pipeline folder. The writers use the release's own pipeline
// protector, so every value decrypts under the release's key ring, and they never close it.
func writePipeline(protector *aesgcm256.PipelineDataProtector, f pipelineFixtures, dir string) error {
	store := memoryStore(f.Store)
	for _, s := range f.Secrets {
		if pipeline.FileName(s.Name) != s.FileName {
			return fmt.Errorf("pipeline: %s's file name isn't %s", s.Name, s.FileName)
		}
	}
	for _, names := range f.Refused {
		refused, err := pipeline.New(protector, names, store, pipeline.Options{})
		if errors.Is(err, pipeline.ErrInvalidArgument) {
			continue
		}
		if err == nil {
			refused.Close()
			return fmt.Errorf("pipeline: the writer accepted [%s]", strings.Join(names, ", "))
		}
		return fmt.Errorf("pipeline: refusing [%s]: %w", strings.Join(names, ", "), err)
	}

	folder := filepath.Join(dir, pipelineDir)
	if err := os.MkdirAll(folder, 0o700); err != nil {
		return err
	}
	if err := writeMainPipeline(protector, f, store, folder); err != nil {
		return err
	}

	missing, err := pipeline.New(protector, f.Missing, store, pipeline.Options{})
	if err != nil {
		return fmt.Errorf("pipeline: the writer over the missing names: %w", err)
	}
	defer missing.Close()
	err = missing.PullSecrets(ctx)
	if err == nil {
		return errors.New("pipeline: pulling secrets the store holds no value for succeeded")
	}
	if !errors.Is(err, pipeline.ErrSecretNotFound) {
		return fmt.Errorf("pipeline: pulling secrets the store holds no value for: %w", err)
	}
	if kept := len(missing.ProtectedSecrets()); kept != 0 {
		return fmt.Errorf("pipeline: pulling only missing secrets kept %d", kept)
	}
	return missing.WriteJSONSecrets(filepath.Join(folder, emptyJSONSecretsFile))
}

// writeMainPipeline pulls the fixtures' secrets and writes them in every layout the writer has.
func writeMainPipeline(protector *aesgcm256.PipelineDataProtector, f pipelineFixtures, store memoryStore, folder string) error {
	names := make([]string, len(f.Secrets))
	for i, s := range f.Secrets {
		names[i] = s.Name
	}
	writer, err := pipeline.New(protector, names, store, pipeline.Options{})
	if err != nil {
		return fmt.Errorf("pipeline: the writer over the secrets: %w", err)
	}
	defer writer.Close()
	if err := writer.PullSecrets(ctx); err != nil {
		return fmt.Errorf("pipeline: pulling the secrets: %w", err)
	}
	var kept []string
	for name := range writer.ProtectedSecrets() {
		kept = append(kept, name)
	}
	slices.Sort(kept)
	expected := f.fileNames()
	slices.Sort(expected)
	if !slices.Equal(kept, expected) {
		return errors.New("pipeline: the writer's protected secrets aren't the fixtures' file names")
	}

	if err := writer.WriteJSONSecrets(filepath.Join(folder, jsonSecretsFile)); err != nil {
		return err
	}
	if err := writeToFile(filepath.Join(folder, streamJSONSecretsFile), func(w io.Writer) error { return writer.WriteJSONSecretsTo(ctx, w) }); err != nil {
		return err
	}
	if err := writer.WriteProtectedSecretFiles(filepath.Join(folder, pipelineFilesDir)); err != nil {
		return err
	}
	if err := writeToFile(filepath.Join(folder, secretsTar), func(w io.Writer) error { return writer.WriteProtectedSecretFilesTo(ctx, w) }); err != nil {
		return err
	}

	// As a deployment would: the archive straight into a tar process's standard input.
	unpacked := filepath.Join(folder, pipelineUnpackedDir)
	if err := os.MkdirAll(unpacked, 0o700); err != nil {
		return err
	}
	if err := untar(unpacked, func(w io.Writer) error { return writer.WriteProtectedSecretFilesTo(ctx, w) }); err != nil {
		return fmt.Errorf("pipeline: piping the archive to tar: %w", err)
	}
	if difference := compareFolders(filepath.Join(folder, pipelineFilesDir), unpacked, f.fileNames()); difference != "" {
		return fmt.Errorf("pipeline: the archive piped to tar unpacked differently: %s", difference)
	}
	return nil
}

// writeToFile has write write into a file it creates, then closes it.
func writeToFile(path string, write func(io.Writer) error) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := write(file); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// fixedWriter is an io.Writer into a buffer that never grows, so nothing written to it is copied
// elsewhere: a write that doesn't fit fails.
type fixedWriter struct {
	buffer []byte
	n      int
}

func (f *fixedWriter) Write(b []byte) (int, error) {
	if len(b) > len(f.buffer)-f.n {
		return 0, errors.New("more than the buffer holds")
	}
	f.n += copy(f.buffer[f.n:], b)
	return len(b), nil
}

// readDEKThroughWriteDEK writes the pipeline key through WriteDEK, as the wrap tool's --dek-stdin
// reads it, into memory, and decodes it into raw: so every wrapper's key file comes from those
// bytes, and every consumer's DEK check proves them. Checks they are exactly the key's 44 base64
// characters as ASCII, without a line ending.
func readDEKThroughWriteDEK(protector *aesgcm256.PipelineDataProtector, raw []byte) error {
	ascii := make([]byte, keyBase64Length+2)
	defer hkdfguard.Wipe(ascii)
	w := &fixedWriter{buffer: ascii}
	if err := protector.WriteDEK(ctx, w); err != nil {
		return fmt.Errorf("WriteDEK: %w", err)
	}
	if w.n != keyBase64Length || subtle.ConstantTimeCompare(ascii[:w.n], protector.KeyBase64()) != 1 {
		return fmt.Errorf("WriteDEK wrote %d bytes, not the key's %d base64 characters", w.n, keyBase64Length)
	}
	if n, err := base64.StdEncoding.Decode(raw, ascii[:w.n]); err != nil || n != aesgcm256.KeySize {
		return errors.New("the pipeline key isn't 32 bytes")
	}
	return nil
}

// wrapNatively has WriteDEK write the pipeline key straight into the standard input of
// `hkdfguard wrap --dek-stdin`: never an argument or an environment variable, and never a copy here.
// Closing its input is what tells the tool the key is complete.
func wrapNatively(cli, path, service string, protector *aesgcm256.PipelineDataProtector) error {
	wrap := exec.Command(cli, "wrap", "-kf", path, "-sn", service, "--dek-stdin")
	if output, err := runWithStdin(wrap, func(w io.Writer) error { return protector.WriteDEK(ctx, w) }); err != nil {
		return fmt.Errorf("hkdfguard wrap: %w: %s", err, output)
	}
	return nil
}

// untar runs the system tar - Windows' own bsdtar, else the tar on PATH - to unpack an archive from
// its standard input into folder: write writes the archive, and its input is closed afterwards.
func untar(folder string, write func(io.Writer) error) error {
	path, err := tarPath()
	if err != nil {
		return err
	}
	tar := exec.Command(path, "-x", "--no-same-owner", "-f", "-", "-C", folder)
	if output, err := runWithStdin(tar, write); err != nil {
		return fmt.Errorf("tar: %w: %s", err, output)
	}
	return nil
}

// runWithStdin starts command, has write write into its standard input, closes that input and
// waits for it to exit, which must be with 0. The output is the command's stdout and stderr.
func runWithStdin(command *exec.Cmd, write func(io.Writer) error) (string, error) {
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	stdin, err := command.StdinPipe()
	if err != nil {
		return "", err
	}
	if err := command.Start(); err != nil {
		return "", err
	}
	writeErr := write(stdin)
	closeErr := stdin.Close()
	if err := command.Wait(); err != nil {
		return strings.TrimSpace(output.String()), err
	}
	if writeErr != nil {
		return strings.TrimSpace(output.String()), writeErr
	}
	return strings.TrimSpace(output.String()), closeErr
}

// compareFolders is "" if each named file in actual is the one in expected byte for byte, else what
// differs.
func compareFolders(expected, actual string, names []string) string {
	for _, name := range names {
		got, err := os.ReadFile(filepath.Join(actual, name))
		if err != nil {
			return name + " is missing"
		}
		want, err := os.ReadFile(filepath.Join(expected, name))
		if err != nil || !bytes.Equal(got, want) {
			return name + " differs"
		}
	}
	return ""
}

// checkPipeline reads the release's pipeline folder as a deployed application would: secrets.json
// through a jsonsecretsfile cache over the release's ring, tampered copies of it refused whole, and
// secrets.tar unpacked by the system tar and read through a filepersecret cache.
func checkPipeline(c *checker, ring *dek.KeyRing, f pipelineFixtures, dir string) {
	folder := filepath.Join(dir, pipelineDir)
	trust, err := keyFileTrust()
	if err != nil {
		c.fail("pipeline: trusting this account: %v", err)
		return
	}
	format := dek.NewDefaultFormatProvider()
	jsonPath := filepath.Join(folder, jsonSecretsFile)

	if secrets, err := jsonsecretsfile.New(jsonPath, trust, ring, format, jsonsecretsfile.Options{}); err != nil {
		c.fail("pipeline: opening %s: %v", jsonSecretsFile, err)
	} else {
		for _, s := range f.Secrets {
			for _, name := range append([]string{s.FileName}, s.AlsoReadAs...) {
				got, err := readCache(secrets, name)
				c.check(err == nil && got == s.Plaintext, "pipeline: %s reads %s as %s: got %d bytes, %s", jsonSecretsFile, s.Name, name, len(got), wrongOr(err))
			}
		}
		for _, name := range append(slices.Clone(f.MissingLookups), f.InvalidLookups...) {
			got, err := readCache(secrets, name)
			c.check(err == nil && got == "", "pipeline: %s has no %s: got %d bytes, %v", jsonSecretsFile, name, len(got), err)
		}
	}

	same, sameErr := sameBytes(filepath.Join(folder, streamJSONSecretsFile), jsonPath)
	c.check(same, "pipeline: %s is %s byte for byte: %s", streamJSONSecretsFile, jsonSecretsFile, differsOr(sameErr, "it differs"))

	emptyPath := filepath.Join(folder, emptyJSONSecretsFile)
	contents, emptyErr := os.ReadFile(emptyPath)
	c.check(emptyErr == nil && string(contents) == "{}", "pipeline: %s is {}: %s", emptyJSONSecretsFile, differsOr(emptyErr, "it isn't"))
	first := f.Secrets[0].FileName
	nothing, nothingErr := readFromNewCache(emptyPath, trust, ring, format, first)
	c.check(nothingErr == nil && nothing == "", "pipeline: %s has no %s: got %d bytes, %v", emptyJSONSecretsFile, first, len(nothing), nothingErr)

	work := filepath.Join(folder, consumerDir)
	if err := os.RemoveAll(work); err != nil {
		c.fail("pipeline: removing %s: %v", consumerDir, err)
		return
	}
	// os.MkdirAll sets no ACL on Windows, so the folder inherits the release folder's.
	if err := os.MkdirAll(work, 0o700); err != nil {
		c.fail("pipeline: making %s: %v", consumerDir, err)
		return
	}
	checkTampered(c, ring, format, trust, jsonPath, work)
	checkArchive(c, ring, f, trust, folder, work)
}

type jsonMember struct{ name, value string }

// checkTampered checks that two copies of secrets.json, each changed one way, are each refused
// whole: a lookup of a member the change didn't touch fails authentication too.
func checkTampered(c *checker, ring *dek.KeyRing, format hkdfguard.EncryptedFormatProvider, trust securefile.KeyFileTrust, jsonPath, work string) {
	members, err := readMembers(jsonPath)
	if err != nil {
		c.fail("pipeline: parsing %s to tamper with it: %v", jsonSecretsFile, err)
		return
	}
	if len(members) < 3 {
		c.fail("pipeline: %s holds %d members, too few to tamper with", jsonSecretsFile, len(members))
		return
	}
	untouched := members[len(members)-1].name

	swapped := slices.Clone(members)
	swapped[0].value, swapped[1].value = members[1].value, members[0].value
	got, err := readFromNewFile(filepath.Join(work, "swapped.json"), swapped, trust, ring, format, untouched)
	c.check(errors.Is(err, hkdfguard.ErrAuthenticationFailed), "pipeline: %s with two values swapped is refused whole: got %d bytes, %v", jsonSecretsFile, len(got), err)

	tampered, err := tamper(members[0].value)
	if err != nil {
		c.fail("pipeline: tampering %s: %v", members[0].name, err)
		return
	}
	flipped := slices.Clone(members)
	flipped[0].value = tampered
	got, err = readFromNewFile(filepath.Join(work, "flipped.json"), flipped, trust, ring, format, untouched)
	c.check(errors.Is(err, hkdfguard.ErrAuthenticationFailed), "pipeline: %s with a flipped tag bit is refused whole: got %d bytes, %v", jsonSecretsFile, len(got), err)
}

// checkArchive unpacks secrets.tar with the system tar, from its standard input, into a fresh
// folder: it must hold exactly the files WriteProtectedSecretFiles wrote, byte for byte, each
// reading through a filepersecret cache as its value.
func checkArchive(c *checker, ring *dek.KeyRing, f pipelineFixtures, trust securefile.KeyFileTrust, folder, work string) {
	unpacked := filepath.Join(work, pipelineUnpackedDir)
	if err := os.MkdirAll(unpacked, 0o700); err != nil {
		c.fail("pipeline: unpacking %s: %v", secretsTar, err)
		return
	}
	archive, err := os.Open(filepath.Join(folder, secretsTar))
	if err == nil {
		err = untar(unpacked, func(w io.Writer) error {
			_, err := io.Copy(w, archive)
			return err
		})
		archive.Close()
	}
	if err != nil {
		c.fail("pipeline: unpacking %s: %v", secretsTar, err)
		return
	}

	names := f.fileNames()
	slices.Sort(names)
	var entries []string
	if listed, err := os.ReadDir(unpacked); err == nil {
		for _, entry := range listed {
			entries = append(entries, entry.Name())
		}
	}
	slices.Sort(entries)
	c.check(slices.Equal(entries, names), "pipeline: %s holds exactly the secrets' files: it holds %d, not %d", secretsTar, len(entries), len(names))

	files, err := filepersecret.New(unpacked, trust, ring, dek.NewDefaultFormatProvider(), filepersecret.Options{})
	if err != nil {
		c.fail("pipeline: opening the unpacked folder: %v", err)
		return
	}
	for _, s := range f.Secrets {
		difference := compareFolders(filepath.Join(folder, pipelineFilesDir), unpacked, []string{s.FileName})
		got, err := readCache(files, s.FileName)
		ok := difference == "" && err == nil && got == s.Plaintext
		if difference == "" {
			difference = fmt.Sprintf("got %d bytes, %s", len(got), wrongOr(err))
		}
		c.check(ok, "pipeline: %s's %s is the written file and reads as its value: %s", secretsTar, s.FileName, difference)
	}
}

// readMembers is the JSON object's members, in file order; each value must be a string.
func readMembers(path string) ([]jsonMember, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	var members []jsonMember
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, _ := token.(string)
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("%s's value: %w", name, err)
		}
		members = append(members, jsonMember{name, value})
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return members, nil
}

// readFromNewFile writes members as a JSON object, in their order, to path, then looks name up
// through a new jsonsecretsfile cache over it. The layout is this driver's own: the cache reads any
// valid JSON object.
func readFromNewFile(path string, members []jsonMember, trust securefile.KeyFileTrust, ring *dek.KeyRing,
	format hkdfguard.EncryptedFormatProvider, name string) (string, error) {
	var out bytes.Buffer
	out.WriteString("{\n")
	for i, m := range members {
		n, _ := json.Marshal(m.name)
		v, _ := json.Marshal(m.value)
		fmt.Fprintf(&out, "  %s: %s", n, v)
		if i < len(members)-1 {
			out.WriteByte(',')
		}
		out.WriteByte('\n')
	}
	out.WriteString("}")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		return "", err
	}
	return readFromNewCache(path, trust, ring, format, name)
}

// readFromNewCache looks name up through a new jsonsecretsfile cache over path, so nothing an
// earlier cache loaded is reused.
func readFromNewCache(path string, trust securefile.KeyFileTrust, ring *dek.KeyRing, format hkdfguard.EncryptedFormatProvider, name string) (string, error) {
	secrets, err := jsonsecretsfile.New(path, trust, ring, format, jsonsecretsfile.Options{})
	if err != nil {
		return "", err
	}
	return readCache(secrets, name)
}

// sameBytes reports whether the files at a and b hold the same bytes.
func sameBytes(a, b string) (bool, error) {
	first, err := os.ReadFile(a)
	if err != nil {
		return false, err
	}
	second, err := os.ReadFile(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(first, second), nil
}

// wrongOr describes a lookup that read the wrong value: the error, else that the plaintext is wrong.
func wrongOr(err error) string {
	if err != nil {
		return err.Error()
	}
	return "wrong plaintext"
}

func differsOr(err error, otherwise string) string {
	if err != nil {
		return err.Error()
	}
	return otherwise
}
