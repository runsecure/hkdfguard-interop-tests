package io.github.runsecure.hkdfguard.interop;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCache;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl;
import io.github.runsecure.hkdfguard.cache.filepersecret.FilePerSecretCacheImpl;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.interop.Pipeline.PipelineFixtures;
import io.github.runsecure.hkdfguard.interop.Wrappers.OpenWrapper;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

/**
 * The Java driver for the HkdfGuard interop matrix: it produces a release (pipeline encryption plus a
 * key file wrapped by one key wrapper, and the secrets pipeline writer's files, JSON and tar archive),
 * consumes any driver's release with its own port of the same wrapper and caches, and reads a remote
 * secret store through its cache over that release's key ring. See the repository README for the
 * contract every driver follows.
 */
public final class Main {
    static final String RELEASE_FILE = "release.json";
    static final String KEY_FILE = "dek.wrapped";
    static final String SECRETS_DIR = "secrets";
    private static final int KEY_SIZE = 32;
    private static final Pattern FORMAT = Pattern.compile("^(enc::v\\d+::)(.+)$", Pattern.DOTALL);
    private static final Set<String> OPTIONS = Set.of("--wrapper", "--store", "--service", "--fixtures", "--dir", "--cli");

    static final ObjectMapper JSON = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .enable(SerializationFeature.INDENT_OUTPUT);

    record Secret(String identifier, String plaintext, List<String> alsoReadAs, List<String> mustNotReadAs) {
        List<String> readAs() {
            var names = new ArrayList<String>(List.of(identifier));
            if (alsoReadAs != null) {
                names.addAll(alsoReadAs);
            }
            return names;
        }

        List<String> notReadAs() {
            return mustNotReadAs != null ? mustNotReadAs : List.of();
        }
    }

    /**
     * One file a producer writes to the release's secrets folder, and what every consumer's
     * FilePerSecretCache must make of it: "value", "missing" or "refused".
     */
    record SecretFile(String name, String plaintext, String plaintextOf, boolean trailingNewline, boolean empty, String copyOf, String expect) {}

    record Fixtures(int keyVersion, List<Secret> secrets, List<SecretFile> files, List<String> missingFiles, PipelineFixtures pipeline) {
        Fixtures {
            files = files != null ? files : List.of();
            missingFiles = missingFiles != null ? missingFiles : List.of();
        }

        /** The value the file is written with: its own, or the named secret's. */
        String plaintext(SecretFile file) {
            if (file.plaintextOf() != null && !file.plaintextOf().isEmpty()) {
                for (var s : secrets) {
                    if (s.identifier().equals(file.plaintextOf())) {
                        return s.plaintext();
                    }
                }
            }
            return file.plaintext() != null ? file.plaintext() : "";
        }
    }

    record Release(String producer, String wrapper, String service, int keyVersion, String dekSha256, Map<String, String> values) {}

    private Main() {}

    public static void main(String[] args) {
        var options = parse(args);
        var command = args[0];
        var wrapper = options.getOrDefault("--wrapper", Wrappers.NATIVE);
        var service = options.get("--service");
        var fixturesPath = options.get("--fixtures");
        var dir = options.get("--dir");
        if (service == null || fixturesPath == null || dir == null
                || (command.equals("produce") && options.get("--cli") == null)
                || (command.equals("cache") && options.get("--store") == null)
                || !Set.of("produce", "consume", "cache").contains(command)) {
            usage();
        }
        try {
            var fixtures = JSON.readValue(Path.of(fixturesPath).toFile(), Fixtures.class);
            var ok = switch (command) {
                case "produce" -> produce(wrapper, service, fixtures, Path.of(dir), options.get("--cli"));
                case "consume" -> consume(wrapper, service, fixtures, Path.of(dir));
                default -> Caches.readStore(options.get("--store"), wrapper, service, Path.of(dir));
            };
            System.exit(ok ? 0 : 1);
        } catch (Exception e) {
            System.err.println("FAIL " + describe(e));
            System.exit(1);
        }
    }

    /** The options after the command, each a known flag with a value; anything else is a usage error. */
    private static Map<String, String> parse(String[] args) {
        if (args.length < 1) {
            usage();
        }
        var options = new HashMap<String, String>();
        for (int i = 1; i < args.length; i += 2) {
            if (!OPTIONS.contains(args[i]) || i + 1 >= args.length) {
                usage();
            }
            options.put(args[i], args[i + 1]);
        }
        return options;
    }

    private static void usage() {
        System.err.println("usage: java io.github.runsecure.hkdfguard.interop.Main produce [--wrapper W] --service S --fixtures F --dir D --cli PATH");
        System.err.println("       java io.github.runsecure.hkdfguard.interop.Main consume [--wrapper W] --service S --fixtures F --dir D");
        System.err.println("       java io.github.runsecure.hkdfguard.interop.Main cache --store C [--wrapper W] --service S --fixtures F --dir D");
        System.exit(2);
    }

    /**
     * Does what a release pipeline does: encrypts every fixture under a fresh pipeline key, writes the
     * values, and wraps the key into the key file - by handing it to the native tool on standard input,
     * or through a network key wrapper in this process.
     */
    private static boolean produce(String wrapperName, String service, Fixtures fixtures, Path dir, String cli) throws Exception {
        try (var pipeline = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), fixtures.keyVersion())) {
            var values = new LinkedHashMap<String, String>();
            for (var s : fixtures.secrets()) {
                values.put(s.identifier(), pipeline.encrypt(s.plaintext(), s.identifier()));
            }

            // The DEK only ever through writeDekAsync, never formatted here.
            var raw = new byte[KEY_SIZE];
            try {
                Pipeline.readDekThroughWriteDek(pipeline, raw);
                // Test only: a hash of the DEK, so every consumer can prove it unwrapped this same key.
                // Never record anything derived from a DEK beside its key file in a real pipeline.
                var digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));

                Files.createDirectories(dir);
                writeSecretFiles(pipeline, fixtures, dir.resolve(SECRETS_DIR));
                Pipeline.writePipeline(pipeline, fixtures.pipeline(), dir);
                var path = dir.resolve(KEY_FILE);
                if (wrapperName.equals(Wrappers.NATIVE)) {
                    wrapNatively(cli, path, service, pipeline);
                } else {
                    try (var open = Wrappers.open(wrapperName, service, Wrappers.WRAP_CONTEXT)) {
                        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
                        int written;
                        try {
                            written = await(open.wrapper().wrapAsync(raw, wrapped));
                        } catch (Exception e) {
                            throw new IllegalStateException("wrapping the pipeline key: " + describe(e), e);
                        }
                        writePrivate(path, Arrays.copyOf(wrapped, written));
                    }
                }

                var release = new Release("java", wrapperName, service, fixtures.keyVersion(), digest, values);
                writePrivate(dir.resolve(RELEASE_FILE), JSON.writeValueAsBytes(release));
            } finally {
                ArrayUtility.zeroMemory(raw);
            }
            System.out.printf("OK produced %d secrets and %d pipeline secrets in %s%n", values.size(), fixtures.pipeline().secrets().size(), dir);
            return true;
        }
    }

    /**
     * Writes the pipeline key with writeDekAsync straight into the standard input of
     * hkdfguard wrap --dek-stdin: never an argument or an environment variable, and never a copy here.
     * Closing its input is what tells the tool the key is complete.
     */
    private static void wrapNatively(String cli, Path path, String service, PipelineDataProtector pipeline) throws Exception {
        var process = new ProcessBuilder(cli, "wrap", "-kf", path.toString(), "-sn", service, "--dek-stdin")
                .redirectErrorStream(true)
                .start();
        var drained = CompletableFuture.supplyAsync(() -> {
            try {
                return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
            } catch (java.io.IOException e) {
                return describe(e);
            }
        });
        try (var stdin = process.getOutputStream()) {
            await(pipeline.writeDekAsync(stdin));
        } catch (Exception e) {
            process.destroy();
            throw e;
        }
        var output = drained.join();
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IllegalStateException("hkdfguard wrap: exit status " + exit + ": " + output);
        }
    }

    /** Writes a file only this account can read where the file system has POSIX permissions. */
    private static void writePrivate(Path path, byte[] data) throws Exception {
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.deleteIfExists(path);
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        }
        Files.write(path, data);
    }

    /** A release's ring over its key file, with the wrapper it was built on; closing closes both. */
    record OpenRelease(Release release, OpenWrapper wrapper, KeyRingImpl ring) implements AutoCloseable {
        @Override
        public void close() {
            ring.close();
            wrapper.close();
        }
    }

    /** Reads dir's release and builds a ring over its key file with this port of the release's wrapper. */
    static OpenRelease openRelease(String wrapperName, String service, Path dir) throws Exception {
        var release = JSON.readValue(dir.resolve(RELEASE_FILE).toFile(), Release.class);
        if (!wrapperName.equals(release.wrapper())) {
            throw new IllegalStateException("the release was wrapped with \"" + release.wrapper() + "\", not \"" + wrapperName + "\"");
        }
        var open = Wrappers.open(wrapperName, service, Wrappers.WRAP_CONTEXT);
        try {
            var ring = new KeyRingBuilder()
                    .withServiceName(service)
                    .withKeyRefreshInterval(60)
                    .withKeyWrapper(open.wrapper())
                    .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
                    .withKeyFile(release.keyVersion(), dir.resolve(KEY_FILE));
            return new OpenRelease(release, open, await(ring.buildAsync()));
        } catch (Exception e) {
            open.close();
            throw new IllegalStateException("building the key ring: " + describe(e), e);
        }
    }

    /**
     * Reads a release as an application would: builds a ring over the wrapper's KEK with the key file,
     * then reveals every value through the configuration purpose of its key, and caches it.
     */
    private static boolean consume(String wrapperName, String service, Fixtures fixtures, Path dir) throws Exception {
        try (var open = openRelease(wrapperName, service, dir)) {
            var release = open.release();
            var ring = open.ring();
            var checks = new Checker();
            for (var s : fixtures.secrets()) {
                var value = release.values().get(s.identifier());
                if (value == null) {
                    checks.fail(s.identifier() + ": missing from the release");
                    continue;
                }
                for (var name : s.readAs()) {
                    var result = attempt(() -> reveal(ring, name, value));
                    checks.check(result.error() == null && s.plaintext().equals(result.got()),
                            s.identifier() + " reads as " + name + ": " + result);
                }
                for (var name : s.notReadAs()) {
                    checks.check(attempt(() -> reveal(ring, name, value)).error() != null, s.identifier() + " must not read as " + name);
                }
            }

            var first = fixtures.secrets().get(0);
            var second = fixtures.secrets().get(1);
            var moved = release.values().get(first.identifier());
            checks.check(attempt(() -> reveal(ring, second.identifier(), moved)).error() != null,
                    first.identifier() + " moved under " + second.identifier() + " fails authentication");

            var tampered = attempt(() -> tamper(moved));
            if (tampered.error() == null) {
                checks.check(attempt(() -> reveal(ring, first.identifier(), tampered.got())).error() != null,
                        first.identifier() + " with a flipped tag bit fails authentication");
            } else {
                checks.fail("tampering " + first.identifier() + ": " + tampered.error());
            }

            var path = dir.resolve(KEY_FILE);
            var digest = attempt(() -> unwrappedDigest(open.wrapper().wrapper(), path));
            checks.check(digest.error() == null && digest.got().equals(release.dekSha256()),
                    "the key file unwraps to the producer's DEK: " + (digest.error() != null ? digest.error() : "digest differs"));

            // A network KEK is shared by every application that may use it, so the context is what keeps
            // one application's key files from another's.
            if (!wrapperName.equals(Wrappers.NATIVE)) {
                OpenWrapper other = null;
                try {
                    other = Wrappers.open(wrapperName, service, Wrappers.OTHER_CONTEXT);
                } catch (Exception e) {
                    checks.fail("creating a wrapper with another context: " + describe(e));
                }
                if (other != null) {
                    try (var refusing = other) {
                        checks.check(attempt(() -> unwrappedDigest(refusing.wrapper(), path)).error() != null,
                                "the key file is refused under another context");
                    }
                }
            }

            checkCache(checks, new ProtectedCacheImpl(ring), fixtures);
            checkSecretFiles(checks, ring, fixtures, dir.resolve(SECRETS_DIR));
            Pipeline.checkPipeline(checks, ring, fixtures.pipeline(), dir);
            return checks.finish("the " + release.producer() + " " + release.wrapper() + " release");
        }
    }

    /**
     * Stores every fixture in a protected cache over the release's ring and reads it back: names that
     * differ in ASCII case share an entry, names that differ in non-ASCII case don't, and an empty
     * value, or a second value under an existing name, is refused.
     */
    private static void checkCache(Checker checks, ProtectedCache cache, Fixtures fixtures) {
        for (var s : fixtures.secrets()) {
            // add zeroes the array it is given, which is this copy of the fixture.
            var added = attempt(() -> {
                cache.add(s.identifier(), s.plaintext().toCharArray());
                return "";
            });
            if (s.plaintext().isEmpty()) {
                checks.check(added.failedWith(IllegalArgumentException.class),
                        "cache: an empty " + s.identifier() + " is refused: " + added.error());
                continue;
            }
            if (added.error() != null) {
                checks.fail("cache: adding " + s.identifier() + ": " + added.error());
                continue;
            }
            for (var name : s.readAs()) {
                var result = attempt(() -> readCache(cache, name));
                checks.check(result.error() == null && s.plaintext().equals(result.got()),
                        "cache: " + s.identifier() + " reads as " + name + ": " + result);
            }
            for (var name : s.notReadAs()) {
                var result = attempt(() -> readCache(cache, name));
                checks.check(result.error() == null && result.got().isEmpty(),
                        "cache: " + s.identifier() + " is missing as " + name + ": " + result);
            }
            if (s.alsoReadAs() != null && !s.alsoReadAs().isEmpty()) {
                var again = s.alsoReadAs().get(0);
                var result = attempt(() -> {
                    cache.add(again, "again".toCharArray());
                    return "";
                });
                checks.check(result.failedWith(IllegalArgumentException.class),
                        "cache: adding " + s.identifier() + " again as " + again + " is refused: " + result.error());
            }
        }
    }

    /**
     * Writes the release's secrets folder as a pipeline would for FilePerSecretCache: one file per
     * secret, holding its value encrypted under the pipeline key for the file's own name.
     */
    private static void writeSecretFiles(AesGcmPipelineDataProtectorImpl pipeline, Fixtures fixtures, Path folder) throws Exception {
        Files.createDirectories(folder);
        var written = new HashMap<String, byte[]>();
        for (var file : fixtures.files()) {
            byte[] contents;
            if (file.empty()) {
                contents = new byte[0];
            } else if (file.copyOf() != null && !file.copyOf().isEmpty()) {
                contents = written.getOrDefault(file.copyOf(), new byte[0]);
            } else {
                String value;
                try {
                    value = pipeline.encrypt(fixtures.plaintext(file), file.name());
                } catch (Exception e) {
                    throw new IllegalStateException("encrypting the file " + file.name() + ": " + describe(e), e);
                }
                contents = (file.trailingNewline() ? value + "\n" : value).getBytes(StandardCharsets.UTF_8);
            }
            written.put(file.name(), contents);
            writePrivate(folder.resolve(file.name()), contents);
        }
    }

    /**
     * Reads the release's secrets folder through a FilePerSecretCache over the release's ring: each
     * file reads as its value, is missing, or is refused as its fixture expects, and a name no file can
     * answer - one that isn't a file name in the folder - is missing.
     */
    private static void checkSecretFiles(Checker checks, KeyRingImpl ring, Fixtures fixtures, Path folder) {
        KeyFileTrust trust;
        try {
            trust = Wrappers.keyFileTrust();
        } catch (Exception e) {
            checks.fail("files: trusting this account: " + describe(e));
            return;
        }
        FilePerSecretCacheImpl files;
        try {
            files = new FilePerSecretCacheImpl(folder, trust, ring, new DefaultFormatProviderImpl());
        } catch (Exception e) {
            checks.fail("files: opening the secrets folder: " + describe(e));
            return;
        }
        for (var file : fixtures.files()) {
            var result = attempt(() -> readCache(files, file.name()));
            switch (file.expect()) {
                case "value" -> checks.check(result.error() == null && fixtures.plaintext(file).equals(result.got()),
                        "files: " + file.name() + " reads as its value: " + result);
                case "missing" -> checks.check(result.error() == null && result.got().isEmpty(),
                        "files: " + file.name() + " is missing: " + result);
                case "refused" -> checks.check(result.failedWith(CryptographicException.class),
                        "files: " + file.name() + " fails authentication: " + result.error());
                default -> checks.fail("files: " + file.name() + " expects \"" + file.expect() + "\", which isn't value, missing or refused");
            }
        }
        for (var name : fixtures.missingFiles()) {
            var result = attempt(() -> readCache(files, name));
            checks.check(result.error() == null && result.got().isEmpty(), "files: " + name + " is missing: " + result);
        }
    }

    /** The value cached under name, or "" if there is none. */
    static String readCache(ProtectedReadOnlyCache cache, String name) {
        var size = cache.findMaxDecryptedLength(name);
        if (size.isEmpty()) {
            return "";
        }
        var result = new char[size.getAsInt()];
        try {
            return new String(result, 0, cache.decrypt(name, result));
        } finally {
            Arrays.fill(result, '\0');
        }
    }

    private static String reveal(KeyRingImpl ring, String name, String value) {
        var protector = ring.createProtector(ProtectedConfigurationPurpose.forKey(name));
        var result = new char[protector.getMaxDecryptedLength(value)];
        try {
            return new String(result, 0, protector.decrypt(value, result));
        } finally {
            Arrays.fill(result, '\0');
        }
    }

    /** Flips one bit in the last byte (the GCM tag) of a formatted value. */
    static String tamper(String value) {
        var match = FORMAT.matcher(value);
        if (!match.matches()) {
            throw new IllegalArgumentException("not an enc::v<version>::<base64> value");
        }
        var body = Base64.getDecoder().decode(match.group(2));
        body[body.length - 1] ^= 0x01;
        return match.group(1) + Base64.getEncoder().encodeToString(body);
    }

    private static String unwrappedDigest(KeyWrapper wrapper, Path path) throws Exception {
        var wrapped = await(wrapper.readKeyFileAsync(path));
        var raw = new byte[WrappedKeyLimits.MAX_BYTES];
        try {
            int written = await(wrapper.unwrapAsync(wrapped, raw));
            var sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(raw, 0, written);
            return HexFormat.of().formatHex(sha256.digest());
        } finally {
            ArrayUtility.zeroMemory(raw);
        }
    }

    /** The future's value, or its own failure rather than an ExecutionException wrapping it. */
    static <T> T await(CompletableFuture<T> future) throws Exception {
        try {
            return future.get();
        } catch (ExecutionException e) {
            if (e.getCause() instanceof Exception cause) {
                throw cause;
            }
            throw e;
        }
    }

    static String describe(Throwable e) {
        return e.getClass().getSimpleName() + ": " + e.getMessage();
    }

    /** What a call returned, or why it failed. Its text gives a value's length only, never the value. */
    record Attempt(String got, Exception failure) {
        String error() {
            return failure == null ? null : describe(failure);
        }

        boolean failedWith(Class<? extends Exception> type) {
            return type.isInstance(failure);
        }

        /** "got N bytes": the length of what was read, never the value. */
        String bytes() {
            return "got " + (got == null ? 0 : got.getBytes(StandardCharsets.UTF_8).length) + " bytes";
        }

        @Override
        public String toString() {
            return bytes() + ", " + (failure == null ? "no error" : error());
        }
    }

    static Attempt attempt(Callable<String> body) {
        try {
            return new Attempt(body.call(), null);
        } catch (Exception e) {
            return new Attempt(null, e);
        }
    }

    static final class Checker {
        private int passed;
        private int failed;

        void check(boolean ok, String message) {
            if (ok) {
                passed++;
            } else {
                fail(message);
            }
        }

        void fail(String message) {
            failed++;
            System.out.println("FAIL " + message);
        }

        /** Ends with one OK or FAIL line about what was read; true if every check passed. */
        boolean finish(String what) {
            if (failed > 0) {
                System.err.printf("FAIL %d of %d checks failed reading %s%n", failed, passed + failed, what);
                return false;
            }
            System.out.printf("OK %d checks passed reading %s%n", passed, what);
            return true;
        }
    }
}
