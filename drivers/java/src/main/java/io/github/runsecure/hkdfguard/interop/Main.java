package io.github.runsecure.hkdfguard.interop;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCache;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.interop.Wrappers.OpenWrapper;
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
 * key file wrapped by one key wrapper), consumes any driver's release with its own port of the same
 * wrapper, and reads a remote secret store through its cache over that release's key ring. See the
 * repository README for the contract every driver follows.
 */
public final class Main {
    static final String RELEASE_FILE = "release.json";
    static final String KEY_FILE = "dek.wrapped";
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

    record Fixtures(int keyVersion, List<Secret> secrets) {}

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

            // The pipeline key's base64 as ASCII bytes, never as a String.
            var base64 = pipeline.getKeyAsBase64();
            var keyText = new byte[base64.remaining()];
            for (int i = 0; i < keyText.length; i++) {
                keyText[i] = (byte) base64.get(base64.position() + i);
            }
            byte[] raw = null;
            try {
                raw = Base64.getDecoder().decode(keyText);
                if (raw.length != KEY_SIZE) {
                    throw new IllegalStateException("the pipeline key is " + raw.length + " bytes, not " + KEY_SIZE);
                }
                // Test only: a hash of the DEK, so every consumer can prove it unwrapped this same key.
                // Never record anything derived from a DEK beside its key file in a real pipeline.
                var digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));

                Files.createDirectories(dir);
                var path = dir.resolve(KEY_FILE);
                if (wrapperName.equals(Wrappers.NATIVE)) {
                    wrapNatively(cli, path, service, keyText);
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
                ArrayUtility.zeroMemory(keyText);
                if (raw != null) {
                    ArrayUtility.zeroMemory(raw);
                }
            }
            System.out.printf("OK produced %d secrets in %s%n", values.size(), dir);
            return true;
        }
    }

    /** Pipes the key's base64 to hkdfguard wrap --dek-stdin: never an argument or environment variable. */
    private static void wrapNatively(String cli, Path path, String service, byte[] keyText) throws Exception {
        var process = new ProcessBuilder(cli, "wrap", "-kf", path.toString(), "-sn", service, "--dek-stdin")
                .redirectErrorStream(true)
                .start();
        try (var stdin = process.getOutputStream()) {
            stdin.write(keyText);
        }
        var output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
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
    private static String tamper(String value) {
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

        @Override
        public String toString() {
            return "got " + (got == null ? 0 : got.getBytes(StandardCharsets.UTF_8).length) + " bytes, " + (failure == null ? "no error" : error());
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
