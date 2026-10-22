package io.github.runsecure.hkdfguard.interop;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

/**
 * The Java driver for the HkdfGuard interop matrix. It consumes any driver's release; producing is left
 * to the Go, Node and Python drivers for now. See the repository README for the contract every driver
 * follows.
 */
public final class Main {
    private static final String RELEASE_FILE = "release.json";
    private static final String KEY_FILE = "dek.wrapped";
    private static final Pattern FORMAT = Pattern.compile("^(enc::v\\d+::)(.+)$", Pattern.DOTALL);

    record Secret(String identifier, String plaintext, List<String> alsoReadAs, List<String> mustNotReadAs) {}

    record Fixtures(int keyVersion, List<Secret> secrets) {}

    record Release(String producer, String service, int keyVersion, String dekSha256, Map<String, String> values) {}

    private Main() {}

    public static void main(String[] args) {
        String service = option(args, "--service");
        String fixturesPath = option(args, "--fixtures");
        String dir = option(args, "--dir");
        if (args.length < 1 || !args[0].equals("consume") || service == null || fixturesPath == null || dir == null) {
            System.err.println("usage: java io.github.runsecure.hkdfguard.interop.Main consume --service S --fixtures F --dir D");
            System.exit(2);
        }
        try {
            var json = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            var fixtures = json.readValue(Path.of(fixturesPath).toFile(), Fixtures.class);
            var release = json.readValue(Path.of(dir, RELEASE_FILE).toFile(), Release.class);
            System.exit(consume(service, fixtures, release, Path.of(dir)) ? 0 : 1);
        } catch (Exception e) {
            System.err.println("FAIL " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    private static String option(String[] args, String name) {
        int i = Arrays.asList(args).indexOf(name);
        return i > 0 && i + 1 < args.length ? args[i + 1] : null;
    }

    /**
     * Reads a release as an application would: builds a ring over the native KEK with the key file, then
     * reveals every value through the configuration purpose of its key.
     */
    private static boolean consume(String service, Fixtures fixtures, Release release, Path dir) throws Exception {
        var wrapper = new NativeHkdfKeyWrapperV1Impl(service);
        var checks = new Checker();
        try (var ring = new KeyRingBuilder()
                .withServiceName(service)
                .withKeyRefreshInterval(60)
                .withKeyWrapper(wrapper)
                .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
                .withKeyFile(release.keyVersion(), dir.resolve(KEY_FILE))
                .buildAsync()
                .get()) {
            for (var s : fixtures.secrets()) {
                var value = release.values().get(s.identifier());
                if (value == null) {
                    checks.fail(s.identifier() + ": missing from the release");
                    continue;
                }
                var names = new ArrayList<String>(List.of(s.identifier()));
                if (s.alsoReadAs() != null) {
                    names.addAll(s.alsoReadAs());
                }
                for (var name : names) {
                    var result = attempt(() -> reveal(ring, name, value));
                    checks.check(result.error() == null && s.plaintext().equals(result.got()),
                            s.identifier() + " reads as " + name + ": " + (result.error() != null ? result.error() : "wrong plaintext"));
                }
                for (var name : s.mustNotReadAs() != null ? s.mustNotReadAs() : List.<String>of()) {
                    checks.check(attempt(() -> reveal(ring, name, value)).error() != null, s.identifier() + " must not read as " + name);
                }
            }

            var first = fixtures.secrets().get(0);
            var second = fixtures.secrets().get(1);
            var moved = release.values().get(first.identifier());
            checks.check(attempt(() -> reveal(ring, second.identifier(), moved)).error() != null,
                    first.identifier() + " moved under " + second.identifier() + " fails authentication");
            checks.check(attempt(() -> reveal(ring, first.identifier(), tamper(moved))).error() != null,
                    first.identifier() + " with a flipped tag bit fails authentication");
        }

        var digest = attempt(() -> unwrappedDigest(wrapper, dir.resolve(KEY_FILE)));
        checks.check(release.dekSha256().equals(digest.got()),
                "the key file unwraps to the producer's DEK: " + (digest.error() != null ? digest.error() : "digest differs"));
        return checks.finish(release.producer());
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

    private static String unwrappedDigest(NativeHkdfKeyWrapperV1Impl wrapper, Path path) throws Exception {
        var wrapped = wrapper.readKeyFileAsync(path).get();
        var raw = new byte[32];
        try {
            int written = wrapper.unwrapAsync(wrapped, raw).get();
            var sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(raw, 0, written);
            return HexFormat.of().formatHex(sha256.digest());
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    record Attempt(String got, String error) {}

    private static Attempt attempt(Callable<String> body) {
        try {
            return new Attempt(body.call(), null);
        } catch (Exception e) {
            return new Attempt(null, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static final class Checker {
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

        boolean finish(String producer) {
            if (failed > 0) {
                System.err.printf("FAIL %d of %d checks failed reading the %s release%n", failed, passed + failed, producer);
                return false;
            }
            System.out.printf("OK %d checks passed reading the %s release%n", passed, producer);
            return true;
        }
    }
}
