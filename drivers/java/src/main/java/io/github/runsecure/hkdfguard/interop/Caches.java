package io.github.runsecure.hkdfguard.interop;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.fasterxml.jackson.core.JsonToken;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.awssecretsmanager.AwsSecretsManagerSecretCacheImpl;
import io.github.runsecure.hkdfguard.cache.azurekeyvault.AzureKeyVaultSecretCacheImpl;
import io.github.runsecure.hkdfguard.cache.googlesecretmanager.GoogleSecretManagerSecretCacheImpl;
import io.github.runsecure.hkdfguard.cache.hashicorpvault.HashiCorpVaultSecretCacheImpl;
import io.github.runsecure.hkdfguard.cache.hashicorpvault.HashiCorpVaultSecretCacheOptions;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.StaticVaultToken;
import io.github.runsecure.hkdfguard.interop.Main.Checker;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;

/** Each port's remote secret cache as the matrix configures it, read over a release's key ring. */
final class Caches {
    /** A key no test secret holds. */
    private static final String MISSING_KEY = "hkdfguard-interop-missing";
    private static final String DEFAULT_VAULT_ADDRESS = "https://127.0.0.1:8200";
    private static final Pattern INTEGER = Pattern.compile("^-?[0-9]{1,15}$");

    private Caches() {}

    /**
     * A member of a JSON object as every port's cache caches it: a string as its text, true or false
     * as its JSON text. An integer is compared as its JSON text too; any other number, null, an object
     * or an array isn't compared (cached is null), since not every port's JSON reader keeps a number's
     * exact text.
     */
    record Member(String cached) {}

    /**
     * Reads the secret the HKDFGUARD_TEST_* settings name for store through this port's cache over the
     * release's key ring, and compares what it reads with the JSON object the settings say the secret
     * holds. No value read is ever printed: a failure says only which check failed.
     */
    static boolean readStore(String store, String wrapperName, String service, Path dir) throws Exception {
        try (var open = Main.openRelease(wrapperName, service, dir)) {
            var ring = open.ring();
            var checks = new Checker();
            switch (store) {
                case "awssecretsmanager" -> {
                    var name = Wrappers.setting("HKDFGUARD_TEST_AWS_SECRET_NAME");
                    var expected = expected("HKDFGUARD_TEST_AWS_SECRET_JSON");
                    try (var client = SecretsManagerAsyncClient.builder()
                            .httpClientBuilder(NettyNioAsyncHttpClient.builder())
                            .credentialsProvider(Wrappers.awsCredentials())
                            .build()) {
                        checkJsonSecret(checks, new AwsSecretsManagerSecretCacheImpl(client, ring, null), name, expected);
                    }
                }
                case "azurekeyvault" -> {
                    var id = Wrappers.setting("HKDFGUARD_TEST_AZURE_SECRET_ID");
                    var expected = expected("HKDFGUARD_TEST_AZURE_SECRET_JSON");
                    var secret = azureSecretId(id);
                    var secrets = new AzureKeyVaultSecretCacheImpl(new SecretClientBuilder()
                            .vaultUrl(secret[0])
                            .credential(new DefaultAzureCredentialBuilder().build()), ring);
                    var name = secret[1];
                    checkJsonSecret(checks, secrets, name, expected);
                    // Key Vault matches secret names ignoring case, and so does its cache.
                    var upper = Main.attempt(() -> Main.readCache(secrets, name.toUpperCase(Locale.ROOT)));
                    checks.check(upper.error() == null && holds(upper.got(), expected),
                            store + ": the secret's name in upper case reads the same secret: " + upper);
                    if ("true".equals(System.getenv("HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS"))) {
                        for (var entry : expected.entrySet()) {
                            var want = entry.getValue().cached();
                            if (want != null) {
                                var got = Main.attempt(() -> Main.readCache(secrets, entry.getKey()));
                                checks.check(got.error() == null && want.equals(got.got()),
                                        store + ": the secret " + entry.getKey() + " reads as expected: " + got);
                            }
                        }
                    }
                }
                case "googlesecretmanager" -> {
                    var resource = Wrappers.setting("HKDFGUARD_TEST_GOOGLE_SECRET_NAME");
                    var expected = expected("HKDFGUARD_TEST_GOOGLE_SECRET_JSON");
                    var parts = resource.split("/", -1);
                    if (parts.length != 4 || !parts[0].equals("projects") || !parts[2].equals("secrets")) {
                        throw new IllegalStateException("HKDFGUARD_TEST_GOOGLE_SECRET_NAME isn't projects/{project}/secrets/{secret}");
                    }
                    try (var secrets = GoogleSecretManagerSecretCacheImpl.create(parts[1], ring, null)) {
                        checkJsonSecret(checks, secrets, parts[3], expected);
                    }
                }
                case "hashicorpvault" -> {
                    var name = Wrappers.setting("HKDFGUARD_TEST_VAULT_SECRET_NAME");
                    var expected = expected("HKDFGUARD_TEST_VAULT_SECRET_JSON");
                    var protector = ring.createProtector(HashiCorpVaultSecretCacheImpl.TOKEN_PURPOSE);
                    var token = StaticVaultToken.protect(protector, Wrappers.setting("HKDFGUARD_TEST_VAULT_TOKEN"));
                    // The cache refuses a client that follows redirects: one could send the token elsewhere.
                    try (var http = Wrappers.vaultHttpClient();
                            var secrets = new HashiCorpVaultSecretCacheImpl(Wrappers.vaultAddress(DEFAULT_VAULT_ADDRESS), token, protector, ring,
                                    HashiCorpVaultSecretCacheOptions.builder().httpClient(http).build(), null)) {
                        var cut = name.indexOf('#');
                        checkKeys(checks, secrets, cut < 0 ? name : name.substring(0, cut), expected);
                    }
                }
                default -> throw new IllegalArgumentException("unknown store \"" + store + "\"");
            }
            var release = open.release();
            return checks.finish(store + " through the " + release.producer() + " " + release.wrapper() + " release's ring");
        }
    }

    /**
     * Checks a secret holding a JSON object: read whole, it holds the expected members, and each member
     * reads as "name#key".
     */
    private static void checkJsonSecret(Checker checks, ProtectedReadOnlyCache secrets, String name, Map<String, Member> expected) {
        var whole = Main.attempt(() -> Main.readCache(secrets, name));
        checks.check(whole.error() == null && holds(whole.got(), expected), "the whole secret holds the expected members: " + whole);
        checkKeys(checks, secrets, name, expected);
    }

    /** Checks each expected member reads as "name#key", and that a key matches only exactly. */
    private static void checkKeys(Checker checks, ProtectedReadOnlyCache secrets, String name, Map<String, Member> expected) {
        for (var entry : expected.entrySet()) {
            var want = entry.getValue().cached();
            if (want != null) {
                var got = Main.attempt(() -> Main.readCache(secrets, name + "#" + entry.getKey()));
                checks.check(got.error() == null && want.equals(got.got()), "#" + entry.getKey() + " reads as expected: " + got);
            }
        }
        for (var key : expected.keySet()) {
            var swapped = swapAsciiCase(key);
            if (!swapped.equals(key) && !expected.containsKey(swapped)) {
                var got = Main.attempt(() -> Main.readCache(secrets, name + "#" + swapped));
                checks.check(got.error() == null && got.got().isEmpty(), "#" + key + ", in another ASCII case, is missing: " + got);
                break;
            }
        }
        var got = Main.attempt(() -> Main.readCache(secrets, name + "#" + MISSING_KEY));
        checks.check(got.error() == null && got.got().isEmpty(), "#" + MISSING_KEY + " is missing: " + got);
    }

    /**
     * Whether value is a JSON object with exactly the expected member names, each comparable member
     * holding what's expected.
     */
    private static boolean holds(String value, Map<String, Member> expected) {
        var got = members(value);
        if (got == null || got.size() != expected.size()) {
            return false;
        }
        for (var entry : expected.entrySet()) {
            var member = got.get(entry.getKey());
            if (member == null) {
                return false;
            }
            var want = entry.getValue().cached();
            if (want != null && !want.equals(member.cached())) {
                return false;
            }
        }
        return true;
    }

    /**
     * The members of the JSON object text holds, sorted by name, or null if text isn't one JSON object.
     * Read token by token, so an integer keeps its exact text.
     */
    private static TreeMap<String, Member> members(String text) {
        try (var parser = Main.JSON.getFactory().createParser(text)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return null;
            }
            var members = new TreeMap<String, Member>();
            for (var token = parser.nextToken(); token != JsonToken.END_OBJECT; token = parser.nextToken()) {
                var name = parser.currentName();
                var value = parser.nextToken();
                String cached = switch (value) {
                    case VALUE_STRING, VALUE_TRUE, VALUE_FALSE -> parser.getText();
                    case VALUE_NUMBER_INT -> INTEGER.matcher(parser.getText()).matches() ? parser.getText() : null;
                    case START_OBJECT, START_ARRAY -> {
                        parser.skipChildren();
                        yield null;
                    }
                    default -> null;
                };
                members.put(name, new Member(cached));
            }
            return parser.nextToken() == null ? members : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static TreeMap<String, Member> expected(String variable) {
        var members = members(Wrappers.setting(variable));
        if (members == null) {
            throw new IllegalStateException(variable + " isn't a JSON object");
        }
        return members;
    }

    /**
     * Splits https://{vault}.vault.azure.net/secrets/{name} into the vault's URL and the secret's
     * name.
     */
    private static String[] azureSecretId(String id) {
        var invalid = new IllegalStateException("HKDFGUARD_TEST_AZURE_SECRET_ID isn't https://{vault}.vault.azure.net/secrets/{name}");
        URI uri;
        try {
            uri = new URI(id);
        } catch (Exception e) {
            throw invalid;
        }
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawPath() == null) {
            throw invalid;
        }
        var path = uri.getRawPath().replaceAll("^/+|/+$", "");
        var parts = path.split("/", -1);
        if (parts.length != 2 || !parts[0].equals("secrets")) {
            throw invalid;
        }
        var host = uri.getHost() + (uri.getPort() >= 0 ? ":" + uri.getPort() : "");
        return new String[] {"https://" + host + "/", parts[1]};
    }

    private static String swapAsciiCase(String s) {
        var chars = s.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            var c = chars[i];
            if ('a' <= c && c <= 'z') {
                chars[i] = (char) (c - 32);
            } else if ('A' <= c && c <= 'Z') {
                chars[i] = (char) (c + 32);
            }
        }
        return new String(chars);
    }
}
