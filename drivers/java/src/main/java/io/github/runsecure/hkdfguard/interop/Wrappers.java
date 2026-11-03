package io.github.runsecure.hkdfguard.interop;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.StaticVaultTokenSource;
import io.github.runsecure.hkdfguard.keywrapping.awskms.AwsKmsKeyWrapperImpl;
import io.github.runsecure.hkdfguard.keywrapping.azurekeyvault.AzureKeyVaultKeyWrapperImpl;
import io.github.runsecure.hkdfguard.keywrapping.googlekms.GoogleKmsKeyWrapperImpl;
import io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.HashiCorpVaultTransitKeyWrapperImpl;
import io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.HashiCorpVaultTransitKeyWrapperOptions;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProviderChain;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.profiles.ProfileFileLocation;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

/** Each port's key wrapper as the matrix configures it, from the HKDFGUARD_TEST_* settings. */
final class Wrappers {
    static final String NATIVE = "native";

    /**
     * The context every port's integration tests bind their key files to, so the matrix runs under the
     * IAM, key and token policies already written for those tests.
     */
    static final String WRAP_CONTEXT = "hkdfguard.integrationtest";
    /** The one those tests check a key file is refused under. */
    static final String OTHER_CONTEXT = "hkdfguard.integrationtest.other";

    private static final String DEFAULT_VAULT_ADDRESS = "http://127.0.0.1:8200";

    private static KeyFileTrust keyFileTrust;

    private Wrappers() {}

    /** A key wrapper and whatever clients it was built over, closed (last first) by close. */
    static final class OpenWrapper implements AutoCloseable {
        private final Deque<AutoCloseable> resources = new ArrayDeque<>();
        private KeyWrapper wrapper;

        KeyWrapper wrapper() {
            return wrapper;
        }

        private <T extends AutoCloseable> T own(T resource) {
            resources.push(resource);
            return resource;
        }

        @Override
        public void close() {
            while (!resources.isEmpty()) {
                try {
                    resources.pop().close();
                } catch (Exception e) {
                    // Nothing more to release; the checks have already been counted.
                }
            }
        }
    }

    /**
     * This port's wrapper named name, over the KEK the HKDFGUARD_TEST_* settings name and bound to
     * context; the native one is over the service's KEK on this host. A network wrapper reads key
     * files only from where this account is trusted to have written them, since the matrix writes and
     * reads them as one account (see {@link #keyFileTrust()}).
     */
    static OpenWrapper open(String name, String service, String context) throws Exception {
        var open = new OpenWrapper();
        if (name.equals(NATIVE)) {
            open.wrapper = new NativeHkdfKeyWrapperV1Impl(service);
            return open;
        }
        var trust = keyFileTrust();
        try {
            switch (name) {
                case "awskms" -> {
                    var key = setting("HKDFGUARD_TEST_AWS_KMS_KEY_ID");
                    var client = open.own(KmsAsyncClient.builder()
                            .httpClientBuilder(NettyNioAsyncHttpClient.builder())
                            .credentialsProvider(awsCredentials())
                            .build());
                    open.wrapper = new AwsKmsKeyWrapperImpl(client, key, Map.of("purpose", context), trust);
                }
                case "azurekeyvault" -> {
                    var wrapKey = setting("HKDFGUARD_TEST_AZURE_WRAP_KEY_ID");
                    var signKey = setting("HKDFGUARD_TEST_AZURE_SIGN_KEY_ID");
                    open.wrapper = new AzureKeyVaultKeyWrapperImpl(wrapKey, signKey, new DefaultAzureCredentialBuilder().build(), context, trust);
                }
                case "googlekms" -> {
                    var key = setting("HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME");
                    var client = open.own(KeyManagementServiceClient.create());
                    open.wrapper = new GoogleKmsKeyWrapperImpl(client, key, context, trust);
                }
                case "hashicorpvault" -> {
                    var key = setting("HKDFGUARD_TEST_VAULT_TRANSIT_KEY");
                    var http = open.own(vaultHttpClient());
                    var tokens = open.own(new StaticVaultTokenSource(setting("HKDFGUARD_TEST_VAULT_TOKEN")));
                    var options = HashiCorpVaultTransitKeyWrapperOptions.builder().httpClient(http);
                    var mount = System.getenv("HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT");
                    if (mount != null && !mount.isEmpty()) {
                        options.mountPath(mount);
                    }
                    open.wrapper = open.own(new HashiCorpVaultTransitKeyWrapperImpl(vaultAddress(DEFAULT_VAULT_ADDRESS), key, tokens, context,
                            trust, options.build()));
                }
                default -> throw new IllegalArgumentException("unknown wrapper \"" + name + "\"");
            }
            return open;
        } catch (Exception | Error e) {
            open.close();
            throw e;
        }
    }

    /**
     * The AWS SDK's own credential sources, taking a profile's access keys ahead of an aws login
     * session as the Go driver's SDK does: the environment's access keys, then the shared credentials
     * file's profile (AWS_PROFILE, or default), then the rest of the SDK's default chain. The Java
     * SDK's default chain alone merges the config file into that profile and takes a login_session
     * there ahead of the profile's keys, even one whose token has expired, so it would run as another
     * principal than the other drivers, or not at all. hkdfguard-java's own AWS integration tests read
     * the credentials file on its own for the same reason.
     */
    static AwsCredentialsProvider awsCredentials() {
        var providers = new ArrayList<AwsCredentialsProvider>();
        providers.add(EnvironmentVariableCredentialsProvider.create());
        var credentialsFile = ProfileFileLocation.credentialsFileLocation();
        if (credentialsFile.isPresent()) {
            var profile = System.getenv("AWS_PROFILE");
            providers.add(ProfileCredentialsProvider.builder()
                    .profileFile(ProfileFile.builder().content(credentialsFile.get()).type(ProfileFile.Type.CREDENTIALS).build())
                    .profileName(profile == null || profile.isEmpty() ? "default" : profile)
                    .build());
        }
        providers.add(DefaultCredentialsProvider.builder().build());
        return AwsCredentialsProviderChain.builder().credentialsProviders(providers).build();
    }

    /**
     * The address of the Vault server HKDFGUARD_TEST_VAULT_ADDR names, else defaultAddress. VAULT_*
     * variables are ignored: the clients are configured from the HKDFGUARD_TEST_* settings alone.
     */
    static URI vaultAddress(String defaultAddress) {
        var address = System.getenv("HKDFGUARD_TEST_VAULT_ADDR");
        return URI.create(address != null && !address.isEmpty() ? address : defaultAddress);
    }

    /**
     * An HttpClient for Vault that follows no redirects (one would carry the token wherever it points,
     * and both Vault modules refuse a client that follows them), trusting the CA
     * HKDFGUARD_TEST_VAULT_CACERT names, and only it, when set.
     */
    static HttpClient vaultHttpClient() throws Exception {
        var builder = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER);
        var ca = System.getenv("HKDFGUARD_TEST_VAULT_CACERT");
        if (ca == null || ca.isEmpty()) {
            return builder.build();
        }
        try (var in = Files.newInputStream(Path.of(ca))) {
            var trusted = KeyStore.getInstance(KeyStore.getDefaultType());
            trusted.load(null, null);
            var index = 0;
            for (var certificate : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                trusted.setCertificateEntry("ca-" + index++, certificate);
            }
            var trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trusted);
            var tls = SSLContext.getInstance("TLS");
            tls.init(null, trustManagers.getTrustManagers(), null);
            return builder.sslContext(tls).build();
        }
    }

    /**
     * Trusts this account to have written the key files it reads, as well as Administrators (or
     * root): the matrix writes and reads every key file as one account. Never trust an application's
     * own account outside a test or developer host.
     */
    static synchronized KeyFileTrust keyFileTrust() throws IOException, InterruptedException {
        if (keyFileTrust == null) {
            keyFileTrust = System.getProperty("os.name").startsWith("Windows")
                    ? KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals(currentUserSid())
                    : KeyFileTrust.ADMINISTRATORS_ONLY.withUnixUserIds(currentUserId());
        }
        return keyFileTrust;
    }

    /** This account's SID, as whoami /user reports it. */
    private static String currentUserSid() throws IOException, InterruptedException {
        var whoami = Path.of(System.getenv("SystemRoot"), "System32", "whoami.exe").toString();
        var process = new ProcessBuilder(whoami, "/user", "/fo", "csv", "/nh").redirectErrorStream(true).start();
        var output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        process.waitFor();
        // "DOMAIN\name","S-1-5-21-..."
        var start = output.lastIndexOf(",\"");
        var sid = start >= 0 && output.endsWith("\"") ? output.substring(start + 2, output.length() - 1) : "";
        if (!sid.startsWith("S-1-")) {
            throw new IllegalStateException("whoami reported no SID");
        }
        return sid;
    }

    /** This process's effective user id: the owner of a file it creates. */
    private static long currentUserId() throws IOException {
        var probe = Files.createTempFile("hkdfguard-interop-", ".uid");
        try {
            return ((Number) Files.getAttribute(probe, "unix:uid")).longValue();
        } finally {
            Files.deleteIfExists(probe);
        }
    }

    static String setting(String name) {
        var value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException(name + " is not set");
        }
        return value;
    }
}
