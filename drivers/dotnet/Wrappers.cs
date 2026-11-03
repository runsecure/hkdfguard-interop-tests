using System.Runtime.InteropServices;
using System.Security.Principal;
using Amazon.KeyManagementService;
using Azure.Identity;
using Google.Cloud.Kms.V1;
using HkdfGuard.Abstractions;
using HkdfGuard.Integration.HashiCorpVault;
using HkdfGuard.KeyWrapping.AwsKms;
using HkdfGuard.KeyWrapping.AzureKeyVault;
using HkdfGuard.KeyWrapping.GoogleKms;
using HkdfGuard.KeyWrapping.HashiCorpVault;
using HkdfGuard.KeyWrapping.V1;
using HkdfGuard.SecureFile;

namespace HkdfGuard.Interop;

internal static partial class Driver
{
    public const string Native = "native";

    // The context every port's integration tests bind their key files to, so the matrix runs under
    // the IAM, key and token policies already written for those tests.
    private const string WrapContext = "hkdfguard.integrationtest";
    // The one those tests check a key file is refused under.
    private const string OtherContext = "hkdfguard.integrationtest.other";

    private const string DefaultVaultAddress = "http://127.0.0.1:8200";

    // This port's wrapper named name, over the KEK the HKDFGUARD_TEST_* settings name and bound to
    // context; the native one is over the service's KEK on this host. A network wrapper reads key
    // files only from where this account is trusted to have written them, since the matrix writes
    // and reads them as one account (see KeyFileTrustForThisAccount).
    private static async Task<OwnedWrapper> NewWrapper(string name, string service, string context)
    {
        if (name == Native)
        {
            return new OwnedWrapper(new NativeHkdfKeyWrapperV1(service));
        }
        var trust = KeyFileTrustForThisAccount();
        switch (name)
        {
            case "awskms":
            {
                var key = Setting("HKDFGUARD_TEST_AWS_KMS_KEY_ID");
                // Region and credentials from the SDK's default chain. The wrapper doesn't dispose its client.
                var client = new AmazonKeyManagementServiceClient();
                try
                {
                    var encryptionContext = new Dictionary<string, string> { ["purpose"] = context };
                    return new OwnedWrapper(new AwsKmsKeyWrapper(client, key, encryptionContext, trust), client);
                }
                catch
                {
                    client.Dispose();
                    throw;
                }
            }
            case "azurekeyvault":
            {
                var wrapKey = new Uri(Setting("HKDFGUARD_TEST_AZURE_WRAP_KEY_ID"));
                var signKey = new Uri(Setting("HKDFGUARD_TEST_AZURE_SIGN_KEY_ID"));
                return new OwnedWrapper(new AzureKeyVaultKeyWrapper(wrapKey, signKey, new DefaultAzureCredential(), context, trust));
            }
            case "googlekms":
            {
                var key = Setting("HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME");
                var client = await KeyManagementServiceClient.CreateAsync();
                return new OwnedWrapper(new GoogleKmsKeyWrapper(client, key, context, trust));
            }
            case "hashicorpvault":
            {
                var key = Setting("HKDFGUARD_TEST_VAULT_TRANSIT_KEY");
                var options = new HashiCorpVaultTransitKeyWrapperOptions
                {
                    // "transit", the engine's default mount, unless the settings name another.
                    MountPath = Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT") is { Length: > 0 } mount ? mount : "transit",
                    Tls = VaultTls(),
                };
                var token = new StaticVaultTokenSource(Setting("HKDFGUARD_TEST_VAULT_TOKEN"));
                try
                {
                    var wrapper = new HashiCorpVaultTransitKeyWrapper(VaultAddress(DefaultVaultAddress), key, token, context, trust, options);
                    return new OwnedWrapper(wrapper, wrapper, token);
                }
                catch
                {
                    token.Dispose();
                    throw;
                }
            }
        }
        throw new ArgumentException($"unknown wrapper \"{name}\"");
    }

    // The Vault server HKDFGUARD_TEST_VAULT_ADDR names, else defaultAddress. VAULT_* variables are
    // ignored: Vault clients are configured from the HKDFGUARD_TEST_* settings alone.
    private static Uri VaultAddress(string defaultAddress)
        => new(Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_ADDR") is { Length: > 0 } address ? address : defaultAddress);

    // Trusts the CA HKDFGUARD_TEST_VAULT_CACERT names, if any; else the operating system's trust store.
    private static VaultTlsOptions? VaultTls()
        => Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_CACERT") is { Length: > 0 } ca
            ? new VaultTlsOptions { ServerCertificateFile = ca }
            : null;

    // Trusts this account to have written the key files it reads, as well as Administrators (or
    // root): the matrix writes and reads every key file as one account. Never trust an application's
    // own account outside a test or developer host.
    private static KeyFileTrust KeyFileTrustForThisAccount()
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new KeyFileTrust { WindowsPrincipals = [identity.User!.Value] };
        }
        return new KeyFileTrust { UnixUserIds = [Libc.geteuid()] };
    }

    private static string Setting(string name)
        => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : throw new InvalidOperationException($"{name} is not set");

    private static class Libc
    {
        [DllImport("libc")]
        public static extern uint geteuid();
    }
}

// A key wrapper and whatever was built for it - its client, its token - released by Dispose.
internal sealed class OwnedWrapper(IKeyWrapper keyWrapper, params IDisposable[] owned) : IDisposable
{
    public IKeyWrapper KeyWrapper { get; } = keyWrapper;

    public void Dispose()
    {
        foreach (var o in owned)
        {
            o.Dispose();
        }
    }
}
