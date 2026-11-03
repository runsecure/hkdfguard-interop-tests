using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Google.Apis.Auth.OAuth2;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.AwsSecretsManager;
using HkdfGuard.Cache.AzureKeyVault;
using HkdfGuard.Cache.GoogleSecretManager;
using HkdfGuard.Cache.HashiCorpVault;
using HkdfGuard.Integration.HashiCorpVault;

namespace HkdfGuard.Interop;

internal static partial class Driver
{
    // A key no test secret holds.
    private const string MissingKey = "hkdfguard-interop-missing";

    private static readonly Regex Integer = new("^-?[0-9]{1,15}$");

    // Reads the secret the HKDFGUARD_TEST_* settings name for store through this port's cache over
    // the release's key ring, and compares what it reads with the JSON object the settings say the
    // secret holds. No value read is ever printed: a failure says only which check failed.
    public static async Task<bool> ReadStore(string store, string wrapperName, string service, string dir)
    {
        var (release, wrapper, ring) = await OpenRelease(wrapperName, service, dir);
        using var ownedWrapper = wrapper;
        await using var ownedRing = ring;

        var checks = new Checker();
        switch (store)
        {
            case "awssecretsmanager":
            {
                var (name, expected) = SecretSettings("HKDFGUARD_TEST_AWS_SECRET_NAME", "HKDFGUARD_TEST_AWS_SECRET_JSON");
                // Region and credentials from the SDK's default chain.
                using var secrets = new AwsSecretsManagerSecretCache(ring);
                await CheckJsonSecret(checks, secrets, name, expected);
                break;
            }
            case "azurekeyvault":
            {
                var (id, expected) = SecretSettings("HKDFGUARD_TEST_AZURE_SECRET_ID", "HKDFGUARD_TEST_AZURE_SECRET_JSON");
                var secret = AzureSecretId(id);
                var secrets = new AzureKeyVaultSecretCache(secret.VaultUri, new DefaultAzureCredential(), ring);
                await CheckJsonSecret(checks, secrets, secret.Name, expected);
                // Key Vault matches secret names ignoring case, and so does its cache.
                var (got, error) = await AttemptAsync(() => ReadCache(secrets, secret.Name.ToUpperInvariant()));
                checks.Check(error is null && Holds(got!, expected), $"{store}: the secret's name in upper case reads the same secret: got {Bytes(got)} bytes, {error ?? "wrong value"}");
                if (Environment.GetEnvironmentVariable("HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS") == "true")
                {
                    foreach (var key in SortedKeys(expected))
                    {
                        if (AsCached(expected[key]) is (var want, true))
                        {
                            var (member, memberError) = await AttemptAsync(() => ReadCache(secrets, key));
                            checks.Check(memberError is null && member == want, $"{store}: the secret {key} reads as expected: got {Bytes(member)} bytes, {memberError ?? "wrong value"}");
                        }
                    }
                }
                break;
            }
            case "googlesecretmanager":
            {
                var (resource, expected) = SecretSettings("HKDFGUARD_TEST_GOOGLE_SECRET_NAME", "HKDFGUARD_TEST_GOOGLE_SECRET_JSON");
                var parts = resource.Split('/');
                if (parts is not ["projects", _, "secrets", _])
                {
                    throw new ArgumentException("HKDFGUARD_TEST_GOOGLE_SECRET_NAME isn't projects/{project}/secrets/{secret}");
                }
                using var secrets = GoogleSecretManagerSecretCache.Create(parts[1], await GoogleCredential.GetApplicationDefaultAsync(), ring);
                await CheckJsonSecret(checks, secrets, parts[3], expected);
                break;
            }
            case "hashicorpvault":
            {
                var (name, expected) = SecretSettings("HKDFGUARD_TEST_VAULT_SECRET_NAME", "HKDFGUARD_TEST_VAULT_SECRET_JSON");
                // The cache holds the token only protected, by a protector on the ring for that alone.
                var protector = ring.CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);
                var token = StaticVaultToken.Protect(protector, Setting("HKDFGUARD_TEST_VAULT_TOKEN"));
                // The cache's own handler follows no redirects: one could send the token elsewhere.
                using var secrets = new HashiCorpVaultSecretCache(VaultAddress("https://127.0.0.1:8200"), token, protector, ring,
                    new HashiCorpVaultSecretCacheOptions { Tls = VaultTls() });
                await CheckKeys(checks, secrets, name.Split('#')[0], expected);
                break;
            }
            default:
                throw new ArgumentException($"unknown store \"{store}\"");
        }
        return checks.Finish($"{store} through the {release.Producer} {release.Wrapper} release's ring");
    }

    // Checks a secret holding a JSON object: read whole, it holds the expected members, and each
    // member reads as "name#key".
    private static async Task CheckJsonSecret(Checker checks, IProtectedReadOnlyCache secrets, string name, Dictionary<string, JsonElement> expected)
    {
        var (got, error) = await AttemptAsync(() => ReadCache(secrets, name));
        checks.Check(error is null && Holds(got!, expected), $"the whole secret holds the expected members: got {Bytes(got)} bytes, {error ?? "wrong value"}");
        await CheckKeys(checks, secrets, name, expected);
    }

    // Checks each expected member reads as "name#key", and that a key matches only exactly.
    private static async Task CheckKeys(Checker checks, IProtectedReadOnlyCache secrets, string name, Dictionary<string, JsonElement> expected)
    {
        var keys = SortedKeys(expected);
        foreach (var key in keys)
        {
            if (AsCached(expected[key]) is (var want, true))
            {
                var (got, error) = await AttemptAsync(() => ReadCache(secrets, $"{name}#{key}"));
                checks.Check(error is null && got == want, $"#{key} reads as expected: got {Bytes(got)} bytes, {error ?? "wrong value"}");
            }
        }
        foreach (var key in keys)
        {
            var swapped = SwapAsciiCase(key);
            if (swapped != key && !expected.ContainsKey(swapped))
            {
                var (got, error) = await AttemptAsync(() => ReadCache(secrets, $"{name}#{swapped}"));
                checks.Check(error is null && got == "", $"#{key}, in another ASCII case, is missing: got {Bytes(got)} bytes, {error ?? "no error"}");
                break;
            }
        }
        var (missing, missingError) = await AttemptAsync(() => ReadCache(secrets, $"{name}#{MissingKey}"));
        checks.Check(missingError is null && missing == "", $"#{MissingKey} is missing: got {Bytes(missing)} bytes, {missingError ?? "no error"}");
    }

    // A member as every port's cache caches it: a string as its text, true or false as its JSON
    // text. An integer is compared as its JSON text too; any other number, null, an object or an
    // array isn't compared, since not every port's JSON reader keeps a number's exact text.
    private static (string Text, bool Comparable) AsCached(JsonElement member) => member.ValueKind switch
    {
        JsonValueKind.String => (member.GetString()!, true),
        JsonValueKind.True => ("true", true),
        JsonValueKind.False => ("false", true),
        JsonValueKind.Number when Integer.IsMatch(member.GetRawText()) => (member.GetRawText(), true),
        _ => ("", false),
    };

    // Whether value is a JSON object with exactly the expected member names, each comparable member
    // holding what's expected.
    private static bool Holds(string value, Dictionary<string, JsonElement> expected)
    {
        Dictionary<string, JsonElement>? got;
        try
        {
            got = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(value);
        }
        catch (JsonException)
        {
            return false;
        }
        if (got is null || got.Count != expected.Count)
        {
            return false;
        }
        foreach (var (key, raw) in expected)
        {
            if (!got.TryGetValue(key, out var member))
            {
                return false;
            }
            var (want, comparable) = AsCached(raw);
            if (comparable && AsCached(member).Text != want)
            {
                return false;
            }
        }
        return true;
    }

    private static (string Name, Dictionary<string, JsonElement> Expected) SecretSettings(string nameVariable, string jsonVariable)
    {
        var name = Setting(nameVariable);
        var text = Setting(jsonVariable);
        Dictionary<string, JsonElement>? expected = null;
        try
        {
            expected = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(text);
        }
        catch (JsonException)
        {
        }
        return (name, expected ?? throw new ArgumentException($"{jsonVariable} isn't a JSON object"));
    }

    // Parses https://{vault}.vault.azure.net/secrets/{name} into the vault's URL and the secret's
    // name; a secret's version isn't one of these.
    private static KeyVaultSecretIdentifier AzureSecretId(string id)
    {
        var invalid = new ArgumentException("HKDFGUARD_TEST_AZURE_SECRET_ID isn't https://{vault}.vault.azure.net/secrets/{name}");
        if (!Uri.TryCreate(id, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw invalid;
        }
        try
        {
            var secret = new KeyVaultSecretIdentifier(uri);
            return secret.Version is null ? secret : throw invalid;
        }
        catch (ArgumentException e) when (e != invalid)
        {
            throw invalid;
        }
    }

    private static List<string> SortedKeys(Dictionary<string, JsonElement> expected)
        => [.. expected.Keys.Order(StringComparer.Ordinal)];

    private static string SwapAsciiCase(string s)
        => string.Create(s.Length, s, static (result, s) =>
        {
            for (var i = 0; i < s.Length; i++)
            {
                result[i] = s[i] switch
                {
                    >= 'a' and <= 'z' => (char)(s[i] - 32),
                    >= 'A' and <= 'Z' => (char)(s[i] + 32),
                    var c => c,
                };
            }
        });
}
