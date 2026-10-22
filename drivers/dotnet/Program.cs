// The .NET driver for the HkdfGuard interop matrix. It consumes any driver's release; producing is
// left to the Go, Node and Python drivers for now. See the repository README for the contract every
// driver follows.

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.KeyWrapping.V1;

const string ReleaseFile = "release.json";
const string KeyFile = "dek.wrapped";

if (args.Length < 1 || args[0] != "consume" || Option("--service") is not { } service || Option("--fixtures") is not { } fixturesPath
    || Option("--dir") is not { } dir)
{
    Console.Error.WriteLine("usage: HkdfGuard.Interop consume --service S --fixtures F --dir D");
    return 2;
}

try
{
    var json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    var fixtures = JsonSerializer.Deserialize<Fixtures>(File.ReadAllText(fixturesPath), json)!;
    var release = JsonSerializer.Deserialize<Release>(File.ReadAllText(Path.Combine(dir, ReleaseFile)), json)!;
    return await Consume(service, fixtures, release, dir) ? 0 : 1;
}
catch (Exception e)
{
    Console.Error.WriteLine($"FAIL {e.GetType().Name}: {e.Message}");
    return 1;
}

string? Option(string name)
{
    var i = Array.IndexOf(args, name);
    return i > 0 && i + 1 < args.Length ? args[i + 1] : null;
}

// Reads a release as an application would: builds a ring over the native KEK with the key file, then
// reveals every value through the configuration purpose of its key.
static async Task<bool> Consume(string service, Fixtures fixtures, Release release, string dir)
{
    var wrapper = new NativeHkdfKeyWrapperV1(service);
    var checks = new Checker();
    await using (var ring = await new KeyRingBuilder()
        .WithServiceName(service)
        .WithKeyRefreshInterval(60)
        .WithKeyWrapper(wrapper)
        .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
        .WithKeyFile(version: release.KeyVersion, pathToFile: Path.Combine(dir, KeyFile))
        .BuildAsync())
    {
        foreach (var s in fixtures.Secrets)
        {
            if (!release.Values.TryGetValue(s.Identifier, out var value))
            {
                checks.Fail($"{s.Identifier}: missing from the release");
                continue;
            }
            foreach (var name in new[] { s.Identifier }.Concat(s.AlsoReadAs ?? []))
            {
                var (got, error) = Attempt(() => Reveal(ring, name, value));
                checks.Check(error is null && got == s.Plaintext, $"{s.Identifier} reads as {name}: {error ?? "wrong plaintext"}");
            }
            foreach (var name in s.MustNotReadAs ?? [])
            {
                checks.Check(Attempt(() => Reveal(ring, name, value)).Error is not null, $"{s.Identifier} must not read as {name}");
            }
        }

        var (first, second) = (fixtures.Secrets[0], fixtures.Secrets[1]);
        var moved = release.Values[first.Identifier];
        checks.Check(Attempt(() => Reveal(ring, second.Identifier, moved)).Error is not null,
            $"{first.Identifier} moved under {second.Identifier} fails authentication");
        checks.Check(Attempt(() => Reveal(ring, first.Identifier, Tamper(moved))).Error is not null,
            $"{first.Identifier} with a flipped tag bit fails authentication");
    }

    string? digest = null, unwrapError = null;
    try
    {
        digest = await UnwrappedDigest(wrapper, Path.Combine(dir, KeyFile));
    }
    catch (Exception e)
    {
        unwrapError = $"{e.GetType().Name}: {e.Message}";
    }
    checks.Check(digest == release.DekSha256, $"the key file unwraps to the producer's DEK: {unwrapError ?? "digest differs"}");
    return checks.Finish(release.Producer);
}

static string Reveal(KeyRing ring, string name, string value)
{
    var protector = ring.CreateProtector(ProtectedConfigurationPurpose.For(name));
    var result = new char[protector.GetMaxDecryptedLength(value)];
    try
    {
        return new string(result, 0, protector.Decrypt(value, result));
    }
    finally
    {
        Array.Clear(result);
    }
}

// Flips one bit in the last byte (the GCM tag) of a formatted value.
static string Tamper(string value)
{
    var match = Regex.Match(value, @"^(enc::v\d+::)(.+)$", RegexOptions.Singleline);
    if (!match.Success)
    {
        throw new FormatException("not an enc::v<version>::<base64> value");
    }
    var body = Convert.FromBase64String(match.Groups[2].Value);
    body[^1] ^= 0x01;
    return match.Groups[1].Value + Convert.ToBase64String(body);
}

static async Task<string> UnwrappedDigest(NativeHkdfKeyWrapperV1 wrapper, string path)
{
    var wrapped = await wrapper.ReadKeyFileAsync(path);
    var raw = new byte[32];
    try
    {
        var written = await wrapper.UnwrapAsync(wrapped, raw);
        return Convert.ToHexStringLower(SHA256.HashData(raw.AsSpan(0, written)));
    }
    finally
    {
        CryptographicOperations.ZeroMemory(raw);
    }
}

static (string? Got, string? Error) Attempt(Func<string> body)
{
    try
    {
        return (body(), null);
    }
    catch (Exception e)
    {
        return (null, $"{e.GetType().Name}: {e.Message}");
    }
}

internal sealed record Secret(
    string Identifier,
    string Plaintext,
    string[]? AlsoReadAs,
    string[]? MustNotReadAs);

internal sealed record Fixtures(int KeyVersion, Secret[] Secrets);

internal sealed record Release(
    string Producer,
    string Service,
    int KeyVersion,
    string DekSha256,
    Dictionary<string, string> Values);

internal sealed class Checker
{
    private int _passed;
    private int _failed;

    public void Check(bool ok, string message)
    {
        if (ok)
        {
            _passed++;
        }
        else
        {
            Fail(message);
        }
    }

    public void Fail(string message)
    {
        _failed++;
        Console.WriteLine($"FAIL {message}");
    }

    public bool Finish(string producer)
    {
        if (_failed > 0)
        {
            Console.Error.WriteLine($"FAIL {_failed} of {_passed + _failed} checks failed reading the {producer} release");
            return false;
        }
        Console.WriteLine($"OK {_passed} checks passed reading the {producer} release");
        return true;
    }
}
