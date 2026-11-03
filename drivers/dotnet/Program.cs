// The .NET driver for the HkdfGuard interop matrix: it produces a release (pipeline encryption plus a
// key file wrapped by one key wrapper), consumes any driver's release with its own port of the same
// wrapper, and reads a remote secret store through its cache over that release's key ring. See the
// repository README for the contract every driver follows.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.Interop;
using HkdfGuard.SecureFile;

var command = args.Length > 0 ? args[0] : null;
var wrapperName = Option("--wrapper") ?? Driver.Native;
var store = Option("--store");
var cli = Option("--cli");
if (command is not ("produce" or "consume" or "cache") || Option("--service") is not { } service
    || Option("--fixtures") is not { } fixturesPath || Option("--dir") is not { } dir
    || (command == "produce" && cli is null) || (command == "cache" && store is null))
{
    Console.Error.WriteLine("usage: HkdfGuard.Interop produce [--wrapper W] --service S --fixtures F --dir D --cli PATH");
    Console.Error.WriteLine("       HkdfGuard.Interop consume [--wrapper W] --service S --fixtures F --dir D");
    Console.Error.WriteLine("       HkdfGuard.Interop cache --store C [--wrapper W] --service S --fixtures F --dir D");
    return 2;
}

try
{
    var fixtures = JsonSerializer.Deserialize<Fixtures>(File.ReadAllText(fixturesPath), Driver.Json)!;
    return command switch
    {
        "produce" => await Driver.Produce(wrapperName, service, fixtures, dir, cli!),
        "consume" => await Driver.Consume(wrapperName, service, fixtures, dir),
        _ => await Driver.ReadStore(store!, wrapperName, service, dir),
    } ? 0 : 1;
}
catch (Exception e)
{
    Console.Error.WriteLine($"FAIL {Driver.Describe(e)}");
    return 1;
}

string? Option(string name)
{
    var i = Array.IndexOf(args, name);
    return i > 0 && i + 1 < args.Length ? args[i + 1] : null;
}

namespace HkdfGuard.Interop
{
    internal static partial class Driver
    {
        private const string ReleaseFile = "release.json";
        private const string KeyFile = "dek.wrapped";
        private const string SecretsDir = "secrets";
        private const int KeySize = 32;

        public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

        // Does what a release pipeline does: encrypts every fixture under a fresh pipeline key, writes
        // the values, and wraps the key into the key file - by handing it to the native tool on
        // standard input, or through a network key wrapper in this process.
        public static async Task<bool> Produce(string wrapperName, string service, Fixtures fixtures, string dir, string cli)
        {
            using var pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), fixtures.KeyVersion);
            var values = new Dictionary<string, string>(fixtures.Secrets.Length);
            foreach (var s in fixtures.Secrets)
            {
                values[s.Identifier] = pipeline.Encrypt(s.Plaintext, s.Identifier);
            }

            var dek = GC.AllocateArray<byte>(KeySize, pinned: true);
            try
            {
                if (!Convert.TryFromBase64Chars(pipeline.GetKeyAsBase64(), dek, out var length) || length != KeySize)
                {
                    throw new InvalidOperationException("The pipeline key isn't 32 bytes.");
                }
                // Test only: a hash of the DEK, so every consumer can prove it unwrapped this same key.
                // Never record anything derived from a DEK beside its key file in a real pipeline.
                var digest = Convert.ToHexStringLower(SHA256.HashData(dek));

                Directory.CreateDirectory(dir);
                await WriteSecretFiles(pipeline, fixtures, Path.Combine(dir, SecretsDir));
                var path = Path.Combine(dir, KeyFile);
                if (wrapperName == Native)
                {
                    WrapNatively(cli, path, service, pipeline);
                }
                else
                {
                    using var wrapper = await NewWrapper(wrapperName, service, WrapContext);
                    var wrapped = new byte[WrappedKeyLimits.MaxBytes];
                    var written = await wrapper.KeyWrapper.WrapAsync(dek, wrapped);
                    await File.WriteAllBytesAsync(path, wrapped.AsMemory(0, written));
                }

                var release = new Release("dotnet", wrapperName, service, fixtures.KeyVersion, digest, values);
                await File.WriteAllTextAsync(Path.Combine(dir, ReleaseFile), JsonSerializer.Serialize(release, Json));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dek);
            }
            Console.WriteLine($"OK produced {values.Count} secrets in {dir}");
            return true;
        }

        // Pipes the pipeline key's base64 to `hkdfguard wrap --dek-stdin`: never an argument or an
        // environment variable. The only copy made here is pinned and zeroed once written.
        private static void WrapNatively(string cli, string path, string service, AesGcmPipelineDataProtector pipeline)
        {
            var start = new ProcessStartInfo(cli)
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var argument in new[] { "wrap", "-kf", path, "-sn", service, "--dek-stdin" })
            {
                start.ArgumentList.Add(argument);
            }
            using var wrap = Process.Start(start) ?? throw new InvalidOperationException($"{cli} didn't start");
            var stdout = wrap.StandardOutput.ReadToEndAsync();
            var stderr = wrap.StandardError.ReadToEndAsync();

            var key = pipeline.GetKeyAsBase64();
            var ascii = GC.AllocateArray<byte>(key.Length, pinned: true);
            try
            {
                Encoding.ASCII.GetBytes(key, ascii);
                wrap.StandardInput.BaseStream.Write(ascii);
                wrap.StandardInput.BaseStream.Flush();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ascii);
            }
            wrap.StandardInput.Close();
            wrap.WaitForExit();
            if (wrap.ExitCode != 0)
            {
                throw new InvalidOperationException($"hkdfguard wrap exited {wrap.ExitCode}: {(stdout.Result + stderr.Result).Trim()}");
            }
        }

        // Reads a release as an application would: builds a ring over the wrapper's KEK with the key
        // file, then reveals every value through the configuration purpose of its key, and caches it.
        public static async Task<bool> Consume(string wrapperName, string service, Fixtures fixtures, string dir)
        {
            var (release, wrapper, ring) = await OpenRelease(wrapperName, service, dir);
            using var ownedWrapper = wrapper;
            await using var ownedRing = ring;

            var checks = new Checker();
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
                    checks.Check(error is null && got == s.Plaintext, $"{s.Identifier} reads as {name}: got {Bytes(got)} bytes, {error ?? "wrong plaintext"}");
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

            var (tampered, tamperError) = Attempt(() => Tamper(moved));
            if (tamperError is null)
            {
                checks.Check(Attempt(() => Reveal(ring, first.Identifier, tampered!)).Error is not null,
                    $"{first.Identifier} with a flipped tag bit fails authentication");
            }
            else
            {
                checks.Fail($"tampering {first.Identifier}: {tamperError}");
            }

            var path = Path.Combine(dir, KeyFile);
            var (digest, unwrapError) = await AttemptAsync(() => UnwrappedDigest(wrapper.KeyWrapper, path));
            checks.Check(unwrapError is null && digest == release.DekSha256, $"the key file unwraps to the producer's DEK: {unwrapError ?? "digest differs"}");

            // A network KEK is shared by every application that may use it, so the context is what
            // keeps one application's key files from another's.
            if (wrapperName != Native)
            {
                OwnedWrapper? other = null;
                try
                {
                    other = await NewWrapper(wrapperName, service, OtherContext);
                }
                catch (Exception e)
                {
                    checks.Fail($"creating a wrapper with another context: {Describe(e)}");
                }
                if (other is not null)
                {
                    using (other)
                    {
                        checks.Check((await AttemptAsync(() => UnwrappedDigest(other.KeyWrapper, path))).Error is not null,
                            "the key file is refused under another context");
                    }
                }
            }

            await CheckCache(checks, new ProtectedCache(ring), fixtures);
            await CheckSecretFiles(checks, ring, fixtures, Path.Combine(dir, SecretsDir));
            return checks.Finish($"the {release.Producer} {release.Wrapper} release");
        }

        // Writes the release's secrets folder as a pipeline would for FilePerSecretCache: one file per
        // secret, holding its value encrypted under the pipeline key for the file's own name. The
        // folder gets no owner-only ACL on Windows; its parent's inherited one applies.
        private static async Task WriteSecretFiles(AesGcmPipelineDataProtector pipeline, Fixtures fixtures, string folder)
        {
            Directory.CreateDirectory(folder);
            var written = new Dictionary<string, byte[]>(fixtures.Files.Length);
            foreach (var file in fixtures.Files)
            {
                byte[] contents;
                if (file.Empty)
                {
                    contents = [];
                }
                else if (file.CopyOf is { Length: > 0 } original)
                {
                    contents = written[original];
                }
                else
                {
                    var value = pipeline.Encrypt(fixtures.PlaintextOf(file), file.Name);
                    contents = Encoding.UTF8.GetBytes(file.TrailingNewline ? value + "\n" : value);
                }
                written[file.Name] = contents;
                await File.WriteAllBytesAsync(Path.Combine(folder, file.Name), contents);
            }
        }

        // Reads the release's secrets folder through a FilePerSecretCache over the release's ring: each
        // file reads as its value, is missing, or is refused as its fixture expects, and a name no file
        // can answer - one that isn't a file name in the folder - is missing.
        private static async Task CheckSecretFiles(Checker checks, KeyRing ring, Fixtures fixtures, string folder)
        {
            FilePerSecretCache files;
            try
            {
                files = new FilePerSecretCache(folder, KeyFileTrustForThisAccount(), ring, new DefaultFormatProvider());
            }
            catch (Exception e)
            {
                checks.Fail($"files: opening the secrets folder: {Describe(e)}");
                return;
            }
            foreach (var file in fixtures.Files)
            {
                var (got, error) = await ReadCaught(files, file.Name);
                switch (file.Expect)
                {
                    case "value":
                        checks.Check(error is null && got == fixtures.PlaintextOf(file), $"files: {file.Name} reads as its value: got {Bytes(got)} bytes, {(error is null ? "wrong plaintext" : Describe(error))}");
                        break;
                    case "missing":
                        checks.Check(error is null && got == "", $"files: {file.Name} is missing: got {Bytes(got)} bytes, {Describe(error)}");
                        break;
                    case "refused":
                        // The specific authentication failure: AES-GCM's tag mismatch, not just any error.
                        checks.Check(error is AuthenticationTagMismatchException, $"files: {file.Name} fails authentication: {Describe(error)}");
                        break;
                    default:
                        checks.Fail($"files: {file.Name} expects \"{file.Expect}\", which isn't value, missing or refused");
                        break;
                }
            }
            foreach (var name in fixtures.MissingFiles)
            {
                var (got, error) = await ReadCaught(files, name);
                checks.Check(error is null && got == "", $"files: {name} is missing: got {Bytes(got)} bytes, {Describe(error)}");
            }
        }

        private static async Task<(string? Got, Exception? Error)> ReadCaught(IProtectedReadOnlyCache cache, string name)
        {
            try
            {
                return (await ReadCache(cache, name), null);
            }
            catch (Exception e)
            {
                return (null, e);
            }
        }

        // Reads dir's release and builds a ring over its key file with this port of the release's
        // wrapper. The caller disposes the ring, then the wrapper.
        private static async Task<(Release Release, OwnedWrapper Wrapper, KeyRing Ring)> OpenRelease(string wrapperName, string service, string dir)
        {
            var release = JsonSerializer.Deserialize<Release>(await File.ReadAllTextAsync(Path.Combine(dir, ReleaseFile)), Json)!;
            if (release.Wrapper != wrapperName)
            {
                throw new InvalidOperationException($"the release was wrapped with \"{release.Wrapper}\", not \"{wrapperName}\"");
            }
            var wrapper = await NewWrapper(wrapperName, service, WrapContext);
            try
            {
                var ring = await new KeyRingBuilder()
                    .WithServiceName(service)
                    .WithKeyRefreshInterval(60)
                    .WithKeyWrapper(wrapper.KeyWrapper)
                    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
                    .WithKeyFile(version: release.KeyVersion, pathToFile: Path.Combine(dir, KeyFile))
                    .BuildAsync();
                return (release, wrapper, ring);
            }
            catch
            {
                wrapper.Dispose();
                throw;
            }
        }

        // Stores every fixture in a protected cache over the release's ring and reads it back: names
        // that differ in ASCII case share an entry, names that differ in non-ASCII case don't, and an
        // empty value, or a second value under an existing name, is refused.
        private static async Task CheckCache(Checker checks, IProtectedCache cache, Fixtures fixtures)
        {
            foreach (var s in fixtures.Secrets)
            {
                var error = TryAdd(cache, s.Identifier, s.Plaintext);
                if (s.Plaintext.Length == 0)
                {
                    checks.Check(error is ArgumentException, $"cache: an empty {s.Identifier} is refused: {Describe(error)}");
                    continue;
                }
                if (error is not null)
                {
                    checks.Fail($"cache: adding {s.Identifier}: {Describe(error)}");
                    continue;
                }
                foreach (var name in new[] { s.Identifier }.Concat(s.AlsoReadAs ?? []))
                {
                    var (got, readError) = await AttemptAsync(() => ReadCache(cache, name));
                    checks.Check(readError is null && got == s.Plaintext, $"cache: {s.Identifier} reads as {name}: got {Bytes(got)} bytes, {readError ?? "wrong plaintext"}");
                }
                foreach (var name in s.MustNotReadAs ?? [])
                {
                    var (got, readError) = await AttemptAsync(() => ReadCache(cache, name));
                    checks.Check(readError is null && got == "", $"cache: {s.Identifier} is missing as {name}: got {Bytes(got)} bytes, {readError ?? "no error"}");
                }
                if (s.AlsoReadAs is [var again, ..])
                {
                    var addError = TryAdd(cache, again, "again");
                    checks.Check(addError is ArgumentException, $"cache: adding {s.Identifier} again as {again} is refused: {Describe(addError)}");
                }
            }
        }

        // Add zeroes the plaintext it is handed, so it gets a copy.
        private static Exception? TryAdd(IProtectedCache cache, string name, string plaintext)
        {
            var copy = plaintext.ToCharArray();
            try
            {
                cache.Add(name, copy);
                return null;
            }
            catch (Exception e)
            {
                return e;
            }
            finally
            {
                Array.Clear(copy);
            }
        }

        // The value cached under name, or "" if there is none.
        private static async Task<string> ReadCache(IProtectedReadOnlyCache cache, string name)
        {
            var size = await cache.GetMaxDecryptedLengthAsync(name);
            if (size == 0)
            {
                return "";
            }
            var result = GC.AllocateArray<char>(size, pinned: true);
            try
            {
                var written = await cache.DecryptAsync(name, result);
                return new string(result, 0, written);
            }
            finally
            {
                Array.Clear(result);
            }
        }

        private static string Reveal(KeyRing ring, string name, string value)
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
        private static string Tamper(string value)
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

        private static async Task<string> UnwrappedDigest(IKeyWrapper wrapper, string path)
        {
            var wrapped = await wrapper.ReadKeyFileAsync(path);
            var raw = GC.AllocateArray<byte>(KeySize, pinned: true);
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

        private static (string? Got, string? Error) Attempt(Func<string> body)
        {
            try
            {
                return (body(), null);
            }
            catch (Exception e)
            {
                return (null, Describe(e));
            }
        }

        private static async Task<(string? Got, string? Error)> AttemptAsync(Func<Task<string>> body)
        {
            try
            {
                return (await body(), null);
            }
            catch (Exception e)
            {
                return (null, Describe(e));
            }
        }

        public static string Describe(Exception? e) => e is null ? "no error" : $"{e.GetType().Name}: {e.Message}";

        // A value's length in UTF-8 bytes: what a failure may say about a value it read, never more.
        private static int Bytes(string? value) => value is null ? 0 : Encoding.UTF8.GetByteCount(value);
    }

    internal sealed record Secret(
        string Identifier,
        string Plaintext,
        string[]? AlsoReadAs,
        string[]? MustNotReadAs);

    // One file a producer writes to the release's secrets folder, and what every consumer's
    // FilePerSecretCache must make of it: "value", "missing" or "refused".
    internal sealed record SecretFile(
        string Name,
        string? Plaintext,
        string? PlaintextOf,
        bool TrailingNewline,
        bool Empty,
        string? CopyOf,
        string Expect);

    internal sealed record Fixtures(int KeyVersion, Secret[] Secrets, SecretFile[] Files, string[] MissingFiles)
    {
        // The value file is written with: its own, or the named secret's.
        public string PlaintextOf(SecretFile file)
            => (file.PlaintextOf is { Length: > 0 } of ? Secrets.FirstOrDefault(s => s.Identifier == of)?.Plaintext : null)
                ?? file.Plaintext ?? "";
    }

    internal sealed record Release(
        string Producer,
        string Wrapper,
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

        public bool Finish(string what)
        {
            if (_failed > 0)
            {
                Console.Error.WriteLine($"FAIL {_failed} of {_passed + _failed} checks failed reading {what}");
                return false;
            }
            Console.WriteLine($"OK {_passed} checks passed reading {what}");
            return true;
        }
    }
}
