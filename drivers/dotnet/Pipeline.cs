using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache;
using HkdfGuard.Cache.JsonSecretsFile;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.Pipeline;
using HkdfGuard.SecureFile;

namespace HkdfGuard.Interop;

// The secrets pipeline half of a release: every fixture in the fixtures' pipeline section is pulled
// through the port's real SecretPipelineWriter base, over an in-memory store, and written in each of
// the writer's layouts to D/pipeline. A consumer reads them back with its own port's caches over the
// release's key ring. See the README's driver contract.
internal static partial class Driver
{
    private const string PipelineDir = "pipeline";
    private const string JsonSecretsFile = "secrets.json";
    private const string StreamJsonSecretsFile = "secrets.stream.json";
    private const string EmptyJsonSecretsFile = "secrets.empty.json";
    private const string SecretsTar = "secrets.tar";
    private const string PipelineFilesDir = "files";
    private const string PipelineUnpackedDir = "unpacked";
    private const string ConsumerDir = "consumed-by-dotnet";

    // The base64 of a 32-byte key: 44 ASCII characters, no line ending.
    private const int KeyBase64Length = 44;

    // Writes the release's pipeline folder. The writers use the release's own pipeline protector, so
    // every value decrypts under the release's key ring, and they never dispose it.
    private static async Task WritePipeline(IPipelineDataProtector pipeline, PipelineFixtures fixtures, string dir)
    {
        foreach (var s in fixtures.Secrets)
        {
            if (SecretPipelineWriter.GetFileName(s.Name) != s.FileName)
            {
                throw new InvalidOperationException($"pipeline: {s.Name}'s file name isn't {s.FileName}");
            }
        }
        foreach (var names in fixtures.Refused)
        {
            try
            {
                using var refused = new InMemorySecretPipelineWriter(pipeline, names, fixtures.Store);
            }
            catch (ArgumentException)
            {
                continue;
            }
            throw new InvalidOperationException($"pipeline: the writer accepted [{string.Join(", ", names)}]");
        }

        var folder = Path.Combine(dir, PipelineDir);
        Directory.CreateDirectory(folder);
        using (var writer = new InMemorySecretPipelineWriter(pipeline, [.. fixtures.Secrets.Select(s => s.Name)], fixtures.Store))
        {
            await writer.PullSecretsAsync();
            var expected = fixtures.Secrets.Select(s => s.FileName).Order(StringComparer.Ordinal);
            if (!writer.ProtectedSecrets.Keys.Order(StringComparer.Ordinal).SequenceEqual(expected, StringComparer.Ordinal))
            {
                throw new InvalidOperationException("pipeline: the writer's protected secrets aren't the fixtures' file names");
            }

            writer.WriteJsonSecrets(Path.Combine(folder, JsonSecretsFile));
            await using (var stream = File.Create(Path.Combine(folder, StreamJsonSecretsFile)))
            {
                await writer.WriteJsonSecretsAsync(stream);
            }
            writer.WriteProtectedSecretFiles(Path.Combine(folder, PipelineFilesDir));
            await using (var stream = File.Create(Path.Combine(folder, SecretsTar)))
            {
                await writer.WriteProtectedSecretFilesAsync(stream);
            }

            // As a deployment would: the archive straight into a tar process's standard input.
            var unpacked = Path.Combine(folder, PipelineUnpackedDir);
            Directory.CreateDirectory(unpacked);
            await Untar(unpacked, destination => writer.WriteProtectedSecretFilesAsync(destination));
            if (CompareFolders(Path.Combine(folder, PipelineFilesDir), unpacked, fixtures.Secrets.Select(s => s.FileName)) is { } difference)
            {
                throw new InvalidOperationException($"pipeline: the archive piped to tar unpacked differently: {difference}");
            }
        }

        using (var missing = new InMemorySecretPipelineWriter(pipeline, fixtures.Missing, fixtures.Store))
        {
            try
            {
                await missing.PullSecretsAsync();
                throw new InvalidOperationException("pipeline: pulling secrets the store holds no value for succeeded");
            }
            catch (KeyNotFoundException)
            {
            }
            if (missing.ProtectedSecrets.Count != 0)
            {
                throw new InvalidOperationException($"pipeline: pulling only missing secrets kept {missing.ProtectedSecrets.Count}");
            }
            missing.WriteJsonSecrets(Path.Combine(folder, EmptyJsonSecretsFile));
        }
    }

    // Writes the pipeline key through WriteDekAsync, as the wrap tool's --dek-stdin reads it, into
    // pinned memory, and decodes it into dek: so every wrapper's key file comes from those bytes,
    // and every consumer's DEK check proves them. Checks they are exactly the key's 44 base64
    // characters as ASCII, without a line ending.
    private static async Task ReadDekThroughWriteDek(IPipelineDataProtector pipeline, byte[] dek)
    {
        var ascii = GC.AllocateArray<byte>(KeyBase64Length + 2, pinned: true);
        try
        {
            int written;
            using (var stream = new MemoryStream(ascii, writable: true))
            {
                await pipeline.WriteDekAsync(stream);
                written = (int)stream.Position;
            }
            var key = pipeline.GetKeyAsBase64();
            var same = written == key.Length;
            for (var i = 0; same && i < written; i++)
            {
                same = ascii[i] == key[i];
            }
            if (written != KeyBase64Length || !same)
            {
                throw new InvalidOperationException($"WriteDekAsync wrote {written} bytes, not the key's {KeyBase64Length} base64 characters");
            }
            if (Base64.DecodeFromUtf8(ascii.AsSpan(0, written), dek, out _, out var length) != OperationStatus.Done || length != KeySize)
            {
                throw new InvalidOperationException("The pipeline key isn't 32 bytes.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ascii);
        }
    }

    // Reads the release's pipeline folder as a deployed application would: secrets.json through a
    // JsonSecretsFileReadOnlyCache over the release's ring, tampered copies of it refused whole, and
    // secrets.tar unpacked by the system tar and read through a FilePerSecretCache.
    private static async Task CheckPipeline(Checker checks, KeyRing ring, PipelineFixtures fixtures, string dir)
    {
        var folder = Path.Combine(dir, PipelineDir);
        var trust = KeyFileTrustForThisAccount();
        var format = new DefaultFormatProvider();
        var jsonPath = Path.Combine(folder, JsonSecretsFile);

        JsonSecretsFileReadOnlyCache? json = null;
        try
        {
            json = new JsonSecretsFileReadOnlyCache(jsonPath, trust, ring, format);
        }
        catch (Exception e)
        {
            checks.Fail($"pipeline: opening {JsonSecretsFile}: {Describe(e)}");
        }
        if (json is not null)
        {
            foreach (var s in fixtures.Secrets)
            {
                foreach (var name in new[] { s.FileName }.Concat(s.AlsoReadAs ?? []))
                {
                    var (got, error) = await ReadCaught(json, name);
                    checks.Check(error is null && got == s.Plaintext, $"pipeline: {JsonSecretsFile} reads {s.Name} as {name}: got {Bytes(got)} bytes, {(error is null ? "wrong plaintext" : Describe(error))}");
                }
            }
            foreach (var name in fixtures.MissingLookups.Concat(fixtures.InvalidLookups))
            {
                var (got, error) = await ReadCaught(json, name);
                checks.Check(error is null && got == "", $"pipeline: {JsonSecretsFile} has no {name}: got {Bytes(got)} bytes, {Describe(error)}");
            }
        }

        var (same, sameError) = AttemptBytes(() => File.ReadAllBytes(Path.Combine(folder, StreamJsonSecretsFile)).AsSpan().SequenceEqual(File.ReadAllBytes(jsonPath)));
        checks.Check(same, $"pipeline: {StreamJsonSecretsFile} is {JsonSecretsFile} byte for byte: {sameError ?? "it differs"}");

        var emptyPath = Path.Combine(folder, EmptyJsonSecretsFile);
        var (empty, emptyError) = AttemptBytes(() => File.ReadAllBytes(emptyPath).AsSpan().SequenceEqual("{}"u8));
        checks.Check(empty, $"pipeline: {EmptyJsonSecretsFile} is {{}}: {emptyError ?? "it isn't"}");
        var (nothing, nothingError) = await ReadFromNewCache(emptyPath, trust, ring, format, fixtures.Secrets[0].FileName);
        checks.Check(nothingError is null && nothing == "", $"pipeline: {EmptyJsonSecretsFile} has no {fixtures.Secrets[0].FileName}: got {Bytes(nothing)} bytes, {Describe(nothingError)}");

        var work = Path.Combine(folder, ConsumerDir);
        if (Directory.Exists(work))
        {
            Directory.Delete(work, recursive: true);
        }
        Directory.CreateDirectory(work);
        await CheckTampered(checks, ring, format, trust, jsonPath, work);
        await CheckArchive(checks, ring, fixtures, trust, folder, work);
    }

    // Two copies of secrets.json, each changed one way, must each be refused whole: a lookup of a
    // member the change didn't touch fails authentication too.
    private static async Task CheckTampered(Checker checks, KeyRing ring, IEncryptedFormatProvider format, KeyFileTrust trust, string jsonPath, string work)
    {
        List<(string Name, string Value)> members;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(jsonPath));
            members = [.. document.RootElement.EnumerateObject().Select(m => (m.Name, m.Value.GetString()!))];
        }
        catch (Exception e)
        {
            checks.Fail($"pipeline: parsing {JsonSecretsFile} to tamper with it: {Describe(e)}");
            return;
        }
        if (members.Count < 3)
        {
            checks.Fail($"pipeline: {JsonSecretsFile} holds {members.Count} members, too few to tamper with");
            return;
        }
        var untouched = members[^1].Name;

        var swapped = new List<(string Name, string Value)>(members);
        (swapped[0], swapped[1]) = ((members[0].Name, members[1].Value), (members[1].Name, members[0].Value));
        var (got, error) = await ReadFromNewCache(WriteMembers(Path.Combine(work, "swapped.json"), swapped), trust, ring, format, untouched);
        checks.Check(error is AuthenticationTagMismatchException, $"pipeline: {JsonSecretsFile} with two values swapped is refused whole: got {Bytes(got)} bytes, {Describe(error)}");

        var flipped = new List<(string Name, string Value)>(members);
        var (tampered, tamperError) = Attempt(() => Tamper(members[0].Value));
        if (tamperError is not null)
        {
            checks.Fail($"pipeline: tampering {members[0].Name}: {tamperError}");
            return;
        }
        flipped[0] = (members[0].Name, tampered!);
        (got, error) = await ReadFromNewCache(WriteMembers(Path.Combine(work, "flipped.json"), flipped), trust, ring, format, untouched);
        checks.Check(error is AuthenticationTagMismatchException, $"pipeline: {JsonSecretsFile} with a flipped tag bit is refused whole: got {Bytes(got)} bytes, {Describe(error)}");
    }

    // Unpacks secrets.tar with the system tar, from its standard input, into a fresh folder: it must
    // hold exactly the files WriteProtectedSecretFiles wrote, byte for byte, each reading through a
    // FilePerSecretCache as its value.
    private static async Task CheckArchive(Checker checks, KeyRing ring, PipelineFixtures fixtures, KeyFileTrust trust, string folder, string work)
    {
        var unpacked = Path.Combine(work, PipelineUnpackedDir);
        Directory.CreateDirectory(unpacked);
        try
        {
            await using var archive = File.OpenRead(Path.Combine(folder, SecretsTar));
            await Untar(unpacked, destination => archive.CopyToAsync(destination));
        }
        catch (Exception e)
        {
            checks.Fail($"pipeline: unpacking {SecretsTar}: {Describe(e)}");
            return;
        }

        var names = fixtures.Secrets.Select(s => s.FileName).ToList();
        var entries = Directory.GetFileSystemEntries(unpacked).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList();
        checks.Check(entries.SequenceEqual(names.Order(StringComparer.Ordinal), StringComparer.Ordinal),
            $"pipeline: {SecretsTar} holds exactly the secrets' files: it holds {entries.Count}, not {names.Count}");

        FilePerSecretCache files;
        try
        {
            files = new FilePerSecretCache(unpacked, trust, ring, new DefaultFormatProvider());
        }
        catch (Exception e)
        {
            checks.Fail($"pipeline: opening the unpacked folder: {Describe(e)}");
            return;
        }
        foreach (var s in fixtures.Secrets)
        {
            var difference = CompareFolders(Path.Combine(folder, PipelineFilesDir), unpacked, [s.FileName]);
            var (got, error) = await ReadCaught(files, s.FileName);
            checks.Check(difference is null && error is null && got == s.Plaintext,
                $"pipeline: {SecretsTar}'s {s.FileName} is the written file and reads as its value: {difference ?? $"got {Bytes(got)} bytes, {(error is null ? "wrong plaintext" : Describe(error))}"}");
        }
    }

    // Runs the system tar - Windows' own bsdtar, else the tar on PATH - to unpack an archive from its
    // standard input into folder: write writes the archive, and its input is closed afterwards.
    private static async Task Untar(string folder, Func<Stream, Task> write)
    {
        var start = new ProcessStartInfo(TarPath())
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in new[] { "-x", "--no-same-owner", "-f", "-", "-C", folder })
        {
            start.ArgumentList.Add(argument);
        }
        using var tar = Process.Start(start) ?? throw new InvalidOperationException("tar didn't start");
        var stdout = tar.StandardOutput.ReadToEndAsync();
        var stderr = tar.StandardError.ReadToEndAsync();
        try
        {
            await write(tar.StandardInput.BaseStream);
        }
        finally
        {
            tar.StandardInput.Close();
        }
        await tar.WaitForExitAsync();
        if (tar.ExitCode != 0)
        {
            throw new InvalidOperationException($"tar exited {tar.ExitCode}: {(await stdout + await stderr).Trim()}");
        }
    }

    private static string TarPath()
        => OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "tar.exe")
            : "tar";

    // null if each named file in actual is the one in expected byte for byte, else what differs.
    private static string? CompareFolders(string expected, string actual, IEnumerable<string> names)
    {
        foreach (var name in names)
        {
            var path = Path.Combine(actual, name);
            if (!File.Exists(path))
            {
                return $"{name} is missing";
            }
            var expectedPath = Path.Combine(expected, name);
            if (!File.Exists(expectedPath))
            {
                return $"{name} is missing from {Path.GetFileName(expected)}";
            }
            if (!File.ReadAllBytes(path).AsSpan().SequenceEqual(File.ReadAllBytes(expectedPath)))
            {
                return $"{name} differs";
            }
        }
        return null;
    }

    // A lookup through a new JsonSecretsFileReadOnlyCache over path, so nothing an earlier cache
    // loaded is reused.
    private static async Task<(string? Got, Exception? Error)> ReadFromNewCache(string path, KeyFileTrust trust, KeyRing ring, IEncryptedFormatProvider format, string name)
    {
        try
        {
            return await ReadCaught(new JsonSecretsFileReadOnlyCache(path, trust, ring, format), name);
        }
        catch (Exception e)
        {
            return (null, e);
        }
    }

    // Writes members as a JSON object, in their order. The layout is this driver's own: the cache
    // reads any valid JSON object.
    private static string WriteMembers(string path, List<(string Name, string Value)> members)
    {
        using (var file = File.Create(path))
        using (var json = new Utf8JsonWriter(file, new JsonWriterOptions { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            json.WriteStartObject();
            foreach (var (name, value) in members)
            {
                json.WriteString(name, value);
            }
            json.WriteEndObject();
        }
        return path;
    }

    private static (bool Ok, string? Error) AttemptBytes(Func<bool> body)
    {
        try
        {
            return (body(), null);
        }
        catch (Exception e)
        {
            return (false, Describe(e));
        }
    }
}

// A SecretPipelineWriter over an in-memory store: each store name maps to its value's exact text,
// handed to the writer as UTF-8 from pinned memory and zeroed after. Names match exactly, and a store
// name is 1 or more ASCII letters, digits, '/', '_', '.' and '-'.
internal sealed partial class InMemorySecretPipelineWriter(IPipelineDataProtector protector, IList<string> secretNames, IReadOnlyDictionary<string, string> store)
    : SecretPipelineWriter(protector, secretNames, IsValidStoreName)
{
    private static bool IsValidStoreName(string name) => StoreName().IsMatch(name);

    [GeneratedRegex(@"^[A-Za-z0-9/_.\-]+$")]
    private static partial Regex StoreName();

    protected override Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        if (store.TryGetValue(name, out var text))
        {
            var secret = GC.AllocateArray<byte>(Encoding.UTF8.GetByteCount(text), pinned: true);
            try
            {
                Encoding.UTF8.GetBytes(text, secret);
                ProtectSecret(secret, requests, values);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
        return Task.CompletedTask;
    }
}

// The fixtures' pipeline section: see fixtures/secrets.json and the README.
internal sealed record PipelineSecret(string Name, string FileName, string Plaintext, string[]? AlsoReadAs);

internal sealed record PipelineFixtures(
    Dictionary<string, string> Store,
    PipelineSecret[] Secrets,
    string[] Missing,
    string[][] Refused,
    string[] MissingLookups,
    string[] InvalidLookups);
