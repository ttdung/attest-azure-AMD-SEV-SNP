using System.Security.Cryptography;

namespace SevSnpDemo.Server;

/// <summary>
/// The workload identity this server commits to in its attestation evidence.
/// </summary>
/// <remarks>
/// <para>
/// A manifest is just a file whose SHA-256 digest stands for "the code and configuration I am
/// running". What goes in it is the operator's choice; the useful property is that the client holds an
/// identical copy and derives the expected digest independently, so neither side takes the other's
/// word for it. A conventional shape:
/// </para>
/// <code>
/// cd /opt/myapp
/// find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum &gt; /var/lib/myapp-manifest.txt
/// </code>
/// <para>
/// Note the manifest is written <em>outside</em> the tree being hashed. Redirecting into it would be
/// self-referential — the shell creates the file before <c>find</c> runs, so <c>find</c> lists it,
/// <c>sha256sum</c> records the digest of the empty file, and the write then changes it. The manifest
/// would never verify. <c>-print0</c>/<c>-z</c>/<c>-0</c> keep paths with spaces intact.
/// </para>
/// <para>
/// Deliberately <b>not</b> a directory walk performed here. Hashing a tree requires pinning traversal
/// order, symlink policy, permission bits, and mtime handling — every one of which is a way for the
/// two sides to disagree and produce a mismatch that looks like an attack. Hashing an explicit file
/// moves that decision to a script the operator can read, and makes the comparison exact.
/// </para>
/// </remarks>
public static class AppManifest
{
    /// <summary>
    /// Resolves the configured manifest digest, or null if none is configured.
    /// </summary>
    /// <remarks>
    /// <c>SEVSNP_MANIFEST</c> names a file to hash. <c>SEVSNP_MANIFEST_HASH</c> supplies the digest
    /// directly, for deployments where the manifest is produced by a build system and the file itself
    /// is not shipped. Setting both is a configuration error rather than a precedence puzzle.
    /// </remarks>
    public static byte[]? Resolve()
    {
        var path = Environment.GetEnvironmentVariable("SEVSNP_MANIFEST");
        var hex = Environment.GetEnvironmentVariable("SEVSNP_MANIFEST_HASH");

        var havePath = !string.IsNullOrWhiteSpace(path);
        var haveHex = !string.IsNullOrWhiteSpace(hex);

        if (havePath && haveHex)
        {
            throw new InvalidOperationException(
                "Set SEVSNP_MANIFEST or SEVSNP_MANIFEST_HASH, not both — otherwise which one binds the " +
                "workload identity depends on a precedence rule nobody will remember.");
        }

        if (haveHex)
        {
            byte[] digest;
            try
            {
                digest = Convert.FromHexString(hex!.Trim());
            }
            catch (FormatException)
            {
                throw new InvalidOperationException("SEVSNP_MANIFEST_HASH is not valid hex.");
            }

            if (digest.Length != SHA256.HashSizeInBytes)
            {
                throw new InvalidOperationException(
                    $"SEVSNP_MANIFEST_HASH must be {SHA256.HashSizeInBytes} bytes " +
                    $"({SHA256.HashSizeInBytes * 2} hex chars), got {digest.Length}.");
            }

            return digest;
        }

        if (!havePath)
        {
            return null;
        }

        if (Directory.Exists(path))
        {
            throw new InvalidOperationException(
                $"SEVSNP_MANIFEST points at a directory ({path}). Supply a manifest *file* instead — " +
                "hashing a tree would require both sides to agree on traversal order, symlinks, and " +
                "permission bits. Generate one with (note: written outside the tree, or it would " +
                "hash itself):\n" +
                $"    cd {path} && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum " +
                "> /var/lib/app-manifest.txt");
        }

        if (!File.Exists(path))
        {
            throw new InvalidOperationException($"SEVSNP_MANIFEST file not found: {path}");
        }

        return SHA256.HashData(File.ReadAllBytes(path!));
    }
}
