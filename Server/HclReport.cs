using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

namespace SevSnpDemo.Server;

/// <summary>
/// Parses the Azure "HCL report" stored in vTPM NV index 0x01400001 on paravisor-backed CVMs.
/// </summary>
/// <remarks>
/// <para>
/// Layout, per Microsoft's guest-attestation client and the independent implementations that
/// interoperate with it:
/// </para>
/// <code>
/// 0x000  attestation_header   32 bytes, signature "HCLA" (0x414C4348 little-endian)
/// 0x020  hw_report          1184 bytes, the SEV-SNP attestation report (unmodified ABI struct)
/// 0x4C0  padding             variable
/// ....   runtime_data       UTF-8 JSON: { "keys": [ JWK... ], "vm-configuration": {...} }
/// </code>
/// <para>
/// The header and report offsets are stable. The <b>runtime data offset is not</b> — published
/// implementations disagree about the padding between the report and the JSON. So rather than trust a
/// constant, this locates the JSON by scanning for its opening brace and determines its exact length
/// with a real JSON reader (trailing NUL padding would otherwise be included and change the hash).
/// </para>
/// <para>
/// The extent is then <em>proved</em> rather than assumed: the SNP report's REPORT_DATA equals
/// <c>SHA-256(runtime_data) || 32 zero bytes</c>, so a correct parse is self-verifying. If the hash
/// does not match, the parse was wrong and this fails loudly instead of shipping bytes the client
/// would reject with a confusing error.
/// </para>
/// </remarks>
public static class HclReport
{
    /// <summary>"HCLA" as a little-endian UINT32.</summary>
    private const uint HclSignature = 0x414C4348;

    private const int HeaderLength = 0x20;
    private const int SnpReportLength = 0x4A0;
    private const int RuntimeDataSearchStart = HeaderLength + SnpReportLength;

    /// <summary>REPORT_DATA offset within the SEV-SNP report, and its length.</summary>
    private const int ReportDataOffset = 0x50;

    private const int ReportDataLength = 64;

    public sealed record Parsed(byte[] SnpReport, byte[] RuntimeData, uint Version, uint RequestType);

    /// <summary>
    /// Splits an HCL report into its SEV-SNP report and runtime-data halves.
    /// </summary>
    /// <exception cref="InvalidDataException">The buffer is not a parseable HCL report.</exception>
    public static Parsed Parse(ReadOnlySpan<byte> hcl)
    {
        if (hcl.Length < RuntimeDataSearchStart)
        {
            throw new InvalidDataException(
                $"HCL report is {hcl.Length} bytes, too short to contain a {HeaderLength}-byte header " +
                $"plus a {SnpReportLength}-byte SNP report.");
        }

        var signature = BinaryPrimitives.ReadUInt32LittleEndian(hcl);
        if (signature != HclSignature)
        {
            throw new InvalidDataException(
                $"HCL header signature is 0x{signature:X8}, expected 0x{HclSignature:X8} (\"HCLA\"). " +
                "This NV index does not contain an Azure HCL report.");
        }

        var version = BinaryPrimitives.ReadUInt32LittleEndian(hcl[4..]);
        var reportSize = BinaryPrimitives.ReadUInt32LittleEndian(hcl[8..]);
        var requestType = BinaryPrimitives.ReadUInt32LittleEndian(hcl[12..]);

        var snpReport = hcl.Slice(HeaderLength, SnpReportLength).ToArray();
        var runtimeData = ExtractRuntimeData(hcl, out var runtimeDataOffset);

        // Self-check: REPORT_DATA must be SHA-256(runtime_data) padded to 64 bytes with zeros. This is
        // what proves the runtime data really belongs to this report — and, incidentally, that the
        // offsets above are right on this machine.
        var reportData = snpReport.AsSpan(ReportDataOffset, ReportDataLength);
        var expected = SHA256.HashData(runtimeData);

        if (!CryptographicOperations.FixedTimeEquals(reportData[..32], expected))
        {
            throw new InvalidDataException(
                $"REPORT_DATA does not match SHA-256(runtime_data). Parsed {runtimeData.Length} bytes of " +
                $"runtime data at offset 0x{runtimeDataOffset:X}. " +
                $"REPORT_DATA[0..32]={Convert.ToHexStringLower(reportData[..32])}, " +
                $"SHA-256(runtime_data)={Convert.ToHexStringLower(expected)}. " +
                "The runtime-data extent was determined incorrectly, or this is not an Azure SNP HCL " +
                "report. hclSize=" + hcl.Length + $", headerReportSize={reportSize}, version={version}.");
        }

        if (reportData[32..].ContainsAnyExcept((byte)0))
        {
            throw new InvalidDataException(
                "REPORT_DATA bytes 32..64 are not all zero; this is not the Azure paravisor's " +
                "SHA-256-plus-padding convention and the binding cannot be interpreted safely.");
        }

        return new Parsed(snpReport, runtimeData, version, requestType);
    }

    /// <summary>
    /// Locates the runtime-data JSON and returns exactly its bytes — no trailing padding.
    /// </summary>
    private static byte[] ExtractRuntimeData(ReadOnlySpan<byte> hcl, out int offset)
    {
        var tail = hcl[RuntimeDataSearchStart..];
        var braceIndex = tail.IndexOf((byte)'{');

        if (braceIndex < 0)
        {
            offset = -1;
            throw new InvalidDataException(
                $"No JSON object found after offset 0x{RuntimeDataSearchStart:X} in the HCL report " +
                $"({hcl.Length} bytes total). Expected the runtime-data document there.");
        }

        offset = RuntimeDataSearchStart + braceIndex;
        var candidate = hcl[offset..];

        // A JSON reader gives the exact end of the top-level object. Slicing on the last '}' in the
        // buffer would be wrong if the padding happened to contain one, and slicing on the first would
        // be wrong for any nested object.
        try
        {
            var reader = new Utf8JsonReader(candidate, isFinalBlock: true, state: default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw new InvalidDataException("Runtime data does not begin with a JSON object.");
            }

            reader.Skip(); // Advances past the entire object.
            return candidate[..(int)reader.BytesConsumed].ToArray();
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(
                $"Runtime data at offset 0x{offset:X} is not valid JSON: {ex.Message}", ex);
        }
    }
}
