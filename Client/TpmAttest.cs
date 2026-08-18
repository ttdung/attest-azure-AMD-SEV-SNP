using System.Buffers.Binary;

namespace SevSnpDemo.Client;

/// <summary>
/// Minimal reader for the TPMS_ATTEST structure produced by TPM2_Quote (TPM 2.0 spec, Part 2 §10.12.8).
/// </summary>
/// <remarks>
/// <para>
/// Only the fields this protocol appraises are decoded — <c>magic</c>, <c>type</c>,
/// <c>qualifiedSigner</c>, and <c>extraData</c>. The PCR selection and digest that follow are located
/// but not interpreted, because nothing here appraises PCR values.
/// </para>
/// <para>
/// Hand-rolled rather than pulled from a TPM library on purpose: the client has no other reason to
/// depend on a TPM stack, and this structure is a fixed big-endian layout that fits in a screen.
/// </para>
/// <code>
/// TPMS_ATTEST ::= {
///   magic            UINT32                 -- must be 0xFF544347, "\xFFTCG"
///   type             UINT16                 -- TPM_ST_ATTEST_QUOTE = 0x8018
///   qualifiedSigner  TPM2B_NAME             -- UINT16 length + bytes
///   extraData        TPM2B_DATA             -- UINT16 length + bytes  <-- the binding
///   clockInfo        TPMS_CLOCK_INFO        -- UINT64 + UINT32 + UINT32 + BYTE = 17 bytes
///   firmwareVersion  UINT64
///   attested         TPMU_ATTEST            -- TPMS_QUOTE_INFO for a quote
/// }
/// </code>
/// </remarks>
/// <summary>One TPMS_PCR_SELECTION: a hash bank plus the PCR indices selected within it.</summary>
public sealed record PcrBankSelection(ushort HashAlg, IReadOnlyList<int> Indices)
{
    /// <summary>TPM_ALG_SHA256.</summary>
    public const ushort Sha256 = 0x000B;
}

public sealed record TpmAttest(
    uint Magic,
    ushort Type,
    byte[] QualifiedSigner,
    byte[] ExtraData,
    ulong FirmwareVersion,
    IReadOnlyList<PcrBankSelection> PcrSelections,
    byte[] PcrDigest)
{
    /// <summary>The only <c>magic</c> value a genuine TPM attestation structure carries.</summary>
    public const uint TpmGeneratedValue = 0xFF544347;

    /// <summary>TPM_ST_ATTEST_QUOTE.</summary>
    public const ushort AttestQuote = 0x8018;

    public bool IsQuote => Magic == TpmGeneratedValue && Type == AttestQuote;

    /// <summary>
    /// Parses a TPMS_ATTEST. Throws <see cref="InvalidDataException"/> on any structural problem.
    /// </summary>
    public static TpmAttest Parse(ReadOnlySpan<byte> buffer)
    {
        var offset = 0;

        var magic = ReadUInt32(buffer, ref offset);
        var type = ReadUInt16(buffer, ref offset);

        // magic is checked here rather than left to the caller: a structure that is not
        // TPM_GENERATED_VALUE cannot be a TPM attestation, and continuing to parse it would produce
        // meaningless field values that might accidentally compare equal to something.
        if (magic != TpmGeneratedValue)
        {
            throw new InvalidDataException(
                $"TPMS_ATTEST magic is 0x{magic:X8}, expected 0x{TpmGeneratedValue:X8}. " +
                "This is not a TPM-generated attestation structure. Note that TPM_GENERATED_VALUE " +
                "exists precisely so that a TPM signature over attacker-chosen data cannot be " +
                "mistaken for an attestation.");
        }

        var qualifiedSigner = ReadSizedBuffer(buffer, ref offset, "qualifiedSigner");
        var extraData = ReadSizedBuffer(buffer, ref offset, "extraData");

        // clockInfo: UINT64 clock, UINT32 resetCount, UINT32 restartCount, BYTE safe.
        Advance(buffer, ref offset, 17, "clockInfo");

        var firmwareVersion = ReadUInt64(buffer, ref offset);

        // attested, as TPMS_QUOTE_INFO: TPML_PCR_SELECTION then TPM2B_DIGEST.
        var selections = ReadPcrSelections(buffer, ref offset);
        var pcrDigest = ReadSizedBuffer(buffer, ref offset, "pcrDigest");

        return new TpmAttest(
            magic, type, qualifiedSigner, extraData, firmwareVersion, selections, pcrDigest);
    }

    /// <summary>
    /// Reads a TPML_PCR_SELECTION: UINT32 count, then per bank a UINT16 hash, a UINT8 select size, and
    /// that many bitmap bytes.
    /// </summary>
    /// <remarks>
    /// The bitmap is little-endian by bit: bit <c>i</c> of byte <c>j</c> selects PCR <c>j*8 + i</c>.
    /// Order matters downstream — <c>pcrDigest</c> is computed over the selected PCR values in the
    /// order they appear here, ascending index within each bank — so the selection is read from the
    /// signed structure rather than assumed from whatever the peer claims separately.
    /// </remarks>
    private static IReadOnlyList<PcrBankSelection> ReadPcrSelections(
        ReadOnlySpan<byte> buffer,
        ref int offset)
    {
        var count = ReadUInt32(buffer, ref offset);

        // A count this large cannot be legitimate and would otherwise drive a huge allocation loop.
        if (count > 16)
        {
            throw new InvalidDataException(
                $"TPML_PCR_SELECTION declares {count} banks; refusing to parse more than 16.");
        }

        var selections = new List<PcrBankSelection>((int)count);

        for (var bank = 0; bank < count; bank++)
        {
            var hashAlg = ReadUInt16(buffer, ref offset);

            var sizeOfSelect = ReadByte(buffer, ref offset);
            var bitmapStart = offset;
            Advance(buffer, ref offset, sizeOfSelect, "pcrSelect bitmap");

            var indices = new List<int>();
            for (var byteIndex = 0; byteIndex < sizeOfSelect; byteIndex++)
            {
                var bits = buffer[bitmapStart + byteIndex];
                for (var bit = 0; bit < 8; bit++)
                {
                    if ((bits & (1 << bit)) != 0)
                    {
                        indices.Add(byteIndex * 8 + bit);
                    }
                }
            }

            selections.Add(new PcrBankSelection(hashAlg, indices));
        }

        return selections;
    }

    private static byte ReadByte(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var start = offset;
        Advance(buffer, ref offset, 1, "BYTE");
        return buffer[start];
    }

    private static void Advance(ReadOnlySpan<byte> buffer, ref int offset, int count, string field)
    {
        if (offset + count > buffer.Length)
        {
            throw new InvalidDataException(
                $"TPMS_ATTEST truncated: need {count} bytes for {field} at offset {offset}, " +
                $"only {buffer.Length - offset} remain.");
        }

        offset += count;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var start = offset;
        Advance(buffer, ref offset, sizeof(ushort), "UINT16");
        return BinaryPrimitives.ReadUInt16BigEndian(buffer[start..]);
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var start = offset;
        Advance(buffer, ref offset, sizeof(uint), "UINT32");
        return BinaryPrimitives.ReadUInt32BigEndian(buffer[start..]);
    }

    private static ulong ReadUInt64(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var start = offset;
        Advance(buffer, ref offset, sizeof(ulong), "UINT64");
        return BinaryPrimitives.ReadUInt64BigEndian(buffer[start..]);
    }

    /// <summary>Reads a TPM2B_* (UINT16 length prefix followed by that many bytes).</summary>
    private static byte[] ReadSizedBuffer(ReadOnlySpan<byte> buffer, ref int offset, string field)
    {
        var size = ReadUInt16(buffer, ref offset);
        var start = offset;
        Advance(buffer, ref offset, size, field);
        return buffer.Slice(start, size).ToArray();
    }
}
