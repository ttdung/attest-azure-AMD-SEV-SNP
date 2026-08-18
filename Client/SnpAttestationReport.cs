using System.Buffers.Binary;

namespace SevSnpDemo.Client;

/// <summary>
/// A parsed AMD SEV-SNP attestation report (ATTESTATION_REPORT, SEV-SNP ABI table 22).
/// </summary>
/// <remarks>
/// Field offsets are fixed by the ABI and are written as literals so they can be checked against the
/// specification by eye. The report is exactly 1184 bytes: 672 bytes of signed content followed by a
/// 512-byte signature field.
/// </remarks>
public sealed class SnpAttestationReport
{
    /// <summary>Total report size in bytes.</summary>
    public const int Size = 1184;

    /// <summary>
    /// Length of the region covered by the signature: bytes 0x000 through 0x29F inclusive.
    /// </summary>
    /// <remarks>
    /// Everything from SIGNATURE onward is excluded, which is why this is exactly the offset of the
    /// SIGNATURE field. Getting this boundary wrong is the classic way to build a verifier that
    /// rejects all valid reports — or, worse, accepts modified ones.
    /// </remarks>
    public const int SignedLength = 0x2A0;

    private readonly byte[] _raw;

    private SnpAttestationReport(byte[] raw) => _raw = raw;

    public static SnpAttestationReport Parse(byte[] raw)
    {
        if (raw.Length != Size)
        {
            throw new InvalidDataException(
                $"A SEV-SNP attestation report is {Size} bytes; got {raw.Length}.");
        }

        return new SnpAttestationReport(raw);
    }

    /// <summary>The full report bytes.</summary>
    public ReadOnlySpan<byte> Raw => _raw;

    /// <summary>The region the AMD secure processor signed.</summary>
    public ReadOnlySpan<byte> SignedRegion => _raw.AsSpan(0, SignedLength);

    // --- Header ---------------------------------------------------------------------------------

    public uint Version => BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(0x000, 4));
    public uint GuestSvn => BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(0x004, 4));
    public ulong Policy => BinaryPrimitives.ReadUInt64LittleEndian(_raw.AsSpan(0x008, 8));
    public ReadOnlySpan<byte> FamilyId => _raw.AsSpan(0x010, 16);
    public ReadOnlySpan<byte> ImageId => _raw.AsSpan(0x020, 16);
    public uint Vmpl => BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(0x030, 4));
    public uint SignatureAlgo => BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(0x034, 4));
    public ulong PlatformInfo => BinaryPrimitives.ReadUInt64LittleEndian(_raw.AsSpan(0x040, 8));
    private uint Flags => BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(0x048, 4));

    // --- Payload --------------------------------------------------------------------------------

    /// <summary>The 64 caller-supplied bytes. This is where the TLS key binding lives.</summary>
    public ReadOnlySpan<byte> ReportData => _raw.AsSpan(0x050, 64);

    /// <summary>Launch measurement of the guest. On Azure CVMs this covers the Azure firmware/paravisor, not your app.</summary>
    public ReadOnlySpan<byte> Measurement => _raw.AsSpan(0x090, 48);

    /// <summary>32 bytes set by the host at launch. Usually unavailable to set on a plain Azure CVM.</summary>
    public ReadOnlySpan<byte> HostData => _raw.AsSpan(0x0C0, 32);

    public ReadOnlySpan<byte> IdKeyDigest => _raw.AsSpan(0x0E0, 48);
    public ReadOnlySpan<byte> AuthorKeyDigest => _raw.AsSpan(0x110, 48);
    public ReadOnlySpan<byte> ReportId => _raw.AsSpan(0x140, 32);

    /// <summary>Unique per-chip identifier. Corresponds to the HWID extension in the VCEK.</summary>
    public ReadOnlySpan<byte> ChipId => _raw.AsSpan(0x1A0, 64);

    /// <summary>The 512-byte signature field: r (72 LE) || s (72 LE) || zero padding.</summary>
    public ReadOnlySpan<byte> Signature => _raw.AsSpan(0x2A0, 512);

    // --- TCB versions ---------------------------------------------------------------------------

    public TcbVersion CurrentTcb => TcbVersion.FromRaw(_raw.AsSpan(0x038, 8));

    /// <summary>The TCB the VCEK was issued against. This is the one to compare with the certificate.</summary>
    public TcbVersion ReportedTcb => TcbVersion.FromRaw(_raw.AsSpan(0x180, 8));

    public TcbVersion CommittedTcb => TcbVersion.FromRaw(_raw.AsSpan(0x1E0, 8));
    public TcbVersion LaunchTcb => TcbVersion.FromRaw(_raw.AsSpan(0x1F0, 8));

    // --- Decoded flags --------------------------------------------------------------------------

    /// <summary>
    /// Guest policy: debugging permitted. Must be false, or the memory is inspectable and the whole
    /// confidentiality claim collapses.
    /// </summary>
    public bool PolicyDebugAllowed => (Policy & (1UL << 19)) != 0;

    /// <summary>Guest policy: SMT permitted. Relevant to cross-thread side-channel exposure.</summary>
    public bool PolicySmtAllowed => (Policy & (1UL << 16)) != 0;

    /// <summary>Guest policy: migration agent permitted.</summary>
    public bool PolicyMigrateMaAllowed => (Policy & (1UL << 18)) != 0;

    public byte PolicyAbiMajor => (byte)((Policy >> 8) & 0xFF);
    public byte PolicyAbiMinor => (byte)(Policy & 0xFF);

    /// <summary>Platform state: SMT is actually enabled on this host.</summary>
    public bool PlatformSmtEnabled => (PlatformInfo & (1UL << 0)) != 0;

    /// <summary>Platform state: transparent SME enabled.</summary>
    public bool PlatformTsmeEnabled => (PlatformInfo & (1UL << 1)) != 0;

    /// <summary>
    /// Which key signed the report: 0 = VCEK, 1 = VLEK, 7 = none.
    /// </summary>
    /// <remarks>
    /// This verifier only handles VCEK. A VLEK-signed report chains through a CSP-specific endorsement
    /// key instead of the per-chip key, so verifying it against a VCEK would be a category error —
    /// hence an explicit check rather than a confusing signature failure downstream.
    /// </remarks>
    public int SigningKeyKind => (int)((Flags >> 2) & 0b111);

    public bool AuthorKeyEnabled => (Flags & 1) != 0;
}

/// <summary>
/// A SEV-SNP TCB_VERSION: four independently-versioned firmware components.
/// </summary>
/// <remarks>
/// Layout per the ABI: BOOTLOADER bits 7:0, TEE bits 15:8, reserved bits 47:16,
/// SNP bits 55:48, MICROCODE bits 63:56.
/// </remarks>
public readonly record struct TcbVersion(byte Bootloader, byte Tee, byte Snp, byte Microcode)
{
    public static TcbVersion FromRaw(ReadOnlySpan<byte> eightBytes) => new(
        Bootloader: eightBytes[0],
        Tee: eightBytes[1],
        Snp: eightBytes[6],
        Microcode: eightBytes[7]);

    /// <summary>
    /// True when every component is at least the corresponding component of <paramref name="floor"/>.
    /// </summary>
    /// <remarks>
    /// Compared component-wise rather than as a packed integer: the components version independently,
    /// so a numeric comparison of the quadword would let a microcode downgrade hide behind a
    /// bootloader bump.
    /// </remarks>
    public bool AtLeast(TcbVersion floor) =>
        Bootloader >= floor.Bootloader &&
        Tee >= floor.Tee &&
        Snp >= floor.Snp &&
        Microcode >= floor.Microcode;

    public override string ToString() => $"bl={Bootloader} tee={Tee} snp={Snp} ucode={Microcode}";
}
