using Tpm2Lib;

namespace SevSnpDemo.Server;

/// <summary>
/// Produces attestation evidence on Azure confidential VMs that boot behind the OpenHCL paravisor,
/// where the guest has no direct SEV-SNP interface.
/// </summary>
/// <remarks>
/// <para>
/// Two artefacts are needed, because the guest cannot choose REPORT_DATA:
/// </para>
/// <list type="number">
/// <item>
/// The <b>HCL report</b> from vTPM NV index <c>0x01400001</c>, containing the SEV-SNP report and the
/// runtime data that names the vTPM attestation key. This is written once at boot and never changes.
/// </item>
/// <item>
/// A fresh <b>TPM2_Quote</b> signed by that AK, whose <c>extraData</c> carries
/// <c>SHA-256(TLS SPKI || client nonce)</c>. This supplies both the binding to the TLS key and the
/// freshness the static report cannot.
/// </item>
/// </list>
/// <para>
/// The AK's private half never leaves the vTPM, and the vTPM belongs to this VM, so possession of a
/// valid quote under an AK that the AMD chain vouches for is what a relaying attacker cannot fake.
/// </para>
/// </remarks>
public sealed class VtpmEvidenceProvider : IDisposable
{
    /// <summary>Azure's NV index holding the HCL attestation report.</summary>
    private const uint NvIndexHclReport = 0x01400001;

    /// <summary>Persistent handle of the AK that Azure provisions in the vTPM.</summary>
    private const uint AkPersistentHandle = 0x81000003;

    /// <summary>
    /// Fallback chunk size if the TPM will not report <c>TPM_PT_NV_BUFFER_MAX</c>.
    /// </summary>
    /// <remarks>
    /// The HCL report is ~2600 bytes, so it always takes several reads and the chunk size genuinely
    /// matters — a value above the TPM's <c>NV_BUFFER_MAX</c> is rejected outright. 512 is the
    /// conservative floor from the TPM 2.0 spec's own minimum requirements.
    /// </remarks>
    private const ushort NvReadChunkFallback = 512;

    /// <summary>
    /// PCR carrying the application manifest digest.
    /// </summary>
    /// <remarks>
    /// 23 is the TCG-designated application-specific PCR, and it is resettable at locality 0 — which is
    /// what lets this process establish it at startup, and also the honest limit of what it proves. See
    /// the class remarks on <see cref="BindManifest"/>.
    /// </remarks>
    private const uint ManifestPcr = 23;

    /// <summary>PCRs included in every quote. 0–7 are boot state; 23 carries the manifest.</summary>
    private static readonly uint[] QuotedPcrs = [0, 1, 2, 3, 4, 5, 6, 7, ManifestPcr];

    private static string DevicePath =>
        Environment.GetEnvironmentVariable("SEVSNP_TPM_DEVICE") is { Length: > 0 } p ? p : "/dev/tpmrm0";

    // The TPM is a single serialised resource and quotes are not fast. One connection, one gate.
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ILogger<VtpmEvidenceProvider> _logger;

    private Tpm2? _tpm;
    private LinuxTpmDevice? _device;
    private HclReport.Parsed? _cachedHcl;
    private string? _manifestBound;

    public VtpmEvidenceProvider(ILogger<VtpmEvidenceProvider> logger) => _logger = logger;

    public sealed record Evidence(
        byte[] SnpReport,
        byte[] RuntimeData,
        byte[] Quote,
        byte[] QuoteSignature,
        string QuoteSigAlg,
        Dictionary<int, string> PcrValues);

    public static bool DeviceExists => File.Exists(DevicePath);

    public sealed record ProbeResult(bool Ok, string Detail);

    /// <summary>
    /// Verifies at startup that the NV index and the AK are both reachable, so a misconfigured VM fails
    /// immediately rather than on every client request.
    /// </summary>
    public ProbeResult Probe()
    {
        if (!DeviceExists)
        {
            return new(false,
                $"{DevicePath} does not exist. Azure CVM attestation needs the vTPM resource manager " +
                "device. Check `ls -l /dev/tpm*` and that the tpm_crb / tpm_tis driver is loaded. " +
                "Override the path with SEVSNP_TPM_DEVICE.");
        }

        try
        {
            var tpm = Connect();

            var nvPublic = tpm.NvReadPublic(new TpmHandle(NvIndexHclReport), out _);
            var akPublic = tpm.ReadPublic(new TpmHandle(AkPersistentHandle), out var akName, out _);
            var hcl = GetHclReport(tpm);
            var manifest = BindManifest(tpm);

            return new(true,
                $"NV 0x{NvIndexHclReport:X8} dataSize={nvPublic.dataSize}, " +
                $"AK 0x{AkPersistentHandle:X8} type={akPublic.type} nameAlg={akPublic.nameAlg} " +
                $"name={Convert.ToHexStringLower(akName)[..16]}…, " +
                $"HCL runtime_data={hcl.RuntimeData.Length} bytes, SNP report bound OK, " +
                $"manifest={manifest}");
        }
        catch (TpmException ex)
        {
            return new(false,
                $"TPM rejected a required command: {ex.Message}. " +
                $"If this is NV_Read on 0x{NvIndexHclReport:X8}, the index may not exist — that index is " +
                "populated only on Azure paravisor-backed CVMs. If it is ReadPublic on " +
                $"0x{AkPersistentHandle:X8}, this image may not pre-provision an AK there; check " +
                "`tpm2_getcap handles-persistent`.");
        }
        catch (Exception ex)
        {
            return new(false, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Reads the (cached) HCL report and produces a fresh quote binding the TLS key and nonce.
    /// </summary>
    /// <param name="qualifyingData">
    /// Exactly 32 bytes: SHA-256(TLS SPKI || nonce). The TPM copies this into the quote's
    /// <c>extraData</c>, which is what the client compares against.
    /// </param>
    public async Task<Evidence> GetEvidenceAsync(byte[] qualifyingData, CancellationToken cancellationToken = default)
    {
        if (qualifyingData.Length != 32)
        {
            throw new ArgumentException(
                $"qualifyingData must be 32 bytes (a SHA-256 digest), got {qualifyingData.Length}.",
                nameof(qualifyingData));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var tpm = Connect();
            var hcl = GetHclReport(tpm);
            BindManifest(tpm);

            // PCRs 0–7 are boot state, reported but not appraised. PCR 23 carries the manifest digest
            // and *is* appraised when the client passes --manifest / --expect-manifest.
            var pcrSelection = new[] { new PcrSelection(TpmAlgId.Sha256, QuotedPcrs) };

            // NullSigScheme tells the TPM to use the key's own signing scheme. Naming a scheme here
            // would fail if Azure provisions the AK with a different one, and the client is told which
            // scheme came back rather than guessing.
            var attest = tpm.Quote(
                new TpmHandle(AkPersistentHandle),
                qualifyingData,
                new NullSigScheme(),
                pcrSelection,
                out var signature);

            var (rawSignature, algorithm) = DescribeSignature(signature);

            // The quote only carries pcrDigest — a hash over the selected PCR values. The client needs
            // the values themselves to recompute it, and sending them is safe: the signed digest is
            // what constrains them, so a tampered value simply fails the recomputation.
            var pcrValues = ReadPcrs(tpm, pcrSelection);

            return new Evidence(
                hcl.SnpReport,
                hcl.RuntimeData,
                attest.GetTpmRepresentation(),
                rawSignature,
                algorithm,
                pcrValues);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Extracts the raw signature bytes and a wire name for the scheme.
    /// </summary>
    /// <remarks>
    /// The scheme is reported rather than assumed. A verifier that guessed PKCS#1 when the TPM actually
    /// used PSS would simply fail, and the failure would look like a compromised key rather than a
    /// mismatched algorithm.
    /// </remarks>
    private static (byte[] Signature, string Algorithm) DescribeSignature(ISignatureUnion signature) =>
        signature switch
        {
            SignatureRsassa rsassa => (rsassa.sig, $"rsassa-{HashName(rsassa.hash)}"),
            SignatureRsapss rsapss => (rsapss.sig, $"rsapss-{HashName(rsapss.hash)}"),
            SignatureEcdsa ecdsa =>
                // TPM ECDSA signatures arrive as separate R and S buffers; concatenating them yields
                // IEEE P1363 form, which is what the client verifies against.
                ([.. ecdsa.signatureR, .. ecdsa.signatureS], $"ecdsa-{HashName(ecdsa.hash)}"),
            _ => throw new NotSupportedException(
                $"The vTPM signed the quote with {signature.GetType().Name}, which this server does not " +
                "know how to describe to a client."),
        };

    private static string HashName(TpmAlgId hash) => hash switch
    {
        TpmAlgId.Sha256 => "sha256",
        TpmAlgId.Sha384 => "sha384",
        TpmAlgId.Sha512 => "sha512",
        _ => throw new NotSupportedException($"Unsupported quote hash algorithm {hash}."),
    };

    private Tpm2 Connect()
    {
        if (_tpm is not null)
        {
            return _tpm;
        }

        _device = new LinuxTpmDevice(DevicePath);
        _device.Connect();
        _tpm = new Tpm2(_device);

        _logger.LogInformation("Connected to vTPM at {Device}.", DevicePath);
        return _tpm;
    }

    /// <summary>
    /// Reads and parses the HCL report, caching it.
    /// </summary>
    /// <remarks>
    /// Caching is correct and not merely an optimisation: the paravisor writes this NV index once
    /// during boot and it is immutable thereafter. Re-reading it per request would cost several TPM
    /// round trips to obtain identical bytes. Freshness lives entirely in the quote.
    /// </remarks>
    private HclReport.Parsed GetHclReport(Tpm2 tpm)
    {
        if (_cachedHcl is not null)
        {
            return _cachedHcl;
        }

        var nvPublic = tpm.NvReadPublic(new TpmHandle(NvIndexHclReport), out _);
        var buffer = new byte[nvPublic.dataSize];
        var maxChunk = ReadNvBufferMax(tpm);

        // The index's attributes include TPMA_NV_OWNERREAD, so owner authorisation with an empty
        // password is the right way in. (TPMA_NV_AUTHREAD is also set, which would allow reading with
        // the index's own auth value instead.)
        var authHandle = new TpmHandle(TpmRh.Owner);

        for (ushort read = 0; read < nvPublic.dataSize;)
        {
            var chunk = (ushort)Math.Min(maxChunk, nvPublic.dataSize - read);
            var part = tpm.NvRead(authHandle, new TpmHandle(NvIndexHclReport), chunk, read);

            if (part.Length == 0)
            {
                throw new InvalidDataException(
                    $"NV_Read returned 0 bytes at offset {read} of {nvPublic.dataSize}; cannot make " +
                    "progress. Checked before copying so a misbehaving TPM cannot spin this loop.");
            }

            part.CopyTo(buffer, read);
            read += (ushort)part.Length;
        }

        _cachedHcl = HclReport.Parse(buffer);

        _logger.LogInformation(
            "HCL report parsed: {ReportBytes}-byte SNP report, {RuntimeBytes}-byte runtime data, " +
            "REPORT_DATA binding verified.",
            _cachedHcl.SnpReport.Length,
            _cachedHcl.RuntimeData.Length);

        return _cachedHcl;
    }

    /// <summary>
    /// Establishes the workload identity in PCR 23, once, at startup.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>PCR_Reset(23)</c> then <c>PCR_Extend(23, manifestDigest)</c>, so the resulting value is
    /// <c>SHA-256(0^32 || manifestDigest)</c> — which the client recomputes from its own copy of the
    /// manifest. The quote covers PCR 23, and the AK signing that quote is endorsed by the SNP report,
    /// so the chain reaches from AMD hardware to "this workload declared manifest X".
    /// </para>
    /// <para>
    /// <b>What this is not.</b> It is not <c>HOST_DATA</c>, and it is weaker in a specific way worth
    /// naming. <c>HOST_DATA</c> is fixed by the hypervisor at <c>SNP_LAUNCH_FINISH</c> and is immutable
    /// for the VM's lifetime — nothing inside the guest, at any privilege, can change it. PCR 23 is
    /// resettable at locality 0, so <b>root inside this guest can reset and re-extend it with a
    /// different digest</b>.
    /// </para>
    /// <para>
    /// So this defends against a <em>dishonest host</em> (the confidential-computing threat model: the
    /// host cannot forge a quote, because the AK lives in vTPM memory the host cannot read) but not
    /// against a <em>compromised guest userland</em>. It raises the bar from "nothing identifies the
    /// workload" to "the workload's own claim is hardware-endorsed", and it is the strongest binding
    /// available on a platform that does not expose <c>HOST_DATA</c>. Do not describe it to a relying
    /// party as equivalent to a launch-time measurement.
    /// </para>
    /// <para>
    /// Bound once here rather than per request: a reset concurrent with an in-flight quote would race,
    /// and re-extending per request would produce a different PCR value every time.
    /// </para>
    /// </remarks>
    private string BindManifest(Tpm2 tpm)
    {
        if (_manifestBound is not null)
        {
            return _manifestBound;
        }

        var digest = AppManifest.Resolve();

        if (digest is null)
        {
            _manifestBound = "not configured (PCR 23 left as found; clients cannot appraise workload identity)";
            _logger.LogWarning(
                "No SEVSNP_MANIFEST configured. PCR 23 will be reported but carries no workload " +
                "identity, so --expect-manifest cannot succeed.");
            return _manifestBound;
        }

        var pcrHandle = new TpmHandle(ManifestPcr);

        try
        {
            tpm.PcrReset(pcrHandle);
        }
        catch (TpmException ex)
        {
            throw new InvalidOperationException(
                $"PCR_Reset({ManifestPcr}) failed: {ex.Message}. PCR {ManifestPcr} should be resettable " +
                "at locality 0; if this vTPM disallows it, pick an unused resettable PCR or bind the " +
                "manifest at launch via HOST_DATA instead.", ex);
        }

        // Confirm the reset actually zeroed the PCR *before* extending. PCR_Reset can return success
        // without having any effect, and distinguishing "reset was a no-op" from "extend produced an
        // unexpected value" after the fact is guesswork — the post-extend value is consistent with
        // either. Checking here makes each failure name itself.
        var afterReset = ReadPcrs(tpm, [new PcrSelection(TpmAlgId.Sha256, [ManifestPcr])])[(int)ManifestPcr];
        var zero = Convert.ToHexStringLower(new byte[System.Security.Cryptography.SHA256.HashSizeInBytes]);

        if (!string.Equals(afterReset, zero, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"PCR_Reset({ManifestPcr}) reported success but the PCR reads {afterReset}, not zero. " +
                "This vTPM does not honour the reset, so clients cannot recompute the expected value. " +
                "Pick a different resettable PCR, or bind the manifest at launch via HOST_DATA.");
        }

        // TpmHash.FromData would HASH this argument (its parameter is named dataToHash), extending
        // SHA-256(digest) instead of digest. The two-argument constructor takes the digest verbatim,
        // which is what PCR_Extend expects and what the client recomputes.
        tpm.PcrExtend(pcrHandle, [new TpmHash(TpmAlgId.Sha256, digest)]);

        var expected = ExpectedManifestPcr(digest);
        var actual = ReadPcrs(tpm, [new PcrSelection(TpmAlgId.Sha256, [ManifestPcr])])[(int)ManifestPcr];

        if (!string.Equals(actual, Convert.ToHexStringLower(expected), StringComparison.Ordinal))
        {
            // The PCR was verified zero a moment ago, so this means the extend itself disagreed with
            // SHA-256(0^32 || digest) — a different bank, or a digest that is not what we think it is.
            throw new InvalidOperationException(
                $"PCR {ManifestPcr} reads {actual} after extending with manifest digest " +
                $"{Convert.ToHexStringLower(digest)}, but SHA-256(0^32 || digest) is " +
                $"{Convert.ToHexStringLower(expected)}. The PCR was confirmed zero before the extend, so " +
                "this is a mismatch in the extend itself rather than a failed reset.");
        }

        _manifestBound = $"PCR{ManifestPcr}=SHA-256(0^32||{Convert.ToHexStringLower(digest)[..16]}…)";

        _logger.LogInformation(
            "Manifest bound: digest {Digest}, PCR {Pcr} = {Value}",
            Convert.ToHexStringLower(digest),
            ManifestPcr,
            actual);

        return _manifestBound;
    }

    /// <summary>The PCR value a client should expect after a reset-then-extend with this digest.</summary>
    /// <remarks>
    /// PCR_Extend computes <c>PCR = H(PCR_old || digest)</c>, and after a reset <c>PCR_old</c> is all
    /// zeroes. The digest is used <em>verbatim</em> — a version of this that hashed the manifest digest
    /// again would produce a value no client could reproduce, which is exactly the bug that shipped
    /// once here (see the note at the PcrExtend call).
    /// </remarks>
    public static byte[] ExpectedManifestPcr(byte[] manifestDigest) =>
        System.Security.Cryptography.SHA256.HashData(
            [.. new byte[System.Security.Cryptography.SHA256.HashSizeInBytes], .. manifestDigest]);

    /// <summary>Reads the selected PCRs, returning index → lowercase hex.</summary>
    /// <remarks>
    /// PCR_Read may return fewer PCRs than requested when the response would exceed the TPM's buffer,
    /// so this loops on the reported selection until every requested index has a value rather than
    /// assuming one call suffices.
    /// </remarks>
    private static Dictionary<int, string> ReadPcrs(Tpm2 tpm, PcrSelection[] selection)
    {
        var wanted = selection.SelectMany(s => s.GetSelectedPcrs()).Distinct().OrderBy(i => i).ToList();
        var values = new Dictionary<int, string>();
        var remaining = new PcrSelection(TpmAlgId.Sha256, wanted.Select(i => i));

        while (values.Count < wanted.Count)
        {
            tpm.PcrRead([remaining], out var returnedSelection, out var returnedValues);

            var returnedIndices = returnedSelection.SelectMany(s => s.GetSelectedPcrs())
                .OrderBy(i => i)
                .ToList();

            if (returnedIndices.Count == 0)
            {
                throw new InvalidDataException(
                    $"PCR_Read returned no PCRs for selection {string.Join(",", wanted)}; cannot make " +
                    "progress.");
            }

            for (var i = 0; i < returnedIndices.Count && i < returnedValues.Length; i++)
            {
                values[(int)returnedIndices[i]] = Convert.ToHexStringLower(returnedValues[i].buffer);
            }

            var stillMissing = wanted.Where(i => !values.ContainsKey((int)i)).ToList();
            if (stillMissing.Count == 0)
            {
                break;
            }

            remaining = new PcrSelection(TpmAlgId.Sha256, stillMissing.Select(i => i));
        }

        return values;
    }

    /// <summary>
    /// Asks the TPM how large a single NV_Read may be, rather than assuming.
    /// </summary>
    /// <remarks>
    /// A chunk larger than <c>TPM_PT_NV_BUFFER_MAX</c> is rejected with a value error, and the HCL
    /// report is far too big for one read, so guessing here would break on any TPM with a smaller
    /// buffer than the guess. Falls back to a conservative 512 if the property is unavailable.
    /// </remarks>
    private ushort ReadNvBufferMax(Tpm2 tpm)
    {
        try
        {
            tpm.GetCapability(Cap.TpmProperties, (uint)Pt.NvBufferMax, 1, out var capability);

            if (capability is TaggedTpmPropertyArray { tpmProperty: [{ } property] } &&
                property.property == Pt.NvBufferMax &&
                property.value is > 0 and <= ushort.MaxValue)
            {
                _logger.LogInformation("TPM NV_BUFFER_MAX = {Max} bytes.", property.value);
                return (ushort)property.value;
            }
        }
        catch (TpmException ex)
        {
            _logger.LogWarning(
                "Could not read TPM_PT_NV_BUFFER_MAX ({Reason}); using {Fallback}-byte reads.",
                ex.Message,
                NvReadChunkFallback);
        }

        return NvReadChunkFallback;
    }

    public void Dispose()
    {
        _tpm?.Dispose();
        _device?.Dispose();
        _gate.Dispose();
    }
}
