namespace SevSnpDemo.Shared;

/// <summary>Which mechanism produced the evidence, and therefore how the client must verify it.</summary>
public static class EvidenceKinds
{
    /// <summary>
    /// The guest asked the AMD secure processor directly, via <c>/sys/kernel/config/tsm/report</c>, and
    /// chose REPORT_DATA itself. One hop: the hardware signature covers the TLS key.
    /// </summary>
    public const string ConfigFsTsm = "configfs-tsm";

    /// <summary>
    /// Azure paravisor-backed CVM. The guest cannot choose REPORT_DATA, so the binding runs through the
    /// vTPM attestation key in two hops. See <see cref="AttestationDocument"/>.
    /// </summary>
    public const string AzureVtpm = "azure-vtpm";
}

/// <summary>
/// Everything a client needs to decide whether it is talking to code running inside a genuine
/// AMD SEV-SNP confidential VM.
/// </summary>
/// <remarks>
/// <para>
/// Two shapes of evidence, distinguished by <see cref="EvidenceKind"/>. Both establish the same end
/// claim — <em>the private key terminating this TLS connection lives inside a genuine SEV-SNP
/// guest</em> — but they get there differently, because the platform decides whether the guest is
/// allowed to choose REPORT_DATA.
/// </para>
///
/// <para><b><see cref="EvidenceKinds.ConfigFsTsm"/> — one hop.</b> The guest requests the report
/// itself and sets:</para>
/// <code>REPORT_DATA = SHA-512( TLS_SubjectPublicKeyInfo_DER || client_nonce )</code>
/// <para>The AMD signature therefore covers the TLS key directly. Simplest and strongest.</para>
///
/// <para><b><see cref="EvidenceKinds.AzureVtpm"/> — two hops.</b> On Azure CVMs that boot behind the
/// OpenHCL paravisor, the guest has no <c>/dev/sev-guest</c> and cannot influence REPORT_DATA. The
/// paravisor generates the report once at boot with
/// <c>REPORT_DATA = SHA-256(runtime_data) || 32 zero bytes</c>, where <c>runtime_data</c> is a JSON
/// document containing the vTPM's attestation key. The chain becomes:</para>
/// <code>
/// AMD hardware --signs--> SNP report
///                           REPORT_DATA = SHA-256(runtime_data)
///                              |
///                              v
///                         runtime_data JSON  --contains-->  AK public key (JWK, kid "HCLAkPub")
///                                                              |
///                                                              | TPM2_Quote, extraData =
///                                                              |   SHA-256(TLS SPKI || nonce)
///                                                              v
///                                                        this TLS key, freshly
/// </code>
/// <para>
/// The AK's private half is non-exportable and lives in the vTPM bound to this VM, so a relaying
/// attacker cannot produce a quote — they would need an AK that the AMD chain vouches for. The
/// anti-relay property survives; it just takes one more link to establish.
/// </para>
/// <para>
/// A consequence worth stating plainly: under <see cref="EvidenceKinds.AzureVtpm"/> the SNP report
/// itself is <b>static</b> — generated at boot, identical across requests. All freshness comes from
/// the nonce inside the quote. A verifier that checked the report and ignored the quote would accept
/// a replay indefinitely.
/// </para>
///
/// <para>
/// In both cases the client must recompute the binding from the SPKI it observed during its
/// <em>own</em> TLS handshake — never the <see cref="ServerSpki"/> field below, which exists only so a
/// mismatch can be reported usefully. Trusting the server's self-reported key would reduce this whole
/// protocol to decoration: any non-confidential host could replay evidence from an unrelated CVM.
/// </para>
/// </remarks>
public sealed record AttestationDocument
{
    /// <summary>Which mechanism produced this evidence. See <see cref="EvidenceKinds"/>.</summary>
    public required string EvidenceKind { get; init; }

    /// <summary>Raw 1184-byte SEV-SNP attestation report, base64.</summary>
    public required string Report { get; init; }

    /// <summary>VCEK leaf certificate, PEM. Signs <see cref="Report"/>; issued for one specific chip.</summary>
    public required string VcekPem { get; init; }

    /// <summary>ASK and ARK certificates, PEM, concatenated. The client trusts ARK only if it matches its pin.</summary>
    public required string CertChainPem { get; init; }

    /// <summary>
    /// DER-encoded SubjectPublicKeyInfo of the server's TLS key, base64. Diagnostic only — see the
    /// remarks on this type.
    /// </summary>
    public required string ServerSpki { get; init; }

    /// <summary>The nonce the client supplied, echoed back, base64url.</summary>
    public required string Nonce { get; init; }

    /// <summary>Where the certificates came from: "THIM" (Azure host) or "KDS" (AMD). Diagnostic only.</summary>
    public required string CertSource { get; init; }

    // ---------------------------------------------------------------------------------------------
    // Present only when EvidenceKind is azure-vtpm. Null otherwise.
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// The exact <c>runtime_data</c> bytes from the HCL report, base64. The SNP report's REPORT_DATA is
    /// SHA-256 of precisely these bytes, so they must be transmitted verbatim — re-serialising the JSON
    /// would change the hash and break verification.
    /// </summary>
    public string? RuntimeData { get; init; }

    /// <summary>TPMS_ATTEST structure returned by TPM2_Quote, base64.</summary>
    public string? AkQuote { get; init; }

    /// <summary>Raw signature over <see cref="AkQuote"/>, base64.</summary>
    public string? AkQuoteSignature { get; init; }

    /// <summary>
    /// Signature scheme of <see cref="AkQuoteSignature"/>, e.g. <c>rsassa-sha256</c> or
    /// <c>rsapss-sha256</c>. The client will not guess: an unrecognised value is a hard failure.
    /// </summary>
    public string? AkQuoteSigAlg { get; init; }

    /// <summary>
    /// SHA-256 bank PCR values covered by the quote, index → lowercase hex.
    /// </summary>
    /// <remarks>
    /// Untrusted on arrival, and safe to send anyway: the quote carries only <c>pcrDigest</c>, a hash
    /// over these values, and it is inside the AK-signed region. The client recomputes the digest from
    /// these values and compares, so a tampered entry fails the recomputation rather than being
    /// believed. PCR 23 carries the application manifest digest — see the server's
    /// <c>VtpmEvidenceProvider.BindManifest</c> for what that does and does not prove.
    /// </remarks>
    public Dictionary<int, string>? PcrValues { get; init; }
}
