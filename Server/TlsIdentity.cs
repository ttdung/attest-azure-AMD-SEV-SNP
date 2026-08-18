using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SevSnpDemo.Server;

/// <summary>
/// The server's TLS identity, generated inside the confidential VM and never written to disk.
/// </summary>
/// <remarks>
/// Generating in memory is not a stylistic choice — it is what makes the attestation mean anything.
/// A private key that exists on the OS disk can be copied out by the operator and used to terminate
/// TLS on an ordinary machine, which is precisely the claim we are trying to refute. Because the key
/// only ever lives in SEV-SNP-encrypted memory, possession of it is evidence of execution inside the
/// enclave, and the attestation report is what transfers that evidence to the client.
///
/// The certificate is self-signed on purpose. Clients do not validate it against a CA; they validate
/// it against the attestation report, which is a strictly stronger statement than "some CA signed a
/// name". The name below is cosmetic.
/// </remarks>
public sealed class TlsIdentity : IDisposable
{
    private TlsIdentity(X509Certificate2 certificate, byte[] spkiDer)
    {
        Certificate = certificate;
        SpkiDer = spkiDer;
    }

    /// <summary>The certificate Kestrel serves, with its private key.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>DER-encoded SubjectPublicKeyInfo. This is the value bound into REPORT_DATA.</summary>
    public byte[] SpkiDer { get; }

    public static TlsIdentity Generate()
    {
        // P-256 keeps the SPKI small and is universally supported. The curve choice is not
        // security-critical here; the binding is what matters.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var request = new CertificateRequest(
            new X500DistinguishedName("CN=sev-snp-demo-server"),
            key,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, false, 0, critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false)); // serverAuth

        var now = DateTimeOffset.UtcNow;
        var selfSigned = request.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(1));

        // Export the public half in the exact form the client will see it in during the handshake:
        // X509Certificate2.PublicKey.ExportSubjectPublicKeyInfo() is byte-identical on both sides,
        // which is why it is safe to hash and compare.
        var spki = selfSigned.PublicKey.ExportSubjectPublicKeyInfo();

        // On Linux, Kestrel needs the key to be usable from a PKCS#12 round-trip.
        var exportable = X509CertificateLoader.LoadPkcs12(
            selfSigned.Export(X509ContentType.Pfx),
            password: null,
            X509KeyStorageFlags.Exportable);

        selfSigned.Dispose();
        return new TlsIdentity(exportable, spki);
    }

    /// <summary>
    /// REPORT_DATA for a given client nonce: SHA-512(SPKI || nonce).
    /// </summary>
    /// <remarks>
    /// SHA-512 is chosen because its 64-byte output is exactly the size of the SEV-SNP REPORT_DATA
    /// field, so nothing has to be truncated or padded — a padding convention is one more thing the
    /// two sides could disagree about.
    ///
    /// Including the nonce buys freshness. Binding the SPKI alone already defeats relay, but a report
    /// generated once at startup could be arbitrarily old, and the client wants to know the platform
    /// TCB is current *now* rather than whenever the process happened to start.
    /// </remarks>
    public byte[] ComputeReportData(ReadOnlySpan<byte> nonce) => SHA512.HashData(Preimage(nonce));

    /// <summary>
    /// Qualifying data for a TPM2_Quote: SHA-256(SPKI || nonce).
    /// </summary>
    /// <remarks>
    /// The same preimage as <see cref="ComputeReportData"/>, hashed with SHA-256 instead, because a
    /// quote's <c>extraData</c> is conventionally one digest wide and the Azure AK's scheme is
    /// SHA-256-based. Using an identical preimage for both paths means the security argument is the
    /// same sentence in both cases — only the transport of the commitment differs.
    /// </remarks>
    public byte[] ComputeQuoteQualifyingData(ReadOnlySpan<byte> nonce) => SHA256.HashData(Preimage(nonce));

    private byte[] Preimage(ReadOnlySpan<byte> nonce)
    {
        var buffer = new byte[SpkiDer.Length + nonce.Length];
        SpkiDer.CopyTo(buffer.AsSpan());
        nonce.CopyTo(buffer.AsSpan(SpkiDer.Length));
        return buffer;
    }

    public void Dispose() => Certificate.Dispose();
}
