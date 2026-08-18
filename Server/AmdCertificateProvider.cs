using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;

namespace SevSnpDemo.Server;

/// <summary>
/// Obtains the VCEK leaf certificate and the ASK/ARK chain needed to verify an attestation report.
/// </summary>
/// <remarks>
/// Two sources, in order of preference:
///
/// 1. <b>Azure THIM</b> via IMDS. The host caches AMD's certificates and serves them on the instance
///    metadata endpoint. This is what Azure recommends and it avoids AMD's rate limits entirely.
/// 2. <b>AMD KDS</b> directly. Correct anywhere, but aggressively rate-limited — a handful of requests
///    per chip per minute. Fine as a fallback, not as a hot path.
///
/// Neither source is trusted. These certificates are just transport; the client independently verifies
/// the chain terminates at the AMD root key it has pinned out-of-band, so a hostile THIM or a hijacked
/// KDS response can only cause verification to fail, never to falsely succeed.
/// </remarks>
public sealed class AmdCertificateProvider(HttpClient httpClient, ILogger<AmdCertificateProvider> logger)
{
    private const string ThimUrl = "http://169.254.169.254/metadata/THIM/amd/certification";
    private const string KdsBase = "https://kdsintf.amd.com/vcek/v1";

    /// <summary>
    /// AMD product line, used only for the KDS fallback URL. Azure DCasv5/ECasv5 are Milan;
    /// newer v6 SKUs are Genoa or Turin. Override with SEVSNP_AMD_PRODUCT.
    /// </summary>
    private static string Product =>
        Environment.GetEnvironmentVariable("SEVSNP_AMD_PRODUCT") is { Length: > 0 } p ? p : "Milan";

    public sealed record CertificateBundle(string VcekPem, string ChainPem, string Source);

    private CertificateBundle? _cached;

    /// <summary>
    /// Fetches the certificate bundle, caching it for the process lifetime.
    /// </summary>
    /// <remarks>
    /// Caching is safe because the VCEK is bound to the chip and the reported TCB, neither of which
    /// changes while the VM is running. A host TCB update requires a reboot, which restarts this
    /// process — so a stale cache is not reachable.
    /// </remarks>
    public async Task<CertificateBundle> GetAsync(
        ReadOnlyMemory<byte> chipId,
        TcbSpl reportedTcb,
        CancellationToken cancellationToken = default)
    {
        if (_cached is not null)
        {
            return _cached;
        }

        try
        {
            _cached = await FetchFromThimAsync(cancellationToken).ConfigureAwait(false);
            logger.LogInformation("Fetched AMD certificates from Azure THIM.");
            return _cached;
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                "THIM unavailable ({Reason}); falling back to AMD KDS. Expect rate limiting.",
                ex.Message);
        }

        _cached = await FetchFromKdsAsync(chipId, reportedTcb, cancellationToken).ConfigureAwait(false);
        logger.LogInformation("Fetched AMD certificates from KDS ({Product}).", Product);
        return _cached;
    }

    private sealed record ThimResponse(
        [property: JsonPropertyName("vcekCert")] string? VcekCert,
        [property: JsonPropertyName("certificateChain")] string? CertificateChain);

    private async Task<CertificateBundle> FetchFromThimAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, ThimUrl);
        request.Headers.Add("Metadata", "true");

        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<ThimResponse>(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("THIM returned an empty body.");

        if (string.IsNullOrWhiteSpace(body.VcekCert) || string.IsNullOrWhiteSpace(body.CertificateChain))
        {
            throw new InvalidDataException("THIM response lacked vcekCert or certificateChain.");
        }

        return new CertificateBundle(body.VcekCert.Trim(), body.CertificateChain.Trim(), "THIM");
    }

    private async Task<CertificateBundle> FetchFromKdsAsync(
        ReadOnlyMemory<byte> chipId,
        TcbSpl tcb,
        CancellationToken cancellationToken)
    {
        var chipIdHex = Convert.ToHexStringLower(chipId.Span);

        var vcekUrl =
            $"{KdsBase}/{Product}/{chipIdHex}" +
            $"?blSPL={tcb.Bootloader:D2}&teeSPL={tcb.Tee:D2}&snpSPL={tcb.Snp:D2}&ucodeSPL={tcb.Microcode:D2}";

        // KDS serves the leaf as raw DER and the chain as PEM.
        var vcekDer = await httpClient.GetByteArrayAsync(vcekUrl, cancellationToken).ConfigureAwait(false);
        var chainPem = await httpClient.GetStringAsync($"{KdsBase}/{Product}/cert_chain", cancellationToken)
            .ConfigureAwait(false);

        using var vcek = X509CertificateLoader.LoadCertificate(vcekDer);
        return new CertificateBundle(ToPem(vcek), chainPem.Trim(), "KDS");
    }

    private static string ToPem(X509Certificate2 certificate)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN CERTIFICATE-----");
        builder.AppendLine(Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END CERTIFICATE-----");
        return builder.ToString();
    }
}

/// <summary>
/// The four security-patch levels packed into a SEV-SNP TCB_VERSION, as needed for the KDS URL.
/// </summary>
public readonly record struct TcbSpl(byte Bootloader, byte Tee, byte Snp, byte Microcode)
{
    /// <summary>
    /// Unpacks a little-endian TCB_VERSION quadword.
    /// </summary>
    /// <remarks>
    /// Layout per the SEV-SNP ABI: BOOTLOADER in bits 7:0, TEE in 15:8, SNP in 55:48,
    /// MICROCODE in 63:56, with bits 47:16 reserved.
    /// </remarks>
    public static TcbSpl FromRaw(ReadOnlySpan<byte> eightBytes) => new(
        Bootloader: eightBytes[0],
        Tee: eightBytes[1],
        Snp: eightBytes[6],
        Microcode: eightBytes[7]);
}
