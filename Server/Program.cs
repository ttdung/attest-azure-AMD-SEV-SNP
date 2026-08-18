using System.Buffers.Text;
using SevSnpDemo.Server;
using SevSnpDemo.Shared;

// ---------------------------------------------------------------------------------------------
// SEV-SNP attested "Hello" server.
//
// Serves two endpoints:
//   GET /hello                    -> "Hello"
//   GET /attestation?nonce=<b64u> -> attestation evidence binding this server's TLS key
//
// Two ways to obtain that evidence, selected at startup:
//
//   configfs-tsm   The guest asks the AMD secure processor directly and chooses REPORT_DATA. One hop.
//                  Available on bare SEV-SNP guests with Linux 6.7+ and CONFIG_TSM_REPORTS.
//
//   azure-vtpm     Azure CVMs behind the OpenHCL paravisor have no /dev/sev-guest and cannot choose
//                  REPORT_DATA. Evidence is the boot-time HCL report from vTPM NV 0x01400001 plus a
//                  fresh TPM2_Quote from the vTPM AK. Two hops.
//
// Must run inside an AMD SEV-SNP guest either way. It refuses to start otherwise rather than falling
// back to something that looks like it works — a demo that silently serves unattested traffic teaches
// exactly the wrong lesson.
// ---------------------------------------------------------------------------------------------

const int MinNonceBytes = 16;
const int MaxNonceBytes = 64;

var builder = WebApplication.CreateBuilder(args);

var port = int.TryParse(Environment.GetEnvironmentVariable("SEVSNP_PORT"), out var configured)
    ? configured
    : 8443;

// The TLS key is generated here, in enclave memory, and never persisted. See TlsIdentity.
var tlsIdentity = TlsIdentity.Generate();

builder.Services.AddSingleton(tlsIdentity);
builder.Services.AddSingleton<SnpReportProvider>();
builder.Services.AddSingleton<VtpmEvidenceProvider>();
builder.Services.AddHttpClient<AmdCertificateProvider>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(15);
});

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(port, listen => listen.UseHttps(tlsIdentity.Certificate));
});

var app = builder.Build();
var logger = app.Services.GetRequiredService<ILogger<Program>>();

// --- Choose an evidence source, or refuse to start ---------------------------------------------

// SEVSNP_EVIDENCE forces a path: "configfs" or "vtpm". Unset means auto-detect, preferring
// configfs-tsm because it binds the TLS key in a single hardware-signed hop.
var requested = Environment.GetEnvironmentVariable("SEVSNP_EVIDENCE")?.Trim().ToLowerInvariant();

var configFsProbe = requested is null or "configfs" ? SnpReportProvider.Probe() : null;
var vtpmProbe = requested is null or "vtpm"
    ? app.Services.GetRequiredService<VtpmEvidenceProvider>().Probe()
    : null;

string evidenceKind;

if (configFsProbe is { Ok: true })
{
    evidenceKind = EvidenceKinds.ConfigFsTsm;
    logger.LogInformation("Evidence source: configfs-tsm (direct). {Detail}", configFsProbe.Detail);
}
else if (vtpmProbe is { Ok: true })
{
    evidenceKind = EvidenceKinds.AzureVtpm;
    logger.LogInformation("Evidence source: azure-vtpm (paravisor). {Detail}", vtpmProbe.Detail);
    logger.LogInformation(
        "The SNP report is static on this platform (written at boot). Freshness and the TLS-key " +
        "binding come from the TPM2_Quote, not the report.");
}
else
{
    logger.LogCritical(
        "No usable attestation evidence source.\n" +
        "  configfs-tsm : {ConfigFs}\n" +
        "  azure-vtpm   : {Vtpm}\n" +
        "Refusing to start — an unattested server would defeat the point of this demo.",
        configFsProbe?.Detail ?? "(not attempted; SEVSNP_EVIDENCE forced vtpm)",
        vtpmProbe?.Detail ?? "(not attempted; SEVSNP_EVIDENCE forced configfs)");
    return 1;
}

logger.LogInformation(
    "TLS SPKI SHA-256: {Pin}",
    Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(tlsIdentity.SpkiDer)));

// --- Endpoints --------------------------------------------------------------------------------

app.MapGet("/hello", () => Results.Text("Hello"));

app.MapGet("/attestation", async (
    string? nonce,
    TlsIdentity identity,
    SnpReportProvider configFsReports,
    VtpmEvidenceProvider vtpmEvidence,
    AmdCertificateProvider certificates,
    ILogger<Program> log,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(nonce))
    {
        return Results.BadRequest(new { error = "Missing 'nonce' query parameter (base64url)." });
    }

    byte[] nonceBytes;
    try
    {
        nonceBytes = Base64Url.DecodeFromChars(nonce);
    }
    catch (FormatException)
    {
        return Results.BadRequest(new { error = "'nonce' is not valid base64url." });
    }

    if (nonceBytes.Length is < MinNonceBytes or > MaxNonceBytes)
    {
        return Results.BadRequest(new
        {
            error = $"'nonce' must decode to {MinNonceBytes}-{MaxNonceBytes} bytes, got {nonceBytes.Length}."
        });
    }

    byte[] snpReport;
    string? runtimeData = null;
    string? quote = null;
    string? quoteSignature = null;
    string? quoteSigAlg = null;
    Dictionary<int, string>? pcrValues = null;

    try
    {
        if (evidenceKind == EvidenceKinds.ConfigFsTsm)
        {
            // The binding. REPORT_DATA = SHA-512(TLS SPKI || nonce), signed by the AMD secure processor.
            snpReport = await configFsReports
                .GetReportAsync(identity.ComputeReportData(nonceBytes), cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            // The binding lives in the quote instead: extraData = SHA-256(TLS SPKI || nonce), signed by
            // the vTPM AK, which the (static) SNP report vouches for via the runtime data.
            var evidence = await vtpmEvidence
                .GetEvidenceAsync(identity.ComputeQuoteQualifyingData(nonceBytes), cancellationToken)
                .ConfigureAwait(false);

            snpReport = evidence.SnpReport;
            runtimeData = Convert.ToBase64String(evidence.RuntimeData);
            quote = Convert.ToBase64String(evidence.Quote);
            quoteSignature = Convert.ToBase64String(evidence.QuoteSignature);
            quoteSigAlg = evidence.QuoteSigAlg;
            pcrValues = evidence.PcrValues;
        }
    }
    catch (Exception ex)
    {
        log.LogError(ex, "Failed to obtain SEV-SNP attestation evidence ({Kind}).", evidenceKind);

        // The detail is the platform's own error. It leaks nothing secret — everything in it is
        // readable by anyone with a shell on the box — and without it a remote operator is left
        // guessing at a bare 503.
        return Results.Problem(
            $"Could not obtain attestation evidence via {evidenceKind}. {ex.Message}",
            statusCode: 503);
    }

    // CHIP_ID at 0x1A0 (64 bytes) and REPORTED_TCB at 0x180 (8 bytes) are only needed to build the
    // AMD KDS fallback URL; THIM does not require them.
    var chipId = snpReport.AsMemory(0x1A0, 64);
    var reportedTcb = TcbSpl.FromRaw(snpReport.AsSpan(0x180, 8));

    AmdCertificateProvider.CertificateBundle bundle;
    try
    {
        bundle = await certificates.GetAsync(chipId, reportedTcb, cancellationToken).ConfigureAwait(false);
    }
    catch (Exception ex)
    {
        log.LogError(ex, "Failed to obtain AMD certificates.");
        return Results.Problem($"Could not obtain the AMD certificate chain. {ex.Message}", statusCode: 503);
    }

    return Results.Json(new AttestationDocument
    {
        EvidenceKind = evidenceKind,
        Report = Convert.ToBase64String(snpReport),
        VcekPem = bundle.VcekPem,
        CertChainPem = bundle.ChainPem,
        ServerSpki = Convert.ToBase64String(identity.SpkiDer),
        Nonce = nonce,
        CertSource = bundle.Source,
        RuntimeData = runtimeData,
        AkQuote = quote,
        AkQuoteSignature = quoteSignature,
        AkQuoteSigAlg = quoteSigAlg,
        PcrValues = pcrValues,
    });
});

logger.LogInformation("Listening on https://0.0.0.0:{Port} (self-signed; verified via attestation)", port);
app.Run();

return 0;
