using System.Buffers.Text;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SevSnpDemo.Client;
using SevSnpDemo.Shared;

// ---------------------------------------------------------------------------------------------
// SEV-SNP attesting client.
//
//   1. TLS-connect to the server, capturing the certificate it actually presents
//   2. GET /attestation?nonce=<fresh>  and verify the evidence against a pinned AMD root
//   3. Only if every check passes, GET /hello over the same (now-attested) connection
//
// The TLS certificate is deliberately not validated against any CA. It is self-signed, and its
// trustworthiness is established by the attestation report instead — a strictly stronger claim than
// "a CA signed this name".
// ---------------------------------------------------------------------------------------------

var options = CommandLine.Parse(args);
if (options is null)
{
    CommandLine.PrintUsage();
    return 2;
}

// --- Trust anchor -----------------------------------------------------------------------------

if (!File.Exists(options.ArkPath))
{
    Console.Error.WriteLine($$"""
        Trust anchor not found: {{options.ArkPath}}

        This client will not fetch the AMD root at verification time — doing so from the network
        would not be pinning. Establish it once, out of band:

            curl -sO https://kdsintf.amd.com/vcek/v1/{{options.Product}}/cert_chain
            # cert_chain contains ASK then ARK. Extract the second (self-signed root):
            openssl crl2pkcs7 -nocrl -certfile cert_chain \
              | openssl pkcs7 -print_certs -outform PEM \
              | awk '/BEGIN/{n++} n==2' > {{options.ArkPath}}
            openssl x509 -in {{options.ArkPath}} -noout -subject -fingerprint -sha384

        Then compare the fingerprint against AMD's published value before trusting it.
        """);
    return 2;
}

X509Certificate2 pinnedArk;
try
{
    pinnedArk = X509CertificateLoader.LoadCertificateFromFile(options.ArkPath);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Could not load the trust anchor: {ex.Message}");
    return 2;
}

Console.WriteLine($"Trust anchor : {pinnedArk.Subject}");
Console.WriteLine($"  SHA-256    : {Convert.ToHexStringLower(SHA256.HashData(pinnedArk.RawData))}");
Console.WriteLine();

// --- TLS with certificate capture -------------------------------------------------------------

X509Certificate2? observedCertificate = null;

using var handler = new HttpClientHandler
{
    // Intentional: accept any certificate, then decide via attestation. Capturing the certificate
    // here is what lets us bind the report to *this* connection.
    ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
    {
        if (certificate is not null)
        {
            observedCertificate = X509CertificateLoader.LoadCertificate(certificate.RawData);
        }

        return true;
    },
};

using var http = new HttpClient(handler) { BaseAddress = new Uri(options.BaseUrl), Timeout = TimeSpan.FromSeconds(30) };

// --- Fetch evidence ---------------------------------------------------------------------------

var nonce = RandomNumberGenerator.GetBytes(32);
var nonceB64Url = Base64Url.EncodeToString(nonce);

Console.WriteLine($"Nonce        : {nonceB64Url}");

AttestationDocument? document;
try
{
    // Deliberately not GetFromJsonAsync: it throws on a non-2xx status and discards the body, which
    // is exactly where the server puts the reason it could not attest. Losing that detail turns a
    // one-line diagnosis into a round trip with curl.
    using var response = await http.GetAsync($"/attestation?nonce={nonceB64Url}");
    var body = await response.Content.ReadAsStringAsync();

    if (!response.IsSuccessStatusCode)
    {
        Console.Error.WriteLine($"Server refused to attest: HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
        Console.Error.WriteLine(ExtractDetail(body));
        return 1;
    }

    document = System.Text.Json.JsonSerializer.Deserialize<AttestationDocument>(
        body,
        new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed to fetch attestation evidence: {ex.Message}");
    return 1;
}

if (document is null)
{
    Console.Error.WriteLine("Server returned an empty attestation document.");
    return 1;
}

if (observedCertificate is null)
{
    Console.Error.WriteLine("No TLS certificate was captured — cannot bind the report to this channel.");
    return 1;
}

var observedSpki = observedCertificate.PublicKey.ExportSubjectPublicKeyInfo();

Console.WriteLine($"TLS SPKI pin : {Convert.ToHexStringLower(SHA256.HashData(observedSpki))}");
Console.WriteLine($"Cert source  : {document.CertSource}");
Console.WriteLine();

// --- Verify -----------------------------------------------------------------------------------

var policy = new AttestationPolicy
{
    MinimumTcb = options.MinimumTcb,
    AllowedMeasurements = options.ExpectedMeasurement is null ? [] : [options.ExpectedMeasurement],
    RequireSmtDisabled = options.RequireSmtDisabled,
    ExpectedHostData = options.ExpectedHostData,
    ExpectedManifestPcr = options.ManifestDigest is null
        ? null
        : SHA256.HashData([.. new byte[SHA256.HashSizeInBytes], .. options.ManifestDigest]),
};

var outcome = AttestationVerifier.Verify(document, observedSpki, nonce, pinnedArk, policy);

Console.WriteLine("Verification");
Console.WriteLine("────────────");
foreach (var step in outcome.Steps)
{
    Console.WriteLine($"  [{(step.Passed ? "PASS" : "FAIL")}] {step.Name}");
    Console.WriteLine($"         {step.Detail}");
}

Console.WriteLine();

if (outcome.Report is { } report)
{
    Console.WriteLine("Report");
    Console.WriteLine("──────");
    Console.WriteLine($"  Version        : {report.Version}");
    // VMPL is the privilege level of whoever *requested* the report, not of the code answering you.
    // On an Azure paravisor CVM this reads 0 because the paravisor itself requested it at VMPL0 —
    // which is precisely why the guest cannot choose REPORT_DATA and the vTPM path exists. Reading 0
    // here is therefore not evidence that your code runs at VMPL0.
    Console.WriteLine($"  VMPL           : {report.Vmpl}   (level of the requester; 0 on Azure = the paravisor asked, not the guest)");
    Console.WriteLine($"  Guest SVN      : {report.GuestSvn}");
    Console.WriteLine($"  Policy         : ABI {report.PolicyAbiMajor}.{report.PolicyAbiMinor}, " +
                      $"debug={report.PolicyDebugAllowed}, smt={report.PolicySmtAllowed}, " +
                      $"migrate_ma={report.PolicyMigrateMaAllowed}");
    Console.WriteLine($"  Platform       : smt_en={report.PlatformSmtEnabled}, tsme_en={report.PlatformTsmeEnabled}");
    Console.WriteLine($"  Current TCB    : {report.CurrentTcb}");
    Console.WriteLine($"  Reported TCB   : {report.ReportedTcb}");
    Console.WriteLine($"  Committed TCB  : {report.CommittedTcb}");
    Console.WriteLine($"  Launch TCB     : {report.LaunchTcb}");
    Console.WriteLine($"  Measurement    : {Convert.ToHexStringLower(report.Measurement)}");
    Console.WriteLine($"  Host data      : {Convert.ToHexStringLower(report.HostData)}");
    Console.WriteLine($"  Chip ID        : {Convert.ToHexStringLower(report.ChipId)[..32]}…");
    Console.WriteLine();
}

if (!outcome.Trusted)
{
    Console.Error.WriteLine("ATTESTATION FAILED — not sending the application request.");
    foreach (var failure in outcome.Failures)
    {
        Console.Error.WriteLine($"  - {failure.Name}: {failure.Detail}");
    }

    return 1;
}

// --- Application traffic, over the now-attested channel ---------------------------------------

var greeting = await http.GetStringAsync("/hello");

Console.WriteLine("ATTESTATION OK");
Console.WriteLine($"  GET /hello -> {greeting}");

if (options.ExpectedMeasurement is null)
{
    Console.WriteLine();
    Console.WriteLine(
        "Note: no --expect-measurement was supplied, so this run proves the server sits in a genuine\n" +
        "      SEV-SNP VM but says nothing about which code is running there. See README §What this\n" +
        "      does and does not prove.");
}

return 0;

// ---------------------------------------------------------------------------------------------

/// <summary>Pulls the human-readable reason out of an RFC 9457 problem+json body, or echoes it raw.</summary>
static string ExtractDetail(string body)
{
    if (string.IsNullOrWhiteSpace(body))
    {
        return "  (empty response body)";
    }

    try
    {
        using var json = System.Text.Json.JsonDocument.Parse(body);
        if (json.RootElement.TryGetProperty("detail", out var detail) &&
            detail.GetString() is { Length: > 0 } text)
        {
            return $"  {text}";
        }
    }
    catch (System.Text.Json.JsonException)
    {
        // Not problem+json; fall through and show whatever came back.
    }

    return $"  {body.Trim()}";
}

internal sealed record ClientOptions(
    string BaseUrl,
    string ArkPath,
    string Product,
    byte[]? ExpectedMeasurement,
    TcbVersion? MinimumTcb,
    bool RequireSmtDisabled,
    byte[]? ExpectedHostData,
    byte[]? ManifestDigest);

internal static class CommandLine
{
    public static ClientOptions? Parse(string[] args)
    {
        var url = "https://localhost:8443";
        var ark = Path.Combine("amd", "ark.pem");
        var product = "Milan";
        byte[]? measurement = null;
        TcbVersion? minimumTcb = null;
        var requireSmtDisabled = false;
        byte[]? hostData = null;
        byte[]? manifestDigest = null;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--url" when i + 1 < args.Length:
                    url = args[++i];
                    break;

                case "--ark" when i + 1 < args.Length:
                    ark = args[++i];
                    break;

                case "--product" when i + 1 < args.Length:
                    product = args[++i];
                    break;

                case "--expect-measurement" when i + 1 < args.Length:
                    try
                    {
                        measurement = Convert.FromHexString(args[++i]);
                    }
                    catch (FormatException)
                    {
                        Console.Error.WriteLine("--expect-measurement must be hex.");
                        return null;
                    }

                    if (measurement.Length != 48)
                    {
                        Console.Error.WriteLine($"--expect-measurement must be 48 bytes (96 hex chars), got {measurement.Length}.");
                        return null;
                    }

                    break;

                case "--min-tcb" when i + 1 < args.Length:
                    var parts = args[++i].Split(',');
                    if (parts.Length != 4 || !parts.All(p => byte.TryParse(p, out _)))
                    {
                        Console.Error.WriteLine("--min-tcb expects four bytes: bootloader,tee,snp,microcode");
                        return null;
                    }

                    minimumTcb = new TcbVersion(
                        byte.Parse(parts[0]), byte.Parse(parts[1]), byte.Parse(parts[2]), byte.Parse(parts[3]));
                    break;

                case "--require-smt-disabled":
                    requireSmtDisabled = true;
                    break;

                case "--expect-host-data" when i + 1 < args.Length:
                    if (!TryParseDigest(args[++i], 32, "--expect-host-data", out hostData))
                    {
                        return null;
                    }

                    break;

                case "--manifest" when i + 1 < args.Length:
                    // Hashed here, from the client's own copy. Taking the digest from the server would
                    // let the server pick what it is measured against, which is no check at all.
                    var manifestPath = args[++i];
                    if (!File.Exists(manifestPath))
                    {
                        Console.Error.WriteLine($"--manifest file not found: {manifestPath}");
                        return null;
                    }

                    manifestDigest = System.Security.Cryptography.SHA256.HashData(
                        File.ReadAllBytes(manifestPath));
                    break;

                case "--expect-manifest" when i + 1 < args.Length:
                    if (!TryParseDigest(args[++i], 32, "--expect-manifest", out manifestDigest))
                    {
                        return null;
                    }

                    break;

                case "-h":
                case "--help":
                    return null;

                default:
                    Console.Error.WriteLine($"Unknown argument: {args[i]}");
                    return null;
            }
        }

        return new ClientOptions(
            url, ark, product, measurement, minimumTcb, requireSmtDisabled, hostData, manifestDigest);
    }

    private static bool TryParseDigest(string value, int expectedLength, string flag, out byte[]? digest)
    {
        digest = null;

        try
        {
            digest = Convert.FromHexString(value);
        }
        catch (FormatException)
        {
            Console.Error.WriteLine($"{flag} must be hex.");
            return false;
        }

        if (digest.Length != expectedLength)
        {
            Console.Error.WriteLine(
                $"{flag} must be {expectedLength} bytes ({expectedLength * 2} hex chars), got {digest.Length}.");
            digest = null;
            return false;
        }

        return true;
    }

    public static void PrintUsage() => Console.Error.WriteLine("""
        Usage: Client [options]

          --url <url>                   Server base URL           (default https://localhost:8443)
          --ark <path>                  Pinned AMD root PEM       (default amd/ark.pem)
          --product <Milan|Genoa|Turin> Used only in help text     (default Milan)
          --expect-measurement <hex>    48-byte MEASUREMENT allow-list entry
          --min-tcb bl,tee,snp,ucode    Minimum acceptable REPORTED_TCB
          --require-smt-disabled        Reject if guest policy permits SMT
          --expect-host-data <hex>      32-byte HOST_DATA to require (launch-time; not settable on
                                        standard Azure CVMs -- see README)
          --manifest <path>             Bind workload identity: hash this file locally and require
                                        the quote's PCR 23 to match (vTPM path only)
          --expect-manifest <hex>       Same check, with the 32-byte manifest digest given directly
          -h, --help                    This message
        """);
}
