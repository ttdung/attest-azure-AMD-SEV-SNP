using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using SevSnpDemo.Shared;

namespace SevSnpDemo.Client;

/// <summary>
/// Verifies the two-hop binding used on Azure paravisor-backed CVMs.
/// </summary>
/// <remarks>
/// <para>
/// On these VMs the guest cannot choose REPORT_DATA, so the SNP report cannot commit to the TLS key
/// directly. It commits to a JSON <c>runtime_data</c> blob instead, which names the vTPM's attestation
/// key; the AK then signs a fresh quote committing to the TLS key. Three links must all hold:
/// </para>
/// <list type="number">
/// <item><c>REPORT_DATA == SHA-256(runtime_data) || 32 zeros</c> — hardware vouches for the runtime data.</item>
/// <item>The AK public key in <c>runtime_data</c> verifies the quote signature — the runtime data
/// vouches for the signer.</item>
/// <item><c>quote.extraData == SHA-256(observed TLS SPKI || nonce)</c> — the signer vouches for this
/// channel, now.</item>
/// </list>
/// <para>
/// Break any one and the chain says nothing. In particular, link 3 is the only source of freshness:
/// the SNP report on this platform is generated once at boot and is byte-identical across every
/// request, so a verifier that checked links 1 and 2 alone would accept an indefinitely old replay.
/// </para>
/// </remarks>
public static class VtpmEvidenceVerifier
{
    /// <summary>Azure's key id for the vTPM attestation key inside the runtime data.</summary>
    private const string AkKeyId = "HCLAkPub";

    public sealed record Result(bool Ok, string? Failure, List<VerificationStep> Steps);

    /// <summary>
    /// Runs links 1–3 above.
    /// </summary>
    /// <param name="document">Evidence from the server.</param>
    /// <param name="report">The already-parsed SNP report (its signature is checked separately).</param>
    /// <param name="observedSpkiDer">SPKI captured from this client's own TLS handshake.</param>
    /// <param name="sentNonce">The nonce this client generated.</param>
    /// <param name="expectedManifestPcr">
    /// Expected PCR 23 value, i.e. SHA-256(0^32 || manifestDigest). Null skips the manifest check.
    /// </param>
    public static Result Verify(
        AttestationDocument document,
        SnpAttestationReport report,
        byte[] observedSpkiDer,
        byte[] sentNonce,
        byte[]? expectedManifestPcr = null)
    {
        var steps = new List<VerificationStep>();

        // --- Field presence -----------------------------------------------------------------------

        if (document.RuntimeData is null || document.AkQuote is null ||
            document.AkQuoteSignature is null || document.AkQuoteSigAlg is null)
        {
            var missing = new List<string>();
            if (document.RuntimeData is null) missing.Add(nameof(document.RuntimeData));
            if (document.AkQuote is null) missing.Add(nameof(document.AkQuote));
            if (document.AkQuoteSignature is null) missing.Add(nameof(document.AkQuoteSignature));
            if (document.AkQuoteSigAlg is null) missing.Add(nameof(document.AkQuoteSigAlg));

            steps.Add(new("vTPM evidence present", false,
                $"Evidence kind is {EvidenceKinds.AzureVtpm} but these fields are absent: " +
                string.Join(", ", missing) + ". Without the quote there is nothing binding the report " +
                "to this TLS connection, so the report alone proves nothing about this server."));

            return new Result(false, "incomplete vTPM evidence", steps);
        }

        byte[] runtimeData, quoteBytes, quoteSignature;
        try
        {
            runtimeData = Convert.FromBase64String(document.RuntimeData);
            quoteBytes = Convert.FromBase64String(document.AkQuote);
            quoteSignature = Convert.FromBase64String(document.AkQuoteSignature);
        }
        catch (FormatException ex)
        {
            steps.Add(new("vTPM evidence present", false, $"Base64 decode failed: {ex.Message}"));
            return new Result(false, "malformed vTPM evidence", steps);
        }

        steps.Add(new("vTPM evidence present", true,
            $"runtime_data {runtimeData.Length} B, quote {quoteBytes.Length} B, " +
            $"signature {quoteSignature.Length} B, alg {document.AkQuoteSigAlg}"));

        // --- Link 1: hardware vouches for the runtime data ---------------------------------------

        var runtimeDigest = SHA256.HashData(runtimeData);
        var link1 = CryptographicOperations.FixedTimeEquals(report.ReportData[..32], runtimeDigest)
                    && !report.ReportData[32..].ContainsAnyExcept((byte)0);

        steps.Add(new("REPORT_DATA commits to runtime_data", link1,
            link1
                ? "REPORT_DATA == SHA-256(runtime_data) || 32 zero bytes"
                : "MISMATCH. The runtime data does not belong to this SNP report. Expected " +
                  $"{Convert.ToHexStringLower(report.ReportData[..32])}, got " +
                  $"{Convert.ToHexStringLower(runtimeDigest)}. Note the runtime data must be forwarded " +
                  "byte-for-byte; re-serialising the JSON changes its hash."));

        if (!link1)
        {
            return new Result(false, "runtime data not bound to the report", steps);
        }

        // --- Link 2: the runtime data names the signer -------------------------------------------

        RSA akPublicKey;
        try
        {
            akPublicKey = ExtractAkPublicKey(runtimeData);
        }
        catch (Exception ex)
        {
            steps.Add(new("Runtime data yields the AK public key", false, ex.Message));
            return new Result(false, "AK public key unavailable", steps);
        }

        steps.Add(new("Runtime data yields the AK public key", true,
            $"JWK kid=\"{AkKeyId}\", RSA-{akPublicKey.KeySize}"));

        // --- Link 2 (continued): the quote verifies under that key -------------------------------

        TpmAttest attest;
        try
        {
            attest = TpmAttest.Parse(quoteBytes);
        }
        catch (InvalidDataException ex)
        {
            steps.Add(new("Quote structure valid", false, ex.Message));
            akPublicKey.Dispose();
            return new Result(false, "malformed quote", steps);
        }

        steps.Add(new("Quote structure valid", attest.IsQuote,
            attest.IsQuote
                ? $"TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE, firmware 0x{attest.FirmwareVersion:X}"
                : $"magic/type is 0x{attest.Magic:X8}/0x{attest.Type:X4}, expected " +
                  $"0x{TpmAttest.TpmGeneratedValue:X8}/0x{TpmAttest.AttestQuote:X4}"));

        bool signatureOk;
        string signatureDetail;
        using (akPublicKey)
        {
            signatureOk = VerifyQuoteSignature(
                akPublicKey, quoteBytes, quoteSignature, document.AkQuoteSigAlg, out var signatureFailure);

            signatureDetail = signatureOk
                ? $"{document.AkQuoteSigAlg} verifies under the AK from runtime_data"
                : signatureFailure!;
        }

        steps.Add(new("Quote signed by the attested AK", signatureOk, signatureDetail));

        // --- Link 3: the signer vouches for this channel, now ------------------------------------

        var expectedExtraData = ComputeQualifyingData(observedSpkiDer, sentNonce);
        var link3 = attest.ExtraData.Length == expectedExtraData.Length
                    && CryptographicOperations.FixedTimeEquals(attest.ExtraData, expectedExtraData);

        steps.Add(new("Quote binds the TLS key and nonce", link3,
            link3
                ? "quote.extraData == SHA-256(observed TLS SPKI || nonce)"
                : "MISMATCH. The quote does not commit to the key that terminated this TLS connection, " +
                  "or the nonce was not honoured. Either the server is relaying evidence from another " +
                  $"machine, or the quote is a replay. Expected " +
                  $"{Convert.ToHexStringLower(expectedExtraData)}, got " +
                  $"{Convert.ToHexStringLower(attest.ExtraData)}"));

        // --- Link 4 (optional): the quote also commits to the workload manifest -------------------

        if (expectedManifestPcr is not null)
        {
            steps.Add(VerifyManifestPcr(document, attest, expectedManifestPcr));
        }

        var ok = steps.All(s => s.Passed);
        return new Result(ok, ok ? null : "vTPM binding failed", steps);
    }

    /// <summary>PCR index carrying the application manifest. Must match the server's ManifestPcr.</summary>
    public const int ManifestPcr = 23;

    /// <summary>
    /// Confirms the quote's <c>pcrDigest</c> really covers the PCR values supplied, and that PCR 23
    /// holds the expected manifest measurement.
    /// </summary>
    /// <remarks>
    /// Two distinct checks, in this order, and the order is the point. The PCR values arrive outside the
    /// signature, so they are worth nothing until the recomputed digest matches the signed
    /// <c>pcrDigest</c>. Only then does comparing PCR 23 mean anything — checking it first against
    /// unverified values would be theatre.
    /// </remarks>
    private static VerificationStep VerifyManifestPcr(
        AttestationDocument document,
        TpmAttest attest,
        byte[] expectedManifestPcr)
    {
        if (document.PcrValues is not { Count: > 0 } supplied)
        {
            return new("Quote commits to the app manifest", false,
                "A manifest was expected but the server sent no PCR values, so the quote's pcrDigest " +
                "cannot be checked. Is SEVSNP_MANIFEST configured on the server?");
        }

        // Rebuild pcrDigest exactly as the TPM did: values concatenated in selection order, ascending
        // index within each bank, hashed with that bank's algorithm.
        var concatenated = new List<byte>();

        foreach (var bank in attest.PcrSelections)
        {
            if (bank.HashAlg != PcrBankSelection.Sha256)
            {
                return new("Quote commits to the app manifest", false,
                    $"Quote selects PCR bank 0x{bank.HashAlg:X4}; only SHA-256 (0x000B) is supported here.");
            }

            foreach (var index in bank.Indices.OrderBy(i => i))
            {
                if (!supplied.TryGetValue(index, out var hex))
                {
                    return new("Quote commits to the app manifest", false,
                        $"Quote covers PCR {index} but the server supplied no value for it, so pcrDigest " +
                        "cannot be recomputed.");
                }

                try
                {
                    concatenated.AddRange(Convert.FromHexString(hex));
                }
                catch (FormatException)
                {
                    return new("Quote commits to the app manifest", false,
                        $"PCR {index} value is not valid hex: \"{hex}\"");
                }
            }
        }

        var recomputed = SHA256.HashData(concatenated.ToArray());

        if (!CryptographicOperations.FixedTimeEquals(recomputed, attest.PcrDigest))
        {
            return new("Quote commits to the app manifest", false,
                "The supplied PCR values do not hash to the quote's signed pcrDigest. Expected " +
                $"{Convert.ToHexStringLower(attest.PcrDigest)}, recomputed " +
                $"{Convert.ToHexStringLower(recomputed)}. The PCR values were altered in transit, or the " +
                "selection was misread.");
        }

        if (!supplied.TryGetValue(ManifestPcr, out var manifestPcrHex))
        {
            return new("Quote commits to the app manifest", false,
                $"pcrDigest verified, but no value for PCR {ManifestPcr} was supplied.");
        }

        byte[] actualManifestPcr;
        try
        {
            actualManifestPcr = Convert.FromHexString(manifestPcrHex);
        }
        catch (FormatException)
        {
            return new("Quote commits to the app manifest", false,
                $"PCR {ManifestPcr} value is not valid hex: \"{manifestPcrHex}\"");
        }

        if (!CryptographicOperations.FixedTimeEquals(actualManifestPcr, expectedManifestPcr))
        {
            return new("Quote commits to the app manifest", false,
                $"pcrDigest verified, but PCR {ManifestPcr} is " +
                $"{Convert.ToHexStringLower(actualManifestPcr)} and the expected " +
                $"SHA-256(0^32 || manifestDigest) is {Convert.ToHexStringLower(expectedManifestPcr)}. " +
                "The server is running a different manifest than the one supplied to this client — or " +
                "no manifest was bound at all, leaving PCR " + ManifestPcr + " as the platform left it.");
        }

        return new("Quote commits to the app manifest", true,
            $"pcrDigest recomputed over {attest.PcrSelections.Sum(b => b.Indices.Count)} PCR values; " +
            $"PCR {ManifestPcr} == SHA-256(0^32 || manifestDigest)");
    }

    /// <summary>SHA-256(SPKI || nonce). Mirrors TlsIdentity.ComputeQuoteQualifyingData.</summary>
    private static byte[] ComputeQualifyingData(byte[] spkiDer, byte[] nonce)
    {
        var buffer = new byte[spkiDer.Length + nonce.Length];
        spkiDer.CopyTo(buffer.AsSpan());
        nonce.CopyTo(buffer.AsSpan(spkiDer.Length));
        return SHA256.HashData(buffer);
    }

    /// <summary>
    /// Pulls the AK out of the runtime data's JWK set.
    /// </summary>
    /// <remarks>
    /// Azure's runtime data looks like
    /// <c>{ "keys": [ { "kid": "HCLAkPub", "kty": "RSA", "n": "...", "e": "AQAB" }, ... ], ... }</c>
    /// with <c>n</c> and <c>e</c> base64url-encoded big-endian integers.
    /// </remarks>
    private static RSA ExtractAkPublicKey(byte[] runtimeData)
    {
        using var json = JsonDocument.Parse(runtimeData);

        if (!json.RootElement.TryGetProperty("keys", out var keys) ||
            keys.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "Runtime data has no \"keys\" array, so it does not name an attestation key. " +
                $"Top-level properties: {string.Join(", ", json.RootElement.EnumerateObject().Select(p => p.Name))}");
        }

        foreach (var key in keys.EnumerateArray())
        {
            if (!key.TryGetProperty("kid", out var kid) || kid.GetString() != AkKeyId)
            {
                continue;
            }

            if (!key.TryGetProperty("kty", out var kty) || kty.GetString() != "RSA")
            {
                throw new InvalidDataException(
                    $"Runtime data key \"{AkKeyId}\" has kty=\"{(key.TryGetProperty("kty", out var k) ? k.GetString() : "absent")}\"; " +
                    "only RSA attestation keys are supported here.");
            }

            if (!key.TryGetProperty("n", out var modulus) || !key.TryGetProperty("e", out var exponent))
            {
                throw new InvalidDataException($"Runtime data key \"{AkKeyId}\" lacks \"n\" or \"e\".");
            }

            var rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = Base64Url.DecodeFromChars(modulus.GetString() ?? string.Empty),
                    Exponent = Base64Url.DecodeFromChars(exponent.GetString() ?? string.Empty),
                });

                return rsa;
            }
            catch
            {
                rsa.Dispose();
                throw;
            }
        }

        var available = keys.EnumerateArray()
            .Select(k => k.TryGetProperty("kid", out var v) ? v.GetString() : "(no kid)");

        throw new InvalidDataException(
            $"Runtime data contains no key with kid \"{AkKeyId}\". Present: {string.Join(", ", available)}");
    }

    /// <summary>
    /// Verifies the quote signature using the scheme the server named.
    /// </summary>
    /// <remarks>
    /// The scheme is never inferred. Trying PKCS#1 and then PSS until one passes would mean a verifier
    /// that cannot tell "wrong algorithm" from "bad signature", and would accept a signature under
    /// whichever scheme happened to be weaker to produce.
    /// </remarks>
    private static bool VerifyQuoteSignature(
        RSA akPublicKey,
        byte[] quote,
        byte[] signature,
        string algorithm,
        out string? failure)
    {
        HashAlgorithmName hash;
        RSASignaturePadding padding;

        switch (algorithm)
        {
            case "rsassa-sha256": hash = HashAlgorithmName.SHA256; padding = RSASignaturePadding.Pkcs1; break;
            case "rsassa-sha384": hash = HashAlgorithmName.SHA384; padding = RSASignaturePadding.Pkcs1; break;
            case "rsassa-sha512": hash = HashAlgorithmName.SHA512; padding = RSASignaturePadding.Pkcs1; break;
            case "rsapss-sha256": hash = HashAlgorithmName.SHA256; padding = RSASignaturePadding.Pss; break;
            case "rsapss-sha384": hash = HashAlgorithmName.SHA384; padding = RSASignaturePadding.Pss; break;
            case "rsapss-sha512": hash = HashAlgorithmName.SHA512; padding = RSASignaturePadding.Pss; break;

            default:
                failure =
                    $"Server reported quote signature algorithm \"{algorithm}\", which this client does " +
                    "not implement. Refusing to guess.";
                return false;
        }

        if (!akPublicKey.VerifyData(quote, signature, hash, padding))
        {
            failure =
                $"{algorithm} verification failed. The quote was not signed by the AK named in " +
                "runtime_data, so the hardware's endorsement does not extend to this quote.";
            return false;
        }

        failure = null;
        return true;
    }
}
