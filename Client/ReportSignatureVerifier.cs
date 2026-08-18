using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SevSnpDemo.Client;

/// <summary>
/// Verifies the ECDSA P-384 signature the AMD secure processor placed over an attestation report.
/// </summary>
public static class ReportSignatureVerifier
{
    /// <summary>SIGNATURE_ALGO value for ECDSA P-384 with SHA-384.</summary>
    private const uint EcdsaP384Sha384 = 1;

    /// <summary>Each of r and s occupies a 72-byte little-endian field in the report.</summary>
    private const int ComponentFieldSize = 72;

    /// <summary>P-384 scalars are 48 bytes; the remaining 24 bytes of each field must be zero.</summary>
    private const int P384ScalarSize = 48;

    /// <summary>
    /// Returns true when <paramref name="report"/>'s signature is valid under the VCEK's public key.
    /// </summary>
    public static bool Verify(SnpAttestationReport report, X509Certificate2 vcek, out string? failureReason)
    {
        if (report.SignatureAlgo != EcdsaP384Sha384)
        {
            failureReason =
                $"Unsupported SIGNATURE_ALGO {report.SignatureAlgo}; this verifier implements only " +
                $"ECDSA P-384/SHA-384 ({EcdsaP384Sha384}).";
            return false;
        }

        if (!TryConvertSignature(report.Signature, out var ieeeP1363, out failureReason))
        {
            return false;
        }

        using var publicKey = vcek.GetECDsaPublicKey();
        if (publicKey is null)
        {
            failureReason = "VCEK does not carry an ECDSA public key.";
            return false;
        }

        var valid = publicKey.VerifyData(
            report.SignedRegion,
            ieeeP1363,
            HashAlgorithmName.SHA384,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        failureReason = valid ? null : "ECDSA verification failed over the signed region.";
        return valid;
    }

    /// <summary>
    /// Converts the report's signature field into the fixed-width big-endian form .NET expects.
    /// </summary>
    /// <remarks>
    /// This is the single most error-prone step in SEV-SNP verification. AMD stores r and s as
    /// <em>little-endian</em> values in 72-byte fields; .NET's
    /// <see cref="DSASignatureFormat.IeeeP1363FixedFieldConcatenation"/> wants
    /// <em>big-endian</em> r‖s at the curve's natural width (48 bytes each for P-384). So each
    /// component must be truncated to 48 bytes and byte-reversed.
    ///
    /// The zero-check on the upper 24 bytes is not decoration: if those bytes are populated, the value
    /// is not a P-384 scalar and silently discarding them would mean verifying a different number than
    /// the one the platform signed.
    /// </remarks>
    private static bool TryConvertSignature(
        ReadOnlySpan<byte> signatureField,
        out byte[] ieeeP1363,
        out string? failureReason)
    {
        ieeeP1363 = [];

        var rField = signatureField[..ComponentFieldSize];
        var sField = signatureField[ComponentFieldSize..(ComponentFieldSize * 2)];

        if (rField[P384ScalarSize..].IndexOfAnyExcept((byte)0) >= 0)
        {
            failureReason = "Signature r component has non-zero bytes above 48 — not a P-384 scalar.";
            return false;
        }

        if (sField[P384ScalarSize..].IndexOfAnyExcept((byte)0) >= 0)
        {
            failureReason = "Signature s component has non-zero bytes above 48 — not a P-384 scalar.";
            return false;
        }

        var result = new byte[P384ScalarSize * 2];
        rField[..P384ScalarSize].CopyTo(result.AsSpan(0, P384ScalarSize));
        sField[..P384ScalarSize].CopyTo(result.AsSpan(P384ScalarSize, P384ScalarSize));

        // Little-endian -> big-endian, per component.
        result.AsSpan(0, P384ScalarSize).Reverse();
        result.AsSpan(P384ScalarSize, P384ScalarSize).Reverse();

        ieeeP1363 = result;
        failureReason = null;
        return true;
    }
}
