using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SevSnpDemo.Client;

/// <summary>
/// Manual X.509 path construction and signature verification for the AMD certificate chain.
/// </summary>
/// <remarks>
/// <para>
/// This deliberately does not use <see cref="X509Chain"/>. AMD signs the ARK and ASK with
/// <b>RSASSA-PSS</b> (SHA-384, MGF1-SHA-384, 48-byte salt). .NET delegates chain building to the
/// platform: OpenSSL on Linux handles PSS, but macOS's Security.framework backend does not, and it
/// fails in a maximally unhelpful way — the ARK is not even considered as a candidate issuer, so the
/// result is <c>PartialChain: One or more certificates required to validate this certificate cannot
/// be found</c>, which reads like a missing certificate rather than an unsupported algorithm.
/// </para>
/// <para>
/// Verified empirically: on macOS, <c>chain.Build(ASK)</c> with the ARK in
/// <see cref="X509ChainPolicy.CustomTrustStore"/> returns false with one chain element, for all three
/// of Milan, Genoa, and Turin.
/// </para>
/// <para>
/// The chain here is short (VCEK → ASK → ARK) and fully known, so doing it by hand is both feasible
/// and more predictable than arguing with three different platform chain engines. What we
/// deliberately keep is every check that matters for this topology: exact issuer/subject DER
/// matching, cryptographic signature verification at each link, validity windows, CA basic
/// constraints on issuers, and termination at the pinned anchor. What we drop is policy machinery
/// that does not apply — name constraints, policy mappings, and cross-certification.
/// </para>
/// </remarks>
public static class CertificateChain
{
    private const string OidRsaPss = "1.2.840.113549.1.1.10";
    private const string OidRsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
    private const string OidRsaPkcs1Sha384 = "1.2.840.113549.1.1.12";
    private const string OidRsaPkcs1Sha512 = "1.2.840.113549.1.1.13";
    private const string OidEcdsaSha256 = "1.2.840.10045.4.3.2";
    private const string OidEcdsaSha384 = "1.2.840.10045.4.3.3";
    private const string OidEcdsaSha512 = "1.2.840.10045.4.3.4";

    private const string OidSha256 = "2.16.840.1.101.3.4.2.1";
    private const string OidSha384 = "2.16.840.1.101.3.4.2.2";
    private const string OidSha512 = "2.16.840.1.101.3.4.2.3";
    private const string OidMgf1 = "1.2.840.113549.1.1.8";

    /// <summary>Guards against a pathological candidate set producing an unbounded walk.</summary>
    private const int MaxDepth = 8;

    public sealed record Outcome(bool Ok, string? Failure, List<X509Certificate2> Path, List<string> Notes);

    /// <summary>
    /// Builds the path from <paramref name="leaf"/> up to <paramref name="anchor"/> and verifies every
    /// link cryptographically.
    /// </summary>
    /// <param name="leaf">The certificate to validate (the VCEK).</param>
    /// <param name="candidates">Untrusted intermediates supplied by the peer (the ASK).</param>
    /// <param name="anchor">The pinned trust anchor. Only this may terminate the path.</param>
    /// <param name="now">Time to evaluate validity windows against.</param>
    public static Outcome Build(
        X509Certificate2 leaf,
        X509Certificate2Collection candidates,
        X509Certificate2 anchor,
        DateTimeOffset now)
    {
        var notes = new List<string>();
        var path = new List<X509Certificate2> { leaf };

        // The anchor must be internally consistent. A self-signature on a self-signed root proves
        // nothing about its authenticity — that comes from the out-of-band fingerprint check — but a
        // root that does not even sign itself means the pinned file is corrupt or is not a root.
        if (!SameName(anchor.SubjectName, anchor.IssuerName))
        {
            return new Outcome(false,
                $"Pinned anchor is not self-issued (subject '{anchor.Subject}' != issuer '{anchor.Issuer}'). " +
                "It is an intermediate, not a root.", path, notes);
        }

        if (!TryVerifySignature(anchor, anchor, out var anchorFailure))
        {
            return new Outcome(false,
                $"Pinned anchor's self-signature does not verify: {anchorFailure}. The file at --ark is " +
                "corrupt.", path, notes);
        }

        notes.Add("Anchor is self-issued and self-signature verifies");

        var current = leaf;

        for (var depth = 0; depth < MaxDepth; depth++)
        {
            if (!CheckValidity(current, now, out var validityFailure))
            {
                return new Outcome(false, validityFailure, path, notes);
            }

            // Reached the anchor?
            if (SameName(current.IssuerName, anchor.SubjectName))
            {
                if (!TryVerifySignature(current, anchor, out var failure))
                {
                    return new Outcome(false,
                        $"'{Describe(current)}' claims to be issued by the pinned anchor, but its signature " +
                        $"does not verify under the anchor's key: {failure}", path, notes);
                }

                if (!IsCertificateAuthority(anchor, out var anchorCaFailure))
                {
                    return new Outcome(false, $"Pinned anchor {anchorCaFailure}", path, notes);
                }

                path.Add(anchor);
                notes.Add($"Path: {string.Join(" -> ", path.Select(Describe))}");
                return new Outcome(true, null, path, notes);
            }

            // Otherwise find an issuer among the peer-supplied candidates.
            var issuer = candidates
                .OfType<X509Certificate2>()
                .FirstOrDefault(candidate =>
                    SameName(candidate.SubjectName, current.IssuerName) &&
                    !path.Any(existing => existing.RawData.AsSpan().SequenceEqual(candidate.RawData)));

            if (issuer is null)
            {
                return new Outcome(false,
                    $"No issuer for '{Describe(current)}' (needs subject '{current.Issuer}'). " +
                    "The peer did not supply the intermediate, or the path does not lead to the pinned " +
                    $"anchor '{anchor.Subject}'.", path, notes);
            }

            if (!TryVerifySignature(current, issuer, out var linkFailure))
            {
                return new Outcome(false,
                    $"Signature on '{Describe(current)}' does not verify under '{Describe(issuer)}': " +
                    linkFailure, path, notes);
            }

            if (!IsCertificateAuthority(issuer, out var caFailure))
            {
                return new Outcome(false, $"'{Describe(issuer)}' {caFailure}", path, notes);
            }

            path.Add(issuer);
            current = issuer;
        }

        return new Outcome(false,
            $"Path exceeded {MaxDepth} certificates without reaching the pinned anchor.", path, notes);
    }

    /// <summary>Exact DER comparison of two distinguished names.</summary>
    /// <remarks>
    /// Byte equality rather than RFC 5280 name matching (which would case-fold and normalise
    /// whitespace in PrintableStrings). AMD's certificates encode these names identically, so exact
    /// matching is correct here and strictly stricter. If a future AMD chain re-encodes a name, this
    /// fails closed with a legible message rather than silently accepting a near-match.
    /// </remarks>
    private static bool SameName(X500DistinguishedName left, X500DistinguishedName right) =>
        left.RawData.AsSpan().SequenceEqual(right.RawData);

    private static string Describe(X509Certificate2 certificate)
    {
        foreach (var part in certificate.Subject.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[3..];
            }
        }

        return certificate.Subject;
    }

    private static bool CheckValidity(X509Certificate2 certificate, DateTimeOffset now, out string? failure)
    {
        var notBefore = certificate.NotBefore.ToUniversalTime();
        var notAfter = certificate.NotAfter.ToUniversalTime();

        if (now < notBefore)
        {
            failure = $"'{Describe(certificate)}' is not valid until {notBefore:u} (now {now:u}).";
            return false;
        }

        if (now > notAfter)
        {
            failure = $"'{Describe(certificate)}' expired at {notAfter:u} (now {now:u}).";
            return false;
        }

        failure = null;
        return true;
    }

    /// <remarks>
    /// AMD's ARK and ASK both carry <c>BasicConstraints: critical, CA:TRUE</c> and
    /// <c>KeyUsage: critical, Certificate Sign</c>. Requiring them means a leaf certificate cannot be
    /// pressed into service as an issuer.
    /// </remarks>
    private static bool IsCertificateAuthority(X509Certificate2 certificate, out string? failure)
    {
        var basicConstraints = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();

        if (basicConstraints is null || !basicConstraints.CertificateAuthority)
        {
            failure = "is used as an issuer but does not assert BasicConstraints CA:TRUE.";
            return false;
        }

        var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsage is not null && !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
        {
            failure = $"is used as an issuer but its KeyUsage ({keyUsage.KeyUsages}) omits KeyCertSign.";
            return false;
        }

        failure = null;
        return true;
    }

    /// <summary>
    /// Verifies <paramref name="certificate"/>'s signature under <paramref name="issuer"/>'s public key.
    /// </summary>
    private static bool TryVerifySignature(
        X509Certificate2 certificate,
        X509Certificate2 issuer,
        out string? failure)
    {
        byte[] tbs;
        string algorithmOid;
        ReadOnlyMemory<byte> algorithmParameters;
        byte[] signature;

        try
        {
            // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
            var reader = new AsnReader(certificate.RawData, AsnEncodingRules.DER).ReadSequence();

            tbs = reader.ReadEncodedValue().ToArray();

            var algorithm = reader.ReadSequence();
            algorithmOid = algorithm.ReadObjectIdentifier();
            algorithmParameters = algorithm.HasData ? algorithm.ReadEncodedValue() : default;

            signature = reader.ReadBitString(out var unusedBits);
            if (unusedBits != 0)
            {
                failure = $"signatureValue BIT STRING has {unusedBits} unused bits.";
                return false;
            }
        }
        catch (AsnContentException ex)
        {
            failure = $"could not parse the certificate DER ({ex.Message}).";
            return false;
        }

        switch (algorithmOid)
        {
            case OidRsaPss:
                return TryVerifyRsaPss(issuer, tbs, signature, algorithmParameters, out failure);

            case OidRsaPkcs1Sha256:
                return TryVerifyRsaPkcs1(issuer, tbs, signature, HashAlgorithmName.SHA256, out failure);
            case OidRsaPkcs1Sha384:
                return TryVerifyRsaPkcs1(issuer, tbs, signature, HashAlgorithmName.SHA384, out failure);
            case OidRsaPkcs1Sha512:
                return TryVerifyRsaPkcs1(issuer, tbs, signature, HashAlgorithmName.SHA512, out failure);

            case OidEcdsaSha256:
                return TryVerifyEcdsa(issuer, tbs, signature, HashAlgorithmName.SHA256, out failure);
            case OidEcdsaSha384:
                return TryVerifyEcdsa(issuer, tbs, signature, HashAlgorithmName.SHA384, out failure);
            case OidEcdsaSha512:
                return TryVerifyEcdsa(issuer, tbs, signature, HashAlgorithmName.SHA512, out failure);

            default:
                failure = $"unsupported signature algorithm {algorithmOid}.";
                return false;
        }
    }

    private static bool TryVerifyRsaPss(
        X509Certificate2 issuer,
        byte[] tbs,
        byte[] signature,
        ReadOnlyMemory<byte> parameters,
        out string? failure)
    {
        if (!TryParsePssParameters(parameters, out var hash, out var saltLength, out failure))
        {
            return false;
        }

        // .NET's RSASignaturePadding.Pss fixes the salt length at the hash length. If AMD ever emits a
        // different salt length, verifying anyway would be checking a different scheme than the one
        // that signed — so refuse rather than quietly succeed or quietly fail.
        var hashLength = HashLength(hash);
        if (saltLength != hashLength)
        {
            failure =
                $"PSS salt length is {saltLength} but .NET only supports salt length == hash length " +
                $"({hashLength} for {hash.Name}). Verifying with the wrong salt length would not be " +
                "the scheme the issuer used.";
            return false;
        }

        using var rsa = issuer.GetRSAPublicKey();
        if (rsa is null)
        {
            failure = $"issuer '{Describe(issuer)}' has no RSA public key.";
            return false;
        }

        if (!rsa.VerifyData(tbs, signature, hash, RSASignaturePadding.Pss))
        {
            failure = $"RSASSA-PSS/{hash.Name} verification failed.";
            return false;
        }

        failure = null;
        return true;
    }

    private static bool TryVerifyRsaPkcs1(
        X509Certificate2 issuer,
        byte[] tbs,
        byte[] signature,
        HashAlgorithmName hash,
        out string? failure)
    {
        using var rsa = issuer.GetRSAPublicKey();
        if (rsa is null)
        {
            failure = $"issuer '{Describe(issuer)}' has no RSA public key.";
            return false;
        }

        if (!rsa.VerifyData(tbs, signature, hash, RSASignaturePadding.Pkcs1))
        {
            failure = $"RSASSA-PKCS1-v1_5/{hash.Name} verification failed.";
            return false;
        }

        failure = null;
        return true;
    }

    private static bool TryVerifyEcdsa(
        X509Certificate2 issuer,
        byte[] tbs,
        byte[] signature,
        HashAlgorithmName hash,
        out string? failure)
    {
        using var ecdsa = issuer.GetECDsaPublicKey();
        if (ecdsa is null)
        {
            failure = $"issuer '{Describe(issuer)}' has no ECDSA public key.";
            return false;
        }

        // X.509 wraps ECDSA signatures as a DER SEQUENCE { r, s }, unlike the raw r||s in the
        // attestation report itself.
        if (!ecdsa.VerifyData(tbs, signature, hash, DSASignatureFormat.Rfc3279DerSequence))
        {
            failure = $"ECDSA/{hash.Name} verification failed.";
            return false;
        }

        failure = null;
        return true;
    }

    /// <summary>
    /// Parses RSASSA-PSS-params (RFC 4055 §3.1).
    /// </summary>
    /// <remarks>
    /// <code>
    /// RSASSA-PSS-params ::= SEQUENCE {
    ///   hashAlgorithm    [0] AlgorithmIdentifier DEFAULT sha1,
    ///   maskGenAlgorithm [1] AlgorithmIdentifier DEFAULT mgf1SHA1,
    ///   saltLength       [2] INTEGER            DEFAULT 20,
    ///   trailerField     [3] INTEGER            DEFAULT 1 }
    /// </code>
    /// The RFC 4055 defaults are SHA-1, which is not acceptable for this chain. Rather than encode
    /// them, an absent field is treated as an error — AMD always states all three explicitly, so a
    /// missing one signals a certificate this code has not been designed against.
    /// </remarks>
    private static bool TryParsePssParameters(
        ReadOnlyMemory<byte> parameters,
        out HashAlgorithmName hash,
        out int saltLength,
        out string? failure)
    {
        hash = default;
        saltLength = 0;

        if (parameters.IsEmpty)
        {
            failure = "RSASSA-PSS certificate carries no parameters; SHA-1 defaults are not accepted.";
            return false;
        }

        try
        {
            var reader = new AsnReader(parameters, AsnEncodingRules.DER).ReadSequence();

            // These are explicit context-specific tags, and they are *constructed* — Asn1Tag's
            // constructor defaults to primitive, so the constructed flag has to be stated or every
            // comparison below silently fails to match.
            var hashTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
            if (!reader.HasData || reader.PeekTag() != hashTag)
            {
                failure = "RSASSA-PSS parameters omit an explicit hashAlgorithm.";
                return false;
            }

            var hashOid = reader.ReadSequence(hashTag).ReadSequence().ReadObjectIdentifier();
            if (!TryMapHash(hashOid, out hash))
            {
                failure = $"unsupported PSS hash algorithm {hashOid}.";
                return false;
            }

            var mgfTag = new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true);
            if (!reader.HasData || reader.PeekTag() != mgfTag)
            {
                failure = "RSASSA-PSS parameters omit an explicit maskGenAlgorithm.";
                return false;
            }

            var mgf = reader.ReadSequence(mgfTag).ReadSequence();
            var mgfOid = mgf.ReadObjectIdentifier();
            if (mgfOid != OidMgf1)
            {
                failure = $"unsupported mask generation function {mgfOid}; only MGF1 is supported.";
                return false;
            }

            var mgfHashOid = mgf.ReadSequence().ReadObjectIdentifier();
            if (!TryMapHash(mgfHashOid, out var mgfHash) || mgfHash != hash)
            {
                // .NET's Pss padding always uses MGF1 with the signature hash. A certificate mixing
                // them would need a different verification path than this one.
                failure =
                    $"MGF1 hash ({mgfHashOid}) differs from the signature hash ({hash.Name}); " +
                    ".NET's PSS padding cannot express that combination.";
                return false;
            }

            var saltTag = new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true);
            if (!reader.HasData || reader.PeekTag() != saltTag)
            {
                failure = "RSASSA-PSS parameters omit an explicit saltLength.";
                return false;
            }

            if (!reader.ReadSequence(saltTag).TryReadInt32(out saltLength))
            {
                failure = "RSASSA-PSS saltLength is not a small integer.";
                return false;
            }

            failure = null;
            return true;
        }
        catch (AsnContentException ex)
        {
            failure = $"could not parse RSASSA-PSS parameters ({ex.Message}).";
            return false;
        }
    }

    private static bool TryMapHash(string oid, out HashAlgorithmName hash)
    {
        switch (oid)
        {
            case OidSha256: hash = HashAlgorithmName.SHA256; return true;
            case OidSha384: hash = HashAlgorithmName.SHA384; return true;
            case OidSha512: hash = HashAlgorithmName.SHA512; return true;
            default: hash = default; return false;
        }
    }

    private static int HashLength(HashAlgorithmName hash) => hash.Name switch
    {
        nameof(HashAlgorithmName.SHA256) => 32,
        nameof(HashAlgorithmName.SHA384) => 48,
        nameof(HashAlgorithmName.SHA512) => 64,
        _ => 0,
    };
}
