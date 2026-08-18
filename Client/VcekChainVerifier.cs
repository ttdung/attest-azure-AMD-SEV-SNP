using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace SevSnpDemo.Client;

/// <summary>
/// Verifies that a VCEK leaf certificate chains to the AMD root key the client has pinned.
/// </summary>
/// <remarks>
/// The pinned ARK is the trust anchor for the entire protocol. It is supplied as a local file
/// established out-of-band, and is deliberately never fetched at verification time — fetching your own
/// trust anchor over the network from the party you are trying to verify is not pinning, it is
/// theatre.
/// </remarks>
public static class VcekChainVerifier
{
    // AMD's VCEK certificate extensions (AMD OID arc 1.3.6.1.4.1.3704.1).
    private const string OidHwId = "1.3.6.1.4.1.3704.1.4";
    private const string OidBlSpl = "1.3.6.1.4.1.3704.1.3.1";
    private const string OidTeeSpl = "1.3.6.1.4.1.3704.1.3.2";
    private const string OidSnpSpl = "1.3.6.1.4.1.3704.1.3.3";
    private const string OidUcodeSpl = "1.3.6.1.4.1.3704.1.3.8";

    public sealed record Result(bool Ok, string? Failure, List<string> Notes);

    /// <summary>
    /// Builds and validates VCEK → ASK → pinned ARK.
    /// </summary>
    /// <param name="vcek">Leaf certificate supplied by the server.</param>
    /// <param name="intermediates">ASK (and possibly a copy of ARK) supplied by the server.</param>
    /// <param name="pinnedArk">The client's trust anchor, loaded from local disk.</param>
    /// <remarks>
    /// Path validation is done by <see cref="CertificateChain"/> rather than <see cref="X509Chain"/>,
    /// because AMD signs the ARK and ASK with RSASSA-PSS and the platform chain engine on macOS cannot
    /// process it. See the remarks on <see cref="CertificateChain"/> for the details and the evidence.
    ///
    /// Revocation is not checked. AMD publishes CRLs under
    /// <c>https://kdsintf.amd.com/vcek/v1/&lt;Product&gt;/crl</c>, but fetching them at verification
    /// time requires network access — which is precisely what pinning the anchor locally exists to
    /// avoid. Called out in the README as a hardening item rather than silently omitted.
    /// </remarks>
    public static Result VerifyChain(
        X509Certificate2 vcek,
        X509Certificate2Collection intermediates,
        X509Certificate2 pinnedArk)
    {
        // Drop any server-supplied copy of the root before path building: the anchor must come from
        // the pin, not the wire. Leaving it in the candidate set would be harmless (it is compared by
        // name and then by signature against the pinned key) but excluding it removes the question.
        var candidates = new X509Certificate2Collection();
        foreach (var intermediate in intermediates.OfType<X509Certificate2>())
        {
            if (intermediate.RawData.AsSpan().SequenceEqual(pinnedArk.RawData))
            {
                continue;
            }

            candidates.Add(intermediate);
        }

        var outcome = CertificateChain.Build(vcek, candidates, pinnedArk, DateTimeOffset.UtcNow);

        if (!outcome.Ok)
        {
            return new Result(
                false,
                $"VCEK does not chain to the pinned AMD root. {outcome.Failure}",
                outcome.Notes);
        }

        var notes = outcome.Notes;
        notes.Add($"Chain length {outcome.Path.Count}, anchored at pinned ARK ({pinnedArk.Subject})");

        return new Result(true, null, notes);
    }

    /// <summary>
    /// Cross-checks the VCEK's AMD extensions against the report's own fields.
    /// </summary>
    /// <remarks>
    /// These are consistency checks, not the load-bearing ones, and it is worth being precise about
    /// why. AMD issues a distinct VCEK per chip and per TCB, so a successful signature verification
    /// already implies the report came from the chip and TCB that certificate belongs to — a mismatched
    /// certificate would simply fail to verify. What these checks buy is a clear diagnostic instead of
    /// an opaque signature failure, and protection against a verifier that accidentally skips the
    /// signature step.
    ///
    /// AMD has encoded these extension values as both DER INTEGER and DER OCTET STRING across firmware
    /// generations, so both are accepted.
    /// </remarks>
    public static Result CrossCheckExtensions(X509Certificate2 vcek, SnpAttestationReport report)
    {
        var notes = new List<string>();

        if (TryReadOctets(vcek, OidHwId, out var hwid))
        {
            if (!hwid.AsSpan().SequenceEqual(report.ChipId))
            {
                return new Result(
                    false,
                    "VCEK HWID extension does not match the report's CHIP_ID — the certificate belongs " +
                    "to a different chip than the one that signed this report.",
                    notes);
            }

            notes.Add("VCEK HWID matches report CHIP_ID");
        }
        else
        {
            notes.Add("VCEK HWID extension absent or unparseable (consistency check skipped)");
        }

        var reported = report.ReportedTcb;
        var pairs = new (string Oid, string Name, byte Expected)[]
        {
            (OidBlSpl, "blSPL", reported.Bootloader),
            (OidTeeSpl, "teeSPL", reported.Tee),
            (OidSnpSpl, "snpSPL", reported.Snp),
            (OidUcodeSpl, "ucodeSPL", reported.Microcode),
        };

        var matched = 0;
        foreach (var (oid, name, expected) in pairs)
        {
            if (!TryReadSmallInteger(vcek, oid, out var actual))
            {
                continue;
            }

            if (actual != expected)
            {
                return new Result(
                    false,
                    $"VCEK {name} extension is {actual} but the report's REPORTED_TCB says {expected}.",
                    notes);
            }

            matched++;
        }

        notes.Add(matched == pairs.Length
            ? $"VCEK TCB extensions match REPORTED_TCB ({reported})"
            : $"VCEK TCB extensions partially readable ({matched}/{pairs.Length} checked)");

        return new Result(true, null, notes);
    }

    private static bool TryReadOctets(X509Certificate2 certificate, string oid, out byte[] value)
    {
        value = [];

        var extension = certificate.Extensions[oid];
        if (extension is null)
        {
            return false;
        }

        try
        {
            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            var tag = reader.PeekTag();

            if (tag.TagValue == (int)UniversalTagNumber.OctetString)
            {
                value = reader.ReadOctetString();
                return true;
            }

            // Some firmware wraps the value differently; fall back to the raw extension bytes.
            value = extension.RawData;
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static bool TryReadSmallInteger(X509Certificate2 certificate, string oid, out byte value)
    {
        value = 0;

        var extension = certificate.Extensions[oid];
        if (extension is null)
        {
            return false;
        }

        try
        {
            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            var tag = reader.PeekTag();

            if (tag.TagValue == (int)UniversalTagNumber.Integer)
            {
                if (!reader.TryReadInt32(out var parsed) || parsed is < 0 or > 255)
                {
                    return false;
                }

                value = (byte)parsed;
                return true;
            }

            if (tag.TagValue == (int)UniversalTagNumber.OctetString)
            {
                var octets = reader.ReadOctetString();
                if (octets.Length == 0)
                {
                    return false;
                }

                // Value is the least-significant byte regardless of field width.
                value = octets[^1];
                return true;
            }

            return false;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    /// <summary>Loads every certificate from a PEM bundle.</summary>
    public static X509Certificate2Collection LoadPemBundle(string pem)
    {
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(pem);
        return collection;
    }
}
