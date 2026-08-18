using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SevSnpDemo.Shared;

namespace SevSnpDemo.Client;

/// <summary>Appraisal policy: what the client insists on before trusting the channel.</summary>
public sealed record AttestationPolicy
{
    /// <summary>Reject unless every TCB component is at least this. Null disables the check.</summary>
    public TcbVersion? MinimumTcb { get; init; }

    /// <summary>Reject unless MEASUREMENT equals one of these (48-byte values). Empty disables the check.</summary>
    public IReadOnlyList<byte[]> AllowedMeasurements { get; init; } = [];

    /// <summary>Reject if the guest policy permits SMT. Off by default — Azure hosts generally run SMT.</summary>
    public bool RequireSmtDisabled { get; init; }

    /// <summary>
    /// Require HOST_DATA to equal this 32-byte value. Null disables the check.
    /// </summary>
    /// <remarks>
    /// HOST_DATA is fixed by the hypervisor at <c>SNP_LAUNCH_FINISH</c> and is immutable for the VM's
    /// lifetime — nothing inside the guest can change it at any privilege level. That makes it the
    /// strongest place to put a workload identity, and it is what Azure Confidential Containers uses for
    /// the CCE policy hash. Standard Azure CVMs do not expose it to the customer, so it reads as all
    /// zeroes there; this check is for platforms where you control launch.
    /// </remarks>
    public byte[]? ExpectedHostData { get; init; }

    /// <summary>
    /// Expected PCR 23 value, i.e. <c>SHA-256(0^32 || manifestDigest)</c>. Null disables the check.
    /// </summary>
    /// <remarks>
    /// The available substitute for HOST_DATA on a platform that does not expose it. Weaker in a
    /// specific way: PCR 23 is resettable inside the guest, so this binds what the workload
    /// <em>claimed</em> at startup, hardware-endorsed, rather than what the hypervisor measured at
    /// launch. Only meaningful on the vTPM evidence path.
    /// </remarks>
    public byte[]? ExpectedManifestPcr { get; init; }
}

public sealed record VerificationStep(string Name, bool Passed, string Detail);

public sealed record VerificationOutcome(bool Trusted, IReadOnlyList<VerificationStep> Steps, SnpAttestationReport? Report)
{
    public IEnumerable<VerificationStep> Failures => Steps.Where(s => !s.Passed);
}

/// <summary>
/// Runs the full appraisal of an attestation document against an observed TLS key.
/// </summary>
public static class AttestationVerifier
{
    /// <summary>
    /// Verifies <paramref name="document"/> and returns a per-step outcome.
    /// </summary>
    /// <param name="document">Evidence returned by the server.</param>
    /// <param name="observedSpkiDer">
    /// SubjectPublicKeyInfo captured from the client's own TLS handshake. This must not come from the
    /// document — see the remarks on <see cref="AttestationDocument"/>.
    /// </param>
    /// <param name="sentNonce">The nonce this client generated for this exchange.</param>
    /// <param name="pinnedArk">The AMD root, loaded from local disk.</param>
    public static VerificationOutcome Verify(
        AttestationDocument document,
        byte[] observedSpkiDer,
        byte[] sentNonce,
        X509Certificate2 pinnedArk,
        AttestationPolicy policy)
    {
        var steps = new List<VerificationStep>();

        // --- 1. Structural parse ------------------------------------------------------------------

        SnpAttestationReport report;
        try
        {
            report = SnpAttestationReport.Parse(Convert.FromBase64String(document.Report));
            steps.Add(new("Report parses", true, $"{SnpAttestationReport.Size} bytes, version {report.Version}"));
        }
        catch (Exception ex)
        {
            steps.Add(new("Report parses", false, ex.Message));
            return new VerificationOutcome(false, steps, null);
        }

        // --- 2. Signing key kind ------------------------------------------------------------------

        if (report.SigningKeyKind != 0)
        {
            var kind = report.SigningKeyKind switch
            {
                1 => "VLEK (CSP-endorsed key)",
                7 => "none",
                var other => $"unknown ({other})",
            };

            steps.Add(new("Signed by VCEK", false,
                $"Report is signed with {kind}; this verifier only handles VCEK."));
            return new VerificationOutcome(false, steps, report);
        }

        steps.Add(new("Signed by VCEK", true, "SIGNING_KEY = 0"));

        // --- 3. The binding -----------------------------------------------------------------------
        // This is the step that makes the exchange meaningful. Everything else could pass while the
        // client talks to an ordinary server relaying someone else's genuine report.
        //
        // How the binding is established depends on the platform, because a paravisor-backed Azure CVM
        // does not let the guest choose REPORT_DATA. The end claim is identical either way; only the
        // number of links differs. An unrecognised evidence kind is a hard failure — silently treating
        // it as one of the known shapes would mean verifying something other than what was sent.

        switch (document.EvidenceKind)
        {
            case EvidenceKinds.ConfigFsTsm:
            {
                var expectedReportData = ComputeExpectedReportData(observedSpkiDer, sentNonce);
                var bindingOk = CryptographicOperations.FixedTimeEquals(expectedReportData, report.ReportData);

                steps.Add(new(
                    "REPORT_DATA binds the TLS key",
                    bindingOk,
                    bindingOk
                        ? "SHA-512(observed TLS SPKI || nonce) == REPORT_DATA"
                        : "MISMATCH. The report does not commit to the key that terminated this TLS " +
                          "connection. Either the server is relaying evidence from a different machine, or " +
                          $"the nonce was not honoured. Expected {Convert.ToHexStringLower(expectedReportData)[..32]}…, " +
                          $"got {Convert.ToHexStringLower(report.ReportData)[..32]}…"));
                break;
            }

            case EvidenceKinds.AzureVtpm:
            {
                var vtpm = VtpmEvidenceVerifier.Verify(
                    document, report, observedSpkiDer, sentNonce, policy.ExpectedManifestPcr);
                steps.AddRange(vtpm.Steps);
                break;
            }

            default:
                steps.Add(new("Evidence kind recognised", false,
                    $"Server reported evidenceKind \"{document.EvidenceKind}\", which this client does " +
                    "not implement. Refusing to guess how the report is bound to this connection."));
                return new VerificationOutcome(false, steps, report);
        }

        // --- 4. Nonce echo ------------------------------------------------------------------------

        var nonceEchoOk = document.Nonce == System.Buffers.Text.Base64Url.EncodeToString(sentNonce);
        steps.Add(new("Nonce echoed", nonceEchoOk,
            nonceEchoOk ? "Server echoed the nonce we sent" : "Server echoed a different nonce"));

        // --- 5. Certificate chain to the pinned AMD root ------------------------------------------

        X509Certificate2 vcek;
        X509Certificate2Collection intermediates;
        try
        {
            var vcekCollection = VcekChainVerifier.LoadPemBundle(document.VcekPem);
            if (vcekCollection.Count == 0)
            {
                steps.Add(new("VCEK parses", false, "No certificate found in vcekPem."));
                return new VerificationOutcome(false, steps, report);
            }

            vcek = vcekCollection[0];
            intermediates = VcekChainVerifier.LoadPemBundle(document.CertChainPem);
            steps.Add(new("VCEK parses", true, $"Subject: {vcek.Subject}"));
        }
        catch (Exception ex)
        {
            steps.Add(new("VCEK parses", false, ex.Message));
            return new VerificationOutcome(false, steps, report);
        }

        var chainResult = VcekChainVerifier.VerifyChain(vcek, intermediates, pinnedArk);
        steps.Add(new("Chains to pinned AMD root", chainResult.Ok,
            chainResult.Ok ? string.Join("; ", chainResult.Notes) : chainResult.Failure!));

        var extResult = VcekChainVerifier.CrossCheckExtensions(vcek, report);
        steps.Add(new("VCEK matches chip and TCB", extResult.Ok,
            extResult.Ok ? string.Join("; ", extResult.Notes) : extResult.Failure!));

        // --- 6. Report signature ------------------------------------------------------------------

        var signatureOk = ReportSignatureVerifier.Verify(report, vcek, out var signatureFailure);
        steps.Add(new("Report signature valid", signatureOk,
            signatureOk ? "ECDSA P-384/SHA-384 over bytes 0x000–0x29F" : signatureFailure!));

        // --- 7. Guest policy ---------------------------------------------------------------------

        steps.Add(new("Debugging disabled", !report.PolicyDebugAllowed,
            report.PolicyDebugAllowed
                ? "Guest policy permits debugging — memory is inspectable by the host, so no " +
                  "confidentiality claim survives."
                : "POLICY.DEBUG = 0"));

        if (policy.RequireSmtDisabled)
        {
            steps.Add(new("SMT disabled", !report.PolicySmtAllowed,
                report.PolicySmtAllowed
                    ? "Guest policy permits SMT; sibling-thread side channels are in scope."
                    : "POLICY.SMT = 0"));
        }

        // --- 8. TCB floor ------------------------------------------------------------------------

        if (policy.MinimumTcb is { } floor)
        {
            var tcbOk = report.ReportedTcb.AtLeast(floor);
            steps.Add(new("TCB at or above floor", tcbOk,
                tcbOk
                    ? $"REPORTED_TCB {report.ReportedTcb} >= {floor}"
                    : $"REPORTED_TCB {report.ReportedTcb} is below the required {floor}; the platform " +
                      "may be exposed to a patched vulnerability."));
        }
        else
        {
            steps.Add(new("TCB at or above floor", true,
                $"No floor configured (observed {report.ReportedTcb}) — see README on why this matters"));
        }

        // --- 9. HOST_DATA -------------------------------------------------------------------------

        if (policy.ExpectedHostData is { } expectedHostData)
        {
            var hostDataOk = CryptographicOperations.FixedTimeEquals(expectedHostData, report.HostData);

            steps.Add(new("HOST_DATA matches", hostDataOk,
                hostDataOk
                    ? $"HOST_DATA == {Convert.ToHexStringLower(expectedHostData)}"
                    : $"HOST_DATA is {Convert.ToHexStringLower(report.HostData)}, expected " +
                      $"{Convert.ToHexStringLower(expectedHostData)}. " +
                      (report.HostData.ContainsAnyExcept((byte)0)
                          ? "The VM was launched with a different HOST_DATA."
                          : "HOST_DATA is all zeroes, which means the platform did not set it — standard " +
                            "Azure CVMs do not expose this field. Use --manifest instead; see README.")));
        }
        else if (report.HostData.ContainsAnyExcept((byte)0))
        {
            // Worth surfacing: the platform bound something here and the client is ignoring it.
            steps.Add(new("HOST_DATA matches", true,
                $"NOT CHECKED — HOST_DATA is non-zero ({Convert.ToHexStringLower(report.HostData)}). " +
                "This platform binds a launch-time value; consider pinning it with --expect-host-data."));
        }

        // --- 10. Measurement ----------------------------------------------------------------------

        if (policy.AllowedMeasurements.Count > 0)
        {
            var measurementOk = policy.AllowedMeasurements.Any(
                allowed => allowed.AsSpan().SequenceEqual(report.Measurement));

            steps.Add(new("Measurement allow-listed", measurementOk,
                measurementOk
                    ? "MEASUREMENT matches a configured value"
                    : $"MEASUREMENT {Convert.ToHexStringLower(report.Measurement)} is not in the allow-list."));
        }
        else
        {
            steps.Add(new("Measurement allow-listed", true,
                "NOT CHECKED — no allow-list configured. This exchange therefore proves the server " +
                "runs in *a* genuine SEV-SNP VM, not that it runs the code you expect."));
        }

        var trusted = steps.All(s => s.Passed);
        return new VerificationOutcome(trusted, steps, report);
    }

    /// <summary>
    /// REPORT_DATA the server should have used: SHA-512(SPKI || nonce). Mirrors TlsIdentity.
    /// </summary>
    private static byte[] ComputeExpectedReportData(byte[] spkiDer, byte[] nonce)
    {
        var buffer = new byte[spkiDer.Length + nonce.Length];
        spkiDer.CopyTo(buffer.AsSpan());
        nonce.CopyTo(buffer.AsSpan(spkiDer.Length));
        return SHA512.HashData(buffer);
    }
}
