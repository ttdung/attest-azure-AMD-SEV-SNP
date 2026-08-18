// ---------------------------------------------------------------------------------------------
// Self-test for the Azure vTPM (two-hop) verification path.
//
// The vTPM path can only be exercised end-to-end on a paravisor-backed Azure CVM, which makes it
// exactly the code most likely to ship broken. These checks build synthetic-but-structurally-real
// evidence — a genuine RSA attestation key, a hand-assembled TPMS_ATTEST, an HCL report whose
// REPORT_DATA really is SHA-256(runtime_data) — and assert that the verifier accepts a correct
// exchange and rejects each way it can be subverted.
//
// The negative cases are the point. "NEG different TLS key (relay)" is the attack the whole design
// exists to stop; if that one ever passes, the protocol is decoration.
//
// Note what this does NOT cover: the AMD certificate chain and the SNP report signature (tested
// separately against real AMD certificates), and whether Azure's actual NV index layout matches
// HclReport's assumptions. The latter is only knowable on real hardware, which is why HclReport
// derives the runtime-data offset by search and then proves it via the REPORT_DATA hash rather than
// trusting a constant.
//
//   dotnet run --project SelfTest
// ---------------------------------------------------------------------------------------------

using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using SevSnpDemo.Client;
using SevSnpDemo.Server;
using SevSnpDemo.Shared;

int failures = 0;
void Check(string label, bool actual, bool expected, string? detail = null)
{
    var ok = actual == expected;
    if (!ok) failures++;
    Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {label} (got {actual}, want {expected})");
    if (detail is not null && !ok) Console.WriteLine($"         {detail}");
}

// ---- synthetic fixture -----------------------------------------------------------------------
using var ak = RSA.Create(2048);
var akParams = ak.ExportParameters(false);
string B64U(byte[] b) => Base64Url.EncodeToString(b);

var runtimeDataJson =
    $"{{\"keys\":[{{\"kid\":\"HCLAkPub\",\"key_ops\":[\"sign\"],\"kty\":\"RSA\",\"e\":\"{B64U(akParams.Exponent!)}\",\"n\":\"{B64U(akParams.Modulus!)}\"}}],\"vm-configuration\":{{\"secure-boot\":true}}}}";
var runtimeData = Encoding.UTF8.GetBytes(runtimeDataJson);

byte[] BuildSnpReport(byte[] rtData)
{
    var r = new byte[1184];
    BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(0x000), 2);      // Version
    BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(0x034), 1);      // SignatureAlgo = ECDSA P384
    SHA256.HashData(rtData).CopyTo(r.AsSpan(0x050));                   // REPORT_DATA[0..32]
    return r;
}

byte[] BuildHcl(byte[] report, byte[] rtData, int padding)
{
    var ms = new MemoryStream();
    var header = new byte[0x20];
    BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0), 0x414C4348); // "HCLA"
    BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), 2);
    BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), (uint)report.Length);
    BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12), 1);
    ms.Write(header); ms.Write(report); ms.Write(new byte[padding]); ms.Write(rtData);
    ms.Write(new byte[64]);   // trailing NUL padding, as on real hardware
    return ms.ToArray();
}

// PCR bitmap for the SHA-256 bank covering the given indices (bit i of byte j -> PCR j*8+i).
byte[] PcrBitmap(IEnumerable<int> indices)
{
    var map = new byte[3];
    foreach (var i in indices) map[i / 8] |= (byte)(1 << (i % 8));
    return map;
}

byte[] BuildAttest(byte[] extraData, uint magic = 0xFF544347, ushort type = 0x8018,
                   Dictionary<int, byte[]>? pcrs = null)
{
    var ms = new MemoryStream();
    var u32 = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(u32, magic); ms.Write(u32);
    var u16 = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(u16, type); ms.Write(u16);
    var signer = SHA256.HashData("qualified-signer"u8.ToArray());
    BinaryPrimitives.WriteUInt16BigEndian(u16, (ushort)(signer.Length + 2)); ms.Write(u16);
    ms.Write([0x00, 0x0B]); ms.Write(signer);                     // TPM2B_NAME: alg + digest
    BinaryPrimitives.WriteUInt16BigEndian(u16, (ushort)extraData.Length); ms.Write(u16);
    ms.Write(extraData);
    ms.Write(new byte[17]);                                        // clockInfo
    ms.Write(new byte[8]);                                         // firmwareVersion

    // TPML_PCR_SELECTION: count=1, SHA-256 bank, 3 bitmap bytes.
    pcrs ??= new Dictionary<int, byte[]>();
    var indices = pcrs.Keys.OrderBy(i => i).ToList();
    BinaryPrimitives.WriteUInt32BigEndian(u32, 1); ms.Write(u32);
    BinaryPrimitives.WriteUInt16BigEndian(u16, 0x000B); ms.Write(u16);
    ms.WriteByte(3); ms.Write(PcrBitmap(indices));

    // pcrDigest over the selected values, ascending index.
    var concat = indices.SelectMany(i => pcrs[i]).ToArray();
    var pcrDigest = SHA256.HashData(concat);
    BinaryPrimitives.WriteUInt16BigEndian(u16, (ushort)pcrDigest.Length); ms.Write(u16); ms.Write(pcrDigest);
    return ms.ToArray();
}

var spki = RandomNumberGenerator.GetBytes(91);
var nonce = RandomNumberGenerator.GetBytes(32);
byte[] Qualifying(byte[] s, byte[] n) => SHA256.HashData([.. s, .. n]);

AttestationDocument Doc(byte[] report, byte[] rtData, byte[] attest, byte[] sig,
    string alg = "rsassa-sha256", Dictionary<int, byte[]>? pcrs = null) => new()
{
    EvidenceKind = EvidenceKinds.AzureVtpm,
    Report = Convert.ToBase64String(report),
    VcekPem = "", CertChainPem = "", ServerSpki = Convert.ToBase64String(spki),
    Nonce = Base64Url.EncodeToString(nonce), CertSource = "test",
    RuntimeData = Convert.ToBase64String(rtData),
    AkQuote = Convert.ToBase64String(attest),
    AkQuoteSignature = Convert.ToBase64String(sig),
    AkQuoteSigAlg = alg,
    PcrValues = pcrs?.ToDictionary(kv => kv.Key, kv => Convert.ToHexStringLower(kv.Value)),
};

// ---- 1. HclReport.Parse across several padding widths -----------------------------------------
Console.WriteLine("HclReport.Parse (runtime-data offset must not be assumed)");
var snpReport = BuildSnpReport(runtimeData);
foreach (var pad in new[] { 0, 0x14, 0x20, 0x37 })
{
    try
    {
        var parsed = HclReport.Parse(BuildHcl(snpReport, runtimeData, pad));
        Check($"padding=0x{pad:X}: runtime data recovered exactly",
            parsed.RuntimeData.AsSpan().SequenceEqual(runtimeData), true);
    }
    catch (Exception ex) { Check($"padding=0x{pad:X}", false, true, ex.Message); }
}
try { HclReport.Parse(BuildHcl(BuildSnpReport("other"u8.ToArray()), runtimeData, 0x14)); Check("NEG mismatched REPORT_DATA rejected", false, true); }
catch (InvalidDataException) { Check("NEG mismatched REPORT_DATA rejected", true, true); }

// ---- 2. VtpmEvidenceVerifier ------------------------------------------------------------------
Console.WriteLine("\nVtpmEvidenceVerifier");
var report = SnpAttestationReport.Parse(snpReport);
var good = BuildAttest(Qualifying(spki, nonce));
var goodSig = ak.SignData(good, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

var r = VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, good, goodSig), report, spki, nonce);
Check("happy path accepted", r.Ok, true, string.Join("\n         ", r.Steps.Where(s => !s.Passed).Select(s => s.Name + ": " + s.Detail)));
foreach (var s in r.Steps) Console.WriteLine($"         · {s.Name}: {s.Detail}");

// negatives
var otherNonce = RandomNumberGenerator.GetBytes(32);
Check("NEG wrong nonce", VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, good, goodSig), report, spki, otherNonce).Ok, false);
Check("NEG different TLS key (relay)", VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, good, goodSig), report, RandomNumberGenerator.GetBytes(91), nonce).Ok, false);

using var evil = RSA.Create(2048);
var evilSig = evil.SignData(good, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
Check("NEG quote signed by non-attested key", VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, good, evilSig), report, spki, nonce).Ok, false);

Check("NEG wrong sig alg claimed", VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, good, goodSig, "rsapss-sha256"), report, spki, nonce).Ok, false);
Check("NEG unknown sig alg", VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, good, goodSig, "made-up"), report, spki, nonce).Ok, false);

var badMagic = BuildAttest(Qualifying(spki, nonce), magic: 0xDEADBEEF);
Check("NEG bad TPM_GENERATED_VALUE", VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, badMagic, ak.SignData(badMagic, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)), report, spki, nonce).Ok, false);

var wrongType = BuildAttest(Qualifying(spki, nonce), type: 0x8017);
Check("NEG not an ATTEST_QUOTE", VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, wrongType, ak.SignData(wrongType, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)), report, spki, nonce).Ok, false);

var tamperedRt = Encoding.UTF8.GetBytes(runtimeDataJson.Replace("\"secure-boot\":true", "\"secure-boot\":fals"));
Check("NEG tampered runtime_data", VtpmEvidenceVerifier.Verify(Doc(snpReport, tamperedRt, good, goodSig), report, spki, nonce).Ok, false);

var noAk = Encoding.UTF8.GetBytes("{\"keys\":[{\"kid\":\"HCLEkPub\",\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"AAA\"}]}");
Check("NEG runtime_data without HCLAkPub", VtpmEvidenceVerifier.Verify(Doc(BuildSnpReport(noAk), noAk, good, goodSig), SnpAttestationReport.Parse(BuildSnpReport(noAk)), spki, nonce).Ok, false);

var missing = Doc(snpReport, runtimeData, good, goodSig) with { AkQuote = null };
Check("NEG missing quote entirely", VtpmEvidenceVerifier.Verify(missing, report, spki, nonce).Ok, false);

// ---- 3. manifest binding via PCR 23 -----------------------------------------------------------
Console.WriteLine("\nManifest binding (PCR 23)");

var manifestDigest = SHA256.HashData("my-app-manifest-v1\n"u8.ToArray());
byte[] ExpectedPcr(byte[] d) => SHA256.HashData([.. new byte[32], .. d]);

// Boot PCRs 0-7 plus PCR 23 carrying the manifest, as the server produces.
Dictionary<int, byte[]> PcrSet(byte[] pcr23)
{
    var d = new Dictionary<int, byte[]>();
    for (var i = 0; i < 8; i++) d[i] = SHA256.HashData([(byte)i]);
    d[23] = pcr23;
    return d;
}

var goodPcrs = PcrSet(ExpectedPcr(manifestDigest));
var mAttest = BuildAttest(Qualifying(spki, nonce), pcrs: goodPcrs);
var mSig = ak.SignData(mAttest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
var expectedPcr23 = ExpectedPcr(manifestDigest);

var mOk = VtpmEvidenceVerifier.Verify(
    Doc(snpReport, runtimeData, mAttest, mSig, pcrs: goodPcrs), report, spki, nonce, expectedPcr23);
Check("manifest binding accepted", mOk.Ok, true,
    string.Join("\n         ", mOk.Steps.Where(s => !s.Passed).Select(s => s.Name + ": " + s.Detail)));
foreach (var s in mOk.Steps.Where(s => s.Name.Contains("manifest"))) Console.WriteLine($"         · {s.Detail}");

// Wrong manifest on the server side.
var otherDigest = SHA256.HashData("my-app-manifest-v2\n"u8.ToArray());
var wrongPcrs = PcrSet(ExpectedPcr(otherDigest));
var wAttest = BuildAttest(Qualifying(spki, nonce), pcrs: wrongPcrs);
var wSig = ak.SignData(wAttest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
Check("NEG server running a different manifest",
    VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, wAttest, wSig, pcrs: wrongPcrs),
        report, spki, nonce, expectedPcr23).Ok, false);

// PCR 23 never bound (left at zero) - the "forgot SEVSNP_MANIFEST" case.
var unboundPcrs = PcrSet(new byte[32]);
var uAttest = BuildAttest(Qualifying(spki, nonce), pcrs: unboundPcrs);
var uSig = ak.SignData(uAttest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
Check("NEG PCR 23 never bound",
    VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, uAttest, uSig, pcrs: unboundPcrs),
        report, spki, nonce, expectedPcr23).Ok, false);

// THE IMPORTANT ONE: correct PCR values in the document, but pcrDigest signed over different ones.
// A verifier that trusted PcrValues without recomputing the digest would accept this.
Check("NEG PcrValues swapped without re-signing",
    VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, wAttest, wSig, pcrs: goodPcrs),
        report, spki, nonce, expectedPcr23).Ok, false);

// Server sent no PCR values at all while a manifest was expected.
Check("NEG manifest expected but no PcrValues",
    VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, mAttest, mSig), report, spki, nonce,
        expectedPcr23).Ok, false);

// A PCR the quote covers is missing from the document.
var partial = goodPcrs.Where(kv => kv.Key != 3).ToDictionary(kv => kv.Key, kv => kv.Value);
Check("NEG covered PCR missing from PcrValues",
    VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, mAttest, mSig, pcrs: partial),
        report, spki, nonce, expectedPcr23).Ok, false);

// No manifest policy configured -> the check is skipped, everything else still passes.
Check("manifest check skipped when not configured",
    VtpmEvidenceVerifier.Verify(Doc(snpReport, runtimeData, mAttest, mSig, pcrs: goodPcrs),
        report, spki, nonce).Ok, true);

// ---- 4. server and client must agree on the PCR 23 formula -------------------------------------
Console.WriteLine("\nPCR 23 expectation formula (server/client agreement)");

// The client computes this inline; the server computes it via ExpectedManifestPcr. They must match,
// and both must extend the manifest digest VERBATIM. Extending SHA-256(digest) instead -- which is
// what Tpm2Lib's TpmHash.FromData does, since it hashes its argument -- yields a value no client can
// reproduce. That bug shipped once; this check exists so it cannot ship again.
var probe = SHA256.HashData("manifest-probe"u8.ToArray());
var serverSide = SevSnpDemo.Server.VtpmEvidenceProvider.ExpectedManifestPcr(probe);
var clientSide = SHA256.HashData([.. new byte[32], .. probe]);
var doubleHashed = SHA256.HashData([.. new byte[32], .. SHA256.HashData(probe)]);

Check("server formula == client formula", serverSide.SequenceEqual(clientSide), true,
    $"server={Convert.ToHexStringLower(serverSide)} client={Convert.ToHexStringLower(clientSide)}");
Check("formula uses the digest verbatim, not re-hashed",
    serverSide.SequenceEqual(doubleHashed), false,
    "ExpectedManifestPcr is hashing the manifest digest a second time");

Console.WriteLine($"\n{(failures == 0 ? "ALL CHECKS PASSED" : $"{failures} CHECK(S) FAILED")}");
return failures == 0 ? 0 : 1;
