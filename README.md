# Attested "Hello" over AMD SEV-SNP

A minimal, self-contained server/client pair that answers one question:

> How does a client know that the server it just connected to is really running inside an AMD
> SEV-SNP confidential VM — and not merely *claiming* to?

The server does almost nothing on purpose. `GET /hello` returns the string `Hello`. The interesting
part is `GET /attestation`, and the fact that the client refuses to send the `/hello` request until
the evidence checks out.

```
Client                                                        Server (inside SEV-SNP CVM)
──────                                                        ───────────────────────────
                                                              on startup:
                                                                generate ECDSA P-256 TLS key
                                                                in guest memory, never persisted

 TLS handshake ──────────────────────────────────────────────►
 ◄────────────────────────── self-signed cert (NOT CA-validated)
   capture the server's SubjectPublicKeyInfo (SPKI)

 nonce ← 32 random bytes
 GET /attestation?nonce=... ────────────────────────────────►
                                                              REPORT_DATA = SHA-512(SPKI ‖ nonce)
                                                              ask the AMD PSP for a report over it
                                                              fetch VCEK + ASK/ARK (THIM, else KDS)
 ◄──────────── { report, vcekPem, certChainPem, nonce, ... }

 verify (ordered steps, see below), the load-bearing one being:
     SHA-512(the SPKI I observed ‖ the nonce I sent) == REPORT_DATA in the signed report

 if and only if every step passes:
 GET /hello ────────────────────────────────────────────────►
 ◄──────────────────────────────────────────────── "Hello"
```

That is the direct (`configfs-tsm`) shape. Azure CVMs cannot supply their own `REPORT_DATA`, so they
use a three-link variant through the vTPM — same end claim, one more hop. See
[Two evidence paths](#two-evidence-paths-because-azure-does-not-let-the-guest-choose-report_data).

---

## Why the TLS certificate is self-signed on purpose

A CA-issued certificate would prove that someone controlled a DNS name. That is not the claim we
want. We want: *the private key terminating this TLS connection lives inside a specific,
measured, genuine SEV-SNP guest.* Only AMD's hardware can attest to that, so AMD's signature —
not a CA's — is the trust root here. The client sets
`ServerCertificateCustomValidationCallback` to accept any certificate and then decides based on
the attestation report, which is a strictly stronger check than PKI validation.

## The attack this defends against, and how

The naive version of this demo — server calls the attestation tooling, returns the report, client
verifies the AMD signature — is **broken**. It is vulnerable to a *relay* (or "attestation
transplant"):

> Mallory runs an ordinary, non-confidential server. She rents one real SEV-SNP CVM on the side, or
> simply saves a report someone published. When a client asks for evidence, she forwards that
> genuine report. Every AMD signature check passes. The client concludes it is talking to a
> confidential VM. It is not.

The fix is a **channel binding**. SEV-SNP lets the guest supply 64 bytes of `REPORT_DATA` that the
secure processor includes inside the signed region of the report. This code puts the TLS public key
there:

```
REPORT_DATA = SHA-512( TLS_SubjectPublicKeyInfo_DER ‖ client_nonce )
```

and the client recomputes it **from the certificate it observed in its own handshake** — never from
the `serverSpki` field the server helpfully includes in the JSON. That one detail is the whole
security argument. A relayed report commits to the *other* machine's key, so the comparison fails.
Mallory cannot produce a report over her own key, because she has no SEV-SNP guest holding it.

The `nonce` on top makes each report fresh, so a report captured earlier from the same server
cannot be replayed after that server's key has been compromised.

> **`AttestationDocument.ServerSpki` is a diagnostic field only.** It exists so a failed comparison
> can be debugged. `AttestationVerifier` never reads it. If you extend this code, do not start.

## Two evidence paths, because Azure does not let the guest choose `REPORT_DATA`

The argument above assumes the guest can put whatever it likes in `REPORT_DATA`. On a bare SEV-SNP
guest it can. On an **Azure confidential VM it usually cannot**, and that changes the shape of the
protocol — so this code implements both and the server picks at startup.

Azure CVMs boot behind the **OpenHCL paravisor**, which owns VMPL0 and mediates the PSP. The guest
gets no `/dev/sev-guest`; `/sys/kernel/config/tsm/report` may exist (the kernel's `tsm` core is
loaded) while no provider is bound to it, so `mkdir` there fails with `ENXIO`. There is no way to
request a report with guest-chosen `REPORT_DATA`.

What Azure gives you instead is a **static** SNP report, written once at boot into vTPM NV index
`0x01400001`, whose `REPORT_DATA` is `SHA-256(runtime_data) ‖ 32 zero bytes` — where `runtime_data`
is a JSON document naming the vTPM's attestation key. The binding to your TLS key therefore takes
one more link:

```
                         evidenceKind = "configfs-tsm"          evidenceKind = "azure-vtpm"
                         ─────────────────────────────          ───────────────────────────
AMD hardware signs  ───► SNP report                             SNP report  (static, boot-time)
                           REPORT_DATA =                          REPORT_DATA = SHA-256(runtime_data)
                           SHA-512(SPKI ‖ nonce)                          │
                                 │                                        ▼
                                 │                              runtime_data JSON
                                 │                                contains AK pubkey (JWK "HCLAkPub")
                                 │                                        │
                                 │                                        │ TPM2_Quote, extraData =
                                 │                                        │   SHA-256(SPKI ‖ nonce)
                                 ▼                                        ▼
                          your TLS key                              your TLS key
                          (1 hop, fresh)                            (3 links, fresh at the quote)
```

The anti-relay property survives. Mallory still cannot produce a quote, because that needs an AK
whose public half appears in `runtime_data` inside a report the AMD chain signs — i.e. an actual
vTPM inside an actual CVM. The AK's private half is non-exportable.

Two consequences worth stating plainly:

- **On the vTPM path the SNP report is identical on every request.** All freshness comes from the
  quote. A verifier that checked the report and skipped the quote would accept an indefinitely old
  replay — which is why `VtpmEvidenceVerifier` treats a missing quote as a hard failure rather than
  degrading to "report looks fine".
- **`runtime_data` must be forwarded byte-for-byte.** `REPORT_DATA` is the hash of exact bytes;
  re-serialising the JSON changes it. `HclReport` extracts the precise extent with a JSON reader
  rather than slicing on a brace, and then *proves* the extent is right by checking the hash.

The client refuses to verify an `evidenceKind` it does not recognise, rather than guessing which
shape to apply.

## Binding your workload identity

Everything above proves *where* the server runs. It says nothing about *what* is running there — a
genuine CVM containing entirely different code passes every check. Closing that gap means committing
to a workload identity inside the signed evidence. There are two places to put it, and they are not
equivalent.

### `HOST_DATA` — the strong option, if your platform exposes it

`HOST_DATA` is 32 bytes fixed by the hypervisor at `SNP_LAUNCH_FINISH`. It is immutable for the VM's
lifetime and **nothing inside the guest can change it at any privilege level**. That makes it the
right home for a workload identity.

The catch: *you* do not set it — the platform does.

| Platform | Can you set `HOST_DATA`? |
| -------- | ------------------------ |
| Azure Confidential Containers (AKS / ACI, Kata CoCo) | Yes — Azure sets it to the CCE security-policy hash |
| Standard Azure CVM (DCasv5/6, ECasv5/6) | **No.** Not exposed; reads all zeroes |
| Your own SEV-SNP host, or any hypervisor you control | Yes, at launch |

So on a standard Azure CVM this is unavailable, and the observed all-zeroes `HOST_DATA` is the
platform declining to bind anything, not a bug. The check is implemented anyway, because it costs
nothing and is what you want the moment you move to a platform that does support it:

```bash
--expect-host-data <64-hex-chars>
```

The client also *notices* a non-zero `HOST_DATA` you are not pinning and says so, rather than letting
a platform-supplied binding pass unexamined.

### Manifest in PCR 23 — what works on a standard Azure CVM

The available substitute. At startup the server does `PCR_Reset(23)` then
`PCR_Extend(23, SHA-256(manifest))`, and every quote covers PCR 23. Since the AK signing that quote is
endorsed by the SNP report, the chain reaches from AMD hardware to "this workload declared manifest X":

```
AMD hardware ─signs─► SNP report ─commits─► runtime_data ─names─► AK ─signs─► quote
                                                                              ├─ extraData → TLS key + nonce
                                                                              └─ pcrDigest → PCR 23 → manifest
```

Server:

```bash
# Write the manifest OUTSIDE the tree being hashed. Redirecting into it is self-referential:
# the shell creates the file before `find` runs, so it hashes itself while empty and the
# manifest never verifies afterwards.
cd ~/attested-hello
find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > ~/manifest.txt

sudo SEVSNP_EVIDENCE=vtpm SEVSNP_MANIFEST=$HOME/manifest.txt ~/attested-hello/Server
```

Then copy that exact file to the client — the digest is over the file's bytes, so both sides need it
byte-identical:

```bash
scp azureuser@<cvm>:~/manifest.txt ./manifest.txt
```

Client — hashing **its own copy**, so the server cannot choose what it is measured against:

```bash
dotnet run --project Client -- --url https://<cvm>:8443 --ark amd/ark.pem \
  --manifest ./manifest.txt
```

Or `--expect-manifest <64-hex-chars>` when the digest comes from a build system rather than a file.
`SEVSNP_MANIFEST_HASH` is the server-side equivalent.

`-print0` / `-z` / `-0` keep paths containing spaces intact. The manifest is a *file*, deliberately
— not a directory walk. Hashing a tree means both sides must
agree on traversal order, symlink policy, permission bits, and mtimes; every one of those is a way to
produce a mismatch that looks like an attack. Moving that decision into a shell script you can read
makes the comparison exact.

### Choosing what to put in the manifest

Hashing the whole publish tree is the most complete option and the most brittle: a self-contained
publish is several hundred files, and any rebuild changes bytes inside the assemblies, so the manifest
becomes per-deployment rather than per-source-version.

A narrower manifest is often the better trade:

```bash
cd "$APPDIR"
for f in Server.dll Server.runtimeconfig.json Server.deps.json; do
  [ -f "$f" ] || { echo "MISSING: $f"; exit 1; }
done
sha256sum Server.dll Server.runtimeconfig.json Server.deps.json > ~/manifest.txt
```

Naming files explicitly gives a deterministic order with no `sort`, and the existence loop is not
ceremony: a renamed or missing file would otherwise silently shrink the manifest, and a shorter
manifest still hashes to *something* the client accepts as valid.

Be explicit about what a narrow manifest gives up:

- **The runtime is not covered.** A self-contained deployment ships `libcoreclr.so` and friends beside
  your assembly. Hashing `Server.dll` alone means anyone who can write to that directory could swap the
  runtime underneath it and the manifest would still verify. The whole-tree manifest does cover this.
- **Environment variables are never covered.** This server is configured entirely through `SEVSNP_*`
  env vars, so no file hash constrains them — and it has no `appsettings.json` at all. Adding one to a
  manifest would look like covering configuration while covering none of the settings that actually
  change behaviour. If configuration matters to your relying party, write the effective values into the
  manifest file itself rather than assuming a config file implies them.

### How much weaker is PCR 23?

Precisely this much: **PCR 23 is resettable at locality 0, so root inside the guest can reset and
re-extend it with any digest.** `HOST_DATA` cannot be touched from inside the guest at all.

So the PCR binding defends against a **dishonest host** — the confidential-computing threat model,
where the host cannot forge a quote because the AK lives in vTPM memory it cannot read — but not
against a **compromised guest userland**. It moves you from "nothing identifies the workload" to "the
workload's own claim is hardware-endorsed and cannot be forged by the host or by a relaying attacker."

That is a real improvement and it is the strongest binding this platform permits. It is not equivalent
to a launch-time measurement, and you should not describe it to a relying party as though it were. If
you need the stronger property, the route is Confidential Containers (where `HOST_DATA` carries the
policy hash) or a host you control.

Two implementation details that carry weight:

- **PCR values are verified, not trusted.** The quote signs only `pcrDigest`. The client recomputes it
  from the transmitted values *using the selection parsed out of the signed quote*, and only then
  compares PCR 23. Checking PCR 23 against unverified values first would be theatre — the self-test
  covers exactly that attack (`NEG PcrValues swapped without re-signing`).
- **The binding happens once, at startup.** A reset concurrent with an in-flight quote would race, and
  re-extending per request would produce a different value every time. The server verifies the PCR
  landed on the expected value and refuses to start if not.

## What this proves — and what it does not

**Proves, with the default configuration:**

- The report was produced by a genuine AMD secure processor whose VCEK chains to the AMD root key
  you pinned locally (`amd/ark.pem`).
- That processor is running the SEV-SNP firmware at the TCB level stated in the report.
- The guest's launch policy has **debugging disabled**, so the host cannot read guest memory.
- The TLS private key you are talking to lives inside *that* guest.

**Does not prove, unless you configure it:**

- **Which software is running.** `MEASUREMENT` is the hash of the initial guest memory (firmware +
  kernel + initrd + cmdline). Without `--expect-measurement`, the client reports it and moves on.
  Someone could run a genuine CVM containing entirely different code. The client prints a loud note
  when the allow-list is empty; this is the single largest gap between this PoC and production.
- **That the platform is patched.** Without `--min-tcb`, an old, vulnerable firmware level is
  accepted. `REPORTED_TCB` is printed either way.
- **That the running process is the measured one.** `MEASUREMENT` covers boot state, not what
  happened afterwards. A CVM that boots a measured image and then `curl | bash`-es something is
  still a genuine CVM. Closing that gap needs a measured boot chain (dm-verity root, IMA, or a
  vTPM-backed runtime measurement) — out of scope here.
- **Anything about MEASUREMENT on Azure specifically.** Azure CVMs boot through a Microsoft
  paravisor, so `MEASUREMENT` covers Microsoft's boot stack, not your application. Binding your
  application identity requires `HOST_DATA` or a runtime measurement — see
  [Hardening](#hardening--known-limitations). Observed on a DCasv6/Genoa CVM: `HOST_DATA` is all
  zeroes, so nothing there identifies the workload by default.
- **Anything from the `VMPL` field.** It reports the privilege level of whoever *requested* the
  report. On an Azure paravisor CVM it reads **0**, because the paravisor requested it at VMPL0 —
  which is exactly why the guest cannot choose `REPORT_DATA`. Reading 0 is therefore not evidence
  that your code runs at VMPL0; it is a hint that your code did not request this report at all.

On the **vTPM path** specifically, two further limits apply:

- **`MEASUREMENT` describes the paravisor's boot stack, not your application** — so an allow-list is
  much less useful there than on a bare guest. `HOST_DATA` or a runtime measurement is the route to
  binding your own code identity.
- **The trust chain includes the vTPM.** The claim becomes "the AMD chain endorses an AK held by this
  VM's vTPM, and that AK signed a commitment to this TLS key." That is one component wider than the
  configfs path, where AMD signs the TLS-key commitment directly. It is the strongest binding the
  platform permits, not the strongest binding that exists.

Being explicit about this is deliberate. A verifier that quietly skips the measurement check while
printing "ATTESTATION OK" is worse than no verifier, because it manufactures confidence.

---

## Layout

```
SEV-SNP/
├── Shared/
│   └── AttestationDocument.cs      Wire format (JSON) — the evidence bundle
├── Server/                          runs INSIDE the CVM (Linux only)
│   ├── TlsIdentity.cs              Ephemeral in-memory TLS key + both binding computations
│   ├── SnpReportProvider.cs        configfs-tsm path: reports straight from the AMD PSP
│   ├── VtpmEvidenceProvider.cs     Azure path: vTPM NV read + TPM2_Quote
│   ├── HclReport.cs                Splits Azure's HCL blob into SNP report + runtime data
│   ├── AmdCertificateProvider.cs   VCEK + chain, from Azure THIM with AMD KDS fallback
│   └── Program.cs                  Kestrel, /hello and /attestation, evidence-source selection
├── Client/                          runs ANYWHERE
│   ├── SnpAttestationReport.cs     1184-byte ABI struct parser
│   ├── ReportSignatureVerifier.cs  ECDSA P-384/SHA-384 over bytes 0x000–0x29F
│   ├── CertificateChain.cs         Manual X.509 path validation (AMD signs with RSA-PSS)
│   ├── VcekChainVerifier.cs        VCEK → ASK → pinned ARK, plus extension cross-checks
│   ├── TpmAttest.cs                TPMS_ATTEST reader (no TPM library needed)
│   ├── VtpmEvidenceVerifier.cs     The three-link Azure chain
│   ├── AttestationVerifier.cs      The appraisal policy; branches on evidenceKind
│   └── Program.cs                  CLI: connect, capture SPKI, verify, then /hello
├── SelfTest/
│   └── Program.cs                  Synthetic-vector tests for the vTPM path
└── amd/
    └── README.md                   How to obtain and independently verify the pinned ARK
```

One NuGet dependency, and only on the server: **`Microsoft.TSS`** (Microsoft's official TSS.MSR
managed TPM stack), needed for the Azure vTPM path's NV read and `TPM2_Quote`. The client has no TPM
dependency at all — the AK arrives as a JWK, so plain `RSA` verification suffices. Everything else
(ASN.1, ECDSA, RSA-PSS, path validation) is the .NET base class library.

### Self-test

The vTPM path can only run end-to-end on a paravisor-backed Azure CVM, which makes it the code most
likely to ship broken. `SelfTest` builds structurally-real synthetic evidence — a genuine RSA
attestation key, a hand-assembled `TPMS_ATTEST`, an HCL report whose `REPORT_DATA` really is
`SHA-256(runtime_data)` — and asserts the verifier accepts a correct exchange and rejects every way
it can be subverted:

```bash
dotnet run --project SelfTest
```

23 checks, including `NEG different TLS key (relay)` — the attack the whole design exists to stop —
and `NEG PcrValues swapped without re-signing`, which catches a verifier that trusts PCR values
instead of recomputing the signed digest over them.
It does **not** cover the AMD chain or report signature (those are verified against real AMD
certificates), nor whether Azure's actual NV layout matches `HclReport`'s assumptions, which is only
knowable on hardware.

---

## Prerequisites

### The server needs a real SEV-SNP guest

Common to both paths:

| Requirement | Check |
| ----------- | ----- |
| SEV-SNP actually active | `dmesg \| grep -i sev` → `Memory Encryption Features active: AMD SEV-SNP` |
| Root | `sudo` — both configfs and `/dev/tpmrm0` need it |
| .NET 10 SDK, *or* publish self-contained (below) | `dotnet --version` |

For the **configfs-tsm** path (bare SEV-SNP guest, no paravisor):

| Requirement | Check |
| ----------- | ----- |
| Linux 6.7+ with `CONFIG_TSM_REPORTS` | `uname -r` |
| configfs mounted | `mount -t configfs none /sys/kernel/config` |
| A TSM provider actually bound | `sudo mkdir /sys/kernel/config/tsm/report/t && cat /sys/kernel/config/tsm/report/t/provider` |

That last row is the one that bites. The directory exists whenever the kernel's `tsm` core is loaded,
**even with no provider bound**, so `ls` succeeding proves nothing — `mkdir` fails with `ENXIO`. The
server therefore probes by creating a real entry rather than calling `Directory.Exists`.

For the **azure-vtpm** path (Azure CVM behind the OpenHCL paravisor):

| Requirement | Check | Expected |
| ----------- | ----- | -------- |
| vTPM resource manager device | `ls -l /dev/tpmrm0` | exists |
| Azure HCL report present in NV | `sudo tpm2_nvreadpublic 0x01400001` | `size: 2600`, attributes include `ownerread` |
| Azure-provisioned AK | `sudo tpm2_getcap handles-persistent` | includes `0x81000003` |

`ownerread` in the NV attributes is what lets the server read the index with owner authorisation and
an empty password. `size: 2600` is larger than any TPM's single-read buffer, so the read is chunked at
whatever `TPM_PT_NV_BUFFER_MAX` reports (queried, not assumed — a chunk above the limit is rejected
outright).

The server **refuses to start** if neither path works, and logs the diagnosis for both. That is
intentional: a demo that silently serves unattested traffic when the hardware is missing teaches
exactly the wrong lesson.

Auto-detection prefers configfs-tsm, because it binds the TLS key in a single hardware-signed hop.
Force a path with `SEVSNP_EVIDENCE=configfs` or `SEVSNP_EVIDENCE=vtpm` — useful for confirming which
one your VM actually supports instead of inferring it from a fallback.

### The client needs the pinned AMD root

Follow [`amd/README.md`](amd/README.md) to produce `amd/ark.pem` and verify its fingerprint. The
client exits with a usage message (and status 2) if the file is absent — it will not fetch the
anchor for you.

---

## Build

```bash
dotnet build SevSnpDemo.sln
```

Warnings are errors in all three projects.

### Deploying the server to the CVM

Publishing self-contained means the CVM needs no .NET runtime installed, and the deployed tree is a
single self-consistent artifact:

```bash
dotnet publish Server -c Release -r linux-x64 --self-contained -o out/server

# Note the trailing /. and the -p. Without the dot, scp nests the directory inside an
# existing ~/attested-hello (giving ~/attested-hello/server/Server); without -p it may
# drop the executable bit.
scp -rp out/server/. azureuser@<cvm>:~/attested-hello/
```

The executable is named after the project, so it is `Server` with a capital S — the published
directory contains `Server` (the apphost) alongside `Server.dll` and the runtime.

On the CVM:

```bash
# Only matters for the configfs-tsm path; harmless otherwise.
sudo mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config

ls -l ~/attested-hello/Server            # confirm the path before blaming the code
chmod +x ~/attested-hello/Server         # in case the exec bit did not survive the copy

sudo SEVSNP_PORT=8443 SEVSNP_AMD_PRODUCT=Milan ~/attested-hello/Server
```

On an Azure paravisor CVM the startup log looks like this instead — note that it names the evidence
path it chose, so you never have to guess which one is in play:

```
info: Program[0] Connected to vTPM at /dev/tpmrm0.
info: Program[0] HCL report parsed: 1184-byte SNP report, 460-byte runtime data, REPORT_DATA binding verified.
info: Program[0] Evidence source: azure-vtpm (paravisor). NV 0x01400001 dataSize=2600, AK 0x81000003 …
info: Program[0] The SNP report is static on this platform (written at boot). Freshness and the
                 TLS-key binding come from the TPM2_Quote, not the report.
info: Program[0] TLS SPKI SHA-256: 9f2c…
```

`command not found` on a path you can see in `ls` means the path is wrong, not the permissions —
a non-executable file gives `Permission denied` instead. The usual cause is the `scp` nesting
described above; `find ~/attested-hello -name Server -type f` will locate it.

Expected startup log:

```
info: Program[0] TSM provider: sev_guest
info: Program[0] TLS SPKI SHA-256: 9f2c…
info: Program[0] Listening on https://0.0.0.0:8443 (self-signed; verified via attestation)
```

### Server configuration

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `SEVSNP_PORT` | `8443` | Listen port |
| `SEVSNP_AMD_PRODUCT` | `Milan` | AMD product line for the KDS fallback URL (`Milan`/`Genoa`/`Turin`) |
| `SEVSNP_EVIDENCE` | auto | Force an evidence path: `configfs` or `vtpm`. Auto prefers `configfs`. |
| `SEVSNP_TPM_DEVICE` | `/dev/tpmrm0` | vTPM device for the Azure path |
| `SEVSNP_MANIFEST` | unset | Path to a manifest file; its SHA-256 is extended into PCR 23 |
| `SEVSNP_MANIFEST_HASH` | unset | The manifest digest directly, as 64 hex chars. Mutually exclusive with the above |

---

## Run the client

```bash
dotnet run --project Client -- \
  --url https://<cvm-ip>:8443 \
  --ark amd/ark.pem
```

Hardened — this is what you should actually use once you know your values:

```bash
dotnet run --project Client -- \
  --url https://<cvm-ip>:8443 \
  --ark amd/ark.pem \
  --min-tcb 12,0,28,88 \
  --expect-measurement <96-hex-chars from a trusted first run>
```

| Flag | Meaning |
| ---- | ------- |
| `--url <url>` | Server base URL (default `https://localhost:8443`) |
| `--ark <path>` | Pinned AMD root PEM (default `amd/ark.pem`) |
| `--product <line>` | Only affects the help text printed when `ark.pem` is missing |
| `--expect-measurement <hex>` | 48-byte `MEASUREMENT` allow-list entry. **Set this in production.** |
| `--min-tcb bl,tee,snp,ucode` | Minimum acceptable `REPORTED_TCB`, compared component-wise |
| `--require-smt-disabled` | Reject if the guest policy permits SMT (Azure hosts generally run SMT, so this fails there) |
| `--expect-host-data <hex>` | Require this 32-byte `HOST_DATA`. Launch-time and immutable, but not settable on standard Azure CVMs |
| `--manifest <path>` | Hash this file locally and require the quote's PCR 23 to match. vTPM path only |
| `--expect-manifest <hex>` | Same check with the 32-byte digest supplied directly |

Exit codes: `0` verified, `1` verification or transport failure, `2` bad usage / missing anchor.

### Sample output

Real output from an Azure **Genoa** CVM on the vTPM path, lightly abbreviated:

```
Trust anchor : CN=ARK-Genoa, O=Advanced Micro Devices, S=CA, L=Santa Clara, C=US, OU=Engineering
  SHA-256    : 4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1

Nonce        : b7TIg1WJaQYdFUnry_A_3-_33gG8vff3Z0AFm83pzbY
TLS SPKI pin : 9029faa897fe8ae07b095a3d84b202c5b1e02d7f0964c6c93682efd7b58458e1
Cert source  : THIM

Verification
────────────
  [PASS] Report parses
         1184 bytes, version 5
  [PASS] Signed by VCEK
         SIGNING_KEY = 0
  [PASS] vTPM evidence present
         runtime_data 1233 B, quote 145 B, signature 256 B, alg rsassa-sha256
  [PASS] REPORT_DATA commits to runtime_data
         REPORT_DATA == SHA-256(runtime_data) || 32 zero bytes
  [PASS] Runtime data yields the AK public key
         JWK kid="HCLAkPub", RSA-2048
  [PASS] Quote structure valid
         TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE, firmware 0x2020031200120004
  [PASS] Quote signed by the attested AK
         rsassa-sha256 verifies under the AK from runtime_data
  [PASS] Quote binds the TLS key and nonce
         quote.extraData == SHA-256(observed TLS SPKI || nonce)
  [PASS] Nonce echoed
         Server echoed the nonce we sent
  [PASS] VCEK parses
         Subject: CN=SEV-VCEK, O=Advanced Micro Devices, S=CA, L=Santa Clara, C=US, OU=Engineering
  [PASS] Chains to pinned AMD root
         Anchor is self-issued and self-signature verifies; Path: SEV-VCEK -> SEV-Genoa -> ARK-Genoa
  [PASS] VCEK matches chip and TCB
         VCEK HWID matches report CHIP_ID; VCEK TCB extensions match REPORTED_TCB (bl=12 tee=0 snp=28 ucode=88)
  [PASS] Report signature valid
         ECDSA P-384/SHA-384 over bytes 0x000–0x29F
  [PASS] Debugging disabled
         POLICY.DEBUG = 0
  [PASS] TCB at or above floor
         REPORTED_TCB bl=12 tee=0 snp=28 ucode=88 >= bl=12 tee=0 snp=28 ucode=88
  [PASS] Measurement allow-listed
         MEASUREMENT matches a configured value

(with --manifest, one further step appears alongside the other quote checks:)
  [PASS] Quote commits to the app manifest
         pcrDigest recomputed over 9 PCR values; PCR 23 == SHA-256(0^32 || manifestDigest)

Report
──────
  Version        : 5
  VMPL           : 0   (level of the requester; 0 on Azure = the paravisor asked, not the guest)
  Policy         : ABI 0.31, debug=False, smt=True, migrate_ma=False
  Reported TCB   : bl=12 tee=0 snp=28 ucode=88
  Measurement    : b2b53ada66639958b707804dade56a9336a6bbd51e625ba93002ce8614482c19…
  Host data      : 0000000000000000000000000000000000000000000000000000000000000000

ATTESTATION OK
  GET /hello -> Hello
```

Note `smt=True` — so `--require-smt-disabled` fails on Azure, as documented.

Your own first run is where you read off the real
`MEASUREMENT` and `REPORTED_TCB` to feed back in as policy.

### Seeing it fail

The failure paths matter more than the success path. Three worth trying:

1. **No evidence at all** — point the client at any ordinary HTTPS server
   (`--url https://example.com`). It fails fetching `/attestation` and never sends `/hello`.
2. **A relayed report** — modify the server to return a report captured from a *different* CVM, or
   simply restart the server (new TLS key) while replaying an old report. Step 3
   (`REPORT_DATA binds the TLS key`) fails with a byte-level mismatch. This is the demo worth
   running, because it is the one that distinguishes this design from the naive one.
3. **The wrong anchor** — pass `--ark` pointing at some other self-signed root. `Chains to pinned
   AMD root` fails.

---

## The verification steps

In `Client/AttestationVerifier.cs`, in order. Every step must pass; there is no partial trust. The
client prints each one individually — the table below groups a few closely related ones.

| # | Step | What a failure means |
| - | ---- | -------------------- |
| 1 | Report parses | Not a 1184-byte SEV-SNP report |
| 2 | Signed by VCEK | Report is VLEK-signed (CSP-endorsed) — this verifier only handles VCEK |
| 3 | **`REPORT_DATA` binds the TLS key** | **Relay attack, or the nonce was ignored** |
| 4 | Nonce echoed | Server did not use the nonce we sent |
| 5 | VCEK parses + chains to pinned ARK | Certificate is not AMD-issued |
| 6 | VCEK matches chip and TCB | Certificate belongs to a different chip/TCB than the report claims |
| 7 | Report signature valid | The report was not signed by that chip |
| 8 | Debugging disabled | Host can read guest memory — no confidentiality claim survives |
| 9 | TCB floor + measurement allow-list | Unpatched platform, or unexpected software |

Two implementation details that are easy to get wrong and are worth pointing at:

- **Signature encoding.** AMD stores `r` and `s` as *little-endian* values in 72-byte fields. .NET's
  `IeeeP1363FixedFieldConcatenation` wants *big-endian* at the curve width (48 bytes each). Each
  component is truncated and byte-reversed, and the upper 24 bytes are asserted zero — silently
  discarding non-zero high bytes would mean verifying a different number than the platform signed.
  See `ReportSignatureVerifier.TryConvertSignature`.
- **TCB comparison is component-wise.** `TcbVersion.AtLeast` compares each of bootloader/TEE/SNP/
  microcode independently. Comparing the packed 64-bit value as an integer would let a microcode
  *downgrade* hide behind a bootloader bump, because microcode sits in the high byte.

---

## Troubleshooting

### `No such device or address` on `/sys/kernel/config/tsm/report/...` (ENXIO)

**This is the normal result on an Azure paravisor CVM, and it is not a bug in the kernel or in this
code.** The kernel's `tsm_report_make_item` returns `ENXIO` when no TEE provider has registered. The
configfs directory exists because the `tsm` core module is loaded; nothing is bound behind it, because
the paravisor owns VMPL0 and does not expose `/dev/sev-guest` to the guest.

The fix is not to make configfs work — it cannot. Use the vTPM path:
`SEVSNP_EVIDENCE=vtpm`, or just let auto-detection fall through to it. See
[Two evidence paths](#two-evidence-paths-because-azure-does-not-let-the-guest-choose-report_data).

Confirm which situation you are in:

```bash
sudo bash -c '
uname -r; lscpu | grep -i "model name"
dmesg | grep -i -E "sev|snp" | head
ls -l /dev/sev-guest /dev/tpm0 /dev/tpmrm0 2>&1
modprobe sev-guest 2>&1; ls -l /dev/sev-guest 2>&1
mkdir /sys/kernel/config/tsm/report/t1 2>&1 \
  && { cat /sys/kernel/config/tsm/report/t1/provider; rmdir /sys/kernel/config/tsm/report/t1; }'
```

No `/dev/sev-guest` and a failing `modprobe` ⇒ paravisor ⇒ vTPM path.

### `503 … Could not obtain attestation evidence via configfs-tsm` (EINVAL)

Different errno, different cause: **`privlevel` below the driver's floor.** configfs-tsm defaults
`privlevel` to 0, but a guest running at VMPL≠0 has a non-zero `privlevel_floor` and the sev-guest
driver rejects the request. `SnpReportProvider.AlignPrivilegeLevel` reads the floor and adopts it.

```bash
sudo bash -c '
cd /sys/kernel/config/tsm/report && mkdir -p diag && cd diag
echo "provider       : $(cat provider 2>&1)"
echo "privlevel      : $(cat privlevel 2>&1)"
echo "privlevel_floor: $(cat privlevel_floor 2>&1)"
head -c 64 /dev/zero > inblob
dd if=outblob of=/tmp/r.bin bs=4096 count=1 status=none && stat -c%s /tmp/r.bin
cd .. && rmdir diag'
```

`EBUSY` instead means the PSP is saturated — it serves one request at a time.

### `503 … Could not obtain attestation evidence via azure-vtpm`

The `detail` names the failing TPM command.

- **`NV_ReadPublic` / `NV_Read` on `0x01400001` fails** — that index is populated only on Azure
  paravisor-backed CVMs. Check `sudo tpm2_nvreadpublic 0x01400001`.
- **`ReadPublic` on `0x81000003` fails** — this image does not pre-provision an AK there. Check
  `sudo tpm2_getcap handles-persistent`.
- **`REPORT_DATA does not match SHA-256(runtime_data)`** — `HclReport`'s view of the blob layout is
  wrong for your image. The message reports the runtime-data offset and length it found and both
  hashes; that is enough to correct the parser. The offsets for the header (`0x00`, 32 bytes) and the
  SNP report (`0x20`, 1184 bytes) are stable; the padding before the JSON is what varies, which is why
  the parser searches rather than assuming.
- **`Quote` fails with an auth error** — the AK may require a policy session on your image rather than
  empty auth. `VtpmEvidenceProvider` currently assumes empty auth.

### `Trust anchor not found: amd/ark.pem`

Expected on a fresh clone; `ark.pem` is deliberately not committed. See [`amd/README.md`](amd/README.md).
Note that `dotnet run --project Client` resolves relative paths against the directory you invoke it
from, so run it from the repo root or pass an absolute `--ark`.

### `VCEK does not chain to the pinned AMD root … No issuer for 'SEV-<X>'`

Your `ark.pem` is for the wrong processor generation. The message names the subject it needed
(`CN=ARK-Milan` / `ARK-Genoa` / `ARK-Turin`) — copy the matching `ark-<Product>.pem` over `ark.pem`,
and set `SEVSNP_AMD_PRODUCT` on the server to match. Confirm the hardware with `lscpu | grep 'Model name'`
on the CVM.

### `sudo: ./attested-hello/Server: command not found`

A path problem, not a permissions one — a non-executable file reports `Permission denied` instead.
`scp -r out/server host:~/attested-hello` nests the directory when `~/attested-hello` already exists.
`find ~/attested-hello -name Server -type f` locates the apphost.

## Hardening / known limitations

Ordered roughly by how much they matter.

1. **Bind a workload identity.** Without one, the client proves "a genuine CVM" rather than "my code
   in a genuine CVM". See [Binding your workload identity](#binding-your-workload-identity): use
   `--manifest` on a standard Azure CVM, `--expect-host-data` where the platform lets you set it, and
   `--expect-measurement` on a bare guest with a deterministic image build (`sev-snp-measure` or
   equivalent). On Azure, `MEASUREMENT` covers Microsoft's paravisor boot stack rather than your
   application, so it is the least useful of the three there.
2. **Set `--min-tcb`.** Read `REPORTED_TCB` from a known-good run and require at least that. As AMD
   publishes firmware fixes, raise it.
3. **Revocation is not checked.** `VcekChainVerifier` sets `RevocationMode = NoCheck` so
   verification works offline (and because a network fetch at verify time is exactly what the pinned
   anchor exists to avoid). AMD publishes CRLs under
   `https://kdsintf.amd.com/vcek/v1/<Product>/crl`; a production verifier should fetch and cache
   them. This is called out here rather than left as a silent omission.
4. **VLEK is rejected outright.** If your host is configured for CSP-endorsed keys, step 2 fails.
   Supporting it means fetching the CSP's endorsement chain instead of the VCEK — a different trust
   root, and a deliberate decision rather than a code tweak.
5. **Path validation is hand-rolled, not `X509Chain`.** Not a limitation so much as a decision worth
   knowing about. AMD signs the ARK and ASK with RSASSA-PSS (SHA-384, MGF1-SHA-384, salt 48 —
   confirmed for all three of Milan, Genoa, and Turin). .NET delegates chain building to the platform,
   and macOS's Security.framework backend cannot process PSS: `chain.Build(ASK)` with the ARK in
   `CustomTrustStore` returns false with a single chain element and reports
   `PartialChain: One or more certificates required to validate this certificate cannot be found` —
   which reads like a missing certificate rather than an unsupported algorithm. `CertificateChain`
   therefore does the walk itself: exact issuer/subject DER matching, per-link signature verification
   (RSA-PSS / RSA-PKCS1 / ECDSA), validity windows, CA basic constraints, and termination only at the
   pinned anchor. It drops policy machinery that does not apply here — name constraints, policy
   mappings, cross-certification. If you extend this beyond the AMD chain, revisit that trade.
6. **The nonce is not tied to a session.** Each `/attestation` call is independent. A long-lived
   connection should re-attest periodically, or bind the attestation into the TLS exporter
   (RA-TLS) rather than a separate HTTP request, so there is no window between "verified" and "used".
7. **`SEVSNP_AMD_PRODUCT` must match the hardware** for the KDS fallback. A wrong value fails
   closed (VCEK fetch 404s), so it is loud, not silent. THIM does not need it.
8. **THIM and KDS are untrusted transports.** The server fetches certificates from them purely as a
   convenience; the client re-anchors everything at the pinned ARK. A hostile THIM can cause
   verification to fail, never to falsely succeed.
9. **Report generation is serialized and slow.** The PSP handles one request at a time.
   `SnpReportProvider` gates on a semaphore to avoid `EBUSY` storms; under real load, cache reports
   per (SPKI, nonce) or move to a session-scoped attestation.

## Relationship to Microsoft Azure Attestation (MAA)

Azure's `cvm-guest-attestation` sample sends the report to MAA and gets back a signed JWT. That is
easier — Microsoft parses the ABI struct, verifies the AMD chain, and applies a policy for you — and
it is the right choice if your clients already trust Microsoft.

This PoC verifies the raw AMD chain instead, which means:

- **No third party in the trust path.** The only external root is AMD's, pinned locally.
- **Works offline / air-gapped.** No verifier service to reach.
- **Clients need no Azure identity** to validate evidence.
- **The cost:** you own the ABI parsing, the signature encoding, and the appraisal policy — all
  three of which have sharp edges (see above). MAA also gives you a policy engine and MEASUREMENT
  reference values that you would otherwise curate yourself.

The two are not exclusive. A server can return both: this document *and* an MAA JWT, letting each
client verify whichever root it prefers. `AttestationDocument` has room for it.

## References

- AMD, *SEV Secure Nested Paging Firmware ABI Specification* (publication 56860) — the `REPORT_DATA`,
  `MEASUREMENT`, `POLICY`, and `TCB_VERSION` field layouts this code parses.
- AMD Key Distribution Service — `https://kdsintf.amd.com/vcek/v1/<Product>/…`
- Linux kernel, `Documentation/ABI/testing/configfs-tsm` — the `inblob`/`outblob` interface.
- Azure, [`confidential-computing-cvm-guest-attestation`](https://github.com/Azure/confidential-computing-cvm-guest-attestation)
  — the MAA-based alternative.
