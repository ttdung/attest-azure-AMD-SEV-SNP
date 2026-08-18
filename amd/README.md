# The pinned AMD root (ARK)

This directory holds the client's **trust anchor**: `ark.pem`, AMD's self-signed AMD Root Key
certificate for your processor generation.

Everything else in this protocol is verified *relative to this file*. If an attacker chooses the
contents of `ark.pem`, they can forge an entire attestation. So this file must be established
out-of-band and checked once by a human — the client deliberately refuses to fetch it at
verification time, because downloading your own trust anchor from the network at the moment you
need it is not pinning.

`ark.pem` is intentionally **not committed** (see `../.gitignore`). Produce it yourself.

## 1. Identify your processor generation

| Azure VM SKU family                      | AMD product line | KDS path |
| ---------------------------------------- | ---------------- | -------- |
| DCasv5 / DCadsv5 / ECasv5 / ECadsv5      | EPYC Milan (3rd gen) | `Milan` |
| DCasv6 / ECasv6 (and other v6 CVM SKUs)  | EPYC Genoa (4th gen) | `Genoa` |
| Newer 5th-gen SKUs                       | EPYC Turin       | `Turin`  |

Confirm from inside the VM rather than guessing:

```bash
lscpu | grep -i 'model name'
```

If the product line is wrong, the VCEK fetch fails and verification fails closed — a wrong guess
is loud, not silent.

## 2. Download the chain and extract the root

AMD publishes ASK + ARK as a two-certificate PEM bundle at
`https://kdsintf.amd.com/vcek/v1/<Product>/cert_chain`. The **second** certificate is the
self-signed ARK.

```bash
PRODUCT=Milan   # or Genoa / Turin

curl -fsSL "https://kdsintf.amd.com/vcek/v1/${PRODUCT}/cert_chain" -o cert_chain.pem

# Split the bundle and keep the self-signed one.
awk '/BEGIN CERTIFICATE/{n++} n==1' cert_chain.pem > ask.pem
awk '/BEGIN CERTIFICATE/{n++} n==2' cert_chain.pem > ark.pem
```

## 3. Verify it before trusting it

The ARK is self-signed, so "the signature checks out" proves nothing on its own — a forged root
is also self-signed. Two independent checks:

```bash
# (a) It really is self-signed and its subject/issuer are AMD's ARK for your product.
openssl x509 -in ark.pem -noout -subject -issuer
#   subject= ... OU = Engineering, CN = ARK-Milan
#   issuer=  ... OU = Engineering, CN = ARK-Milan     <- identical

# (b) It actually signs the ASK you received.
openssl verify -CAfile ark.pem -partial_chain ask.pem
#   ask.pem: OK

# (c) Record the fingerprint and compare it against AMD's published value / a second
#     network path / a colleague's copy. Do not skip this step.
openssl x509 -in ark.pem -noout -fingerprint -sha384
```

AMD's key-distribution documentation and the AMD SEV-SNP firmware ABI specification are the
authoritative references for the expected ARK. Fingerprints are deliberately not hardcoded in this
repo — a value copied from an unverified source and committed here would just move the trust
problem, while looking like it had solved it.

Once verified, the same `ark.pem` is reusable for every VM on that processor generation, forever.
It is a long-lived root.

## 4. Optional: keep the ASK too

The server ships the ASK to the client on every attestation, so the client does not need a local
copy. Keeping `ask.pem` is still useful for the `openssl verify` check above and for offline
debugging.

## Files

| File             | Committed | Purpose |
| ---------------- | --------- | ------- |
| `ark.pem`        | No        | The pinned trust anchor. Client requires it. |
| `ask.pem`        | No        | AMD SEV signing key. Optional; used for local verification. |
| `cert_chain.pem` | No        | Raw two-cert bundle as downloaded. |
