# OEVP DSSE v1 Envelope Binding Specification

Status: Pre-1.0 Draft  
Specification Reference: DSSE v1 Specification (in-toto / Secure Systems Lab)

---

## 1. Important Standards Clarifications

1. **DSSE is NOT RFC 9162**: RFC 9162 is *Certificate Transparency Version 2.0*. DSSE is the *Dead Simple Signing Envelope* specification maintained in the Secure Systems Lab / in-toto ecosystem.
2. **DSSE does not establish trust**: The `keyid` field in a DSSE signature entry is an unauthenticated key-selection hint. A receipt signer is trusted **only** if the relying party explicitly supplies an accepted public key or trust root.
3. **DSSE does not require RFC 8785 for signature security**: DSSE guarantees cryptographic integrity over exact payload bytes through Pre-Authentication Encoding (`PAE`). In OEVP, RFC 8785 (JCS) is applied to the receipt dictionary before base64 encoding to provide deterministic content identity and byte stability; DSSE authenticates those exact bytes.

---

## 2. Envelope Format

OEVP receipts are packaged into standard DSSE v1 envelopes:

```json
{
  "payloadType": "application/vnd.oev.verification-receipt+json",
  "payload": "<Base64-encoded canonical JSON bytes of VerificationReceipt>",
  "signatures": [
    {
      "keyid": "verifier-key-2026-01",
      "sig": "<Base64-encoded Ed25519 signature>"
    }
  ]
}
```

- **`payloadType`**: MUST be `application/vnd.oev.verification-receipt+json`.
- **`payload`**: Standard Base64 encoding of the JCS-canonicalized Verification Receipt (including its `receipt_digest`).
- **`signatures`**: Array containing at least one signature object with `sig` (Base64) and optional `keyid` string.

---

## 3. Pre-Authentication Encoding (PAE)

The signature is computed over the normative DSSE v1 PAE serialization:

$$\text{PAE}(t, p) = \text{"DSSEv1 "} + \text{ASCII}(\text{len}(t)) + \text{" "} + t + \text{" "} + \text{ASCII}(\text{len}(p)) + \text{" "} + p$$

Where:
- $t$ is the UTF-8 bytes of `payloadType`
- $p$ is the exact decoded bytes of `payload`
- $\text{ASCII}(n)$ is the decimal string representation of byte length $n$

---

## 4. Cryptographic Primitives & Key Management

For the pre-application MVP, OEVP specifies:
- **Signature Algorithm**: Ed25519 (PureEd25519 / RFC 8032).
- **Key Serialization**: SubjectPublicKeyInfo PEM (RFC 5280) for public keys, PKCS#8 PEM (RFC 5208) for private keys.

---

## 5. Trust Evaluation & Strict No-Self-Trust Rule

When verifying a signed receipt:
1. The verifier checks whether the mathematical signature verifies over `PAE(payloadType, payload)`.
2. The verifier queries the caller-supplied verifier trust roots (`--verifier-keys`).
3. **If the signing key is not in the caller's trust roots**, the receipt is marked `SIGNER_UNTRUSTED`.
4. Embedded public keys, envelope `keyid` strings, and self-asserted signer identities are treated strictly as unauthenticated hints.
