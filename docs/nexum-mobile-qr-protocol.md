# Nexum Mobile QR Protocol v1

## Overview

Protocol for QR-based Falcon challenge-response between a storefront/GLQN and Nexum Vault (iOS).

The storefront displays a QR code containing a canonical challenge. The mobile app scans it, presents details for human verification, signs with Falcon, and returns the response via QR or HTTP callback.

---

## Encoding

- **All JSON**: UTF-8
- **QR payload**: Raw JSON string (no base64 wrapping of the outer envelope)
- **Binary fields** (publicKey, signature, nonce): base64url without padding
- **Dates**: ISO-8601 UTC with `Z` suffix (e.g. `2026-06-17T10:30:00Z`)
- **Canonical JSON**: Stable key order (sorted lexicographically at every nesting level), no insignificant whitespace

---

## Challenge Format

Displayed as QR by storefront. Scanned by Nexum Vault.

```json
{
  "version": 1,
  "type": "nexum.challenge",
  "purpose": "login",
  "challengeId": "ch_01JXYZ1234567890ABCDEF",
  "nonce": "base64url-encoded-32-random-bytes",
  "issuedAt": "2026-06-17T10:30:00Z",
  "expiresAt": "2026-06-17T10:35:00Z",
  "origin": "https://igrowpro.pl",
  "callbackUrl": "https://igrowpro.pl/api/nexum/verify-response",
  "payloadHash": "base64url-sha256-of-payload-if-applicable",
  "display": {
    "title": "Sign in to igrowpro.pl",
    "description": "Authenticate your session",
    "amount": "",
    "counterparty": ""
  }
}
```

### Fields

| Field | Required | Description |
|---|---|---|
| `version` | yes | Protocol version, currently `1` |
| `type` | yes | Must be `"nexum.challenge"` |
| `purpose` | yes | One of: `login`, `checkout`, `escrow`, `message` |
| `challengeId` | yes | Unique ID, prefixed `ch_`, max 64 chars |
| `nonce` | yes | 32 random bytes, base64url-encoded |
| `issuedAt` | yes | ISO-8601 UTC |
| `expiresAt` | yes | ISO-8601 UTC, must be after `issuedAt` |
| `origin` | yes | HTTPS origin of the storefront |
| `callbackUrl` | no | POST endpoint for returning response |
| `payloadHash` | no | SHA-256 of associated payload, base64url |
| `display` | no | Human-readable details |

### Display Object

| Field | Required | Description |
|---|---|---|
| `title` | no | Short title for the action |
| `description` | no | Longer description |
| `amount` | no | e.g. `"0.5 XMR"` for checkout |
| `counterparty` | no | e.g. shop name |

---

## Response Format

Returned by Nexum Vault via QR or HTTP POST to `callbackUrl`.

```json
{
  "version": 1,
  "type": "nexum.response",
  "challengeId": "ch_01JXYZ1234567890ABCDEF",
  "publicKey": "base64url-encoded-falcon-public-key",
  "keyId": "vk_20260617_abc123",
  "algorithm": "Falcon-1024",
  "signature": "base64url-encoded-falcon-signature",
  "nonce": "base64url-encoded-signer-nonce-40-bytes",
  "signedAt": "2026-06-17T10:30:15Z",
  "device": {
    "name": "Alice iPhone",
    "platform": "ios"
  }
}
```

### Fields

| Field | Required | Description |
|---|---|---|
| `version` | yes | Protocol version, currently `1` |
| `type` | yes | Must be `"nexum.response"` |
| `challengeId` | yes | Must match the challenge |
| `publicKey` | yes | Falcon public key, base64url |
| `keyId` | yes | Key identifier from vault |
| `algorithm` | yes | `"Falcon-1024"` |
| `signature` | yes | Falcon signature over canonical challenge, base64url |
| `nonce` | yes | 40-byte signer nonce for Falcon, base64url |
| `signedAt` | yes | ISO-8601 UTC |
| `device` | no | Device metadata |

### Device Object

| Field | Required | Description |
|---|---|---|
| `name` | no | User-assigned device name |
| `platform` | no | `"ios"` |

---

## Canonical Challenge String

The signature is computed over the **canonical JSON string** of the challenge object.

Rules:
1. JSON keys sorted lexicographically at every nesting level (recursive)
2. No whitespace between keys/values
3. UTF-8 encoding
4. String values are not re-escaped; use exact UTF-8 bytes

Example for a given challenge, the canonical form is deterministic and identical across all implementations.

---

## Signature Computation

1. Parse challenge JSON
2. Produce canonical JSON string (sorted keys, no whitespace)
3. Convert to UTF-8 bytes
4. Sign with Falcon-1024 using the private key
5. Falcon internally hashes with SHAKE-256; the signer generates a 40-byte nonce
6. Output: signature bytes + nonce bytes

The verifier:
1. Receives response JSON
2. Looks up the challenge by `challengeId`
3. Produces canonical JSON string of the challenge
4. Verifies Falcon signature over canonical bytes using `publicKey` from response and `nonce` from response

---

## Replay Protection

Each challenge includes:
- `challengeId`: unique, single-use
- `nonce`: random, unpredictable
- `expiresAt`: short validity window (typically 1-5 minutes)
- `origin`: bound to specific storefront

The signature covers all of these through canonical JSON, so any tampering invalidates the signature.

Backend should:
- Track used `challengeId` values
- Reject expired challenges
- Reject unknown origins
- Reject replayed `challengeId`

---

## Verification Flow (Storefront / Backend)

1. Receive response (via QR scan or POST to `callbackUrl`)
2. Parse response JSON
3. Look up original challenge by `challengeId`
4. Verify `challengeId` not already used
5. Verify challenge not expired
6. Reconstruct canonical challenge JSON
7. Decode `publicKey` from response (base64url)
8. Decode `signature` from response (base64url)
9. Decode `nonce` from response (base64url)
10. Verify Falcon signature over canonical challenge bytes using public key and nonce
11. If `payloadHash` was present, verify it matches the actual payload
12. Mark `challengeId` as used
13. Grant access / process action

---

## Security Considerations

- Private key never leaves the device
- Private key is encrypted at rest with Keychain/Secure Enclave derived key
- Biometric auth required before signing
- Challenge expires quickly
- No secrets logged
- `callbackUrl` uses HTTPS only
- Unknown origins trigger warning UI

---

## Test Vectors

See `ios/NexumVault/NexumVaultTests/TestVectors/` for:
- Canonical JSON examples
- Challenge/response pairs
- Public key + signature + verification result
