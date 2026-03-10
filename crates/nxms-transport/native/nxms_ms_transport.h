#pragma once
#include <stddef.h>
#include <stdint.h>

/*
 * NXMS (Nexum Multisig Transport) — C transport primitives for moving Monero multisig
 * blobs (multisig_info / export_multisig_info / txset) between 2-of-3 parties.
 *
 * Crypto suite lock (no negotiation):
 *   - KEM: FrodoKEM-640-SHAKE via liboqs (OQS KEM API), called through ff_kem_* wrappers.
 *   - Signature: Falcon-1024-CT (round3 reference), called through ff_falcon_* wrappers.
 *
 * This module is intentionally "small surface":
 *   - one-shot KEM per message (no long-lived session state)
 *   - deterministic AAD construction
 *   - fail-closed on any mismatch
 *
 * Dependencies (already present in your nexum_cli):
 *   - src/pqc_kem.c + src/pqc_kem.h   (liboqs)
 *   - src/pqc_falcon.c + src/pqc_falcon.h (vendor/falcon)
 */

#ifdef __cplusplus
extern "C" {
#endif

#define NXMS_ESCROW_ID_LEN 16
#define NXMS_NONCE_LEN     24
#define NXMS_TAG_LEN       32


// --- production hardening knobs (compile-time) ---
#ifndef NXMS_MAX_PAYLOAD
// Max payload size to defend against memory/CPU DoS. Override at build time if needed.
#define NXMS_MAX_PAYLOAD (16u * 1024u * 1024u) /* 16 MiB */
#endif

#ifndef NXMS_MAX_ID_LEN
// Max length (bytes) for sender_id/to_id/msg_type (C string, excluding NUL).
#define NXMS_MAX_ID_LEN 128u
#endif

#ifndef NXMS_MIN_KEM_BYTES
#define NXMS_MIN_KEM_BYTES 64u
#endif
#ifndef NXMS_MAX_KEM_PK_LEN
#define NXMS_MAX_KEM_PK_LEN 32768u
#endif
#ifndef NXMS_MAX_KEM_CT_LEN
#define NXMS_MAX_KEM_CT_LEN 32768u
#endif
#ifndef NXMS_MAX_KEM_SK_LEN
#define NXMS_MAX_KEM_SK_LEN 65536u
#endif
#ifndef NXMS_MAX_SIG_SK_LEN
#define NXMS_MAX_SIG_SK_LEN 65536u
#endif
#ifndef NXMS_MAX_SIG_PK_LEN
#define NXMS_MAX_SIG_PK_LEN 65536u
#endif
// Strict suite identifiers used on-the-wire and for fail-closed checks.
#define NXMS_KEM_ID "FrodoKEM-640-SHAKE"
#define NXMS_SIG_ID "Falcon-1024-CT"

/*
 * Encrypt + authenticate + sign a packet carrying an arbitrary payload (e.g. wallet-rpc blob).
 *
 * Inputs:
 *   - sender_id/to_id: ASCII identifiers (for AAD binding; may be nick / node_id / account id)
 *   - msg_type: ASCII message type label (e.g. "PrepareMultisigInfo", "TxSetSigned")
 *   - escrow_id_raw: 16-byte stable escrow id (UUID bytes or other 16-byte id)
 *   - seq: monotonic message sequence per (escrow_id, sender_id)
 *   - recipient_pk_kem: recipient FrodoKEM public key
 *   - sender_sk_sig: sender Falcon secret key
 *   - plaintext: payload bytes
 *
 * Outputs (allocated; caller frees with nxms_ms_free()):
 *   - kem_ct: Frodo ciphertext (to allow recipient to decaps)
 *   - nonce: 24 random bytes (used for payload stream cipher)
 *   - ciphertext: encrypted payload (same length as plaintext)
 *   - tag: 32-byte keyed SHAKE256 tag (quick reject before signature verify)
 *   - sig: Falcon-1024-CT signature over canonical "sig_message"
 */
int nxms_ms_encrypt_packet(const char *sender_id,
                           const char *to_id,
                           const char *msg_type,
                           const uint8_t escrow_id_raw[NXMS_ESCROW_ID_LEN],
                           uint64_t seq,
                           const uint8_t *recipient_pk_kem, size_t recipient_pk_kem_len,
                           const uint8_t *sender_sk_sig, size_t sender_sk_sig_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t **kem_ct, size_t *kem_ct_len,
                           uint8_t **nonce, size_t *nonce_len,
                           uint8_t **ciphertext, size_t *ciphertext_len,
                           uint8_t **tag, size_t *tag_len,
                           uint8_t **sig, size_t *sig_len);

/*
 * Verify + decrypt.
 *
 * Performs (fail-closed):
 *   1) KEM decapsulation (Frodo) -> shared secret
 *   2) derive ke/km -> recompute tag -> compare (constant-time compare recommended at higher layer)
 *   3) verify Falcon signature
 *   4) decrypt (XOR SHAKE keystream)
 *
 * Ownership/contract:
 *   - On call entry, if output pointers are provided, function resets:
 *       *out_plain = NULL, *out_plain_len = 0
 *   - On any error return (rc != 0), outputs stay NULL/0.
 *   - On success (rc == 0), caller owns *out_plain and must release via nxms_ms_free().
 */
int nxms_ms_verify_decrypt(const char *sender_id,
                           const char *to_id,
                           const char *msg_type,
                           const uint8_t escrow_id_raw[NXMS_ESCROW_ID_LEN],
                           uint64_t seq,
                           const uint8_t *kem_ct, size_t kem_ct_len,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t *tag, size_t tag_len,
                           const uint8_t *sig, size_t sig_len,
                           const uint8_t *recipient_sk_kem, size_t recipient_sk_kem_len,
                           const uint8_t *sender_pk_sig, size_t sender_pk_sig_len,
                           uint8_t **out_plain, size_t *out_plain_len);

/*
 * Free memory returned by NXMS transport APIs.
 * Safe to call with NULL.
 */
void nxms_ms_free(void *ptr);

/*
 * Securely wipe + free memory returned by NXMS transport APIs.
 * Intended for plaintext buffers returned by `nxms_ms_verify_decrypt()`.
 * Safe to call with NULL.
 */
void nxms_ms_free_secure(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif
