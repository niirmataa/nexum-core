#pragma once
#include <stddef.h>
#include <stdint.h>

int ff_dm_encrypt_packet(const char *sender_nick,
                         const char *to_nick,
                         const char *kem_id,
                         const uint8_t *prekey_id_raw, size_t prekey_id_len,
                         const uint8_t *pk_ot, size_t pk_ot_len,
                         const uint8_t *sender_sk_sig, size_t sender_sk_sig_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t **ct, size_t *ct_len,
                         uint8_t **dm_nonce, size_t *dm_nonce_len,
                         uint8_t **ciphertext, size_t *ciphertext_len,
                         uint8_t **tag, size_t *tag_len,
                         uint8_t **sig, size_t *sig_len);

int ff_dm_verify_decrypt(const char *sender_nick,
                         const char *to_nick,
                         const char *kem_id,
                         const uint8_t *prekey_id_raw, size_t prekey_id_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t *dm_nonce, size_t dm_nonce_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         const uint8_t *tag, size_t tag_len,
                         const uint8_t *sig, size_t sig_len,
                         const uint8_t *recipient_sk_ot, size_t recipient_sk_ot_len,
                         const uint8_t *sender_pk_sig, size_t sender_pk_sig_len,
                         uint8_t **out_plain, size_t *out_plain_len);
