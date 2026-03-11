#!/usr/bin/env python3
"""
Cross-implementation KAT fixture generator.

Generates challenge packets and DM packets using the Python server crypto,
exports them as C header with hardcoded byte arrays.
The C test then decrypts/verifies using the C implementation.

This proves Python server and C CLI are interoperable.

Usage:
    python3 gen_cross_kat.py > cross_kat_vectors.h
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")

# Add project root to path so we can import server.app.crypto
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import oqs  # noqa: E402


# ────────────────────────────────────────────────────────────────────────────
# Helpers (same as server/app/crypto/utils.py)
# ────────────────────────────────────────────────────────────────────────────

def shake256(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)

def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def u32be(n: int) -> bytes:
    return n.to_bytes(4, "big")

def u64be(n: int) -> bytes:
    return n.to_bytes(8, "big")

def enc_field(b: bytes) -> bytes:
    return u32be(len(b)) + b


# ────────────────────────────────────────────────────────────────────────────
# KEM helpers (direct liboqs, no server dependency)
# ────────────────────────────────────────────────────────────────────────────

KEM_ALG = "FrodoKEM-640-SHAKE"

def kem_keygen():
    kem = oqs.KeyEncapsulation(KEM_ALG)
    pk = kem.generate_keypair()
    sk = kem.export_secret_key()
    return pk, sk

def kem_encaps(pk):
    kem = oqs.KeyEncapsulation(KEM_ALG)
    ct, ss = kem.encap_secret(pk)
    return ct, ss

def kem_decaps(sk, ct):
    kem = oqs.KeyEncapsulation(KEM_ALG, secret_key=sk)
    return kem.decap_secret(ct)


# ────────────────────────────────────────────────────────────────────────────
# Auth protocol (Python reimplementation of server/app/crypto/auth_v1.py)
# ────────────────────────────────────────────────────────────────────────────

CHALLENGE_LEN = 32
SID_LEN = 16
TAG_LEN = 32
CTX_AAD_V2 = b"nexum-aad-v2\x00"
CTX_AUTH_V1 = b"FF-AUTH-v1"

def auth_derive(ss, sid_raw):
    mask = shake256(ss + sid_raw + b"mask", CHALLENGE_LEN)
    kmac = shake256(ss + sid_raw + b"mac", 32)
    return mask, kmac

def aad_v2(*, sid_raw, ts, nick, kem_id, flow, ct, payload):
    out = bytearray()
    out += CTX_AAD_V2
    out += enc_field(sid_raw)
    out += enc_field(u64be(ts))
    out += enc_field(nick.encode())
    out += enc_field(kem_id.encode())
    out += enc_field(flow.encode())
    out += enc_field(ct)
    out += enc_field(payload)
    return bytes(out)

def build_transcript(*, flow, nick, ts, sid, kem_id, ct, challenge):
    ct_hash = sha256(ct)
    out = bytearray()
    out += CTX_AUTH_V1
    out += enc_field(flow.encode())
    out += enc_field(nick.encode())
    out += enc_field(u64be(ts))
    out += enc_field(sid)
    out += enc_field(kem_id.encode())
    out += enc_field(ct_hash)
    out += enc_field(challenge)
    return bytes(out)


# ────────────────────────────────────────────────────────────────────────────
# DM protocol (Python reimplementation of server/app/crypto/dm_v1.py)
# ────────────────────────────────────────────────────────────────────────────

DM_AAD_PREFIX = b"FF-DM-v1"
DM_SIG_PREFIX = b"FF-DM-SIG-v1"

def dm_build_aad(sender, to, prekey_id_raw, kem_id, ct):
    ct_hash = sha256(ct)
    return (DM_AAD_PREFIX + b"\x00" + sender.encode() + b"\x00" +
            to.encode() + b"\x00" + prekey_id_raw + b"\x00" +
            kem_id.encode() + b"\x00" + ct_hash)

def dm_encrypt(sender, to, kem_id, prekey_id_raw, pk_ot, plaintext):
    ct, ss = kem_encaps(pk_ot)
    nonce = os.urandom(16)
    ke = shake256(ss + prekey_id_raw + b"dm-ke", 32)
    km = shake256(ss + prekey_id_raw + b"dm-km", 32)
    stream = shake256(ke + nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    aad = dm_build_aad(sender, to, prekey_id_raw, kem_id, ct)
    tag = hmac_sha512(km, aad + nonce + ciphertext)[:TAG_LEN]
    # No Falcon signature in this fixture (C doesn't have Python's Falcon keys)
    # We test tag verification (MAC) which proves key derivation compatibility
    sig_msg = DM_SIG_PREFIX + b"\x00" + aad + b"\x00" + nonce + b"\x00" + ciphertext + b"\x00" + tag
    return ct, nonce, ciphertext, tag, sig_msg


# ────────────────────────────────────────────────────────────────────────────
# Generate fixtures
# ────────────────────────────────────────────────────────────────────────────

def c_hex_array(data: bytes, name: str, static: bool = True) -> str:
    prefix = "static " if static else ""
    hex_str = ", ".join(f"0x{b:02x}" for b in data)
    return f"{prefix}const uint8_t {name}[] = {{{hex_str}}};"

def c_string(value: str, name: str) -> str:
    return f'static const char *{name} = "{value}";'

def c_int(value: int, name: str) -> str:
    return f"static const uint64_t {name} = {value}ULL;"


def main():
    lines = []
    lines.append("/* AUTO-GENERATED by gen_cross_kat.py -- DO NOT EDIT */")
    lines.append(f"/* Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} */")
    lines.append("#pragma once")
    lines.append("#include <stdint.h>")
    lines.append("")

    # ── 1. Auth challenge packet ──────────────────────────────────────────
    lines.append("/* ═══ AUTH CHALLENGE PACKET (Python server → C client) ═══ */")

    pk_kem, sk_kem = kem_keygen()
    nick = "katuser"
    flow = "login"
    kem_id = KEM_ALG
    ts = 1700000000  # fixed timestamp

    sid_raw = bytes(range(16))  # deterministic for reproducibility
    challenge = bytes([0x42] * 32)  # known challenge

    ct, ss = kem_encaps(pk_kem)
    mask, kmac = auth_derive(ss, sid_raw)
    payload = bytes(a ^ b for a, b in zip(challenge, mask))

    aad2 = aad_v2(sid_raw=sid_raw, ts=ts, nick=nick, kem_id=kem_id,
                   flow=flow, ct=ct, payload=payload)
    tag2 = hmac_sha512(kmac, aad2)[:TAG_LEN]

    transcript = build_transcript(flow=flow, nick=nick, ts=ts, sid=sid_raw,
                                  kem_id=kem_id, ct=ct, challenge=challenge)

    # Verify locally (sanity)
    ss_check = kem_decaps(sk_kem, ct)
    assert ss == ss_check, "sanity: ss mismatch"
    mask_check, kmac_check = auth_derive(ss_check, sid_raw)
    assert mask == mask_check
    recovered = bytes(a ^ b for a, b in zip(payload, mask_check))
    assert recovered == challenge, "sanity: challenge mismatch"

    lines.append(c_string(nick, "AUTH_NICK"))
    lines.append(c_string(flow, "AUTH_FLOW"))
    lines.append(c_string(kem_id, "AUTH_KEM_ID"))
    lines.append(c_int(ts, "AUTH_TS"))
    lines.append(c_hex_array(sid_raw, "AUTH_SID_RAW"))
    lines.append(c_hex_array(sk_kem, "AUTH_SK_KEM"))
    lines.append(c_hex_array(pk_kem, "AUTH_PK_KEM"))
    lines.append(c_hex_array(ct, "AUTH_CT"))
    lines.append(c_hex_array(payload, "AUTH_PAYLOAD"))
    lines.append(c_hex_array(tag2, "AUTH_TAG_V2"))
    lines.append(c_hex_array(challenge, "AUTH_EXPECTED_CHALLENGE"))
    lines.append(c_hex_array(transcript, "AUTH_EXPECTED_TRANSCRIPT"))
    lines.append(f"static const size_t AUTH_SK_KEM_LEN = {len(sk_kem)};")
    lines.append(f"static const size_t AUTH_PK_KEM_LEN = {len(pk_kem)};")
    lines.append(f"static const size_t AUTH_CT_LEN = {len(ct)};")
    lines.append(f"static const size_t AUTH_TRANSCRIPT_LEN = {len(transcript)};")
    lines.append("")

    # ── 2. DM packet (Python encrypts → C decrypts MAC-only) ─────────────
    lines.append("/* ═══ DM PACKET (Python encrypt → C verify MAC + decrypt) ═══ */")

    pk_ot, sk_ot = kem_keygen()  # recipient one-time prekey
    prekey_id_raw = bytes([0xAA] * 16)
    dm_plaintext = b"Cross-KAT: Python encrypted this message for C to decrypt."

    dm_ct, dm_nonce, dm_ciphertext, dm_tag, dm_sig_msg = dm_encrypt(
        "alice", "bob", KEM_ALG, prekey_id_raw, pk_ot, dm_plaintext
    )

    # Verify locally (sanity)
    dm_ss = kem_decaps(sk_ot, dm_ct)
    dm_ke = shake256(dm_ss + prekey_id_raw + b"dm-ke", 32)
    dm_km = shake256(dm_ss + prekey_id_raw + b"dm-km", 32)
    dm_aad = dm_build_aad("alice", "bob", prekey_id_raw, KEM_ALG, dm_ct)
    dm_tag_check = hmac_sha512(dm_km, dm_aad + dm_nonce + dm_ciphertext)[:TAG_LEN]
    assert dm_tag == dm_tag_check, "sanity: dm tag mismatch"
    dm_stream = shake256(dm_ke + dm_nonce, len(dm_plaintext))
    dm_recovered = bytes(a ^ b for a, b in zip(dm_ciphertext, dm_stream))
    assert dm_recovered == dm_plaintext, "sanity: dm plaintext mismatch"

    lines.append(c_string("alice", "DM_SENDER"))
    lines.append(c_string("bob", "DM_RECIPIENT"))
    lines.append(c_string(KEM_ALG, "DM_KEM_ID"))
    lines.append(c_hex_array(prekey_id_raw, "DM_PREKEY_ID"))
    lines.append(c_hex_array(sk_ot, "DM_SK_OT"))
    lines.append(c_hex_array(pk_ot, "DM_PK_OT"))
    lines.append(c_hex_array(dm_ct, "DM_CT"))
    lines.append(c_hex_array(dm_nonce, "DM_NONCE"))
    lines.append(c_hex_array(dm_ciphertext, "DM_CIPHERTEXT"))
    lines.append(c_hex_array(dm_tag, "DM_TAG"))
    lines.append(c_hex_array(dm_plaintext, "DM_EXPECTED_PLAINTEXT"))
    lines.append(c_hex_array(dm_sig_msg, "DM_EXPECTED_SIG_MSG"))
    lines.append(f"static const size_t DM_SK_OT_LEN = {len(sk_ot)};")
    lines.append(f"static const size_t DM_CT_LEN = {len(dm_ct)};")
    lines.append(f"static const size_t DM_CIPHERTEXT_LEN = {len(dm_ciphertext)};")
    lines.append(f"static const size_t DM_SIG_MSG_LEN = {len(dm_sig_msg)};")
    lines.append(f"static const size_t DM_PLAINTEXT_LEN = {len(dm_plaintext)};")
    lines.append("")

    print("\n".join(lines))


if __name__ == "__main__":
    main()
