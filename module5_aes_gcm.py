import json
import os
import time
from dataclasses import dataclass
from typing import Optional
from Crypto.Cipher import AES
from module2_adaptive_engine import SecurityProfile

MIN_TAG_LENGTH = 12   
MAX_TAG_LENGTH = 16   


PROFILE_FIELDS = ("level", "chaos_model","chaos_iterations","hkdf_hash","hkdf_length","aes_tag_length","aes_nonce_length",)
_AAD_VERSION = 1


@dataclass
class EncryptedPayload:
    nonce:      bytes
    ciphertext: bytes
    auth_tag:   bytes
    tag_length: int


@dataclass
class EncryptionResult:
    payload:          EncryptedPayload
    plaintext_size:   int
    ciphertext_size:  int
    encryption_time:  float
    throughput_mbps:  float


@dataclass
class DecryptionResult:
    plaintext:        bytes
    tag_verified:     bool
    decryption_time:  float
    throughput_mbps:  float
    error:            str = ""      


def profile_to_dict(profile: SecurityProfile) -> dict:
    return {name: getattr(profile, name) for name in PROFILE_FIELDS}


def build_packet_aad(
    kem_ciphertext: bytes,
    hkdf_salt: bytes,
    profile_fields: dict,
    demo_mode: bool,
) -> bytes:

    canonical = {
        "v": _AAD_VERSION,
        "kem_ct": kem_ciphertext.hex(),
        "salt": hkdf_salt.hex(),
        "demo": bool(demo_mode),
        "profile": {name: profile_fields[name] for name in PROFILE_FIELDS},
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_session_key(session_key: bytes) -> None:
    if len(session_key) < 32:
        raise ValueError(
            f"Session key too short: got {len(session_key)} bytes, "
            f"need at least 32 bytes for AES-256.")


def _extract_aes_key(session_key: bytes) -> bytes:
    return session_key[:32]


def _validate_tag_length(tag_length: int) -> None:
    if not isinstance(tag_length, int) or isinstance(tag_length, bool) \
            or not (MIN_TAG_LENGTH <= tag_length <= MAX_TAG_LENGTH):
        raise ValueError(
            f"GCM tag length {tag_length!r} is outside the allowed range "
            f"{MIN_TAG_LENGTH}-{MAX_TAG_LENGTH} bytes."
        )


def encrypt(
    plaintext:    bytes,
    session_key:  bytes,
    profile:      SecurityProfile,
    aad:          Optional[bytes] = None,
    verbose:      bool = True,
) -> EncryptionResult:
    _validate_session_key(session_key)
    _validate_tag_length(profile.aes_tag_length)
    aes_key = _extract_aes_key(session_key)
    nonce = os.urandom(profile.aes_nonce_length)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=profile.aes_tag_length)

    if aad is not None:
        cipher.update(aad)

    t_start = time.perf_counter()
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    t_end = time.perf_counter()
    enc_time = t_end - t_start
    size_mb = len(plaintext) / (1024 ** 2)
    throughput = size_mb / enc_time if enc_time > 0 else float("inf")

    payload = EncryptedPayload(nonce=nonce, ciphertext=ciphertext, auth_tag=auth_tag, tag_length=profile.aes_tag_length,)
    result = EncryptionResult(payload=payload,plaintext_size=len(plaintext),ciphertext_size=len(ciphertext),encryption_time=enc_time,throughput_mbps=throughput,)

    if verbose:
        _print_encryption_summary(result, profile, aad_bound=aad is not None)

    return result


def _rejected(reason: str, verbose: bool) -> DecryptionResult:
    result = DecryptionResult(plaintext=b"", tag_verified=False, decryption_time=0.0, throughput_mbps=0.0, error=reason,)
    if verbose:
        _print_decryption_summary(result)
    return result


def decrypt(
    payload:      EncryptedPayload,
    session_key:  bytes,
    aad:          Optional[bytes] = None,
    verbose:      bool = True,
) -> DecryptionResult:
    _validate_session_key(session_key)
    aes_key = _extract_aes_key(session_key)

    try:
        _validate_tag_length(payload.tag_length)
    except ValueError as exc:
        return _rejected(f"REJECTED before decryption: {exc}", verbose)
    if len(payload.auth_tag) != payload.tag_length:
        return _rejected(
            f"REJECTED before decryption: tag is {len(payload.auth_tag)} bytes "
            f"but tag_length says {payload.tag_length}.", verbose)

    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=payload.nonce, mac_len=payload.tag_length)
    except (ValueError, TypeError) as exc:
        return _rejected(f"REJECTED before decryption: bad nonce ({exc}).", verbose)

    if aad is not None:
        cipher.update(aad)

    t_start = time.perf_counter()
    error = ""
    try:
        plaintext = cipher.decrypt_and_verify(payload.ciphertext, payload.auth_tag)
        tag_verified = True
    except ValueError:
        plaintext = b""
        tag_verified = False
        error = "GCM tag mismatch"
    t_end = time.perf_counter()

    dec_time = t_end - t_start
    size_mb = len(payload.ciphertext) / (1024 ** 2)
    throughput = size_mb / dec_time if dec_time > 0 else float("inf")

    result = DecryptionResult(plaintext=plaintext,tag_verified=tag_verified,decryption_time=dec_time,throughput_mbps=throughput,error=error,)

    if verbose:
        _print_decryption_summary(result)

    return result


def _print_encryption_summary(result: EncryptionResult, profile: SecurityProfile,
                              aad_bound: bool = False) -> None:
    p = result.payload
    print("\n")
    print("   MODULE 5 — AES-256-GCM  ENCRYPTION")
    print("\n")
    print(f"  {'Security Profile':<28} {profile.level}")
    print(f"  {'Plaintext Size':<28} {result.plaintext_size:,} bytes")
    print(f"  {'Ciphertext Size':<28} {result.ciphertext_size:,} bytes")
    print(f"  {'Nonce (hex)':<28} {p.nonce.hex()}")
    print(f"  {'Auth Tag Length':<28} {len(p.auth_tag) * 8} bits")
    print(f"  {'Auth Tag (hex)':<28} {p.auth_tag.hex()}")
    print(f"  {'Packet metadata in AAD':<28} {'yes (profile, salt, KEM ciphertext)' if aad_bound else 'no'}")
    print(f"  {'Ciphertext preview (hex)':<28} {p.ciphertext[:16].hex()} …")
    print(f"  {'Encryption Time':<28} {result.encryption_time * 1000:.4f} ms")
    print(f"  {'Throughput':<28} {result.throughput_mbps:.2f} MB/s")
    print("\n")


def _print_decryption_summary(result: DecryptionResult) -> None:
    if result.tag_verified:
        status = " [+] TAG VERIFIED — data is authentic"
    elif result.error.startswith("REJECTED"):
        status = f" [!] {result.error}"
    else:
        status = " [!] TAG MISMATCH — data was TAMPERED"
    print("\n")
    print("   MODULE 5 — AES-256-GCM  DECRYPTION")
    print(f"  Integrity Check : {status}")
    print(f"  {'Recovered Size':<28} {len(result.plaintext):,} bytes")
    print(f"  {'Decryption Time':<28} {result.decryption_time * 1000:.4f} ms")
    print(f"  {'Throughput':<28} {result.throughput_mbps:.2f} MB/s")
    print("\n")
