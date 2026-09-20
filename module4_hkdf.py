import time
import hmac
import hashlib
from dataclasses import dataclass
from typing import Any, Optional

@dataclass
class DerivedSessionKey:
    sessionKey: bytes
    rawKeyLength: int
    hashAlgorithm: str
    derivationTime: float

_HASH_MAP = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

def _hkdfExtract(salt: bytes, ikm: bytes, hashFunc) -> bytes:
    # RFC 5869 extract step
    hashLen = hashFunc().digest_size
    if not salt:
        salt = b"\x00" * hashLen
    return hmac.new(salt, ikm, hashFunc).digest()

def _hkdfExpand(prk: bytes, info: bytes, length: int, hashFunc) -> bytes:
    # RFC 5869 expand step
    okm = bytearray()
    prevBlock = b""
    blockIndex = 1

    while len(okm) < length:
        prevBlock = hmac.new(prk, prevBlock + info + bytes([blockIndex]), hashFunc).digest()
        okm.extend(prevBlock)
        blockIndex += 1

    return bytes(okm[:length])

def deriveSessionKey(
    kemSecret: bytes,
    chaosKeystream: bytes,
    profile: Optional[Any] = None,
    hashAlgo: str = "sha256",
    outputLength: int = 32,
    salt: Optional[bytes] = None,
    infoPayload: bytes = b"mlkem-chaos-hybrid-aes-gcm",
    verbose: bool = True
) -> DerivedSessionKey:
    tStart = time.perf_counter()

    resolvedAlgo = hashAlgo
    resolvedLength = outputLength


    if profile is not None:
        if hasattr(profile, "hkdf_hash"):
            resolvedAlgo = profile.hkdf_hash
        if hasattr(profile, "hkdf_length"):
            resolvedLength = profile.hkdf_length
        if salt is None and hasattr(profile, "level"):
            salt = hashlib.sha256(str(profile.level).encode()).digest()

    if salt is None:
        salt = hashlib.sha256(b"hybrid-chaos-pq-salt").digest()

    hashFunc = _HASH_MAP.get(resolvedAlgo.lower(), hashlib.sha256)

    # Entropy mix
    ikm = kemSecret + chaosKeystream

    # extraction and expansion
    prk = _hkdfExtract(salt, ikm, hashFunc)
    derivedKey = _hkdfExpand(prk, infoPayload, resolvedLength, hashFunc)

    tEnd = time.perf_counter()
    elapsed = tEnd - tStart

    result = DerivedSessionKey(sessionKey=derivedKey,rawKeyLength=len(derivedKey),hashAlgorithm=resolvedAlgo.upper(),derivationTime=elapsed)

    if verbose:
        print(f" [+] Input KEM secret   : {len(kemSecret)} bytes")
        print(f" [+] Input shaos stream : {len(chaosKeystream)} bytes")
        print(f" [+] Mixed entropy (IKM): {len(ikm)} bytes")
        print(f" [+] Hash primitive     : {result.hashAlgorithm}")
        print(f" [+] Target key output  : {result.rawKeyLength * 8} bits ({result.rawKeyLength} bytes)")
        print(f" [+] Session key preview: {derivedKey[:16].hex()}...")
        print(f" [+] Derivation time    : {elapsed * 1000:.4f} ms")

    return result