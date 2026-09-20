import io
import os
import time
import socket
import hashlib
import functools
import threading
import contextlib
from datetime import datetime
from flask import Flask, request, jsonify, render_template

from module1_mlkem import MlKem768
from module2_adaptive_engine import run_adaptive_engine, SecurityProfile, _PROFILE_TABLE
from module3_chaos_engine import run_chaos_module, ChaosInstabilityError
from module4_hkdf import deriveSessionKey
from module5_aes_gcm import (
    encrypt, decrypt, EncryptedPayload, profile_to_dict, build_packet_aad,
)


def _self_test_module1():
    engine = MlKem768()
    kp = engine.generateKeyPair()
    encap = engine.encapsulate(kp.publicKey)
    recovered = engine.decapsulate(encap.cipherText, kp.privateKey)
    return (encap.sharedSecret == recovered), engine._useNative


MODULE1_OK, MODULE1_NATIVE = _self_test_module1()
KemEngine = MlKem768
KEM_LABEL = (
    "Module 1 — ML-KEM-768 (native, post-quantum)" if MODULE1_NATIVE
    else "Module 1 — classical DH-2048 fallback (NOT post-quantum)")


def _get_lan_ip() -> str:
    """Best-effort LAN IP so the app can show a shareable link. Opens no
    real connection — just asks the OS which interface would be used."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LAN_IP = _get_lan_ip()


STATE = {
    "receiver_keypair": None,
    "channel": None,
    "log": [],
}

STATE_LOCK = threading.RLock()


def locked(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with STATE_LOCK:
            return fn(*args, **kwargs)
    return wrapper


def _log(msg: str):
    stamp = datetime.now().strftime("%H:%M:%S")
    STATE["log"].append(f"[{stamp}] {msg}")
    STATE["log"][:] = STATE["log"][-60:]


def _capture(name, fn, *args, **kwargs):
    buf = io.StringIO()
    t0 = time.perf_counter()
    with contextlib.redirect_stdout(buf):
        result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - t0
    return result, {"name": name, "text": buf.getvalue(), "ms": round(elapsed * 1000, 3)}


def _decode_packet(packet: dict):
    """Turn the stored packet into raw bytes / values, or None if it is malformed."""
    try:
        return {
            "kem_ciphertext": bytes.fromhex(packet["kem_ciphertext"]),
            "hkdf_salt": bytes.fromhex(packet["hkdf_salt"]),
            "demo_mode": bool(packet["demo_mode"]),
            "profile": packet["profile"],
            "nonce": bytes.fromhex(packet["aes"]["nonce"]),
            "ciphertext": bytes.fromhex(packet["aes"]["ciphertext"]),
            "auth_tag": bytes.fromhex(packet["aes"]["auth_tag"]),
            "tag_length": packet["aes"]["tag_length"],}
    except (KeyError, ValueError, TypeError, AttributeError):
        return None


def _validate_profile_fields(p) -> str:
    if not isinstance(p, dict):
        return "profile is missing or malformed"
    level = p.get("level")
    if level not in _PROFILE_TABLE:
        return f"unknown security level {level!r}"
    for key, expected in _PROFILE_TABLE[level].items():
        if p.get(key) != expected:
            return f"profile field '{key}' does not match the {level} profile"
    return ""


def _reject(packet: dict, reason: str, stages: list):
    _log(f"Receiver rejected the packet before decryption: {reason}")
    stages.append({"name": "Receiver — packet validation", "text": f"REJECTED: {reason}\n", "ms": 0})
    return jsonify({
        "ok": True,
        "tag_verified": False,
        "plaintext": None,
        "was_tampered": bool(packet.get("tampered")),
        "passphrase_hint": f"PACKET REJECTED — {reason}",
        "stages": stages,
        "log": STATE["log"],
    })


app = Flask(__name__)


@app.get("/")
def landing():
    return render_template("landing.html", kem_label=KEM_LABEL, module1_ok=MODULE1_OK, lan_ip=LAN_IP)


@app.get("/demo")
def demo():
    return render_template("index.html", role="full", kem_label=KEM_LABEL, module1_ok=MODULE1_OK, lan_ip=LAN_IP)


@app.get("/sender")
def sender_page():
    return render_template("index.html", role="sender", kem_label=KEM_LABEL, module1_ok=MODULE1_OK, lan_ip=LAN_IP)


@app.get("/receiver")
def receiver_page():
    return render_template("index.html", role="receiver", kem_label=KEM_LABEL, module1_ok=MODULE1_OK, lan_ip=LAN_IP)


@app.get("/api/status")
def status():
    channel = STATE["channel"]
    return jsonify({
        "kem_label": KEM_LABEL,
        "module1_ok": MODULE1_OK,
        "receiver_ready": STATE["receiver_keypair"] is not None,
        "channel_has_packet": channel is not None,
        "channel_tampered": bool(channel and channel.get("tampered")),
        "log": list(STATE["log"]),
    })


@app.post("/api/reset")
@locked
def reset():
    STATE["receiver_keypair"] = None
    STATE["channel"] = None
    STATE["log"] = []
    _log("Session reset. No keys published, nothing on the channel.")
    return jsonify({"ok": True, "log": STATE["log"]})


@app.post("/api/receiver/keygen")
@locked
def receiver_keygen():
    engine = KemEngine()
    keypair = engine.generateKeyPair()
    STATE["receiver_keypair"] = keypair
    STATE["channel"] = None
    _log(f"Receiver generated a keypair via {KEM_LABEL} "
         f"(public key {len(keypair.publicKey)} bytes, shared with Sender below; "
         f"private key {len(keypair.privateKey)} bytes, kept secret).")
    return jsonify({
        "ok": True,
        "publicKeyHex": keypair.publicKey.hex(),
        "publicKeyLength": len(keypair.publicKey),
        "kem_label": KEM_LABEL,
        "log": STATE["log"],
    })


@app.post("/api/sender/send")
@locked
def sender_send():
    data = request.get_json(force=True)
    message = (data.get("message") or "").encode("utf-8")
    passphrase = (data.get("passphrase") or "").strip()
    demo_mode = bool(data.get("demo_mode", True))

    if not message:
        return jsonify({"ok": False, "error": "Message is empty."}), 400
    if not passphrase:
        return jsonify({"ok": False, "error": "Shared passphrase is required — agree on one with your friend first."}), 400
    if STATE["receiver_keypair"] is None:
        return jsonify({"ok": False, "error": "Receiver hasn't generated a keypair yet."}), 400

    stages = []

    profile, log2 = _capture("Module 2 — Adaptive Profile (Sender)", run_adaptive_engine, verbose=True)
    stages.append(log2)

    t0 = time.perf_counter()
    engine = KemEngine()
    encap = engine.encapsulate(STATE["receiver_keypair"].publicKey)
    t1 = time.perf_counter()
    stages.append({
        "name": f"Module 1 — {KEM_LABEL} (Sender encapsulates)",
        "text": (
            f"Encapsulated against the Receiver's public key.\n"
            f"KEM ciphertext length : {len(encap.cipherText)} bytes\n"
            f"Shared secret (hex)   : {encap.sharedSecret.hex()[:32]}...\n"
        ),
        "ms": round((t1 - t0) * 1000, 3),
    })

    t0 = time.perf_counter()
    chaos_seed = hashlib.sha256(encap.sharedSecret + passphrase.encode("utf-8")).digest()
    t1 = time.perf_counter()
    stages.append({
        "name": "Chaos Seed Mixing (Sender)",
        "text": (
            "chaos_seed = SHA256(KEM_secret || shared_passphrase)\n"
            f"chaos_seed (hex): {chaos_seed.hex()[:32]}...\n"
            "(the passphrase itself is never placed on the channel — it was "
            "POSTed directly from this browser to the server)\n"
        ),
        "ms": round((t1 - t0) * 1000, 3),
    })

    try:
        chaos_result, log3 = _capture(
            "Module 3 — Chaos Keystream (Sender)",
            run_chaos_module, profile, seed=chaos_seed, verbose=True, demo_mode=demo_mode,
        )
    except ChaosInstabilityError as exc:
        return jsonify({"ok": False, "error": f"Chaos stage could not produce a stable trajectory: {exc}"}), 500
    stages.append(log3)

    hkdf_salt = os.urandom(32)

    # mix the KEM secret + chaos keystream
    derived, log4 = _capture(
        "Module 4 — HKDF (Sender)",
        deriveSessionKey, kemSecret=encap.sharedSecret, chaosKeystream=chaos_result.keystream,
        profile=profile, salt=hkdf_salt, verbose=True,
    )
    stages.append(log4)

    profile_fields = profile_to_dict(profile)
    aad = build_packet_aad(encap.cipherText, hkdf_salt, profile_fields, demo_mode)

    # AES method encrypt
    encryption, log5 = _capture(
        "Module 5 — AES-GCM Encrypt (Sender)",
        encrypt, message, derived.sessionKey, profile, aad=aad, verbose=True,
    )
    stages.append(log5)

    packet = {
        "kem_ciphertext": encap.cipherText.hex(),
        "hkdf_salt": hkdf_salt.hex(),
        "demo_mode": demo_mode,
        "profile": profile_fields,
        "aes": {
            "nonce": encryption.payload.nonce.hex(),
            "ciphertext": encryption.payload.ciphertext.hex(),
            "auth_tag": encryption.payload.auth_tag.hex(),
            "tag_length": encryption.payload.tag_length,
        },
        "plaintext_size": len(message),
        "tampered": False,
    }
    STATE["channel"] = packet

    _log(f"Sender encrypted {len(message)} bytes under a {profile.level} profile "
         f"({profile.chaos_model} chaos + shared passphrase, {profile.hkdf_hash.upper()} HKDF, "
         f"{profile.aes_tag_length * 8}-bit GCM tag, packet metadata bound as AAD) "
         f"and placed the packet on the channel.")

    return jsonify({
        "ok": True,
        "packet_summary": {
            "kem_ciphertext_preview": packet["kem_ciphertext"][:32] + "...",
            "aes_ciphertext_preview": packet["aes"]["ciphertext"][:32] + "...",
            "auth_tag": packet["aes"]["auth_tag"],
            "profile_level": profile.level,
            "chaos_model": profile.chaos_model,
            "plaintext_size": packet["plaintext_size"],
        },
        "stages": stages,
        "log": STATE["log"],
    })


@app.post("/api/tamper")
@locked
def tamper():
    if STATE["channel"] is None:
        return jsonify({"ok": False, "error": "Nothing on the channel to tamper with."}), 400

    body = request.get_json(force=True, silent=True) or {}
    target = body.get("target", "ciphertext")
    packet = STATE["channel"]

    if target == "ciphertext":
        ct = bytearray(bytes.fromhex(packet["aes"]["ciphertext"]))
        ct[0] ^= 0xFF
        packet["aes"]["ciphertext"] = bytes(ct).hex()
        _log("An attacker on the channel flipped one byte of the ciphertext in transit.")
    elif target == "tag_length":
        packet["aes"]["tag_length"] = 4
        packet["aes"]["auth_tag"] = packet["aes"]["auth_tag"][:8]   # 8 hex chars = 4 bytes
        _log("An attacker on the channel truncated the GCM tag to 4 bytes (a tag-shortening attack).")
    elif target == "profile":
        new_level = "LOW" if packet["profile"].get("level") != "LOW" else "HIGH"
        packet["profile"] = {"level": new_level, **_PROFILE_TABLE[new_level]}
        _log(f"An attacker on the channel rewrote the security profile to {new_level} (a downgrade attempt).")
    else:
        return jsonify({"ok": False, "error": f"Unknown tamper target {target!r}."}), 400

    packet["tampered"] = True
    return jsonify({"ok": True, "log": STATE["log"]})


@app.post("/api/receiver/receive")
@locked
def receiver_receive():
    data = request.get_json(force=True) if request.data else {}
    passphrase = (data.get("passphrase") or "").strip()

    if STATE["receiver_keypair"] is None:
        return jsonify({"ok": False, "error": "Receiver hasn't generated a keypair yet."}), 400
    if STATE["channel"] is None:
        return jsonify({"ok": False, "error": "Nothing on the channel yet."}), 400
    if not passphrase:
        return jsonify({"ok": False, "error": "Shared passphrase is required — enter the same one the Sender used."}), 400

    packet = STATE["channel"]
    stages = []

    fields = _decode_packet(packet)
    if fields is None:
        return jsonify({"ok": False, "error": "The packet on the channel is malformed."}), 400

    p = fields["profile"]
    profile_error = _validate_profile_fields(p)
    if profile_error:
        return _reject(packet, profile_error, stages)

    if fields["tag_length"] != p["aes_tag_length"]:
        return _reject(packet, f"tag length {fields['tag_length']!r} does not match the profile "
                               f"({p['aes_tag_length']} bytes)", stages)
    if len(fields["auth_tag"]) != fields["tag_length"]:
        return _reject(packet, "tag bytes do not match the stated tag length", stages)

    profile = SecurityProfile(
        level=p["level"],
        chaos_model=p["chaos_model"],
        chaos_iterations=p["chaos_iterations"],
        hkdf_hash=p["hkdf_hash"],
        hkdf_length=p["hkdf_length"],
        aes_tag_length=p["aes_tag_length"],
        aes_nonce_length=p["aes_nonce_length"],
        rationale="Reconstructed from the profile metadata transmitted with the packet "
                  "(validated against Module 2's profile table; the Receiver does not "
                  "resample its own hardware for this).",
    )

    t0 = time.perf_counter()
    engine = KemEngine()
    try:
        recovered_secret = engine.decapsulate(fields["kem_ciphertext"], STATE["receiver_keypair"].privateKey)
    except (ValueError, TypeError) as exc:
        return _reject(packet, f"KEM ciphertext is invalid ({exc})", stages)
    t1 = time.perf_counter()
    stages.append({
        "name": f"Module 1 — {KEM_LABEL} (Receiver decapsulates)",
        "text": (
            f"Decapsulated using the Receiver's private key.\n"
            f"Recovered secret (hex): {recovered_secret.hex()[:32]}...\n"
        ),
        "ms": round((t1 - t0) * 1000, 3),
    })

    t0 = time.perf_counter()
    chaos_seed = hashlib.sha256(recovered_secret + passphrase.encode("utf-8")).digest()
    t1 = time.perf_counter()
    stages.append({
        "name": "Chaos Seed Mixing (Receiver)",
        "text": (
            "chaos_seed = SHA256(recovered_secret || shared_passphrase)\n"
            f"chaos_seed (hex): {chaos_seed.hex()[:32]}...\n"
        ),
        "ms": round((t1 - t0) * 1000, 3),
    })

    try:
        chaos_result, log3 = _capture(
            "Module 3 — Chaos Keystream (Receiver, regenerated)",
            run_chaos_module, profile, seed=chaos_seed, verbose=True, demo_mode=fields["demo_mode"],
        )
    except ChaosInstabilityError as exc:
        return jsonify({"ok": False, "error": f"Chaos stage could not produce a stable trajectory: {exc}"}), 500
    stages.append(log3)

    # HKDF
    derived, log4 = _capture(
        "Module 4 — HKDF (Receiver)",
        deriveSessionKey, kemSecret=recovered_secret, chaosKeystream=chaos_result.keystream,
        profile=profile, salt=fields["hkdf_salt"], verbose=True,
    )
    stages.append(log4)

    aad = build_packet_aad(fields["kem_ciphertext"], fields["hkdf_salt"],
                           profile_to_dict(profile), fields["demo_mode"])

    payload = EncryptedPayload(nonce=fields["nonce"],ciphertext=fields["ciphertext"],auth_tag=fields["auth_tag"],tag_length=fields["tag_length"],)
    decryption, log5 = _capture("Module 5 — AES-GCM Decrypt (Receiver)",decrypt, payload, derived.sessionKey, aad=aad, verbose=True,)
    stages.append(log5)

    plaintext_str = None
    if decryption.tag_verified:
        plaintext_str = decryption.plaintext.decode("utf-8", errors="replace")

    passphrase_hint = ""
    if packet.get("tampered") and not decryption.tag_verified:
        _log("Receiver rejected the packet: GCM tag mismatch — tampering correctly detected.")
    elif decryption.tag_verified:
        _log(f"Receiver decrypted and verified the message successfully ({len(decryption.plaintext)} bytes).")
    else:
        _log("Receiver rejected the packet: GCM tag mismatch — either tampered in transit, "
             "or the passphrase entered here doesn't match the Sender's.")
        passphrase_hint = "TAG MISMATCH — check that you and the Sender entered the exact same shared passphrase."

    return jsonify({
        "ok": True,
        "tag_verified": decryption.tag_verified,
        "plaintext": plaintext_str,
        "was_tampered": bool(packet.get("tampered")),
        "passphrase_hint": passphrase_hint,
        "stages": stages,
        "log": STATE["log"],
    })


if __name__ == "__main__":
    print(f"KEM engine in use: {KEM_LABEL}")
    print(f"On this machine     : http://127.0.0.1:5000")
    print(f"Share with a friend : http://{LAN_IP}:5000  (must be on the same Wi-Fi/network)")
    app.run(host="0.0.0.0", port=5000, debug=False)
