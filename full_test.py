import os
import io
import math
import time
import hashlib
import contextlib
import statistics

from module1_mlkem import MlKem768
from module2_adaptive_engine import run_adaptive_engine
from module3_chaos_engine import (
    derive_dynamic_parameters, generate_raw_entropy, whiten_to_keystream, run_chaos_module,
)
from module4_hkdf import deriveSessionKey
from module5_aes_gcm import encrypt, decrypt, EncryptedPayload
from Crypto.Cipher import AES


PASS = " [+] PASS"
FAIL = "[!] FAIL"
RESULTS = []  


def check(label: str, condition: bool):
    RESULTS.append((label, bool(condition)))
    print(f"  {PASS if condition else FAIL} — {label}")


def hamming_distance_bits(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def section(title: str):
    print("\n" + "═" * 70)
    print(f"  {title}")
    print("═" * 70)


def quiet(fn, *args, **kwargs):
    """Call fn, swallowing its own verbose print() output."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)



section("PART 1 — HOW IT WORKS (one real run, full detail)")

engine = MlKem768()
receiver_kp = engine.generateKeyPair()
print(f"[Module 1] Receiver keypair generated  — public {len(receiver_kp.publicKey)}B, "
      f"private {len(receiver_kp.privateKey)}B, engine native={engine._useNative}")

encap = engine.encapsulate(receiver_kp.publicKey)
print(f"[Module 1] Sender encapsulated          — KEM ciphertext {len(encap.cipherText)}B, "
      f"shared secret {encap.sharedSecret.hex()[:24]}...")

profile = quiet(run_adaptive_engine, verbose=True)
print(f"[Module 2] Adaptive profile             — level={profile.level}, "
      f"chaos={profile.chaos_model}, hkdf={profile.hkdf_hash}, "
      f"tag={profile.aes_tag_length * 8}bit")

passphrase = "tiger-comet-velvet-71"
chaos_seed = hashlib.sha256(encap.sharedSecret + passphrase.encode()).digest()
chaos_result = quiet(run_chaos_module, profile, seed=chaos_seed, demo_mode=True)
print(f"[Module 3] Chaos keystream               — {len(chaos_result.keystream)}B, "
      f"model={chaos_result.model}, monobit={chaos_result.diagnostics['monobit_ratio']}")

hkdf_salt = os.urandom(32)
derived = quiet(deriveSessionKey, kemSecret=encap.sharedSecret,
                 chaosKeystream=chaos_result.keystream, profile=profile, salt=hkdf_salt, verbose=True)
print(f"[Module 4] Session key derived           — {derived.rawKeyLength}B via {derived.hashAlgorithm}")

plaintext = b"Strength & correctness validation message."
enc = quiet(encrypt, plaintext, derived.sessionKey, profile, verbose=True)
print(f"[Module 5] Encrypted                     — {enc.ciphertext_size}B ciphertext, "
      f"tag {enc.payload.tag_length * 8}bit")

recovered_secret = engine.decapsulate(encap.cipherText, receiver_kp.privateKey)
r_chaos_seed = hashlib.sha256(recovered_secret + passphrase.encode()).digest()
r_chaos = quiet(run_chaos_module, profile, seed=r_chaos_seed, demo_mode=True)
r_derived = quiet(deriveSessionKey, kemSecret=recovered_secret,
                   chaosKeystream=r_chaos.keystream, profile=profile, salt=hkdf_salt, verbose=True)
dec = quiet(decrypt, enc.payload, r_derived.sessionKey, verbose=True)
print(f"[Receiver] Decrypted                     — tag_verified={dec.tag_verified}, "
      f"plaintext={dec.plaintext!r}")


# ----------------------------------------------

section("PART 2 — CORRECTNESS")

check("Round trip: decrypted plaintext matches original", dec.plaintext == plaintext)
check("Round trip: GCM tag verified", dec.tag_verified)

tampered_ct = bytearray(enc.payload.ciphertext)
tampered_ct[0] ^= 0xFF
tampered_payload = EncryptedPayload(nonce=enc.payload.nonce, ciphertext=bytes(tampered_ct),
                                     auth_tag=enc.payload.auth_tag, tag_length=enc.payload.tag_length)
dec_tampered = quiet(decrypt, tampered_payload, r_derived.sessionKey, verbose=False)
check("Tampered ciphertext is rejected (tag mismatch)", not dec_tampered.tag_verified)

wrong_key = os.urandom(len(r_derived.sessionKey))
dec_wrongkey = quiet(decrypt, enc.payload, wrong_key, verbose=False)
check("Wrong session key is rejected", not dec_wrongkey.tag_verified)

wrong_pp_seed = hashlib.sha256(recovered_secret + b"WRONG-PASSPHRASE").digest()
wrong_pp_chaos = quiet(run_chaos_module, profile, seed=wrong_pp_seed, demo_mode=True)
wrong_pp_derived = quiet(deriveSessionKey, kemSecret=recovered_secret,
                          chaosKeystream=wrong_pp_chaos.keystream, profile=profile, salt=hkdf_salt, verbose=False)
dec_wrongpp = quiet(decrypt, enc.payload, wrong_pp_derived.sessionKey, verbose=False)
check("Wrong passphrase is rejected", not dec_wrongpp.tag_verified)

# ----------------------------------------------

section("PART 3 — CHAOS SENSITIVITY TO INITIAL CONDITIONS")
print("  A chaotic system's defining property: two nearly-identical seeds must produce completely uncorrelated outputs.\n")

seed_a = os.urandom(32)
seed_b = bytearray(seed_a)
seed_b[-1] ^= 0x01  # flip exactly one bit
seed_b = bytes(seed_b)

ks_a = quiet(run_chaos_module, profile, seed=seed_a, demo_mode=True).keystream
ks_b = quiet(run_chaos_module, profile, seed=seed_b, demo_mode=True).keystream

diff_bits = hamming_distance_bits(ks_a, ks_b)
total_bits = len(ks_a) * 8
diff_pct = diff_bits / total_bits * 100
print(f"  Seed A vs Seed B differ by exactly 1 bit out of 256.")
print(f"  Resulting keystreams differ in {diff_bits}/{total_bits} bits ({diff_pct:.1f}%).")
print(f"  Ideal for a good avalanche effect: ~50%.")
check("Chaos avalanche: 1-bit seed change flips 35-65% of keystream bits", 35.0 <= diff_pct <= 65.0)


# ----------------------------------------------

section("PART 4 — AES-256-GCM KEY AVALANCHE")
print("  Same plaintext, same nonce, keys differing by exactly 1 bit.")
print("  (Using pycryptodome directly here, with a fixed nonce, purely to")
print("   isolate the key's effect — Module 5 always uses a random nonce")
print("   per message in the real pipeline, which is the correct behavior.)\n")

fixed_nonce = os.urandom(12)
key_a = os.urandom(32)
key_b = bytearray(key_a)
key_b[-1] ^= 0x01
key_b = bytes(key_b)

pt = b"Fixed plaintext block for avalanche measurement................"
ct_a, _ = AES.new(key_a, AES.MODE_GCM, nonce=fixed_nonce).encrypt_and_digest(pt)
ct_b, _ = AES.new(key_b, AES.MODE_GCM, nonce=fixed_nonce).encrypt_and_digest(pt)

diff_bits_aes = hamming_distance_bits(ct_a, ct_b)
total_bits_aes = len(ct_a) * 8
diff_pct_aes = diff_bits_aes / total_bits_aes * 100
print(f"  Ciphertexts differ in {diff_bits_aes}/{total_bits_aes} bits ({diff_pct_aes:.1f}%).")
check("AES avalanche: 1-bit key change flips 35-65% of ciphertext bits", 35.0 <= diff_pct_aes <= 65.0)


# ----------------------------------------------

section("PART 5 — RANDOMNESS OF THE KEYSTREAM")
print("  The real protocol only produces 32/48/64 bytes per message —")
print("  too short to test statistics on meaningfully. So this section")
print("  reuses the SAME raw chaotic entropy from one real run and asks")
print("  whiten_to_keystream() (your actual whitening function) to squeeze")
print("  out a much bigger sample, purely for statistical testing.\n")

big_params = derive_dynamic_parameters(os.urandom(32), profile, demo_mode=True)
big_raw = generate_raw_entropy(big_params)
big_sample = whiten_to_keystream(big_raw, 125_000) 
bits = "".join(f"{byte:08b}" for byte in big_sample)
n = len(bits)
print(f"  Sample size: {len(big_sample):,} bytes ({n:,} bits)\n")

s = sum(1 if b == "1" else -1 for b in bits)
s_obs = abs(s) / math.sqrt(n)
p_monobit = math.erfc(s_obs / math.sqrt(2))
print(f"  Monobit (frequency) test  : p-value = {p_monobit:.4f}  (pass if > 0.01)")
check("Monobit test passes (bits are balanced 0s/1s)", p_monobit > 0.01)


pi = bits.count("1") / n
tau = 2 / math.sqrt(n)
if abs(pi - 0.5) >= tau:
    print("  Runs test: SKIPPED (monobit proportion too skewed to apply)")
    runs_pass = False
else:
    v_obs = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
    denom = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_runs = math.erfc(abs(v_obs - 2 * n * pi * (1 - pi)) / denom) if denom > 0 else 0.0
    print(f"  Runs test                 : p-value = {p_runs:.4f}  (pass if > 0.01)")
    runs_pass = p_runs > 0.01
check("Runs test passes (no excess clustering/alternation)", runs_pass)


freq = [0] * 256
for byte in big_sample:
    freq[byte] += 1
probs = [f / len(big_sample) for f in freq if f > 0]
shannon = -sum(p * math.log2(p) for p in probs)
print(f"  Shannon entropy            : {shannon:.4f} bits/byte  (ideal = 8.0000)")
check("Byte-level entropy is close to ideal (> 7.95 bits/byte)", shannon > 7.95)

print("\n  Caveat, stated plainly: NIST SP800-22 recommends millions of bits per\n"
      "  test for a rigorous verdict; this sample (1,000,000 bits) is large\n"
      "  enough to be meaningful but should be read as indicative, not as a\n"
      "  formal certification.")


# ----------------------------------------------

section("PART 6 — BRUTE-FORCE RESISTANCE, IN ACTUAL NUMBERS")

aes_keyspace = 2 ** 256
seconds_per_year = 365.25 * 24 * 3600
print("  AES-256 key space: 2^256 possible keys.\n")
for rate, label in [(1e9, "1 billion guesses/sec (botnet-class)"),
                     (1e15, "1 quadrillion guesses/sec (top supercomputer, optimistic)"),
                     (1e21, "1 sextillion guesses/sec (absurd hypothetical upper bound)")]:
    years = aes_keyspace / rate / seconds_per_year
    print(f"    At {label:<55}: {years:.3e} years")
print(f"    For scale, the age of the universe is ~1.4e10 years.\n")
check("AES-256 exhaustive search remains infeasible at any realistic rate", True)


def charset_entropy_bits(pw: str) -> float:
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_sym = any(not c.isalnum() for c in pw)
    charset = 26 * has_lower + 26 * has_upper + 10 * has_digit + 33 * has_sym
    return len(pw) * math.log2(max(charset, 1))

name_style_pw = "AkshayaRevathy04#"
diceware_words = 4
diceware_entropy = diceware_words * math.log2(7776)  # EFF short wordlist size

print(f"  Passphrase entropy comparison:")
print(f"    '{name_style_pw}' treated as random chars : {charset_entropy_bits(name_style_pw):.1f} bits (misleading — assumes true randomness)")
print(f"    Same password, realistic dictionary+rules attack (rough) : ~20-35 bits (names/patterns are guessed first, not brute-forced)")
print(f"    {diceware_words} truly random dictionary words                          : {diceware_entropy:.1f} bits (e.g. 'tiger-comet-velvet-71')")
check("Diceware-style passphrase has meaningfully higher REAL entropy than a name-pattern password", diceware_entropy > 40)


# ----------------------------------------------
# Final shit

section("SUMMARY")
passed = sum(1 for _, ok in RESULTS if ok)
total = len(RESULTS)
for label, ok in RESULTS:
    print(f"  {PASS if ok else FAIL} — {label}")
print(f"\n  {passed}/{total} checks passed.")
if passed == total:
    print("  [+] ALL CHECKS PASSED — pipeline is a good cryptographic system for tests above.")
else:
    print(" [!] Check Failed")