import argparse
import hashlib
import json
import math
import os
import platform
import random
import statistics
import string
import sys
import time

import web_app
from web_app import app, STATE
from module2_adaptive_engine import SecurityProfile, _PROFILE_TABLE
from module3_chaos_engine import (derive_dynamic_parameters, generate_validated_entropy, whiten_to_keystream, run_chaos_module,)
from module4_hkdf import deriveSessionKey
from module1_mlkem import MlKem768
from module5_aes_gcm import encrypt, build_packet_aad, profile_to_dict
from Crypto.Cipher import AES

LEVELS = ["LOW", "MEDIUM", "HIGH"]
PASSPHRASE = "blue-umbrella-42"
RESULTS = {}


def make_profile(level: str) -> SecurityProfile:
    return SecurityProfile(level=level, rationale="metrics benchmark", **_PROFILE_TABLE[level])


def wilson(k: int, n: int, z: float = 1.96):
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(x):
    return f"{100 * x:.2f}%"


def safe_div(a, b):
    return a / b if b else float("nan")



def flip_bit_hex(h: str) -> str:
    b = bytearray(bytes.fromhex(h))
    i = random.randrange(len(b))
    b[i] ^= 1 << random.randrange(8)
    return b.hex()


def m_ct_bitflip(p, ctx):     p["aes"]["ciphertext"] = flip_bit_hex(p["aes"]["ciphertext"])
def m_tag_bitflip(p, ctx):    p["aes"]["auth_tag"] = flip_bit_hex(p["aes"]["auth_tag"])
def m_nonce_bitflip(p, ctx):  p["aes"]["nonce"] = flip_bit_hex(p["aes"]["nonce"])
def m_kemct_bitflip(p, ctx):  p["kem_ciphertext"] = flip_bit_hex(p["kem_ciphertext"])
def m_salt_bitflip(p, ctx):   p["hkdf_salt"] = flip_bit_hex(p["hkdf_salt"])
def m_ct_truncate(p, ctx):    p["aes"]["ciphertext"] = p["aes"]["ciphertext"][:-2]
def m_demo_flag(p, ctx):      p["demo_mode"] = not p["demo_mode"]
def m_wrong_pass(p, ctx):     ctx["passphrase"] = "".join(random.choices(string.ascii_lowercase, k=12))


def m_profile_swap(p, ctx):
    new = random.choice([l for l in LEVELS if l != p["profile"]["level"]])
    p["profile"] = {"level": new, **_PROFILE_TABLE[new]}


def m_profile_edit(p, ctx):
    p["profile"]["chaos_iterations"] += random.randint(1, 1000)


def m_tag_truncate(p, ctx):
    n = random.choice([4, 8])
    p["aes"]["tag_length"] = n
    p["aes"]["auth_tag"] = p["aes"]["auth_tag"][: 2 * n]


ATTACKS = [
    ("Ciphertext bit flip", m_ct_bitflip, None),
    ("Auth tag bit flip", m_tag_bitflip, None),
    ("Nonce bit flip", m_nonce_bitflip, None),
    ("KEM ciphertext bit flip", m_kemct_bitflip, None),
    ("HKDF salt bit flip", m_salt_bitflip, None),
    ("Ciphertext truncated", m_ct_truncate, None),
    ("Tag truncated to 4 or 8 B", m_tag_truncate, None),
    ("Profile swapped to another level", m_profile_swap, None),
    ("Profile field edited", m_profile_edit, None),
    ("demo_mode flag flipped", m_demo_flag, 25),     
    ("Wrong passphrase", m_wrong_pass, None),
]


def run_trial(mutator=None, demo=True):
    """One send + one receive through the real Flask routes. Returns (accepted, plaintext_ok)."""
    client = app.test_client()
    client.post("/api/reset")
    client.post("/api/receiver/keygen")
    msg = "".join(random.choices(string.ascii_letters + string.digits + " ", k=random.randint(1, 400)))
    sent = client.post("/api/sender/send", json={"message": msg, "passphrase": PASSPHRASE, "demo_mode": demo})
    assert sent.status_code == 200, sent.get_json()
    ctx = {"passphrase": PASSPHRASE}
    if mutator:
        mutator(STATE["channel"], ctx)
    resp = client.post("/api/receiver/receive", json={"passphrase": ctx["passphrase"]})
    if resp.status_code != 200:
        return False, False
    data = resp.get_json()
    accepted = bool(data["tag_verified"])
    return accepted, accepted and data["plaintext"] == msg


def section_a(trials):
    print("\n" + "=" * 78)
    print("A. TAMPER DETECTION AS A BINARY CLASSIFIER")
    print("=" * 78)
    print("Positive class = the packet was attacked (should be rejected).")
    print("Predicted positive = the receiver rejected it. Legitimate packets are the negative class.\n")

    per_attack = {}
    for name, mutator, cap in ATTACKS:
        n = min(trials, cap) if cap else trials
        rejected = sum(1 for _ in range(n) if not run_trial(mutator)[0])
        per_attack[name] = (rejected, n)
        print(f"  attack  {name:<34} rejected {rejected}/{n}")

    total_attacks = sum(n for _, n in per_attack.values())
    n_legit = total_attacks                 
    accepted_ok = 0
    accepted = 0
    for _ in range(n_legit):
        acc, ok = run_trial(None)
        accepted += acc
        accepted_ok += ok
    print(f"  legit   unmodified packets                 accepted {accepted}/{n_legit} "
          f"(plaintext correct in {accepted_ok})")

    TP = sum(r for r, _ in per_attack.values())
    FN = total_attacks - TP
    TN = accepted
    FP = n_legit - accepted
    N = TP + TN + FP + FN
    accuracy = (TP + TN) / N
    precision = safe_div(TP, TP + FP)
    recall = safe_div(TP, TP + FN)
    specificity = safe_div(TN, TN + FP)
    f1 = safe_div(2 * precision * recall, precision + recall)
    far = safe_div(FN, TP + FN)      # false accept rate: attacks that got through
    frr = safe_div(FP, FP + TN)      # false reject rate: good packets refused
    lo, hi = wilson(TP, TP + FN)

    print("\nConfusion matrix (rows = truth, columns = receiver decision)")
    print("| | Rejected | Accepted |")
    print("| --- | --- | --- |")
    print(f"| Attacked packet | TP = {TP} | FN = {FN} |")
    print(f"| Legitimate packet | FP = {FP} | TN = {TN} |")
    print("\n| Metric | Value |")
    print("| --- | --- |")
    print(f"| Trials | {N} ({total_attacks} attacked, {n_legit} legitimate) |")
    print(f"| Accuracy | {pct(accuracy)} |")
    print(f"| Precision | {pct(precision)} |")
    print(f"| Recall (detection rate) | {pct(recall)} (95% CI {pct(lo)} to {pct(hi)}) |")
    print(f"| Specificity | {pct(specificity)} |")
    print(f"| F1 score | {f1:.4f} |")
    print(f"| False accept rate | {pct(far)} |")
    print(f"| False reject rate | {pct(frr)} |")
    if FN == 0:
        print(f"\nNo attack got through in {total_attacks} tries. That bounds the true miss rate below "
              f"about {100 * 3 / total_attacks:.2f}% at 95% confidence (rule of three).")

    # Replay is reported separately: the current code has no replay protection.
    replay_rejected = 0
    R = min(trials, 20)
    for _ in range(R):
        client = app.test_client()
        client.post("/api/reset")
        client.post("/api/receiver/keygen")
        client.post("/api/sender/send", json={"message": "replay me", "passphrase": PASSPHRASE, "demo_mode": True})
        client.post("/api/receiver/receive", json={"passphrase": PASSPHRASE})           # first delivery
        second = client.post("/api/receiver/receive", json={"passphrase": PASSPHRASE})  # replay
        replay_rejected += (second.status_code != 200 or not second.get_json()["tag_verified"])
    print(f"\nReplay of an already-delivered valid packet: rejected {replay_rejected}/{R} "
          f"(replay protection is not implemented yet, so 0 is expected)")

    RESULTS["A_tamper_detection"] = {
        "per_attack": {k: {"rejected": r, "trials": n} for k, (r, n) in per_attack.items()},
        "confusion": {"TP": TP, "FN": FN, "FP": FP, "TN": TN},
        "accuracy": accuracy, "precision": precision, "recall": recall, "specificity": specificity,
        "f1": f1, "false_accept_rate": far, "false_reject_rate": frr, "recall_ci95": [lo, hi],
        "replay_rejected": [replay_rejected, R],
    }


def bit_diff_pct(a: bytes, b: bytes) -> float:
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    return 100.0 * diff / (8 * len(a))


def flip_random_bit(data: bytes) -> bytes:
    b = bytearray(data)
    b[random.randrange(len(b))] ^= 1 << random.randrange(8)
    return bytes(b)


def summarize(values):
    return {"mean": statistics.mean(values), "std": statistics.pstdev(values),
            "min": min(values), "max": max(values),
            "within_40_60": sum(40 <= v <= 60 for v in values) / len(values)}


def section_b(trials):
    print("\n" + "=" * 78)
    print("B. AVALANCHE STATISTICS (ideal mean = 50%)")
    print("=" * 78)
    n = max(trials * 2, 100)
    print(f"{n} trials per row; every trial flips one random input bit.\n")
    print("| Test | Mean | Std | Min | Max | Trials within 40-60% |")
    print("| --- | --- | --- | --- | --- | --- |")
    out = {}
    RESULTS["B_trials"] = n

    for model_level in LEVELS:
        prof = make_profile(model_level)
        vals = []
        for _ in range(n):
            seed = os.urandom(32)
            a = run_chaos_module(prof, seed=seed, output_length=64, verbose=False, demo_mode=True).keystream
            b = run_chaos_module(prof, seed=flip_random_bit(seed), output_length=64, verbose=False, demo_mode=True).keystream
            vals.append(bit_diff_pct(a, b))
        s = summarize(vals)
        label = f"Chaos keystream, 1-bit seed flip ({prof.chaos_model})"
        print(f"| {label} | {s['mean']:.2f}% | {s['std']:.2f} | {s['min']:.1f}% | {s['max']:.1f}% | {pct(s['within_40_60'])} |")
        out[label] = s

    prof = make_profile("MEDIUM")

    def session_key(kem_secret, passphrase, salt):
        seed = hashlib.sha256(kem_secret + passphrase.encode()).digest()
        ks = run_chaos_module(prof, seed=seed, verbose=False, demo_mode=True).keystream
        return deriveSessionKey(kemSecret=kem_secret, chaosKeystream=ks, profile=prof, salt=salt, verbose=False).sessionKey

    for label, change in [
        ("Session key, 1-bit KEM secret flip", "kem"),
        ("Session key, 1-character passphrase change", "pass"),
        ("Session key, 1-bit salt flip", "salt"),
    ]:
        vals = []
        for _ in range(n):
            secret, salt = os.urandom(32), os.urandom(32)
            pw = "".join(random.choices(string.ascii_lowercase, k=12))
            base = session_key(secret, pw, salt)
            if change == "kem":
                other = session_key(flip_random_bit(secret), pw, salt)
            elif change == "pass":
                i = random.randrange(len(pw))
                pw2 = pw[:i] + random.choice([c for c in string.ascii_lowercase if c != pw[i]]) + pw[i + 1:]
                other = session_key(secret, pw2, salt)
            else:
                other = session_key(secret, pw, flip_random_bit(salt))
            vals.append(bit_diff_pct(base, other))
        s = summarize(vals)
        print(f"| {label} | {s['mean']:.2f}% | {s['std']:.2f} | {s['min']:.1f}% | {s['max']:.1f}% | {pct(s['within_40_60'])} |")
        out[label] = s
    RESULTS["B_avalanche"] = out



def monobit_p(bits):
    n = len(bits)
    s = sum(1 if b == "1" else -1 for b in bits)
    return math.erfc(abs(s) / math.sqrt(n) / math.sqrt(2))


def runs_p(bits):
    n = len(bits)
    pi = bits.count("1") / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0
    v = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
    return math.erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))


def to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def section_c(sequences):
    print("\n" + "=" * 78)
    print("C. NIST-STYLE RANDOMNESS: PROPORTION OF SEQUENCES THAT PASS")
    print("=" * 78)
    seq_bits = 100_000
    seq_bytes = seq_bits // 8
    alpha = 0.01
    p_hat = 1 - alpha
    lower = p_hat - 3 * math.sqrt(p_hat * (1 - p_hat) / sequences)
    print(f"{sequences} independent sequences of {seq_bits:,} bits (Lorenz, demo budget). "
          f"A batch passes when the pass proportion is at least {lower:.4f}.\n")
    prof = make_profile("MEDIUM")
    counts = {"whitened": {"monobit": 0, "runs": 0}, "raw": {"monobit": 0, "runs": 0}}
    for _ in range(sequences):
        _, raw, _ = generate_validated_entropy(os.urandom(32), prof, demo_mode=True)
        white = to_bits(whiten_to_keystream(raw, seq_bytes))
        rawb = to_bits(raw[:seq_bytes])
        for name, bits in (("whitened", white), ("raw", rawb)):
            counts[name]["monobit"] += monobit_p(bits) > alpha
            counts[name]["runs"] += runs_p(bits) > alpha
    print("| Stream | Test | Sequences passed | Proportion | Batch verdict |")
    print("| --- | --- | --- | --- | --- |")
    out = {}
    for name, label in (("whitened", "Pipeline output (after SHAKE-256)"), ("raw", "Raw chaotic bytes (before whitening)")):
        for test in ("monobit", "runs"):
            k = counts[name][test]
            prop = k / sequences
            print(f"| {label} | {test} | {k}/{sequences} | {prop:.4f} | {'PASS' if prop >= lower else 'FAIL'} |")
            out[f"{name}_{test}"] = {"passed": k, "sequences": sequences, "proportion": prop}
    RESULTS["C_randomness"] = out



def section_d(samples):
    print("\n" + "=" * 78)
    print("D. MACHINE-LEARNING DISTINGUISHER (keystream vs os.urandom)")
    print("=" * 78)
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import StratifiedKFold, cross_validate
    except ImportError:
        print("numpy / scikit-learn not installed. Run:  pip install numpy scikit-learn   (or use --skip-ml)")
        return

    L = 256
    prof = make_profile("MEDIUM")
    white, raw = [], []
    for _ in range(samples):
        _, r, _ = generate_validated_entropy(os.urandom(32), prof, demo_mode=True)
        raw.append(r[:L])
        white.append(whiten_to_keystream(r, L))
    rand = [os.urandom(L) for _ in range(samples)]
    rng = np.random.default_rng(0)
    biased = [np.packbits(rng.random(L * 8) < 0.55).tobytes() for _ in range(samples)]

    def features_raw(chunks):
        return np.array([list(c) for c in chunks], dtype=float)

    def features_hist(chunks):
        return np.array([np.bincount(np.frombuffer(c, dtype=np.uint8), minlength=256) / len(c) for c in chunks])

    datasets = [
        ("Pipeline keystream vs random", white, "expected ~50% (cannot tell apart)"),
        ("Raw chaotic bytes vs random", raw, "expected ~100% (raw chaos is easy to spot)"),
        ("Positive control: 55% ones vs random", biased, "expected high (proves the test has power)"),
    ]
    models = [
        ("Logistic regression on byte histogram", features_hist, lambda: LogisticRegression(max_iter=2000)),
        ("Random forest on raw byte positions", features_raw, lambda: RandomForestClassifier(n_estimators=100, random_state=0)),
    ]
    scoring = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    print(f"{samples} samples per class, {L} bytes each, 5-fold cross-validation, mean +/- std.\n")
    print("| Dataset | Model | Accuracy | Precision | Recall | F1 | ROC-AUC |")
    print("| --- | --- | --- | --- | --- | --- | --- |")
    out = {}
    for ds_name, positives, note in datasets:
        y = np.array([1] * len(positives) + [0] * len(rand))
        for m_name, feat, make in models:
            X = feat(list(positives) + rand)
            res = cross_validate(make(), X, y, cv=cv, scoring=scoring)
            row = {s: (float(res[f"test_{s}"].mean()), float(res[f"test_{s}"].std())) for s in scoring}
            cells = " | ".join(f"{row[s][0]:.3f} +/- {row[s][1]:.3f}" for s in scoring)
            print(f"| {ds_name} | {m_name} | {cells} |")
            out[f"{ds_name} / {m_name}"] = {"scores": row, "note": note}
    print("\nReading it: accuracy and AUC near 0.50 mean the classifier does no better than a coin flip.")
    RESULTS["D_distinguisher"] = out



WORDS = ("the of and to in is that for it as with was on be by this have from or one had not but what all were when we "
         "there can an your which their said if do will each about how up out them then she many some so these would other "
         "into has more her two like him see time could no make than first been its who now people my made over did down only "
         "way find use may water long little very after words called just where most know").split()


def english_like(n_bytes: int) -> bytes:
    out = bytearray()
    while len(out) < n_bytes:
        out += (random.choice(WORDS) + " ").encode()
    return bytes(out[:n_bytes])


def shannon_bits_per_byte(data: bytes) -> float:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def pipeline_session(engine, kp, profile, plaintext, demo=True):
    """The full pipeline without the web layer: KEM, chaos, HKDF, AES-GCM with the packet AAD."""
    encap = engine.encapsulate(kp.publicKey)
    seed = hashlib.sha256(encap.sharedSecret + PASSPHRASE.encode()).digest()
    ks = run_chaos_module(profile, seed=seed, verbose=False, demo_mode=demo)
    salt = os.urandom(32)
    derived = deriveSessionKey(kemSecret=encap.sharedSecret, chaosKeystream=ks.keystream, profile=profile,
                               salt=salt, verbose=False)
    aad = build_packet_aad(encap.cipherText, salt, profile_to_dict(profile), demo)
    enc = encrypt(plaintext, derived.sessionKey, profile, aad=aad, verbose=False)
    return derived.sessionKey, salt, enc, encap


def section_e(trials, sequences, ml_samples, skip_ml):
    print("\n" + "=" * 78)
    print("E. OVERALL ALGORITHM, END TO END")
    print("=" * 78)
    out = {}

    print("\nE1. Per-level correctness and tamper detection (real Flask routes, demo budget)\n")
    n = max(trials, 30)
    attack_pool = [a for a in ATTACKS if a[0] != "demo_mode flag flipped"]
    print("| Level | Chaos model | Legitimate accepted | Attacks rejected | Accuracy | Precision | Recall | F1 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    per_level = {}
    for level in LEVELS:
        web_app.run_adaptive_engine = lambda verbose=True, _l=level, **kw: make_profile(_l)
        ok = sum(run_trial(None)[1] for _ in range(n))
        rej = sum(1 for _ in range(n) if not run_trial(random.choice(attack_pool)[1])[0])
        TP, FN, TN, FP = rej, n - rej, ok, n - ok
        acc = (TP + TN) / (2 * n)
        prec, rec = safe_div(TP, TP + FP), safe_div(TP, TP + FN)
        f1 = safe_div(2 * prec * rec, prec + rec)
        per_level[level] = {"legit_accepted": ok, "attacks_rejected": rej, "n": n, "accuracy": acc,
                            "precision": prec, "recall": rec, "f1": f1, "chaos_model": _PROFILE_TABLE[level]["chaos_model"]}
        print(f"| {level} | {_PROFILE_TABLE[level]['chaos_model']} | {ok}/{n} | {rej}/{n} | {pct(acc)} | {pct(prec)} | {pct(rec)} | {f1:.4f} |")
    out["per_level"] = per_level

    print("\nFull chaos budget, round trip only (this is the setting a real deployment would use)\n")
    print("| Level | Trials | Correct round trips |")
    print("| --- | --- | --- |")
    full_budget = {}
    for level, k in (("LOW", 30), ("MEDIUM", 10), ("HIGH", 5)):
        web_app.run_adaptive_engine = lambda verbose=True, _l=level, **kw: make_profile(_l)
        ok = sum(run_trial(None, demo=False)[1] for _ in range(k))
        full_budget[level] = {"trials": k, "correct": ok}
        print(f"| {level} | {k} | {ok}/{k} |")
    out["full_budget"] = full_budget


    engine = MlKem768()
    kp = engine.generateKeyPair()
    prof = make_profile("LOW")
    N = 5000
    print(f"\nE2. Uniqueness over {N} independent sessions (LOW profile, one receiver keypair)\n")
    keys, nonces, salts, kemcts = [], [], [], []
    for _ in range(N):
        key, salt, enc, encap = pipeline_session(engine, kp, prof, b"x" * 32)
        keys.append(key); nonces.append(enc.payload.nonce); salts.append(salt); kemcts.append(encap.cipherText)
    uniq = {"session keys": len(set(keys)), "AES nonces": len(set(nonces)),
            "HKDF salts": len(set(salts)), "KEM ciphertexts": len(set(kemcts))}
    print("| Value | Unique / total |")
    print("| --- | --- |")
    for k, v in uniq.items():
        print(f"| {k} | {v}/{N} |")
    pair_d = []
    for _ in range(20000):
        i, j = random.sample(range(N), 2)
        pair_d.append(bit_diff_pct(keys[i], keys[j]))
    ones = [0] * (8 * len(keys[0]))
    for key in keys:
        for bit in range(8 * len(key)):
            ones[bit] += (key[bit // 8] >> (7 - bit % 8)) & 1
    frac = [c / N for c in ones]
    print(f"\nPairwise key difference over 20,000 random pairs: mean {statistics.mean(pair_d):.2f}%, "
          f"std {statistics.pstdev(pair_d):.2f} (ideal 50%).")
    print(f"Per-bit share of ones across all keys: lowest {min(frac):.3f}, highest {max(frac):.3f} "
          f"(ideal 0.500; expected spread about +/- {3 * 0.5 / math.sqrt(N):.3f}).")
    out["uniqueness"] = {"sessions": N, **{k: v for k, v in uniq.items()},
                         "pair_diff_mean": statistics.mean(pair_d), "pair_diff_std": statistics.pstdev(pair_d),
                         "bit_share_min": min(frac), "bit_share_max": max(frac)}

    # E3. Ciphertext randomness and entropy
    print(f"\nE3. Ciphertext randomness ({sequences} sessions, 12,500-byte plaintexts)\n")
    prof_m = make_profile("MEDIUM")
    counts = {"mono": 0, "runs": 0}
    ent_ct, ent_pt = [], []
    for _ in range(sequences):
        _, _, enc, _ = pipeline_session(engine, kp, prof_m, bytes(12500))
        bits = to_bits(enc.payload.ciphertext)
        counts["mono"] += monobit_p(bits) > 0.01
        counts["runs"] += runs_p(bits) > 0.01
        text = english_like(12500)
        _, _, enc_t, _ = pipeline_session(engine, kp, prof_m, text)
        ent_pt.append(shannon_bits_per_byte(text))
        ent_ct.append(shannon_bits_per_byte(enc_t.payload.ciphertext))
    p_hat = 0.99
    lower = p_hat - 3 * math.sqrt(p_hat * (1 - p_hat) / sequences)
    print("| Measure | Result |")
    print("| --- | --- |")
    print(f"| Ciphertext of all-zero plaintext, monobit | {counts['mono']}/{sequences} sequences pass (need {lower:.4f}) |")
    print(f"| Ciphertext of all-zero plaintext, runs | {counts['runs']}/{sequences} sequences pass |")
    print(f"| Entropy of English-like plaintext | {statistics.mean(ent_pt):.3f} bits/byte |")
    print(f"| Entropy of its ciphertext | {statistics.mean(ent_ct):.3f} bits/byte (ideal 8.000) |")
    out["ciphertext_randomness"] = {"sequences": sequences, "monobit_passed": counts["mono"], "runs_passed": counts["runs"],
                                    "required": lower, "plaintext_entropy": statistics.mean(ent_pt),
                                    "ciphertext_entropy": statistics.mean(ent_ct)}

  
    nsens = max(trials * 2, 100)
    print(f"\nE4. Sensitivity of ciphertext and tag to a one-bit input change ({nsens} trials per row)\n")

    def key_for(secret, pw, salt):
        seed = hashlib.sha256(secret + pw.encode()).digest()
        ks = run_chaos_module(prof_m, seed=seed, verbose=False, demo_mode=True).keystream
        return deriveSessionKey(kemSecret=secret, chaosKeystream=ks, profile=prof_m, salt=salt, verbose=False).sessionKey[:32]

    def gcm(key, nonce, pt):
        c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        return c.encrypt_and_digest(pt)

    rows = {"1-bit plaintext flip": ([], []), "1-bit KEM secret flip": ([], []),
            "1-character passphrase change": ([], []), "1-bit salt flip": ([], [])}
    for _ in range(nsens):
        secret, salt, nonce = os.urandom(32), os.urandom(32), os.urandom(12)
        pw = "".join(random.choices(string.ascii_lowercase, k=12))
        pt = os.urandom(64)
        c0, t0 = gcm(key_for(secret, pw, salt), nonce, pt)
        variants = {
            "1-bit plaintext flip": gcm(key_for(secret, pw, salt), nonce, flip_random_bit(pt)),
            "1-bit KEM secret flip": gcm(key_for(flip_random_bit(secret), pw, salt), nonce, pt),
            "1-character passphrase change": gcm(key_for(secret, pw[:-1] + ("a" if pw[-1] != "a" else "b"), salt), nonce, pt),
            "1-bit salt flip": gcm(key_for(secret, pw, flip_random_bit(salt)), nonce, pt),
        }
        for name, (c1, t1) in variants.items():
            rows[name][0].append(bit_diff_pct(c0, c1))
            rows[name][1].append(bit_diff_pct(t0, t1))
    print("| Input change | Ciphertext bits changed (mean +/- std) | Tag bits changed (mean +/- std) |")
    print("| --- | --- | --- |")
    sens = {}
    for name, (cv, tv) in rows.items():
        print(f"| {name} | {statistics.mean(cv):.2f}% +/- {statistics.pstdev(cv):.2f} | {statistics.mean(tv):.2f}% +/- {statistics.pstdev(tv):.2f} |")
        sens[name] = {"ct_mean": statistics.mean(cv), "ct_std": statistics.pstdev(cv),
                      "tag_mean": statistics.mean(tv), "tag_std": statistics.pstdev(tv)}
    print("\nA one-bit plaintext change flips only one ciphertext bit. That is correct for AES-GCM, which is a counter-mode stream")
    print("cipher, and the tag still changes completely, so the change is caught. Key-side changes flip about half of everything.")
    out["sensitivity"] = sens

    # E5. Ciphertext distinguisher
    if not skip_ml:
        try:
            import numpy as np
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.linear_model import LogisticRegression
            from sklearn.model_selection import StratifiedKFold, cross_validate
        except ImportError:
            print("\nE5 skipped: numpy / scikit-learn not installed.")
        else:
            L = 256
            print(f"\nE5. Can a classifier tell ciphertext from random bytes? ({ml_samples} samples per class, {L} bytes, 5-fold CV)\n")
            plains, cts = [], []
            for _ in range(ml_samples):
                pt = english_like(L)
                _, _, enc, _ = pipeline_session(engine, kp, prof, pt)
                plains.append(pt); cts.append(enc.payload.ciphertext)
            rand = [os.urandom(L) for _ in range(ml_samples)]
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
            scoring = ["accuracy", "precision", "recall", "f1", "roc_auc"]
            feats = {"Logistic regression": (lambda cs: np.array([np.bincount(np.frombuffer(c, dtype=np.uint8), minlength=256) / len(c) for c in cs]),
                                             lambda: LogisticRegression(max_iter=2000)),
                     "Random forest": (lambda cs: np.array([list(c) for c in cs], dtype=float),
                                       lambda: RandomForestClassifier(n_estimators=100, random_state=0))}
            print("| Dataset | Model | Accuracy | Precision | Recall | F1 | ROC-AUC |")
            print("| --- | --- | --- | --- | --- | --- | --- |")
            dist = {}
            rand_b = [os.urandom(L) for _ in range(ml_samples)]
            for ds, pos in (("Pipeline ciphertext vs random", cts),
                            ("Negative control: random vs random", rand_b),
                            ("Positive control: plaintext vs random", plains)):
                y = np.array([1] * len(pos) + [0] * len(rand))
                for mname, (fx, mk) in feats.items():
                    res = cross_validate(mk(), fx(list(pos) + rand), y, cv=cv, scoring=scoring)
                    sc = {s: (float(res[f"test_{s}"].mean()), float(res[f"test_{s}"].std())) for s in scoring}
                    print(f"| {ds} | {mname} | " + " | ".join(f"{sc[s][0]:.3f} +/- {sc[s][1]:.3f}" for s in scoring) + " |")
                    dist[f"{ds} / {mname}"] = sc
            out["ciphertext_distinguisher"] = dist
    RESULTS["E_overall"] = out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=50, help="trials per attack type in section A")
    ap.add_argument("--sequences", type=int, default=100, help="sequences in section C")
    ap.add_argument("--ml-samples", type=int, default=1000, help="samples per class in section D")
    ap.add_argument("--skip-ml", action="store_true")
    ap.add_argument("--seed", type=int, default=12345, help="seed for the test harness's own choices (not the crypto)")
    args = ap.parse_args()
    random.seed(args.seed)

    # Skip Module 2's 1-second hardware sampling: pick a profile directly, so the run is fast and covers all levels.
    web_app.run_adaptive_engine = lambda verbose=True, **kw: make_profile(random.choice(LEVELS))

    engine_native = web_app.MODULE1_NATIVE
    print(f"Machine: {platform.platform()} | Python {platform.python_version()} | "
          f"KEM: {'native ML-KEM-768' if engine_native else 'classical DH fallback'}")
    RESULTS["environment"] = {"platform": platform.platform(), "python": platform.python_version(),
                              "kem_native": engine_native, "harness_seed": args.seed, "date": time.strftime("%Y-%m-%d")}
    t0 = time.time()
    section_a(args.trials)
    section_b(args.trials)
    section_c(args.sequences)
    if not args.skip_ml:
        section_d(args.ml_samples)
    section_e(args.trials, args.sequences, args.ml_samples, args.skip_ml)
    RESULTS["elapsed_seconds"] = round(time.time() - t0, 1)
    with open("metrics_results.json", "w") as f:
        json.dump(RESULTS, f, indent=2)
    print(f"\nDone in {RESULTS['elapsed_seconds']} s. Full numbers saved to metrics_results.json")


if __name__ == "__main__":
    sys.exit(main())