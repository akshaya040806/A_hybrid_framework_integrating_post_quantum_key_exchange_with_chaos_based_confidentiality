import hashlib
import math
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Literal, Tuple

from module2_adaptive_engine import SecurityProfile

ChaosModel = Literal["henon", "lorenz", "chen", "rossler"]


@dataclass
class ChaosParameters:
    model: ChaosModel
    control: dict
    initial_state: Tuple[float, ...]
    dt: float = 0.01
    warmup_iterations: int = 0
    production_iterations: int = 0


@dataclass
class ChaosKeystreamResult:
    model: ChaosModel
    params: ChaosParameters
    keystream: bytes
    keystream_bits: int
    generation_time: float
    throughput_mbps: float
    diagnostics: dict = field(default_factory=dict)


class ChaosInstabilityError(Exception):
    """Raised when a chaotic trajectory diverges, overflows, or collapses into
    a fixed point / short cycle, i.e. it is not usable as an entropy source."""


def _counter_stream(seed: bytes, n_needed: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n_needed:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:n_needed])


def _bytes_to_unit_floats(b: bytes) -> list:
    n = len(b) // 8
    floats = []
    for i in range(n):
        chunk = b[i * 8:(i + 1) * 8]
        as_int = int.from_bytes(chunk, "big")
        floats.append(as_int / 2**64)
    return floats


def _scale(u: float, lo: float, hi: float) -> float:
    return lo + u * (hi - lo)


_PARAM_BANDS: dict = {
    "henon": {
        "control": {"a": (1.39, 1.41), "b": (0.29, 0.31)},
        "state":   {"x0": (-0.5, 0.5), "y0": (-0.5, 0.5)},
    },
    "lorenz": {
        "control": {"sigma": (9.5, 10.5), "rho": (27.0, 29.0), "beta": (2.6, 2.7)},
        "state":   {"x0": (0.1, 1.0), "y0": (0.1, 1.0), "z0": (0.1, 1.0)},
    },
    "chen": {
        "control": {"a": (34.0, 36.0), "b": (2.8, 3.2), "c": (27.0, 29.0)},
        "state":   {"x0": (-1.0, 1.0), "y0": (-1.0, 1.0), "z0": (-1.0, 1.0)},
    },
    "rossler": {
        "control": {"a": (0.15, 0.20), "b": (0.15, 0.20), "c": (5.5, 6.5)},
        "state":   {"x0": (0.1, 1.0), "y0": (0.1, 1.0), "z0": (0.1, 1.0)},
    },
}


DEMO_SPEEDUP_FACTOR = 25
DEMO_MIN_ITERATIONS = 400
STATE_BOUND = 1.0e4
MIN_UNIQUE_RATIO = 0.95
MIN_SAMPLE_FOR_UNIQUENESS = 100
MAX_DERIVATION_ATTEMPTS = 16


def derive_dynamic_parameters(
    seed: bytes,
    profile: SecurityProfile,
    demo_mode: bool = False,
    attempt: int = 0,
) -> ChaosParameters:
    
    model = profile.chaos_model
    band = _PARAM_BANDS[model]

    n_control = len(band["control"])
    n_state = len(band["state"])
    stream_seed = seed + model.encode()
    if attempt > 0:
        stream_seed += b"|retry|" + attempt.to_bytes(2, "big")
    stream = _counter_stream(stream_seed, (n_control + n_state) * 8)
    floats = _bytes_to_unit_floats(stream)

    control = {}
    for (name, (lo, hi)), u in zip(band["control"].items(), floats[:n_control]):
        control[name] = _scale(u, lo, hi)

    state_vals = []
    for (name, (lo, hi)), u in zip(band["state"].items(), floats[n_control:]):
        state_vals.append(_scale(u, lo, hi))

    iteration_budget = profile.chaos_iterations
    if demo_mode:
        iteration_budget = max(DEMO_MIN_ITERATIONS, iteration_budget // DEMO_SPEEDUP_FACTOR)
    warmup = max(200, iteration_budget // 5)
    production = max(1, iteration_budget - warmup)

    return ChaosParameters(
        model=model,
        control=control,
        initial_state=tuple(state_vals),
        dt=0.01,
        warmup_iterations=warmup,
        production_iterations=production,
    )


def _iterate_henon(params: ChaosParameters):
    a, b = params.control["a"], params.control["b"]
    x, y = params.initial_state
    while True:
        x, y = 1.0 - a * x * x + y, b * x
        yield (x, y)


def _lorenz_deriv(state, sigma, rho, beta):
    x, y, z = state
    return (sigma * (y - x), x * (rho - z) - y, x * y - beta * z)


def _chen_deriv(state, a, b, c):
    x, y, z = state
    return (a * (y - x), (c - a) * x - x * z + c * y, x * y - b * z)


def _rossler_deriv(state, a, b, c):
    x, y, z = state
    return (-y - z, x + a * y, b + z * (x - c))


def _rk4_step(state, dt, deriv_fn, *params):
    k1 = deriv_fn(state, *params)
    s2 = tuple(state[i] + 0.5 * dt * k1[i] for i in range(3))
    k2 = deriv_fn(s2, *params)
    s3 = tuple(state[i] + 0.5 * dt * k2[i] for i in range(3))
    k3 = deriv_fn(s3, *params)
    s4 = tuple(state[i] + dt * k3[i] for i in range(3))
    k4 = deriv_fn(s4, *params)
    return tuple(
        state[i] + (dt / 6.0) * (k1[i] + 2 * k2[i] + 2 * k3[i] + k4[i])
        for i in range(3)
    )


def _iterate_ode(params: ChaosParameters, deriv_fn, control_order):
    ctrl = tuple(params.control[name] for name in control_order)
    state = params.initial_state
    while True:
        state = _rk4_step(state, params.dt, deriv_fn, *ctrl)
        yield state


_GENERATORS = {
    "henon":   lambda p: _iterate_henon(p),
    "lorenz":  lambda p: _iterate_ode(p, _lorenz_deriv, ("sigma", "rho", "beta")),
    "chen":    lambda p: _iterate_ode(p, _chen_deriv, ("a", "b", "c")),
    "rossler": lambda p: _iterate_ode(p, _rossler_deriv, ("a", "b", "c")),
}


def _pack_state(state: Tuple[float, ...]) -> bytes:
    return b"".join(struct.pack(">d", v) for v in state)


def _check_state(state: Tuple[float, ...]) -> None:
    for v in state:
        if not math.isfinite(v) or abs(v) > STATE_BOUND:
            raise ChaosInstabilityError(
                f"trajectory left the allowed range (value = {v!r})"
            )


def generate_raw_entropy(params: ChaosParameters) -> bytes:
    gen = _GENERATORS[params.model](params)

    try:
        state = params.initial_state
        for _ in range(params.warmup_iterations):
            state = next(gen)
        _check_state(state)

        raw = bytearray()
        seen_first = set()
        for _ in range(params.production_iterations):
            state = next(gen)
            _check_state(state)
            seen_first.add(state[0])
            raw += _pack_state(state)
    except (OverflowError, ZeroDivisionError) as exc:
        raise ChaosInstabilityError(f"numeric failure: {exc}") from exc

    if params.production_iterations >= MIN_SAMPLE_FOR_UNIQUENESS:
        unique_ratio = len(seen_first) / params.production_iterations
        if unique_ratio < MIN_UNIQUE_RATIO:
            raise ChaosInstabilityError(
                f"trajectory is (nearly) periodic: only {unique_ratio:.1%} distinct values"
            )
    return bytes(raw)


def generate_validated_entropy(
    seed: bytes,
    profile: SecurityProfile,
    demo_mode: bool = False,
):
    last_error = None
    for attempt in range(MAX_DERIVATION_ATTEMPTS):
        params = derive_dynamic_parameters(seed, profile, demo_mode=demo_mode, attempt=attempt)
        try:
            raw = generate_raw_entropy(params)
        except ChaosInstabilityError as exc:
            last_error = exc
            continue
        return params, raw, attempt + 1
    raise ChaosInstabilityError(
        f"no valid chaotic trajectory after {MAX_DERIVATION_ATTEMPTS} attempts "
        f"(last error: {last_error})"
    )


def whiten_to_keystream(raw_entropy: bytes, output_length: int) -> bytes:
    return hashlib.shake_256(raw_entropy).digest(output_length)


def _keystream_diagnostics(keystream: bytes) -> dict:
    total_bits = len(keystream) * 8
    ones = sum(bin(byte).count("1") for byte in keystream)
    monobit_ratio = ones / total_bits

    # Simple byte uniformity check
    hist = [0] * 256
    for b in keystream:
        hist[b] += 1
    expected = len(keystream) / 256
    chi_sq = sum((count - expected) ** 2 / expected for count in hist) if expected > 0 else 0.0

    return {
        "monobit_ratio": round(monobit_ratio, 4),
        "byte_chi_square": round(chi_sq, 2),
        "sample_bytes_hex": keystream[:16].hex(),
    }


def run_chaos_module(
    profile: SecurityProfile,
    seed: bytes = None,
    output_length: int = None,
    verbose: bool = True,
    demo_mode: bool = False,
) -> ChaosKeystreamResult:
    if seed is None:
        seed = os.urandom(32)
    if output_length is None:
        output_length = profile.hkdf_length

    if verbose:
        print("\nMODULE 3 — DYNAMIC CHAOTIC KEYSTREAM ENGINE")
        if demo_mode:
            print("(DEMO MODE — iterations reduced for speed,")
            print(f"NOT the real security-relevant budget. "
                  f"÷{DEMO_SPEEDUP_FACTOR} of production)")
        print(f"  Selected model (from Module 2) : {profile.chaos_model}")
        print("\n")

    t_start = time.perf_counter()

    params, raw, attempts = generate_validated_entropy(seed, profile, demo_mode=demo_mode)
    keystream = whiten_to_keystream(raw, output_length)

    t_end = time.perf_counter()
    gen_time = t_end - t_start
    size_mb = len(keystream) / (1024 ** 2)
    throughput = size_mb / gen_time if gen_time > 0 else float("inf")

    diagnostics = _keystream_diagnostics(keystream)
    diagnostics["demo_mode"] = demo_mode
    diagnostics["derivation_attempts"] = attempts

    result = ChaosKeystreamResult(
        model=profile.chaos_model,
        params=params,
        keystream=keystream,
        keystream_bits=len(keystream) * 8,
        generation_time=gen_time,
        throughput_mbps=throughput,
        diagnostics=diagnostics,
    )

    if verbose:
        print(f"  {'Control parameters':<25} { {k: round(v, 5) for k, v in params.control.items()} }")
        print(f"  {'Initial state':<25} { tuple(round(v, 5) for v in params.initial_state) }")
        print(f"  {'Warm-up iterations':<25} {params.warmup_iterations:,}")
        print(f"  {'Production iterations':<25} {params.production_iterations:,}")
        print(f"  {'Trajectory attempts':<25} {attempts} (1 = first derivation was stable)")
        print(f"  {'Raw entropy collected':<25} {len(raw):,} bytes")
        print(f"  {'Keystream length':<25} {len(keystream)} bytes ({result.keystream_bits} bits)")
        print(f"  {'Generation time':<25} {gen_time * 1000:.4f} ms")
        print(f"  {'Throughput':<25} {throughput:.2f} MB/s")
        print()
        print(f"  [+] Monobit ratio     : {diagnostics['monobit_ratio']}  (ideal ≈ 0.5000)")
        print(f"  [+] Byte chi-square   : {diagnostics['byte_chi_square']}  "
              f"(informational only: too few bytes for a statistical verdict)")
        print(f"  [+] Keystream preview : {diagnostics['sample_bytes_hex']} …")
        print("\n")

    return result


if __name__ == "__main__":
    import sys
    from module2_adaptive_engine import run_adaptive_engine

    fast = "--fast-demo" in sys.argv

    profile = run_adaptive_engine(verbose=True)
    run_chaos_module(profile, verbose=True, demo_mode=fast)
