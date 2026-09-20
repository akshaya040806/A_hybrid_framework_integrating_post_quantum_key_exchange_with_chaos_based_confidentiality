import psutil
import platform
from dataclasses import dataclass
from typing import Literal
import time


SecurityLevel = Literal["LOW", "MEDIUM", "HIGH"]


@dataclass
class HardwareSnapshot:
    """Raw hardware readings captured at a single moment."""
    cpu_percent: float          
    ram_available_mb: float
    battery_percent: float   
    on_power: bool        


@dataclass
class SecurityProfile:
    level: SecurityLevel
    chaos_model: str         
    chaos_iterations: int       

    hkdf_hash: str          
    hkdf_length: int            

    aes_tag_length: int        
    aes_nonce_length: int     

    rationale: str       


def _sample_hardware(cpu_interval: float = 1.0) -> HardwareSnapshot:
    cpu = psutil.cpu_percent(interval=cpu_interval)

    ram_info = psutil.virtual_memory()
    ram_available_mb = ram_info.available / (1024 ** 2)

    battery = psutil.sensors_battery()
    if battery is None:
        battery_percent = 100.0
        on_power = True
    else:
        battery_percent = battery.percent
        on_power = battery.power_plugged

    return HardwareSnapshot(
        cpu_percent=cpu,
        ram_available_mb=ram_available_mb,
        battery_percent=battery_percent,
        on_power=on_power,
    )


def _compute_resource_score(snap: HardwareSnapshot) -> float:
    cpu_score = max(0.0, 100.0 - snap.cpu_percent)
    RAM_CEILING_MB = 4096.0
    ram_score = min(snap.ram_available_mb / RAM_CEILING_MB, 1.0) * 100.0

    # Battery score
    if snap.on_power:
        battery_score = 100.0
    else:
        battery_score = snap.battery_percent  

    weighted = (0.40 * cpu_score + 0.35 * ram_score + 0.25 * battery_score)
    return round(weighted, 2)


def _score_to_level(score: float) -> SecurityLevel:
    if score < 35.0:
        return "LOW"
    elif score < 65.0:
        return "MEDIUM"
    else:
        return "HIGH"



_PROFILE_TABLE: dict[SecurityLevel, dict] = {
    "LOW": {
        "chaos_model":      "henon",        
        "chaos_iterations": 5_000,
        "hkdf_hash":        "sha256",
        "hkdf_length":      32,          
        "aes_tag_length":   12,           
        "aes_nonce_length": 12,
    },
    "MEDIUM": {
        "chaos_model":      "lorenz",      
        "chaos_iterations": 50_000,
        "hkdf_hash":        "sha384",
        "hkdf_length":      48,           
        "aes_tag_length":   14,       
        "aes_nonce_length": 12,
    },
    "HIGH": {
        "chaos_model":      "chen",       
        "chaos_iterations": 200_000,
        "hkdf_hash":        "sha512",
        "hkdf_length":      64,            
        "aes_tag_length":   16,       
        "aes_nonce_length": 12,
    },
}


def _build_profile(level: SecurityLevel, snap: HardwareSnapshot, score: float) -> SecurityProfile:
    cfg = _PROFILE_TABLE[level]
    rationale = (
        f"Resource score {score}/100 → {level} profile | "
        f"CPU {snap.cpu_percent:.1f}% | "
        f"RAM free {snap.ram_available_mb:.0f} MB | "
        f"Battery {snap.battery_percent:.0f}% "
        f"({'plugged in' if snap.on_power else 'on battery'})"
    )
    return SecurityProfile(
        level=level,
        chaos_model=cfg["chaos_model"],
        chaos_iterations=cfg["chaos_iterations"],
        hkdf_hash=cfg["hkdf_hash"],
        hkdf_length=cfg["hkdf_length"],
        aes_tag_length=cfg["aes_tag_length"],
        aes_nonce_length=cfg["aes_nonce_length"],
        rationale=rationale,
    )


def run_adaptive_engine(cpu_interval: float = 1.0,verbose: bool = True,) -> SecurityProfile:

    if verbose:
        print("\n" + "═" * 55)
        print("   MODULE 2 — ADAPTIVE SECURITY ENGINE")
        print("═" * 55)
        print("  Sampling hardware metrics …", end="", flush=True)

    snap = _sample_hardware(cpu_interval=cpu_interval)
    score = _compute_resource_score(snap)
    level = _score_to_level(score)
    profile = _build_profile(level, snap, score)

    if verbose:
        print(" done.\n")
        print(f"  {'Metric':<25} {'Value':>15}")
        print("  " + "─" * 42)
        print(f"  {'CPU Usage':<25} {snap.cpu_percent:>14.1f}%")
        print(f"  {'RAM Available':<25} {snap.ram_available_mb:>11.0f} MB")
        print(f"  {'Battery':<25} {snap.battery_percent:>14.0f}%")
        print(f"  {'On Power':<25} {str(snap.on_power):>15}")
        print(f"  {'Resource Score':<25} {score:>14.2f}")
        print()
        print(f" [+] Security Level   : {level}")
        print(f" [+] Chaos Model      : {profile.chaos_model}")
        print(f" [+] Chaos Iterations : {profile.chaos_iterations:,}")
        print(f" [+] HKDF Hash        : {profile.hkdf_hash.upper()}")
        print(f" [+] HKDF Key Length  : {profile.hkdf_length * 8} bits")
        print(f" [+] AES GCM Tag      : {profile.aes_tag_length * 8} bits")
        print(f" [+] AES Nonce        : {profile.aes_nonce_length * 8} bits")
        print()
        print(f"  Rationale: {profile.rationale}")
        print("═" * 55 + "\n")

    return profile


if __name__ == "__main__":
    profile = run_adaptive_engine(verbose=True)
