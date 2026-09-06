"""Device capability profiling.

Classifies the current host into a coarse device tier so the model
selector can pick an appropriately-sized model. Deliberately
conservative: when a signal is unavailable (e.g. can't read /proc on
this platform), we fall back to the most constrained assumption
rather than guessing generously -- an oversized model that fails to
load is worse than an undersized one that under-performs.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from enum import Enum


class DeviceTier(str, Enum):
    CONSTRAINED = "constrained"      # <256MB free RAM budget for AI -- heuristics only
    STANDARD_EDGE = "standard_edge"  # 256MB-2GB -- small quantized classifier fits
    EDGE_SERVER = "edge_server"      # 2GB+ -- larger classifier or small guard LLM fits


# Conservative thresholds, in MB, for the RAM budget we assume is
# actually available to the AI subsystem (not total device RAM --
# this should be a fraction of it, since the OS, the gateway process
# itself, and other workloads also need headroom).
_STANDARD_EDGE_MIN_MB = 256
_EDGE_SERVER_MIN_MB = 2048


@dataclass
class DeviceProfile:
    available_ram_mb: int
    available_disk_mb: int
    cpu_cores: int
    tier: DeviceTier

    def as_dict(self) -> dict:
        return {
            "available_ram_mb": self.available_ram_mb,
            "available_disk_mb": self.available_disk_mb,
            "cpu_cores": self.cpu_cores,
            "tier": self.tier.value,
        }


def _read_available_ram_mb() -> int:
    """Reads available (not total) memory from /proc/meminfo on Linux.
    Falls back to a conservative constant on platforms where this file
    doesn't exist (e.g. during unit tests, or non-Linux hosts) -- callers
    needing deterministic behavior should inject a value instead of
    relying on this fallback."""
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    return kb // 1024
    except (FileNotFoundError, OSError, ValueError, IndexError):
        pass
    return 128  # conservative fallback: assume constrained


def _read_available_disk_mb(path: str = "/") -> int:
    try:
        usage = shutil.disk_usage(path)
        return usage.free // (1024 * 1024)
    except OSError:
        return 0


def _read_cpu_cores() -> int:
    return os.cpu_count() or 1


def classify_tier(available_ram_mb: int) -> DeviceTier:
    if available_ram_mb >= _EDGE_SERVER_MIN_MB:
        return DeviceTier.EDGE_SERVER
    if available_ram_mb >= _STANDARD_EDGE_MIN_MB:
        return DeviceTier.STANDARD_EDGE
    return DeviceTier.CONSTRAINED


def profile_device(
    ram_override_mb: int | None = None,
    disk_override_mb: int | None = None,
    cpu_override: int | None = None,
) -> DeviceProfile:
    """Build a DeviceProfile for the current host.

    Overrides exist so this is testable/deterministic and so an
    installer UI can let a user manually declare their device's
    budget rather than trusting auto-detection on unusual hardware.
    """
    ram_mb = ram_override_mb if ram_override_mb is not None else _read_available_ram_mb()
    disk_mb = disk_override_mb if disk_override_mb is not None else _read_available_disk_mb()
    cores = cpu_override if cpu_override is not None else _read_cpu_cores()

    return DeviceProfile(
        available_ram_mb=ram_mb,
        available_disk_mb=disk_mb,
        cpu_cores=cores,
        tier=classify_tier(ram_mb),
    )
