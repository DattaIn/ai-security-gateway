"""Model selection.

Given a device's profile and a list of candidate manifests, picks the
best fit: the highest-benchmark model whose `min_tier` the device
actually meets or exceeds. Never selects a model the device profile
says won't fit -- an oversized model failing to load or thrashing a
constrained device is worse than running the smaller one.
"""
from __future__ import annotations

from ai_security_gateway.model_manager.device_profile import DeviceProfile, DeviceTier
from ai_security_gateway.model_manager.manifest import ModelManifest

# Ordering used to compare tiers ("does the device meet-or-exceed this
# model's minimum tier"), lowest requirement first.
_TIER_ORDER = [DeviceTier.CONSTRAINED, DeviceTier.STANDARD_EDGE, DeviceTier.EDGE_SERVER]


def _tier_rank(tier: DeviceTier) -> int:
    return _TIER_ORDER.index(tier)


class NoSuitableModelError(Exception):
    pass


def device_meets_requirement(device_tier: DeviceTier, model_min_tier: DeviceTier) -> bool:
    return _tier_rank(device_tier) >= _tier_rank(model_min_tier)


def select_best_model(
    device_profile: DeviceProfile,
    candidates: list[ModelManifest],
) -> ModelManifest:
    """Among manifests the device tier can actually support, returns the
    one with the highest benchmark recall. Ties broken by smaller
    size_mb (prefer the lighter model when accuracy is equal)."""
    eligible = [
        m for m in candidates
        if device_meets_requirement(device_profile.tier, m.min_tier)
    ]
    if not eligible:
        raise NoSuitableModelError(
            f"No model in the candidate list fits device tier '{device_profile.tier.value}'. "
            f"Device should rely on heuristic-only detection."
        )

    eligible.sort(key=lambda m: (-m.benchmark_recall_at_1pct_fpr, m.size_mb))
    return eligible[0]


def select_update_candidate(
    device_profile: DeviceProfile,
    current_manifest: ModelManifest | None,
    candidates: list[ModelManifest],
) -> ModelManifest | None:
    """Used for the runtime update-check path: returns a candidate to
    switch to only if it (a) fits the device tier and (b) strictly
    improves on the currently-installed model's benchmark score.
    Returns None if there's nothing better available -- callers should
    treat that as "no update needed", not an error."""
    try:
        best_fit = select_best_model(device_profile, candidates)
    except NoSuitableModelError:
        return None

    if current_manifest is None:
        return best_fit

    if best_fit.model_id == current_manifest.model_id and best_fit.version == current_manifest.version:
        return None

    if best_fit.benchmark_recall_at_1pct_fpr > current_manifest.benchmark_recall_at_1pct_fpr:
        return best_fit

    return None
