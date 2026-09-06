import pytest

from ai_security_gateway.model_manager.device_profile import DeviceProfile, DeviceTier
from ai_security_gateway.model_manager.registry import LocalModelRegistry
from ai_security_gateway.model_manager.selector import (
    NoSuitableModelError,
    select_best_model,
    select_update_candidate,
)


def profile_for(tier: DeviceTier) -> DeviceProfile:
    ram_by_tier = {
        DeviceTier.CONSTRAINED: 128,
        DeviceTier.STANDARD_EDGE: 512,
        DeviceTier.EDGE_SERVER: 4096,
    }
    return DeviceProfile(
        available_ram_mb=ram_by_tier[tier],
        available_disk_mb=10000,
        cpu_cores=4,
        tier=tier,
    )


def test_constrained_device_has_no_suitable_model():
    registry = LocalModelRegistry()
    with pytest.raises(NoSuitableModelError):
        select_best_model(profile_for(DeviceTier.CONSTRAINED), registry.list_models())


def test_standard_edge_device_selects_22m_model():
    registry = LocalModelRegistry()
    selected = select_best_model(profile_for(DeviceTier.STANDARD_EDGE), registry.list_models())
    assert selected.model_id == "llama-prompt-guard-2-22m"


def test_edge_server_device_selects_highest_benchmark_model():
    registry = LocalModelRegistry()
    selected = select_best_model(profile_for(DeviceTier.EDGE_SERVER), registry.list_models())
    # llama-guard-3-1b has the highest benchmark score among eligible models
    assert selected.model_id == "llama-guard-3-1b"


def test_update_candidate_returns_none_when_current_already_best():
    registry = LocalModelRegistry()
    current = registry.fetch_manifest("llama-prompt-guard-2-22m")
    candidate = select_update_candidate(
        profile_for(DeviceTier.STANDARD_EDGE), current, registry.list_models()
    )
    assert candidate is None


def test_update_candidate_returns_new_version_with_better_benchmark():
    registry = LocalModelRegistry()
    current = registry.fetch_manifest("llama-prompt-guard-2-22m")
    registry.publish_new_version(
        "llama-prompt-guard-2-22m", version="2.0.0", benchmark_recall_at_1pct_fpr=0.99
    )
    candidate = select_update_candidate(
        profile_for(DeviceTier.STANDARD_EDGE), current, registry.list_models()
    )
    assert candidate is not None
    assert candidate.version == "2.0.0"


def test_update_candidate_none_for_device_with_no_current_and_no_fit():
    registry = LocalModelRegistry()
    candidate = select_update_candidate(profile_for(DeviceTier.CONSTRAINED), None, registry.list_models())
    assert candidate is None
