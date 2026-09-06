from ai_security_gateway.model_manager.device_profile import DeviceProfile, DeviceTier
from ai_security_gateway.model_manager.orchestrator import ModelManagerOrchestrator
from ai_security_gateway.model_manager.registry import LocalModelRegistry


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


# ---------------------------------------------------------------------------
# Happy path: install-time setup
# ---------------------------------------------------------------------------

def test_install_time_setup_activates_best_fit_model_for_standard_edge():
    registry = LocalModelRegistry()
    orchestrator = ModelManagerOrchestrator(registry)

    result = orchestrator.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))

    assert result.used_heuristics_only is False
    assert result.selected_manifest.model_id == "llama-prompt-guard-2-22m"
    assert result.swap_result.outcome.value == "activated"
    assert orchestrator.loader.active_manifest.model_id == "llama-prompt-guard-2-22m"


def test_install_time_setup_activates_best_fit_model_for_edge_server():
    registry = LocalModelRegistry()
    orchestrator = ModelManagerOrchestrator(registry)

    result = orchestrator.install_time_setup(profile_for(DeviceTier.EDGE_SERVER))

    assert result.used_heuristics_only is False
    assert result.selected_manifest.model_id == "llama-guard-3-1b"


def test_install_time_setup_falls_back_to_heuristics_for_constrained_device():
    registry = LocalModelRegistry()
    orchestrator = ModelManagerOrchestrator(registry)

    result = orchestrator.install_time_setup(profile_for(DeviceTier.CONSTRAINED))

    assert result.used_heuristics_only is True
    assert result.selected_manifest is None
    assert orchestrator.loader.active_manifest is None


# ---------------------------------------------------------------------------
# Adversarial scenarios -- the whole reason this module has a threat model
# ---------------------------------------------------------------------------

def test_install_time_setup_falls_back_when_registry_serves_tampered_artifact():
    """Simulates a MITM'd download or a compromised CDN edge serving
    different bytes than what the (legitimately signed) manifest
    describes. The orchestrator must NOT activate this model."""
    registry = LocalModelRegistry()
    registry.publish_tampered_artifact("llama-prompt-guard-2-22m")
    orchestrator = ModelManagerOrchestrator(registry)

    result = orchestrator.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))

    assert result.used_heuristics_only is True
    assert "Verification failed" in result.reason
    assert orchestrator.loader.active_manifest is None


def test_install_time_setup_falls_back_when_registry_serves_unsigned_manifest():
    """Simulates a compromised or spoofed registry endpoint publishing
    a manifest with no valid signature -- e.g. an attacker who can
    intercept/replace the registry response but does not hold the
    pinned private key. The orchestrator must reject it outright."""
    registry = LocalModelRegistry()
    registry.publish_unsigned_manifest("llama-prompt-guard-2-22m", version="99.0.0")
    orchestrator = ModelManagerOrchestrator(registry)

    result = orchestrator.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))

    assert result.used_heuristics_only is True
    assert "Verification failed" in result.reason


# ---------------------------------------------------------------------------
# Runtime update-check flow
# ---------------------------------------------------------------------------

def test_runtime_update_check_noop_when_nothing_better_available():
    registry = LocalModelRegistry()
    orchestrator = ModelManagerOrchestrator(registry)
    orchestrator.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))

    result = orchestrator.check_for_runtime_update(profile_for(DeviceTier.STANDARD_EDGE))

    assert result.swap_result is None
    assert result.selected_manifest.model_id == "llama-prompt-guard-2-22m"


def test_runtime_update_check_swaps_to_improved_version_when_published():
    registry = LocalModelRegistry()
    orchestrator = ModelManagerOrchestrator(registry)
    orchestrator.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))

    registry.publish_new_version(
        "llama-prompt-guard-2-22m", version="2.0.0", benchmark_recall_at_1pct_fpr=0.995
    )

    result = orchestrator.check_for_runtime_update(profile_for(DeviceTier.STANDARD_EDGE))

    assert result.swap_result.outcome.value == "activated"
    assert orchestrator.loader.active_manifest.version == "2.0.0"


def test_runtime_update_check_rejects_tampered_update_and_keeps_serving_old_model():
    """The device already has a working model installed. A malicious
    'update' with a tampered artifact must not knock out a working
    gateway -- the old model should keep serving traffic."""
    registry = LocalModelRegistry()
    orchestrator = ModelManagerOrchestrator(registry)
    orchestrator.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))
    original_version = orchestrator.loader.active_manifest.version

    registry.publish_new_version(
        "llama-prompt-guard-2-22m", version="2.0.0", benchmark_recall_at_1pct_fpr=0.995
    )
    registry.publish_tampered_artifact("llama-prompt-guard-2-22m")

    result = orchestrator.check_for_runtime_update(profile_for(DeviceTier.STANDARD_EDGE))

    assert result.swap_result is None
    assert "failed verification" in result.reason
    # Old model is still the active one -- no downtime, no silent compromise.
    assert orchestrator.loader.active_manifest.version == original_version
