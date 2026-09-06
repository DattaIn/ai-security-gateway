"""Standalone demo: walks through the full model lifecycle for three
device tiers, then demonstrates the registry rejecting a tampered
artifact and an unsigned manifest.

Usage:
    python scripts/demo_model_manager.py
"""
from __future__ import annotations

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


def print_result(label: str, result) -> None:
    if result.used_heuristics_only and result.selected_manifest is None:
        print(f"[{label}] No model fits this device -> heuristics-only. Reason: {result.reason}")
        return
    if result.swap_result and result.swap_result.outcome.value == "activated":
        m = result.selected_manifest
        print(f"[{label}] Activated: {m.display_name} v{m.version} (benchmark={m.benchmark_recall_at_1pct_fpr})")
    else:
        print(f"[{label}] Not activated. Reason: {result.reason}")


def main() -> None:
    print("=== Install-time setup across device tiers ===")
    for tier in (DeviceTier.CONSTRAINED, DeviceTier.STANDARD_EDGE, DeviceTier.EDGE_SERVER):
        registry = LocalModelRegistry()  # fresh registry+trust-root per device, like separate installs
        orchestrator = ModelManagerOrchestrator(registry)
        result = orchestrator.install_time_setup(profile_for(tier))
        print_result(tier.value, result)

    print("\n=== Runtime update check: registry publishes a better model ===")
    registry = LocalModelRegistry()
    orchestrator = ModelManagerOrchestrator(registry)
    orchestrator.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))
    print(f"Currently active: {orchestrator.loader.active_manifest.display_name} "
          f"v{orchestrator.loader.active_manifest.version}")

    registry.publish_new_version("llama-prompt-guard-2-22m", version="2.0.0", benchmark_recall_at_1pct_fpr=0.99)
    result = orchestrator.check_for_runtime_update(profile_for(DeviceTier.STANDARD_EDGE))
    print_result("runtime-update", result)
    print(f"Now active: {orchestrator.loader.active_manifest.display_name} "
          f"v{orchestrator.loader.active_manifest.version}")

    print("\n=== Adversarial scenario 1: tampered artifact (MITM'd download) ===")
    registry2 = LocalModelRegistry()
    registry2.publish_tampered_artifact("llama-prompt-guard-2-22m")
    orchestrator2 = ModelManagerOrchestrator(registry2)
    result = orchestrator2.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))
    print_result("tampered-artifact", result)

    print("\n=== Adversarial scenario 2: unsigned/forged manifest (spoofed registry) ===")
    registry3 = LocalModelRegistry()
    registry3.publish_unsigned_manifest("llama-prompt-guard-2-22m", version="99.0.0")
    orchestrator3 = ModelManagerOrchestrator(registry3)
    result = orchestrator3.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))
    print_result("unsigned-manifest", result)

    print("\n=== Adversarial scenario 3: model passes verification but fails canary tests ===")
    from ai_security_gateway.model_manager.canary_swap import CanarySwapLoader

    class AlwaysBenignClassifier:
        def __init__(self, verified_artifact):
            pass

        def classify(self, text: str) -> str:
            return "benign"  # would let every attack through -- must be rejected

    registry4 = LocalModelRegistry()
    orchestrator4 = ModelManagerOrchestrator(
        registry4, loader=CanarySwapLoader(classifier_factory=lambda va: AlwaysBenignClassifier(va))
    )
    result = orchestrator4.install_time_setup(profile_for(DeviceTier.STANDARD_EDGE))
    print_result("fails-canary", result)


if __name__ == "__main__":
    main()
