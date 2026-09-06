"""Stub classifier and lifecycle orchestrator.

`StubModelClassifier` stands in for a real ONNX Runtime / transformers
inference session, since this sandbox can't download or run actual
multi-hundred-MB model weights. It implements the exact same
`ModelClassifier` interface a real model wrapper would, and is driven
by simple keyword heuristics ONLY so the canary-swap and orchestration
logic can be exercised end to end with realistic pass/fail behavior.
Swapping in a real backend means writing one new factory function --
nothing else in this module changes.

`ModelManagerOrchestrator` is the top-level entry point: it ties the
device profiler, selector, downloader/verifier, and canary-swap loader
together into the lifecycle operations described in the design:
install-time selection, and a runtime update check.
"""
from __future__ import annotations

from dataclasses import dataclass

from ai_security_gateway.model_manager.canary_swap import CanarySwapLoader, SwapResult
from ai_security_gateway.model_manager.device_profile import DeviceProfile
from ai_security_gateway.model_manager.downloader import (
    ArtifactVerificationError,
    ModelDownloaderVerifier,
    VerifiedArtifact,
)
from ai_security_gateway.model_manager.manifest import ModelManifest
from ai_security_gateway.model_manager.registry import LocalModelRegistry
from ai_security_gateway.model_manager.selector import (
    NoSuitableModelError,
    select_best_model,
    select_update_candidate,
)

_MALICIOUS_MARKERS = (
    "ignore previous instructions",
    "you are now dan",
    "reveal your system prompt",
    "no restrictions",
)


class StubModelClassifier:
    """A deliberately simple stand-in classifier. NOT the real
    detection logic -- see `detectors/prompt_injection.py` for the
    production heuristic engine this AI layer is meant to supplement
    on ambiguous cases."""

    def __init__(self, verified_artifact: VerifiedArtifact):
        self.manifest = verified_artifact.manifest
        # A real implementation would deserialize verified_artifact.artifact_bytes
        # into an inference session here.

    def classify(self, text: str) -> str:
        lowered = text.lower()
        if any(marker in lowered for marker in _MALICIOUS_MARKERS):
            return "malicious"
        return "benign"


def default_classifier_factory(verified_artifact: VerifiedArtifact) -> StubModelClassifier:
    return StubModelClassifier(verified_artifact)


@dataclass
class InstallResult:
    selected_manifest: ModelManifest | None
    swap_result: SwapResult | None
    used_heuristics_only: bool
    reason: str = ""


class ModelManagerOrchestrator:
    """Wires profiler -> selector -> downloader/verifier -> canary-swap
    loader into the two lifecycle flows the gateway needs: install-time
    selection, and a periodic runtime update check."""

    def __init__(
        self,
        registry: LocalModelRegistry,
        loader: CanarySwapLoader | None = None,
    ):
        self._registry = registry
        self._downloader = ModelDownloaderVerifier(registry, registry.trusted_public_key_bytes)
        self._loader = loader or CanarySwapLoader(classifier_factory=default_classifier_factory)

    @property
    def loader(self) -> CanarySwapLoader:
        return self._loader

    def install_time_setup(self, device_profile: DeviceProfile) -> InstallResult:
        """Runs once at install: pick the best model the device tier
        supports, download+verify it, canary-test it, and activate it.
        Falls back cleanly to heuristics-only if no model fits or the
        candidate fails verification/canary."""
        candidates = self._registry.list_models()
        try:
            selected = select_best_model(device_profile, candidates)
        except NoSuitableModelError as e:
            return InstallResult(
                selected_manifest=None,
                swap_result=None,
                used_heuristics_only=True,
                reason=str(e),
            )

        try:
            verified = self._downloader.fetch_and_verify(selected.model_id)
        except ArtifactVerificationError as e:
            return InstallResult(
                selected_manifest=selected,
                swap_result=None,
                used_heuristics_only=True,
                reason=f"Verification failed, falling back to heuristics only: {e}",
            )

        swap_result = self._loader.attempt_swap(verified)
        used_heuristics_only = swap_result.outcome.value != "activated"
        return InstallResult(
            selected_manifest=selected,
            swap_result=swap_result,
            used_heuristics_only=used_heuristics_only,
            reason="" if not used_heuristics_only else f"Swap did not activate: {swap_result.outcome.value}",
        )

    def check_for_runtime_update(self, device_profile: DeviceProfile) -> InstallResult:
        """Runs periodically (not per-request): checks whether a better
        model than the currently active one is available for this
        device's tier, and if so, downloads+verifies+canary-swaps to
        it. No-ops cleanly if nothing better is available."""
        candidates = self._registry.list_models()
        current = self._loader.active_manifest
        candidate = select_update_candidate(device_profile, current, candidates)

        if candidate is None:
            return InstallResult(
                selected_manifest=current,
                swap_result=None,
                used_heuristics_only=current is None,
                reason=(
                    "No update available; current model already best fit."
                    if current else "No suitable model installed."
                ),
            )

        try:
            verified = self._downloader.fetch_and_verify(candidate.model_id)
        except ArtifactVerificationError as e:
            return InstallResult(
                selected_manifest=current,
                swap_result=None,
                used_heuristics_only=current is None,
                reason=f"Update candidate failed verification, keeping current model: {e}",
            )

        swap_result = self._loader.attempt_swap(verified)
        if swap_result.outcome.value == "activated":
            return InstallResult(selected_manifest=candidate, swap_result=swap_result, used_heuristics_only=False)

        # Canary or load failure: the loader already kept the OLD model active.
        return InstallResult(
            selected_manifest=current,
            swap_result=swap_result,
            used_heuristics_only=current is None,
            reason=f"Update candidate rejected ({swap_result.outcome.value}); kept previous model active.",
        )
