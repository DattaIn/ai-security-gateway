"""Local/mock model registry.

Stands in for a cloud-hosted registry endpoint. Same interface a real
`HttpRegistryClient` would expose (`list_models`, `fetch_manifest`,
`fetch_artifact`), so swapping this for a real HTTPS-backed client
later doesn't require touching the selector, verifier, or hot-swap
logic -- only this one adapter changes.

Ships pre-populated with manifests for the three models discussed:
Llama Prompt Guard 2 (22M, 86M) and Llama Guard 3 (1B). Artifact
bytes are NOT real model weights -- this sandbox can't download or
run actual multi-hundred-MB models -- they're small synthetic
placeholders whose sha256 matches what the manifest declares, so the
full verify-then-load pipeline is exercised faithfully end to end.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ai_security_gateway.model_manager.device_profile import DeviceTier
from ai_security_gateway.model_manager.manifest import ManifestSigner, ModelManifest


@dataclass
class RegistryEntry:
    manifest: ModelManifest
    artifact_bytes: bytes


class ModelRegistryError(Exception):
    pass


class LocalModelRegistry:
    """A registry client backed by an in-memory catalog instead of a
    network call. `trusted_public_key_bytes` is what a real deployment
    would ship baked into the gateway binary/config, pinned at build
    time -- never fetched from the same channel as the models
    themselves, or an attacker controlling the registry could rotate
    both the key and the models together."""

    def __init__(self, signer: ManifestSigner | None = None):
        self._signer = signer or ManifestSigner()
        self.trusted_public_key_bytes = self._signer.public_key_bytes
        self._catalog: dict[str, RegistryEntry] = {}
        self._seed_default_catalog()

    def _make_entry(
        self,
        model_id: str,
        version: str,
        display_name: str,
        min_tier: DeviceTier,
        quantization: str,
        size_mb: int,
        benchmark_recall_at_1pct_fpr: float,
        synthetic_payload: bytes,
    ) -> RegistryEntry:
        sha256 = hashlib.sha256(synthetic_payload).hexdigest()
        manifest = ModelManifest(
            model_id=model_id,
            version=version,
            display_name=display_name,
            min_tier=min_tier,
            quantization=quantization,
            size_mb=size_mb,
            sha256=sha256,
            benchmark_recall_at_1pct_fpr=benchmark_recall_at_1pct_fpr,
            artifact_url=f"mock://registry/{model_id}/{version}",
        )
        self._signer.sign(manifest)
        return RegistryEntry(manifest=manifest, artifact_bytes=synthetic_payload)

    def _seed_default_catalog(self) -> None:
        catalog_specs = [
            {
                "model_id": "llama-prompt-guard-2-22m",
                "version": "1.0.0",
                "display_name": "Llama Prompt Guard 2 - 22M",
                "min_tier": DeviceTier.STANDARD_EDGE,
                "quantization": "int8",
                "size_mb": 31,
                "benchmark_recall_at_1pct_fpr": 0.94,
                "synthetic_payload": b"SYNTHETIC-WEIGHTS-prompt-guard-2-22m-v1.0.0",
            },
            {
                "model_id": "llama-prompt-guard-2-86m",
                "version": "1.0.0",
                "display_name": "Llama Prompt Guard 2 - 86M",
                "min_tier": DeviceTier.EDGE_SERVER,
                "quantization": "int8",
                "size_mb": 90,
                "benchmark_recall_at_1pct_fpr": 0.975,
                "synthetic_payload": b"SYNTHETIC-WEIGHTS-prompt-guard-2-86m-v1.0.0",
            },
            {
                "model_id": "llama-guard-3-1b",
                "version": "1.0.0",
                "display_name": "Llama Guard 3 - 1B",
                "min_tier": DeviceTier.EDGE_SERVER,
                "quantization": "int4",
                "size_mb": 650,
                "benchmark_recall_at_1pct_fpr": 0.981,
                "synthetic_payload": b"SYNTHETIC-WEIGHTS-llama-guard-3-1b-v1.0.0",
            },
        ]
        for spec in catalog_specs:
            entry = self._make_entry(**spec)
            self._catalog[entry.manifest.model_id] = entry

    # -- Public registry interface -----------------------------------------

    def list_models(self) -> list[ModelManifest]:
        return [entry.manifest for entry in self._catalog.values()]

    def fetch_manifest(self, model_id: str) -> ModelManifest:
        entry = self._catalog.get(model_id)
        if entry is None:
            raise ModelRegistryError(f"No such model in registry: '{model_id}'")
        return entry.manifest

    def fetch_artifact(self, model_id: str) -> bytes:
        entry = self._catalog.get(model_id)
        if entry is None:
            raise ModelRegistryError(f"No such model in registry: '{model_id}'")
        return entry.artifact_bytes

    # -- Test/demo helpers ----------------------------------------------------

    def publish_new_version(
        self,
        model_id: str,
        version: str,
        benchmark_recall_at_1pct_fpr: float,
        synthetic_payload: bytes | None = None,
    ) -> ModelManifest:
        """Simulates the registry publishing an updated version of an
        existing model -- used to test the runtime update-check path."""
        existing = self._catalog.get(model_id)
        if existing is None:
            raise ModelRegistryError(f"Cannot publish update for unknown model '{model_id}'")

        payload = synthetic_payload or (existing.artifact_bytes + f"-{version}".encode())
        entry = self._make_entry(
            model_id=model_id,
            version=version,
            display_name=existing.manifest.display_name,
            min_tier=existing.manifest.min_tier,
            quantization=existing.manifest.quantization,
            size_mb=existing.manifest.size_mb,
            benchmark_recall_at_1pct_fpr=benchmark_recall_at_1pct_fpr,
            synthetic_payload=payload,
        )
        self._catalog[model_id] = entry
        return entry.manifest

    def publish_tampered_artifact(self, model_id: str) -> None:
        """Test helper: simulates a MITM'd or corrupted download by
        swapping the artifact bytes WITHOUT re-signing the manifest --
        i.e. the manifest's sha256/signature now describe the ORIGINAL
        artifact, not this one. A correct verifier must reject this."""
        entry = self._catalog.get(model_id)
        if entry is None:
            raise ModelRegistryError(f"No such model in registry: '{model_id}'")
        self._catalog[model_id] = RegistryEntry(
            manifest=entry.manifest,
            artifact_bytes=entry.artifact_bytes + b"-TAMPERED",
        )

    def publish_unsigned_manifest(self, model_id: str, version: str) -> ModelManifest:
        """Test helper: publishes a manifest with no valid signature at
        all, simulating an attacker-controlled registry or a
        man-in-the-middle response."""
        existing = self._catalog.get(model_id)
        if existing is None:
            raise ModelRegistryError(f"Cannot publish for unknown model '{model_id}'")
        payload = existing.artifact_bytes + f"-{version}-forged".encode()
        forged_manifest = ModelManifest(
            model_id=model_id,
            version=version,
            display_name=existing.manifest.display_name,
            min_tier=existing.manifest.min_tier,
            quantization=existing.manifest.quantization,
            size_mb=existing.manifest.size_mb,
            sha256=hashlib.sha256(payload).hexdigest(),
            benchmark_recall_at_1pct_fpr=0.999,  # attacker claims a suspiciously perfect score
            artifact_url=f"mock://registry/{model_id}/{version}",
            signature="",  # deliberately unsigned
        )
        self._catalog[model_id] = RegistryEntry(manifest=forged_manifest, artifact_bytes=payload)
        return forged_manifest
