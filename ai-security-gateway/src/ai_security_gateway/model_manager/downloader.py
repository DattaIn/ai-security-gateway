"""Downloader/Verifier.

The single choke point through which every model artifact must pass
before it is eligible to be loaded. Two independent checks are
enforced, and BOTH must pass:

  1. Manifest signature verifies against the pinned trusted public key
     (proves the manifest itself wasn't forged or altered).
  2. Downloaded artifact's sha256 matches the (verified) manifest's
     declared hash (proves the artifact wasn't swapped or corrupted
     in transit, even if the manifest describing it is authentic).

Either failure raises -- there is no partial trust, no "warn and
continue" path. A model that fails verification is never handed to
the loader.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ai_security_gateway.model_manager.manifest import (
    ManifestVerificationError,
    ModelManifest,
    verify_manifest,
)
from ai_security_gateway.model_manager.registry import LocalModelRegistry, ModelRegistryError


class ArtifactVerificationError(Exception):
    pass


@dataclass
class VerifiedArtifact:
    manifest: ModelManifest
    artifact_bytes: bytes


class ModelDownloaderVerifier:
    def __init__(self, registry: LocalModelRegistry, trusted_public_key_bytes: bytes):
        self._registry = registry
        self._trusted_public_key_bytes = trusted_public_key_bytes

    def fetch_and_verify(self, model_id: str) -> VerifiedArtifact:
        """Fetches a model's manifest and artifact from the registry and
        verifies both before returning. Raises on any failure -- callers
        must not catch and silently proceed with an unverified model."""
        try:
            manifest = self._registry.fetch_manifest(model_id)
        except ModelRegistryError as e:
            raise ArtifactVerificationError(f"Could not fetch manifest: {e}") from e

        # Check 1: manifest signature.
        try:
            verify_manifest(manifest, self._trusted_public_key_bytes)
        except ManifestVerificationError as e:
            raise ArtifactVerificationError(f"Rejected model '{model_id}': {e}") from e

        # Check 2: artifact integrity against the (now-trusted) manifest hash.
        try:
            artifact_bytes = self._registry.fetch_artifact(model_id)
        except ModelRegistryError as e:
            raise ArtifactVerificationError(f"Could not fetch artifact: {e}") from e

        actual_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        if actual_sha256 != manifest.sha256:
            raise ArtifactVerificationError(
                f"Artifact hash mismatch for '{model_id}' v{manifest.version}: "
                f"expected {manifest.sha256}, got {actual_sha256}. "
                f"Artifact rejected -- possible tampering or corrupted download."
            )

        return VerifiedArtifact(manifest=manifest, artifact_bytes=artifact_bytes)
