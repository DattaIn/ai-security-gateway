import pytest

from ai_security_gateway.model_manager.downloader import (
    ArtifactVerificationError,
    ModelDownloaderVerifier,
)
from ai_security_gateway.model_manager.manifest import ManifestSigner
from ai_security_gateway.model_manager.registry import LocalModelRegistry


def make_downloader(registry: LocalModelRegistry) -> ModelDownloaderVerifier:
    return ModelDownloaderVerifier(registry, registry.trusted_public_key_bytes)


def test_fetch_and_verify_succeeds_for_authentic_model():
    registry = LocalModelRegistry()
    downloader = make_downloader(registry)
    verified = downloader.fetch_and_verify("llama-prompt-guard-2-22m")
    assert verified.manifest.model_id == "llama-prompt-guard-2-22m"
    assert len(verified.artifact_bytes) > 0


def test_fetch_and_verify_rejects_tampered_artifact():
    registry = LocalModelRegistry()
    registry.publish_tampered_artifact("llama-prompt-guard-2-22m")
    downloader = make_downloader(registry)
    with pytest.raises(ArtifactVerificationError, match="hash mismatch"):
        downloader.fetch_and_verify("llama-prompt-guard-2-22m")


def test_fetch_and_verify_rejects_unsigned_manifest():
    registry = LocalModelRegistry()
    registry.publish_unsigned_manifest("llama-prompt-guard-2-22m", version="99.0.0")
    downloader = make_downloader(registry)
    with pytest.raises(ArtifactVerificationError, match="Rejected model"):
        downloader.fetch_and_verify("llama-prompt-guard-2-22m")


def test_fetch_and_verify_rejects_wrong_trust_root():
    registry = LocalModelRegistry()
    attacker_signer = ManifestSigner()
    # Downloader pinned to a DIFFERENT public key than the one that
    # actually signed the registry's manifests -- simulates a gateway
    # correctly configured with its own trust root rejecting a
    # registry it doesn't recognize.
    downloader = ModelDownloaderVerifier(registry, attacker_signer.public_key_bytes)
    with pytest.raises(ArtifactVerificationError, match="Rejected model"):
        downloader.fetch_and_verify("llama-prompt-guard-2-22m")


def test_fetch_and_verify_raises_for_unknown_model():
    registry = LocalModelRegistry()
    downloader = make_downloader(registry)
    with pytest.raises(ArtifactVerificationError, match="Could not fetch manifest"):
        downloader.fetch_and_verify("does-not-exist")
