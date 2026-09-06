import pytest

from ai_security_gateway.model_manager.device_profile import DeviceTier
from ai_security_gateway.model_manager.manifest import (
    ManifestSigner,
    ManifestVerificationError,
    ModelManifest,
    verify_manifest,
)


def make_manifest(**overrides) -> ModelManifest:
    defaults = {
        "model_id": "test-model",
        "version": "1.0.0",
        "display_name": "Test Model",
        "min_tier": DeviceTier.STANDARD_EDGE,
        "quantization": "int8",
        "size_mb": 30,
        "sha256": "a" * 64,
        "benchmark_recall_at_1pct_fpr": 0.9,
        "artifact_url": "mock://registry/test-model/1.0.0",
    }
    defaults.update(overrides)
    return ModelManifest(**defaults)


def test_validly_signed_manifest_passes_verification():
    signer = ManifestSigner()
    manifest = signer.sign(make_manifest())
    verify_manifest(manifest, signer.public_key_bytes)  # should not raise


def test_unsigned_manifest_is_rejected():
    manifest = make_manifest()  # signature left as default empty string
    signer = ManifestSigner()
    with pytest.raises(ManifestVerificationError):
        verify_manifest(manifest, signer.public_key_bytes)


def test_manifest_signed_with_wrong_key_is_rejected():
    real_signer = ManifestSigner()
    attacker_signer = ManifestSigner()
    manifest = attacker_signer.sign(make_manifest())
    with pytest.raises(ManifestVerificationError):
        verify_manifest(manifest, real_signer.public_key_bytes)


def test_tampering_with_a_field_after_signing_invalidates_signature():
    signer = ManifestSigner()
    manifest = signer.sign(make_manifest())
    manifest.size_mb = 999999  # tamper after signing
    with pytest.raises(ManifestVerificationError):
        verify_manifest(manifest, signer.public_key_bytes)


def test_tampering_with_sha256_after_signing_invalidates_signature():
    signer = ManifestSigner()
    manifest = signer.sign(make_manifest())
    manifest.sha256 = "f" * 64  # attacker points to different artifact
    with pytest.raises(ManifestVerificationError):
        verify_manifest(manifest, signer.public_key_bytes)
