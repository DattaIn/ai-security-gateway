import pytest

from ai_security_gateway.model_manager.manifest import verify_manifest
from ai_security_gateway.model_manager.registry import LocalModelRegistry, ModelRegistryError


def test_default_catalog_has_three_models():
    registry = LocalModelRegistry()
    models = registry.list_models()
    ids = {m.model_id for m in models}
    assert ids == {"llama-prompt-guard-2-22m", "llama-prompt-guard-2-86m", "llama-guard-3-1b"}


def test_all_seeded_manifests_are_validly_signed():
    registry = LocalModelRegistry()
    for manifest in registry.list_models():
        verify_manifest(manifest, registry.trusted_public_key_bytes)  # should not raise


def test_fetch_artifact_matches_manifest_hash():
    import hashlib
    registry = LocalModelRegistry()
    for manifest in registry.list_models():
        artifact = registry.fetch_artifact(manifest.model_id)
        assert hashlib.sha256(artifact).hexdigest() == manifest.sha256


def test_fetch_unknown_model_raises():
    registry = LocalModelRegistry()
    with pytest.raises(ModelRegistryError):
        registry.fetch_manifest("does-not-exist")
    with pytest.raises(ModelRegistryError):
        registry.fetch_artifact("does-not-exist")


def test_publish_new_version_updates_catalog_and_stays_signed():
    registry = LocalModelRegistry()
    updated = registry.publish_new_version(
        "llama-prompt-guard-2-22m", version="1.1.0", benchmark_recall_at_1pct_fpr=0.97
    )
    assert updated.version == "1.1.0"
    fetched = registry.fetch_manifest("llama-prompt-guard-2-22m")
    assert fetched.version == "1.1.0"
    verify_manifest(fetched, registry.trusted_public_key_bytes)  # still validly signed


def test_publish_tampered_artifact_breaks_hash_match():
    import hashlib
    registry = LocalModelRegistry()
    registry.publish_tampered_artifact("llama-prompt-guard-2-22m")
    manifest = registry.fetch_manifest("llama-prompt-guard-2-22m")
    artifact = registry.fetch_artifact("llama-prompt-guard-2-22m")
    assert hashlib.sha256(artifact).hexdigest() != manifest.sha256


def test_publish_unsigned_manifest_fails_verification():
    registry = LocalModelRegistry()
    forged = registry.publish_unsigned_manifest("llama-prompt-guard-2-22m", version="99.0.0")
    assert forged.signature == ""
