"""Model manifest schema and signature verification.

Every model the gateway can install or hot-swap to is described by a
`ModelManifest`. In a real deployment this manifest is served by a
cloud registry over HTTPS; here it's represented as a plain dataclass
so the registry client can be backed by an in-memory/local mock
without changing any of the verification or selection logic.

The signature scheme: the registry's private key signs a canonical
JSON encoding of every field EXCEPT `signature` itself. The gateway
only ships the corresponding PUBLIC key (`TRUSTED_PUBLIC_KEY`,
generated once and pinned). This means a compromised or spoofed
registry endpoint cannot get an unsigned or tampered manifest accepted
-- verification happens locally, against a key the attacker doesn't
have the private half of.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from ai_security_gateway.model_manager.device_profile import DeviceTier


@dataclass
class ModelManifest:
    model_id: str
    version: str
    display_name: str
    min_tier: DeviceTier
    quantization: str
    size_mb: int
    sha256: str
    benchmark_recall_at_1pct_fpr: float
    artifact_url: str
    signature: str = field(default="", repr=False)

    def _signable_payload(self) -> bytes:
        payload = {k: v for k, v in asdict(self).items() if k != "signature"}
        # DeviceTier is an Enum -- normalize to its value for stable JSON.
        payload["min_tier"] = self.min_tier.value if isinstance(self.min_tier, DeviceTier) else self.min_tier
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def as_dict(self) -> dict:
        d = asdict(self)
        d["min_tier"] = self.min_tier.value if isinstance(self.min_tier, DeviceTier) else self.min_tier
        return d


class ManifestSigner:
    """Represents the REGISTRY side: holds the private key and signs
    manifests before publishing them. The gateway never has access to
    this class or the private key in a real deployment -- it's
    provided here only so tests and the local mock registry can
    produce validly-signed manifests without needing an external HSM."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey | None = None):
        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()

    @property
    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, manifest: ModelManifest) -> ModelManifest:
        signature_bytes = self._private_key.sign(manifest._signable_payload())
        manifest.signature = signature_bytes.hex()
        return manifest


class ManifestVerificationError(Exception):
    pass


def verify_manifest(manifest: ModelManifest, trusted_public_key_bytes: bytes) -> None:
    """Raises ManifestVerificationError if the manifest's signature does
    not verify against the pinned trusted public key. Callers MUST
    treat any exception here as "reject this manifest" -- there is no
    partial-trust fallback."""
    if not manifest.signature:
        raise ManifestVerificationError(f"Manifest for '{manifest.model_id}' has no signature.")

    public_key = ed25519.Ed25519PublicKey.from_public_bytes(trusted_public_key_bytes)
    try:
        public_key.verify(bytes.fromhex(manifest.signature), manifest._signable_payload())
    except (InvalidSignature, ValueError) as e:
        raise ManifestVerificationError(
            f"Signature verification failed for model '{manifest.model_id}' v{manifest.version}: {e}"
        ) from e
