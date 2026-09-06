# AI Model Lifecycle Management

Extends the base gateway (see [architecture.md](architecture.md)) with
the ability to select, download, verify, and hot-swap a small AI
classifier model to supplement the heuristic detector on ambiguous
cases -- while remaining safe to run unattended on edge hardware.

## Why this exists

The heuristic prompt-injection detector in `detectors/prompt_injection.py`
is fast, free, and explainable, but it's pattern-based -- a
sufficiently novel paraphrase can slip past it. A small fine-tuned
classifier (e.g. Meta's Llama Prompt Guard 2) catches a different,
complementary set of cases. Running it on *every* request is wasteful
on constrained hardware, so it's invoked only for requests the
heuristic engine itself flags as ambiguous (score in the 0.4-0.75
FLAG band) -- the two layers cover each other's blind spots.

## Component map

| Component | File | Responsibility |
|---|---|---|
| Device Capability Profiler | `model_manager/device_profile.py` | Classifies the host into a device tier from available RAM |
| Model Manifest & Signing | `model_manager/manifest.py` | Ed25519 signature scheme over model metadata |
| Model Registry | `model_manager/registry.py` | Catalog of available models (mock/local here; HTTPS-backed in production) |
| Downloader/Verifier | `model_manager/downloader.py` | Enforces signature + hash checks before anything is trusted |
| Model Selector | `model_manager/selector.py` | Picks the best-fit model for a device tier; decides if an update is worth taking |
| Canary-Swap Loader | `model_manager/canary_swap.py` | Stages, regression-tests, and atomically activates a new model |
| Orchestrator | `model_manager/orchestrator.py` | Wires the above into install-time setup and periodic runtime update checks |

## Device tiers

| Tier | Available RAM budget | What fits |
|---|---|---|
| `constrained` | < 256 MB | Heuristics only -- no AI model is installed |
| `standard_edge` | 256 MB - 2 GB | Llama Prompt Guard 2 22M (INT8, ~31 MB) |
| `edge_server` | 2 GB+ | Llama Prompt Guard 2 86M or Llama Guard 3 1B |

Thresholds are deliberately conservative: they represent the RAM
budget available *to the AI subsystem specifically*, not total device
RAM, since the OS and the gateway process itself need headroom too.

## The trust chain

```
Registry operator's PRIVATE key (never leaves the registry)
        |
        | signs
        v
Model Manifest (id, version, size, sha256, benchmark score, ...)
        |
        | fetched over the network (untrusted transport)
        v
Gateway's pinned PUBLIC key  ---verifies--->  Manifest accepted/rejected
        |
        | (if accepted) fetch artifact, hash it
        v
Compare artifact sha256 to the (now-trusted) manifest's declared hash
        |
        v
   Match -> proceed to canary testing
   Mismatch -> reject, fall back to previous/heuristics-only
```

Two independent failures are both defended against:

1. **A forged or altered manifest** (attacker doesn't have the private
   key) -- caught by signature verification.
2. **A tampered or corrupted artifact** (manifest is authentic, but the
   bytes delivered don't match what it describes -- e.g. a MITM'd CDN
   response) -- caught by the hash comparison, which only means
   anything *because* the manifest carrying that hash was itself
   already verified.

## Canary testing: authenticity isn't correctness

A model can be genuinely signed by the real registry and still be a
bad idea to activate -- a bug in a new release, a regression
introduced by fine-tuning, or (worst case) a model that was
compromised upstream *before* it was ever signed. The canary-swap
loader treats "verified" and "safe to activate" as two separate gates:

1. Load the verified artifact into a **staging** slot, never the live one.
2. Run it against a small fixed set of known benign/malicious examples.
3. Only flip the active pointer if every canary case passes.
4. On any failure (load error or wrong classification), discard the
   staged model and keep whatever was previously active -- no downtime,
   no silent degradation, and the failure is recorded in `loader.history`.

This is the same blue/green deployment pattern used for service
releases, applied to a model artifact instead.

## Runtime update flow

Unlike the request pipeline, this does NOT run per-request. On a
schedule (e.g. daily, or on a fleet-management trigger), the
orchestrator's `check_for_runtime_update()`:

1. Asks the registry for the current catalog.
2. Picks the best model the device tier supports.
3. Compares it to the currently active model's benchmark score.
4. If -- and only if -- it's a genuine improvement, downloads,
   verifies, and canary-swaps to it.
5. If verification or canary testing fails, the previous model keeps
   serving traffic and the failure is surfaced for operator visibility.

## What's still out of scope (see also threat-model.md's Limitations)

- **Real model inference.** `StubModelClassifier` is a keyword-based
  stand-in; a production build swaps it for an ONNX Runtime session
  loading real quantized weights. The lifecycle logic around it
  (verify, stage, canary, swap) does not change.
- **A real cloud registry.** `LocalModelRegistry` is an in-memory mock
  with the same public interface an `HttpRegistryClient` would expose.
- **Key rotation/revocation.** The trusted public key is pinned once;
  a production system needs a documented rotation procedure and a way
  to revoke a compromised registry key without bricking devices in the
  field.
