# Design Decisions

## Why heuristic/pattern-based detection instead of an ML classifier?

Explainability. When the gateway blocks a request, the policy engine
can state exactly which pattern families fired and why the score
crossed the threshold. That's a hard requirement for a security control
that will be audited — "the model said 0.83" is not an acceptable
answer to "why did this get blocked?" A production system would likely
layer a fine-tuned classifier *on top of* this layer for the cases
heuristics miss, not replace it, since the two approaches fail
differently (heuristics miss paraphrases; classifiers can be
inconsistent and offer no rationale).

## Why sum signal weights instead of taking the max or averaging?

Real injection attempts stack techniques (e.g., a delimiter escape
*combined with* a role-hijack phrase is a stronger signal than either
alone). Taking the max would treat that combination as no worse than
the single strongest technique; averaging would dilute a strong signal
by diving it against several weak ones. A capped sum lets weak signals
combine into a block while still letting one unambiguous strong signal
block on its own.

## Why scan and redact both input and output, not just input?

Most public discussion of prompt injection focuses on the user's
direct prompt, but *indirect* injection — where a retrieved document,
tool result, or the model's own generation carries the attack — only
shows up on the output side. A gateway that only filters input has a
large blind spot. The canary-token technique specifically exists to
catch a class of leak that no amount of input filtering can prevent
(the model deciding, mid-generation, to repeat something it was told
never to repeat).

## Why block on critical DLP findings in the input before ever calling the LLM?

If a user pastes a real credential into a prompt, sending it to a
third-party LLM API at all is itself the exposure — redacting the
response afterward doesn't undo the fact that the secret already left
the trust boundary. Blocking pre-emptively is the only control that
actually prevents this class of leak; redaction is a mitigation for
the (allowed) medium/low-severity categories, not a substitute for
blocking the critical ones.

## Why a hash-chained audit log instead of a plain log file?

An audit trail that can be silently edited after the fact isn't
useful evidence in an incident investigation. The hash chain doesn't
prevent tampering, but it makes tampering *detectable*: any edit to
a historical entry breaks the chain from that point forward, which
`verify_chain()` will catch. This is a lightweight analogue of the
tamper-evidence properties used in real security logging systems,
scoped appropriately for a reference/portfolio implementation.

## Why a pluggable `LlmBackend` interface with a mock default?

Two reasons. First, the gateway's value proposition is provider-agnostic
security, so the code should reflect that structurally, not just in
prose. Second, using a deterministic mock in the test/CI suite means the
attack simulation suite runs in milliseconds, with no API cost and no
flakiness from a real model's non-determinism — important for a suite
that's meant to run on every commit.

## What's deliberately NOT solved here

- **AuthN/AuthZ** — `client_id` is trusted as given. A real deployment
  sits this behind an API gateway or service mesh that authenticates
  the caller first.
- **Distributed state** — rate limiting and audit logging are
  single-process/in-memory. Horizontal scaling requires a shared store.
- **Semantic understanding of intent** — this is a pattern/heuristic
  layer, not a guarantee against a sufficiently novel paraphrase. See
  `docs/threat-model.md`'s Limitations section.
