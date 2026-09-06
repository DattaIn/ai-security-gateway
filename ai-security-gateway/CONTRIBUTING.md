# Contributing

## Ground rules

- **No real secrets, no real proprietary data, ever.** All test
  credentials, PII, and attack payloads in this repo are synthetic.
  Do not add real API keys, real personal data, or content sourced
  from a proprietary/employer system.
- **New detection logic needs a test.** A new pattern in
  `detectors/prompt_injection.py` or `detectors/dlp.py` should come
  with both a positive test (it fires on the attack it targets) and a
  negative test (it doesn't fire on a plausible benign phrase), to
  guard against false positives creeping in silently.
- **New attack techniques go in `tests/test_attack_suite.py`**, with
  an OWASP LLM Top 10 category comment, so the suite stays organized
  as a threat-mapped reference, not a junk drawer of regressions.

## Local development

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check src/ tests/
bandit -r src/
```

All four should pass cleanly before opening a PR — this mirrors what
CI enforces in `.github/workflows/ci.yml`.

## Adding a new detector signal family

1. Add the pattern list and a `DetectionSignal(...)` entry in
   `detectors/prompt_injection.py`, with a weight calibrated against
   the existing families (see `docs/design-decisions.md` for the
   reasoning behind current weights).
2. Add unit tests in `tests/test_prompt_injection.py`.
3. Add an end-to-end case in `tests/test_attack_suite.py` if the
   technique is realistic enough to matter operationally.
4. Update the signal-family table in `docs/security-controls.md`.

## Adding a new DLP rule

1. Add a `DlpRule(...)` entry in `detectors/dlp.py` with an
   appropriate `Severity`.
2. Add unit tests in `tests/test_dlp.py` covering both detection and
   redaction.
3. Update the DLP rule catalog table in `docs/security-controls.md`.
