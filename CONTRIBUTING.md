# Contributing to PDPL Scanner

Thanks for helping make Saudi PDPL compliance easier to verify. PDPL is evolving and the detection
rules always have room to improve, so contributions are welcome.

## Ground rules

- **This tool is not legal advice and must never claim to be.** Keep that framing intact in any
  user-facing text you add. We surface obligations and detect technical issues; we do not certify
  compliance.
- **Accuracy over coverage.** A false sense of compliance is worse than a missing rule. When in
  doubt, mark a control `assisted` or `manual` rather than asserting a hard `auto` PASS/FAIL.
- **Cite the source.** New controls or overlays should reference the PDPL article, Implementing
  Regulation, or the relevant authority's framework (SAMA, NDMO, CST, NCA, MOH/SFDA, SDAIA).

## Dev setup

```bash
git clone https://github.com/imohad/pdpl-scanner
cd pdpl-scanner
pip install -e ".[dev]"
pytest -q
```

## Where things live

- `pdpl_scanner/rules.py` — detection patterns (regex, KSA identifiers, cross-border signals).
- `pdpl_scanner/controls.py` — the core control catalog (PDPL article -> detect -> severity -> fix).
- `pdpl_scanner/entity_profiles.py` — entity types, residency posture, sector overlays.
- `pdpl_scanner/scanner.py` — the engine.
- `pdpl_scanner/report.py` — JSON / markdown / SARIF output.
- `controls/pdpl-controls.yaml` — human-readable mirror of the catalog (keep in sync).

## Good first contributions

- New detection patterns or language/framework coverage (Go, Java, C#, Terraform, etc.).
- False-positive fixes (add a fixture that reproduces it first).
- Sector-overlay refinements as SAMA/CST/NCA/NDMO guidance updates.
- Better Arabic remediation wording.

## Adding a detection rule

1. Add the pattern to `RULES` in `rules.py` with a control id, severity, and mode.
2. Add or update the control in `controls.py` (and the YAML mirror) with bilingual title + fix.
3. Add a fixture under `tests/fixtures/` and an assertion in `tests/test_scanner.py`.
4. Run `pytest -q`. Keep rules high-recall but document expected false positives.

## Pull requests

Keep PRs focused. Include a short note on the regulatory basis for any new control. Update
`CHANGELOG.md`. By contributing you agree your work is released under the project's MIT license.
