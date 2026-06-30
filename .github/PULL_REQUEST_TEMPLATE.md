<!-- Thanks for contributing to pdpl-scanner! -->

## What & why
Briefly describe the change and the PDPL obligation / rule it affects.

## Type
- [ ] New / improved detection rule
- [ ] False-positive fix
- [ ] Language / framework coverage
- [ ] Sector-overlay refinement
- [ ] Reporting / tooling / docs

## Checklist
- [ ] `pytest -q` passes
- [ ] Added/updated tests (including a **negative** case for new rules to guard against false positives)
- [ ] Updated `pdpl_scanner/controls.py` **and** the YAML mirror `controls/pdpl-controls.yaml` if a control changed
- [ ] Updated `docs/` and `CHANGELOG.md` if user-facing
- [ ] Regulatory references cited for any rule/severity change

## Notes for reviewers
Anything tricky, trade-offs, or follow-ups.
