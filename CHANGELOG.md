# Changelog

## [1.1.0] - 2026
Coverage, accuracy, and usability.

**New detection**
- `PDPL-CB-02` — personal data sent to a foreign third-party processor (analytics, email, CRM, AI,
  observability, payments: mixpanel, segment, sendgrid, twilio, openai, stripe, datadog, …).
  Entity-aware severity, like `PDPL-CB-01`.
- `PDPL-SEC-02` — database/transport TLS disabled (`sslmode=disable`, `ssl_mode="disable"`, `ssl=false`).
- **Assisted controls now run in the deterministic engine** as high-recall `LEAD`s (not just in the
  Claude skill): `PDPL-DSR-02` (soft-delete erasure), `PDPL-SEN-01` (sensitive data without visible
  encryption), and repo-wide `PDPL-DSR-01` / `PDPL-RET-01` / `PDPL-LB-01` when no export / retention /
  consent signal is found. Leads never fail the gate on their own.

**Accuracy**
- `PDPL-SEC-03` placeholder/low-entropy triage: default values like `changeme` / `your_password`
  downgrade to a medium `LEAD` instead of a gate-blocking critical. Real-format secrets stay critical.

**Suppression**
- Inline `# pdpl-ignore` / `# pdpl-ignore[CONTROL,…]` directives (cover the line and the one below).
- `.pdplignore` file (gitignore-style globs) and glob support in `--exclude`.

**Reporting**
- Standalone bilingual **HTML report** (`--html`).
- SARIF `partialFingerprints` for stable dedup of code-scanning alerts across runs.
- `--show-pass` lists auto controls evaluated clean; `passed_controls` added to JSON.

**Packaging & DX**
- PyPI release workflow (OIDC trusted publishing) and `.pre-commit-hooks.yaml`.
- README badges, community files (SECURITY.md, CODE_OF_CONDUCT.md, issue/PR templates).

## [1.0.0] - 2026
First public release.

- Deterministic scanner with zero runtime dependencies (stdlib only).
- Entity-aware engine: government, financial (SAMA), health, telecom/cloud (CST), critical
  infrastructure (NCA), private/general, non-profit. NDMO data classification tightens residency.
- Cross-border findings escalate by entity (prohibited / in-Kingdom default / allowed with safeguards).
- Sector overlay manual controls: SAMA, NDMO, CST CCRF, NCA ECC/CCC, health (MOH/SFDA), SDAIA AI Framework.
- KSA identifier detection: national ID, iqama, Saudi mobile, Saudi IBAN, Arabic field names.
- Outputs: JSON, bilingual (Arabic RTL + English) markdown, SARIF 2.1.0 for GitHub code scanning.
- GitHub Action + interactive `init` questionnaire.
- Bundled Claude skill for AI-enriched triage.
