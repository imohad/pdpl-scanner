# Changelog

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
