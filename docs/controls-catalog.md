# Controls Catalog

Every control maps a PDPL obligation to a **detection mode**:

- **auto** — deterministic code pattern. Produces a real PASS/FAIL with `file:line` evidence.
- **assisted** — high-recall lead. A match is something to look at, best triaged in context by a human
  or the bundled Claude skill.
- **manual** — organizational/legal obligation with no code signal. Always surfaced as a checklist item.

The machine-readable source of truth is [`../controls/pdpl-controls.yaml`](../controls/pdpl-controls.yaml)
and `pdpl_scanner/controls.py`. This page is the readable summary.

## Code-detectable controls

| ID | Domain | Severity | Mode | PDPL reference | What it catches |
|---|---|---|---|---|---|
| `PDPL-LB-01` | Legal Basis & Consent | critical | assisted | Arts. 5-6 | Personal-data write with no consent / legal-basis gate |
| `PDPL-LB-03` | Legal Basis & Consent | high | auto | Art. 6 | Pre-ticked / default-on consent |
| `PDPL-DSR-01` | Data Subject Rights | high | assisted | Arts. 4, 9 | No data access / export path for subjects |
| `PDPL-DSR-02` | Data Subject Rights | high | assisted | Arts. 4, 18 | Soft-delete-only erasure (PII retained) |
| `PDPL-CB-01` | Cross-Border Transfer | critical¹ | auto | Art. 29 + Transfer Regs | Personal data reaching a non-KSA region/endpoint |
| `PDPL-SEC-01` | Security Safeguards | critical | auto | Art. 19 | TLS verification disabled / plaintext transport of PII |
| `PDPL-SEC-03` | Security Safeguards | critical | auto | Art. 19 | Hardcoded secret / credential / connection string |
| `PDPL-SEC-05` | Security Safeguards | high | auto | Art. 19 | Weak hashing (MD5/SHA1) for credentials |
| `PDPL-LOG-01` | Logging & Exposure | high | auto | Art. 19 + minimization | Personal/sensitive data written to logs |
| `PDPL-SEN-01` | Sensitive Personal Data | critical | assisted | Art. 1 + safeguards | Sensitive fields without elevated handling |
| `PDPL-RET-01` | Retention & Deletion | medium | assisted | Art. 18 | No retention limit / purge on personal-data stores |

¹ `PDPL-CB-01` severity is set at runtime by the entity profile: **critical** for
government/financial/critical-infrastructure (effectively prohibited without regulator approval),
**high** for everyone else (allowed with safeguards). See [entity-types.md](entity-types.md).

## Manual-verify controls (organizational)

These are real PDPL obligations the scanner cannot prove from code. Every report lists the ones that
apply to your entity profile.

| ID | Obligation | PDPL reference |
|---|---|---|
| `PDPL-GOV-02` | Record of Processing Activities (RoPA) maintained and retained | Art. 31 + RoPA Guideline |
| `PDPL-GOV-03` | Controller registration on the National Data Governance Platform | Controller registration rules |
| `PDPL-GOV-04` | DPO appointed and registered where required | DPO appointment rules |
| `PDPL-GOV-05` | Processor agreements (DPAs) with breach/deletion/audit terms | Controller-processor obligations |
| `PDPL-GOV-06` | DPIA for high-risk / large-scale / sensitive processing | Implementing Regs |
| `PDPL-GOV-07` | Privacy notice present, accessible, complete at collection | Art. 12 |
| `PDPL-BR-01` | 72-hour breach notification runbook to SDAIA | Art. 20 + Art. 24 + Breach Guide |

## Sector overlay controls

Added automatically based on entity type (see [entity-types.md](entity-types.md)):

| Overlay | Example controls |
|---|---|
| NDMO | Data classification applied; CDPO / data office; periodic NDMO reports |
| NCA-ECC | Hosting and storage inside the Kingdom (ECC 4.2.3.3) |
| NCA-CCC | Cloud Cybersecurity Controls for the hosting model |
| SAMA | Cloud approval before use and for any cloud outside KSA; in-Kingdom residency + key management; outsourcing register |
| CST-CCRF | Workloads mapped to cloud level; Saudi Government content not exported |
| MOH-HEALTH | Health data under elevated controls (encryption, RBAC, audit log) |
| SFDA-AI | AI/ML medical device assessed under SFDA MDS-G010 |
| SDAIA-AI | AI on personal data aligned to the AI Adoption Framework's five pillars |
