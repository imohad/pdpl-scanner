# Entity Types and Residency Posture

Saudi data-protection compliance is layered. The PDPL is the base law for everyone, but sector
regulators stack their own requirements on top, and the strictest of them govern where personal data
may live. This is why the scanner asks who you are before it judges a cross-border data flow.

## The compliance surface

A single workload in the Kingdom can sit under several authorities at once:

- **SDAIA / PDPL** — the base personal-data law (Royal Decree M/19, amended by M/148) and its
  Implementing Regulations + Transfer Regulations. Applies to anyone processing the data of people in
  Saudi Arabia, including entities outside the Kingdom.
- **NDMO** — the National Data Management Office (under SDAIA) sets the national Data Classification
  Policy (four levels) and the Data Management & Personal Data Protection Standards for public entities
  and their data partners.
- **CST (CCRF)** — the Cloud Computing Regulatory Framework defines cloud service levels aligned to the
  NDMO classification, and bars moving Saudi Government content outside the Kingdom, even temporarily,
  unless permitted.
- **NCA** — Essential Cybersecurity Controls (ECC 4.2.3.3 requires hosting and storage inside the
  Kingdom) and Cloud Cybersecurity Controls (CCC), mandatory for government, semi-government, and
  operators of Critical National Infrastructure.
- **SAMA** — the Saudi Central Bank's Cloud Computing Regulatory Framework, Cyber Security Framework,
  and Rules on Outsourcing govern all SAMA-supervised entities.
- **Health authorities** — the PDPL treats health data as sensitive, and MOH / Saudi Health Council /
  Saudi Health Information Exchange policies and SFDA guidance add controls for the health sector.

## Data classification drives residency

NDMO's four levels (and the CST cloud levels they map to) set the hosting floor:

| Classification | CST level | Hosting consequence |
|---|---|---|
| Top Secret | Level 4 | In-Kingdom, CST-licensed provider, Saudi-national operational control for government workloads |
| Secret | Level 3 | Must be hosted in-Kingdom |
| Confidential | Level 2 | In-Kingdom by default; cross-border only under PDPL + CCRF conditions |
| Public | Level 1 | May be hosted outside the Kingdom subject to PDPL and sector rules |

The scanner treats `secret` and `top_secret` as in-Kingdom-mandatory regardless of entity type, and
upgrades `confidential` private-sector data from "allowed with safeguards" to "in-Kingdom by default."

## How each entity type changes the verdict

### government / public entity
Overlays: NDMO + NCA ECC. Residency: **prohibited without approval**. Government data is expected to
remain within national borders; classification levels decide the hosting model. The scanner surfaces
NDMO classification, the entity data office / CDPO obligation, and the NCA in-Kingdom hosting control.

### financial (SAMA-regulated)
Covers banks, insurance, finance companies, payment service providers, credit bureaus, and fintech.
Overlays: SAMA + NCA ECC. Residency: **prohibited without approval**. Highly sensitive customer and
financial data must reside in-Kingdom with in-Kingdom key management; SAMA approval is required before
using cloud services and explicitly before any cloud located outside the Kingdom, and material
outsourcing abroad needs SAMA no-objection. A cross-border flow here is a critical finding.

### critical_infrastructure
Overlays: NCA ECC + CCC. Residency: **prohibited without approval**. NCA ECC 4.2.3.3 requires hosting
and storage inside the Kingdom for in-scope organizations.

### health
Overlays: MOH/Saudi Health Council + SFDA. Residency: **in-Kingdom by default**. Health data is
sensitive under the PDPL and attracts elevated controls (encryption, role-based access, audit logging)
per MOH and Saudi Health Information Exchange policies. AI/ML used as a medical device is also assessed
under SFDA MDS-G010.

### telecom / cloud_provider
Overlays: CST CCRF (+ NCA CCC for providers). Residency: **in-Kingdom by default**. CST-registered
providers must not transfer Saudi Government content outside the Kingdom unless permitted.

### private_general / nonprofit
Overlays: none beyond the PDPL base. Residency: **allowed with safeguards**. Cross-border transfers are
permitted with a lawful transfer basis plus appropriate safeguards (Standard Contractual Clauses,
adequacy where SDAIA has recognized it, or a listed exception) and a transfer risk assessment, minimized
to what is necessary. Prefer in-Kingdom hosting where feasible.

## Cross-cutting modifiers

Independent of entity type, these answers in the questionnaire change obligations:

- **processes_sensitive_data** — health, biometric, genetic, credit, criminal, religious/ethnic. Raises
  handling requirements and contributes to the DPO and DPIA triggers.
- **processes_children_data** — engages the Children's Personal Data Protection Policy; triggers DPO.
- **cross_border_transfers** — triggers DPO and mandates a transfer risk assessment under the Transfer
  Regulations.
- **large_scale_processing** — combined with sensitive data, triggers DPIA and DPO.
- **uses_ai_on_personal_data** — adds the SDAIA AI Adoption Framework overlay (data governance, model
  accountability, transparency, human oversight, risk management) on top of PDPL.
- **is_public_entity** — adds NDMO and registration obligations.

The scanner computes the DPO, registration, and DPIA triggers from these answers and lists the matching
manual-verify controls in every report.
