# PDPL Coverage Map

What Saudi Arabia's **Personal Data Protection Law (PDPL)** requires, versus what this tool actually
checks — with an honest accounting of the gaps. This is the disclaimer ("engineering-layer, not a legal
certification") made concrete.

**Detection modes:** **AUTO** = deterministic, gates the build (confirmed `FAIL`) · **ASSISTED** =
high-recall `LEAD`, surfaced for human/skill triage (never gates on its own) · **MANUAL** = real
obligation surfaced as a checklist item · **GAP** = not addressed by the tool.

> **Verification.** The PDPL article references below were independently checked on **2026-07-01** via a
> multi-source, adversarially-verified research pass (primary source: SDAIA's published PDPL text +
> the standalone Transfer Regulation, corroborated by tier-1 legal commentary). Items marked
> *(working map)* could not be affirmatively confirmed from primary text in that pass and should be
> treated as provisional. References remain a **working map, not legal advice** — confirm high-stakes
> decisions against [SDAIA's current published text](https://sdaia.gov.sa/en/SDAIA/about/Pages/RegulationsAndPolicies.aspx).

---

## 1. Obligations the tool covers

| PDPL obligation | Verified reference | Tool control(s) | Mode |
|---|---|---|---|
| Security safeguards (technical & org. measures) | Art. 19 *(working map)* | `SEC-01` TLS · `SEC-02` DB TLS · `SEC-03` secrets · `SEC-05` weak hashing · `LOG-01` PII in logs | **AUTO** |
| Cross-border transfer | **Art. 29** ✓ verified | `CB-01` non-KSA region · `CB-02` foreign processors | **AUTO** |
| Consent must be affirmative / not pre-ticked | **Art. 5** (consent) + **Art. 7** (no precondition) ✓ verified | `LB-03` pre-ticked consent | **AUTO** |
| Lawful basis for processing | **Arts. 5–7** ✓ verified (Art. 5 consent · Art. 6 *non-consent* bases · Art. 7) | `LB-01` write without a basis signal | ASSISTED |
| Right of access / obtain a copy | **Art. 4** (4-2) + **Art. 9** ✓ verified | `DSR-01` no export path | ASSISTED |
| Right to destruction / erasure | **Art. 4** (4-5) + **Art. 18** ✓ verified | `DSR-02` soft-delete-only | ASSISTED |
| Sensitive-data elevated handling | Art. 1 (definition) *(working map)* | `SEN-01` sensitive field w/o encryption | ASSISTED |
| Retention / destroy when purpose ends | **Art. 18** ✓ verified | `RET-01` no retention/purge | ASSISTED |
| Transparency / privacy notice | Art. 12 *(working map)* | `GOV-07` | MANUAL |
| Records of Processing Activities | **Art. 31** + Implementing **Art. 33** ✓ verified | `GOV-02` | MANUAL |
| Controller registration | National Data Governance Platform (qualified) ✓ verified | `GOV-03` | MANUAL |
| DPO appointment | Implementing Regs *(working map)* | `GOV-04` | MANUAL |
| Processor agreements (DPAs) | Controller–processor obligations | `GOV-05` | MANUAL |
| DPIA | Implementing Regs *(working map)* | `GOV-06` | MANUAL |
| Breach notification (72 h) | **Art. 20** (law) + Implementing **Art. 24** ✓ verified | `BR-01` | MANUAL |
| Sector overlays (residency/approvals) | NDMO / NCA ECC-2:2024 / SAMA / CST / MOH / SFDA / SDAIA-AI | 8 overlay controls (entity-driven) | MANUAL |

**Cross-border specifics (verified):** SDAIA has **not yet published the adequacy country list**
(Transfer Regulation Art. 3 creates the mechanism). Transfers rely on **exactly three appropriate
safeguards** — Standard Contractual Clauses, **Binding Common Rules**, Certificate of accreditation —
plus a transfer risk assessment (Transfer Reg Art. 7). **Penalties (verified):** Art. 35 (up to
2 years + SAR 3M for sensitive-data disclosure with intent to harm / for benefit); Art. 36 (up to
SAR 5M for other violations; doubled for repeat).

---

## 2. Gaps — PDPL obligations the tool does *not* address

| Obligation | Status | Detectable by a code scanner? |
|---|---|---|
| **Right to correction / rectification** (Art. 4(4)) | Not covered — only access & erasure are modeled | Partially (assisted, like DSR-01) |
| **Purpose limitation / over-collection** | Not covered | Hard — needs data-flow + purpose context |
| **Encryption at rest** | Only *in-transit* TLS (`SEC-01/02`) is detected | Partially (config heuristics) |
| **Access control / least-privilege** | Not detected (surfaced via overlays only) | Partially (framework-specific) |
| **Automated decision-making / profiling** | Not covered *(standalone PDPL provision not confirmed in 2026 review — open)* | Partially |
| **Direct-marketing consent** | Not covered *(standalone provision not confirmed — open)* | Partially |
| **Data accuracy** | Not covered | No — inherently not code-detectable |
| **Children's / incapacity data** | Drives the entity profile, but no in-code detection | Partially |

> **Note on minimization:** PDPL data minimization is verified for the *transfer* context
> (Art. 29(2)(c)); a general standalone minimization obligation was not separately confirmed in the
> 2026 review and is treated as an open item.

---

## 3. Bottom line

- **Strong where it should be:** the **engineering-detectable layer** — Art. 19 security and Art. 29
  transfers — is covered deterministically and gates CI. That is exactly the slice a static scanner can
  *prove*.
- **High-recall, not proof:** rights, consent, retention, sensitive data → ASSISTED `LEAD`s for triage,
  never silently passed.
- **Checklist by design:** the organizational/legal layer (RoPA, DPO, registration, DPIA, breach
  runbook, sector approvals) is *surfaced*, not faked.
- **Real gaps** are mostly obligations a static scanner fundamentally can't prove (data accuracy,
  purpose limitation, correction rights) — which is precisely why a green scan is **not** a compliance
  certificate.

**Coverage:** ~90% of PDPL's obligation *areas* are touched (detected, led, or surfaced). The
unaddressed items need data-flow analysis or human/legal judgment a code scanner can't supply.

---

### Changelog of verified corrections (2026-07-01 review)
- `PDPL-LB-03` citation **corrected** from *"Art. 6"* → **Art. 5 + Art. 7** (Art. 6 is the *no-consent*
  exceptions article — the opposite of affirmative consent).
- `PDPL-LB-01` clarified to **Arts. 5–7**.
- NCA ECC overlay updated from the retired ECC-1:2018 clause *"4.2.3.3"* → **ECC-2:2024**.
- Penalties documented with article numbers (**Art. 35 / Art. 36**); transfer-safeguard trio and the
  unpublished adequacy list confirmed.
