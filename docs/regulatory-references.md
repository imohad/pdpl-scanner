# Regulatory References

The detection rules and entity overlays in this scanner are distilled from the following Saudi
regulatory instruments and authority frameworks. Article references in the tool are a **working map,
not legal advice**, and the Implementing Regulations were under amendment through 2025–2026. Always
verify high-stakes decisions against the authority's current published text and your own counsel.

## Personal Data Protection Law (PDPL) — SDAIA

- **PDPL**: Royal Decree No. M/19 (16 Sep 2021), amended by Royal Decree No. M/148 (27 Mar 2023).
- In force 14 Sep 2023; one-year grace period; **full enforcement since 14 Sep 2024**.
- Regulator: **Saudi Data & AI Authority (SDAIA)**, via the National Data Governance Platform.
- **Implementing Regulations** and **Regulations on Personal Data Transfer Outside the Kingdom**
  (published 7 Sep 2023; a third public consultation on amendments ran Apr–May 2025).
- SDAIA — Laws and Regulations: https://sdaia.gov.sa/en/SDAIA/about/Pages/RegulationsAndPolicies.aspx

Key obligations encoded here:
- Lawful basis for processing (consent as the default basis): **consent is governed by Art. 5**
  (Art. 5(2) gives the withdrawal right) and **Art. 7** (consent may not be a precondition of a
  service); **Art. 6 lists the cases where processing needs *no* consent** — so affirmative-consent
  controls cite Arts. 5/7, not Art. 6.
- Data subject rights (**PDPL Art. 4**: informed, access, obtain-a-copy, correction, destruction):
  access detail in Art. 9, retention/destruction carve-out in Art. 18.
- **Breach notification**: notify SDAIA within **72 hours** of awareness (Art. 20 PDPL, Art. 24
  Implementing Regulations, Personal Data Breach Incidents Procedural Guide). No materiality threshold;
  notify affected subjects where harm is likely.
- **Records of Processing Activities (RoPA)**: purposes, data categories, recipients, cross-border
  arrangements, retention, security measures; retained and produced to SDAIA on request.
- **DPIA** for high-risk / large-scale sensitive / automated-decision processing.
- **Cross-border transfer** (Art. 29 + standalone Transfer Regulation + Feb/Mar-2025 Risk Assessment
  Guideline): Art. 29(2) requires no prejudice to national interests, an adequate level of protection,
  and minimization. SDAIA has **not yet published the adequacy/"appropriate level of protection"
  country list** (Transfer Regulation Art. 3 creates the mechanism, reviewed every 4 years), so
  transfers rely on **exactly three appropriate safeguards** — Standard Contractual Clauses (SDAIA's
  four SCC forms, Sep 2024, non-modifiable), **Binding Common Rules** (not "binding corporate rules"),
  and a Certificate of accreditation — plus a transfer risk assessment (Transfer Reg Art. 7).
- **Controller registration** (National Data Governance Platform — a qualified obligation) and
  **DPO appointment** rules, with DPO contact details submitted to SDAIA's platform.
- **Penalties**: **Art. 35** — up to **2 years + SAR 3 million** for disclosing/publishing sensitive
  personal data with intent to harm or for personal benefit; **Art. 36** — up to **SAR 5 million** for
  other violations; fines may **double for repeat** violations (a PDPL Violations Committee issues the
  administrative fines).

## NDMO — National Data Management Office (under SDAIA)

- National Data Management & Personal Data Protection Standards (15 domains, 77 controls, 191
  specifications) for public entities and their data partners.
- **Data Classification Policy**: four levels — **Top Secret, Secret, Confidential (Restricted),
  Public** — driving storage location, encryption, access, retention, and cross-border eligibility.
- National Data Governance Interim Regulations (open data, data sharing, freedom of information).
- NDMO policies: https://sdaia.gov.sa/ndmo/

## CST — Communications, Space & Technology Commission

- **Cloud Computing Regulatory Framework (CCRF)**: cloud service levels aligned to the NDMO
  classification; clause barring transfer of Saudi Government content outside the Kingdom, even
  temporarily, unless permitted (3-3-8).

## NCA — National Cybersecurity Authority

- **Essential Cybersecurity Controls** — current version **ECC-2:2024** (a restructuring of ECC-1:2018,
  108 controls, hyphenated numbering) requires information hosting and storage **inside the Kingdom**
  for government, semi-government, and CNI operators. (The old ECC-1:2018 dotted clause "4.2.3.3" does
  not carry over to ECC-2:2024's numbering — cite the standard, verify the clause against current text.)
- **Cloud Cybersecurity Controls (CCC)** for cloud hosting models.
- **Data Cybersecurity Controls (DCC)** operationalizing PDPL security obligations.

## SAMA — Saudi Central Bank (financial sector)

- **Cloud Computing Regulatory Framework**: highly sensitive customer/financial data resides
  in-Kingdom; SAMA approval required before cloud use and **explicitly before any cloud outside the
  Kingdom**.
- **Cyber Security Framework** (May 2017) for banking, insurance, and finance.
- **Rules on Outsourcing**: register material outsourcing; SAMA no-objection for material outsourcing
  abroad.
- SAMA Rulebook: https://rulebook.sama.gov.sa/

## Health sector

- PDPL treats **health data as sensitive**, attracting elevated safeguards.
- **MOH** privacy policy; **Saudi Health Information Exchange** policies (audit log, emergency access,
  integrity, authentication, encryption; ISO 27000 / SSAE 16 alignment).
- **Saudi Health Council** and the **Insurance Authority** (sole insurance regulator since 2024,
  consolidating CHI and SAMA insurance oversight).
- **SFDA MDS-G010**: AI/ML used as a medical device (classification, marketing authorization, clinical
  efficacy, data integrity, cybersecurity).

## AI

- **SDAIA AI Adoption Framework** — first issued Sep 2024 (four maturity levels); a Nov 2025 update set
  a **mandatory governance baseline** for public-sector entities across five pillars: data governance,
  model accountability, transparency, human oversight, risk management. Applies on top of the PDPL where
  AI processes personal data of people in the Kingdom. Saudi Arabia designated 2026 the Year of AI.
- SDAIA AI Ethics Principles (2023) and Generative AI Guidelines (2024).

---

*If you find an outdated reference or a rule that no longer matches current guidance, please open an
issue or PR — see [CONTRIBUTING.md](../CONTRIBUTING.md).*
