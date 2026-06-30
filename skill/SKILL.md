---
name: pdpl-compliance-review
description: >
  Use this skill when asked to review code, a repository, a service, or a feature for Saudi PDPL
  (Personal Data Protection Law / نظام حماية البيانات الشخصية) compliance, or for SDAIA, NDMO, SAMA,
  CST, or NCA data-protection obligations. Triggers include "PDPL review", "is this compliant with
  Saudi data law", "check data residency", "هل هذا متوافق مع نظام حماية البيانات", "افحص الامتثال",
  cross-border data-transfer questions about KSA, or any request to audit a codebase before shipping
  in Saudi Arabia. This skill triages the deterministic pdpl-scanner output, removes false positives,
  and writes a bilingual (Arabic RTL + English) report tailored to the entity type.
---

# PDPL Compliance Review

This skill is the **intelligence layer** on top of the `pdpl-scanner` CLI. The CLI is deterministic and
high-recall: it finds every candidate quickly and identically every time, which is what you want gating
CI. But a regex cannot tell whether a `console.log` near a `nationalId` actually leaks the value or just
logs a request id. That judgment is the skill's job: run the scanner, then open each candidate in context,
drop the false positives, and explain the rest in the entity's terms.

## Skill or agent? Why this is a skill.

The deliverable people asked for is "anyone can invoke it from GitHub and add it to their scanning and
compliance testing." That has to run for everyone, including teams with no AI in their pipeline. So the
**portable core is a CLI + GitHub Action** (deterministic, zero-dependency, works in any CI). This skill
is the optional layer for when Claude is in the loop: triage, narrative, and entity-aware remediation.
An autonomous agent is the wrong shape here, because compliance verdicts must be reproducible and
auditable, not re-derived freshly each run. Keep the gate deterministic; use the model to interpret.

## Workflow

1. **Establish the entity profile.** Residency rules depend on who the entity is. If `pdpl.config.yaml`
   exists, read it. Otherwise ask: entity type (government / financial / health / telecom /
   cloud_provider / critical_infrastructure / private_general / nonprofit), highest NDMO data
   classification, and whether it handles sensitive data, children's data, cross-border transfers,
   large-scale processing, or AI on personal data. Do not assume `private_general`; the wrong profile
   produces the wrong verdict.

2. **Run the deterministic scanner.**
   ```bash
   pdpl-scan <path> --entity <type> --json findings.json --markdown report.md --html report.html
   ```
   If the package is not installed, run it from the repo: `pip install -e .` then `pdpl-scan ...`.
   Each finding carries a `status`: `fail` = confirmed auto finding (gates the build); `warn` = an
   assisted **LEAD** to triage. Some LEADs (`DSR-01`/`RET-01`/`LB-01`) are **repo-wide** and have no
   `file:line` — judge them against the whole tree. `passed_controls` lists auto checks that ran clean.

3. **Triage every finding.** For each candidate in `findings.json`, open the cited `file:line` and
   decide:
   - **Confirmed** — real violation. Keep it, sharpen the remediation to the entity.
   - **False positive** — e.g. a logger that logs an id but not the value, a non-KSA region token in a
     comment or a vendor name, a "password" field that is a variable name not a literal. Drop it and say
     why in one line.
   - **Needs human/legal** — assisted/manual controls. Frame them as questions for the DPO, not failures.
   Read `references/triage-guide.md` for the per-control judgment calls.

4. **Apply the entity overlay.** A cross-border flow is `critical` and effectively prohibited for a bank
   or government entity, but `high` and remediable for a private SaaS. Make sure the severity and the
   remediation language match the profile. Surface the sector manual controls (SAMA cloud approval, NDMO
   classification, NCA in-Kingdom hosting, health controls, AI framework) the scanner attached.

5. **Write the bilingual report.** Lead with the verdict (gate + score), then confirmed findings ranked
   by severity with file:line and a concrete fix, then the manual-verify checklist. Mirror it in Arabic
   (RTL). Always close with the scope line: this is an engineering-layer scan, **not a legal
   certification**, and does not replace SDAIA registration, a DPIA, sector approvals, or legal review.

## Update mode (keeping the rules current)

PDPL and its sector overlays change. When asked to "update the PDPL rules", "check for regulatory
changes", "refresh compliance", or "حدّث قواعد الامتثال", do this:

1. Note the current `RULES_LAST_UPDATED` date in `pdpl_scanner/_meta.py`.
2. Research what changed since that date from the primary sources: SDAIA (PDPL Implementing
   Regulations, Transfer Regulations, AI Adoption Framework), NDMO (classification/standards), CST
   (CCRF), NCA (ECC/CCC), SAMA (cloud framework, outsourcing rules), and the health authorities
   (MOH / Saudi Health Council / SFDA). Prefer the regulators' own publications.
3. Translate concrete changes into edits: new or changed detection patterns in `rules.py`, control
   severity/wording in `controls.py`, residency or overlay logic in `entity_profiles.py`, and the
   YAML mirror `controls/pdpl-controls.yaml`. Cite the source for each change in the PR description.
4. Bump `RULES_LAST_UPDATED` to the date the review was completed. Run `pytest -q`. Propose a release.

Be conservative: if a change is ambiguous or not yet in force, mark the affected control `assisted` or
`manual` and note the uncertainty rather than asserting a new hard `auto` PASS/FAIL. Never claim the
rules are current without having actually done the research for the dates in question.

## Hard rules

- **Never call a clean scan "PDPL compliant."** Say the engineering layer is clean and point to the
  manual-verify checklist. A green gate is necessary, not sufficient.
- **Cite the file:line** for every confirmed finding. No vibes-based claims.
- **Match the entity.** Do not give a private-SaaS cross-border answer to a SAMA-regulated entity.
- **Cite the PDPL basis** for each finding (the scanner provides it) but flag that article references
  are a working map and the Implementing Regulations were under amendment in 2025–2026.
- **No em dashes in Arabic output.** Keep Arabic sharp, direct, and professional.

## Reference

- `references/triage-guide.md` — per-control confirm/dismiss heuristics and the KSA identifier list.
- Repo docs: `docs/entity-types.md`, `docs/controls-catalog.md`, `docs/regulatory-references.md`.
