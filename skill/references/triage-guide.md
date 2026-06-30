# Triage Guide

Per-control heuristics for turning scanner candidates into a defensible report. The scanner is
high-recall on purpose; this guide is how you decide what survives.

## KSA personal-data identifiers (what makes data in-scope)

- **Saudi national ID**: 10 digits starting with `1`. **Iqama** (residency): 10 digits starting with `2`.
- **Saudi mobile**: `+9665XXXXXXXX` or `05XXXXXXXX`.
- **Saudi IBAN**: `SA` + 22 digits.
- **Arabic field names**: الهوية، الإقامة، الجوال، العنوان، تاريخ الميلاد، جواز.
- **Sensitive (elevated)**: health, biometric, genetic, religion, ethnicity, credit score, criminal
  record, salary, card number/CVV. Arabic: صحي، طبي، بصمة، الديانة، العرق، راتب، بطاقة.

If none of these are near the finding, downgrade or dismiss: PDPL governs personal data, not arbitrary
strings.

## Per-control judgment

### PDPL-CB-01 — cross-border transfer
Confirm when a real personal-data payload reaches a non-KSA endpoint/region: an SDK init with a foreign
region, an outbound request body carrying identifiers, a database/replica in a foreign region.
**Dismiss** when the token is a comment, a vendor brand name, a region string in unreachable/test code,
or the payload provably carries no personal data. **Entity matters most here**: for government/financial/
CNI this is critical and the fix is "must reside in-Kingdom; obtain SAMA/regulator approval"; for private
entities it is high and the fix is "lawful transfer basis + SCCs/adequacy/exception + transfer risk
assessment + minimization."

### PDPL-CB-02 — foreign third-party processor (assisted-leaning auto)
Confirm when personal data is sent to a known foreign processor endpoint (analytics, email, CRM, AI,
observability, payments: mixpanel/segment/sendgrid/twilio/openai/stripe/datadog…). Even "anonymous"
analytics usually carries device/IP/identifier data, so default to confirm when a PII payload is nearby.
**Dismiss** a bare dependency reference or doc link with no personal data. Same entity-aware framing as
CB-01: for a bank/government this is critical (treat the SaaS as a cross-border transfer needing approval
+ a DPA); for private entities it's high (lawful basis + DPA + minimization). Prefer an in-Kingdom or
adequacy-listed alternative.

### PDPL-SEC-03 — hardcoded secret
Confirm on real literals: AWS keys (`AKIA…`), private-key blocks, credentialed connection strings, or an
assignment of a long literal to a secret-named variable. The scanner now **auto-downgrades obvious
placeholders** (`changeme`, `your_password`, low-entropy/templated values) to a medium LEAD — keep those
as "verify + don't ship the default," not a critical. **Dismiss** `process.env.X` / `${SECRET}` and
variable *names* with no literal value. Any confirmed live secret = rotate immediately, not just relocate.

### PDPL-SEC-01 — transport security
Confirm `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, or `http://` carrying
personal data. **Dismiss** localhost/dev URLs and health-check pings with no personal data.

### PDPL-SEC-02 — database/transport TLS disabled
Confirm `sslmode=disable`, `ssl_mode="disable"`, or `ssl: false` on a connection that carries personal
data between services (app↔DB, app↔broker). **Dismiss** local-dev compose files clearly scoped to
localhost. Fix is `sslmode=require`/`verify-full` (or mTLS).

### PDPL-LOG-01 — personal data in logs
The highest false-positive control. Confirm only when the logged expression actually contains a personal
value or sensitive field, not merely a nearby variable. A `logger.info("request received")` next to a
`nationalId` declaration is a **dismiss**. `logger.info(user.nationalId)` is a **confirm**.

### PDPL-LB-03 — pre-ticked consent
Confirm a consent/opt-in input defaulted to checked/true. **Dismiss** non-consent toggles (dark mode,
remember-me) that merely matched on "checked".

### PDPL-LB-01 — consent / lawful-basis gate (assisted, repo-wide)
The CLI now emits this as a repo-wide LEAD when personal data is handled but no consent/legal-basis signal
(`consent`, `legal_basis`, `opt-in`, الموافقة) appears anywhere. Confirm when writes genuinely lack a
documented basis; **dismiss** when basis is enforced elsewhere (middleware, a policy layer, server-side
checks the scanner can't see). Frame as "gate writes on a documented lawful basis; persist basis/purpose/
consent metadata."

### PDPL-DSR-01 / DSR-02 — access & erasure (assisted)
These are about absence. The CLI emits DSR-01 repo-wide when no export/portability path (`/me/data`,
`download-data`) exists, and DSR-02 per soft-delete flag (`is_deleted`/`deleted_at`). If erasure is
soft-only with no purge/anonymization and no documented lawful-retention exception, confirm. Frame as
"add a hard-delete/anonymization path."

### PDPL-SEN-01 — sensitive data (assisted)
Confirm sensitive fields without encryption/least-privilege/minimization. Recommend a DPIA when the
processing is large-scale or high-risk. For health entities, tie to MOH/HIE controls; for AI on personal
data, tie to the SDAIA AI Adoption Framework.

### PDPL-RET-01 — retention (assisted)
Confirm a personal-data store with no TTL/retention/purge. **Dismiss** ephemeral caches and stores that
already expire. Recommend a per-dataset retention period.

## Manual controls — frame as questions, not failures

`PDPL-GOV-02..07`, `PDPL-BR-01`, and the sector overlays (SAMA/NDMO/CST/NCA/health/AI) cannot be proven
from code. Present them as a sign-off checklist for the DPO/legal: "Is the RoPA current? Is the controller
registered? Is there a 72-hour breach runbook? For a bank: is SAMA cloud approval on file?" Never count
them as scan failures and never let their absence be read as a code defect.

## Output discipline

- One line of rationale per dismissed finding (so the report is auditable).
- file:line for every confirmed finding.
- Verdict first, then findings, then manual checklist, then the scope/disclaimer.
- Bilingual: English then Arabic (RTL). No em dashes in Arabic. Keep it sharp.
