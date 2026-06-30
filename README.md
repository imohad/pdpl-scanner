# PDPL Scanner

**Entity-aware compliance scanner for Saudi Arabia's Personal Data Protection Law (PDPL).**

Drop it into any project's CI to scan code for PDPL violations and gate merges on them. It finds the issues a generic privacy linter misses, because Saudi compliance is not one rulebook: the hosting and residency rules and the regulator overlays change depending on *who the entity is* and *what data it handles*. A cross-border data flow that is merely "fix your safeguards" for a private SaaS is effectively **prohibited** for a SAMA-regulated bank or a government entity. This scanner knows the difference.

> Built and maintained by [Mohammad AlShammari](https://www.linkedin.com/). PDPL = نظام حماية البيانات الشخصية. Output is bilingual (Arabic RTL + English).

> ⚠️ **This tool is an aid, not a legal certification and not a substitute for manual review.** A passing scan means the engineering layer is clean of what this tool checks, not that your organization is compliant. Always complete the manual-verify checklist and confirm with your DPO/legal. **Rules change** — the catalog is current as of the date in [`pdpl_scanner/_meta.py`](pdpl_scanner/_meta.py), shown in every report; re-verify periodically with `pdpl-scan update`. See [DISCLAIMER.md](DISCLAIMER.md). | **الأداة مساعِدة وليست شهادة امتثال ولا بديلاً عن التدقيق اليدوي. الأنظمة تتغيّر، فأعد التحقق دورياً.** التفاصيل في [DISCLAIMER.md](DISCLAIMER.md) والقسم العربي بالأسفل.

**[العربية ↓](#نظرة-عامة-بالعربية)** — A full Arabic walkthrough is at the bottom of this file.

---

## What it does

- **Scans code and config** for technical PDPL violations: cross-border data flows, missing/disabled encryption, hardcoded secrets, personal data in logs, pre-ticked consent, weak hashing, missing data-subject-rights paths, soft-delete-only erasure, no retention limits, mishandled sensitive data.
- **Knows Saudi identifiers**: national ID, iqama, Saudi mobile (`+9665…` / `05…`), Saudi IBAN, plus Arabic field names. This is where generic scanners are blind.
- **Adjusts to the entity**: an interactive questionnaire (or a committed `pdpl.config.yaml`) sets the entity type and data classification, which re-weights findings and surfaces the right sector obligations (SAMA, NDMO, CST, NCA, health).
- **Separates what it can prove from what it can't**: code-detectable controls return a real PASS/FAIL; organizational obligations (SDAIA registration, DPO, RoPA, processor contracts, DPIA, the 72-hour breach runbook) are surfaced as a **manual-verify checklist**, never silently passed.
- **Integrates natively with GitHub**: emits SARIF so findings show up on the Security tab and inline on pull requests.

### What it is not

This is an **engineering-layer** scanner. It is **not a legal certification of PDPL compliance** and does not replace SDAIA registration, a DPIA, sector approvals, or legal review. A clean scan means your code is clean, not that your organization is compliant. The manual-verify checklist exists precisely so a green report is never mistaken for a clean bill of health.

---

## Quick start

### Option A — GitHub Action (recommended)

Add `.github/workflows/pdpl-scan.yml`:

```yaml
name: PDPL Compliance
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  pdpl-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: imohad/pdpl-scanner@v1
        with:
          entity: "financial"     # or commit a pdpl.config.yaml instead
          fail-on: "critical"
```

Findings appear in the Security tab and on the PR. The build fails on critical violations.

### Option B — CLI

```bash
pip install pdpl-scanner            # or: pip install git+https://github.com/imohad/pdpl-scanner

pdpl-scan init                      # interactive questionnaire -> pdpl.config.yaml
pdpl-scan .                         # scan using that config
```

One-off without a config:

```bash
pdpl-scan ./src --entity health --fail-on critical,high \
  --json findings.json --sarif results.sarif --markdown report.md
```

Exit code is non-zero when the gate fails, so it blocks CI out of the box.

### Option C — as a library

```python
from pdpl_scanner import scan, EntityProfile
from pdpl_scanner.report import to_markdown

profile = EntityProfile(type="financial", cross_border_transfers=True, processes_sensitive_data=True)
result = scan("./src", profile=profile)
print(result.gate, result.score)
print(to_markdown(result))
```

---

## Entity types and why they matter

The questionnaire asks who you are. That answer changes the residency verdict and the obligations:

| Entity type | Regulator overlay | Residency posture for in-scope personal data |
|---|---|---|
| `government` | NDMO + NCA ECC | **Prohibited without approval** — must stay in-Kingdom; classification-driven |
| `financial` | SAMA + NCA ECC | **Prohibited without approval** — SAMA approval required before cloud, explicitly for any cloud outside KSA |
| `critical_infrastructure` | NCA ECC + CCC | **Prohibited without approval** — hosting inside the Kingdom (ECC 4.2.3.3) |
| `health` | MOH / Saudi Health Council + SFDA | **In-Kingdom by default** — health data is sensitive; HIE controls apply |
| `telecom` / `cloud_provider` | CST CCRF | **In-Kingdom by default** — Saudi Government content must not leave the Kingdom |
| `private_general` / `nonprofit` | PDPL base | **Allowed with safeguards** — lawful basis + SCCs/adequacy/exception + transfer risk assessment |

NDMO data classification (`top_secret` / `secret` / `confidential` / `public`) tightens residency further: anything classified `secret` or above must remain in-Kingdom regardless of entity type.

The same data flow therefore produces different verdicts. To a bank, code shipping customer data to `eu-west-1` is a **critical** finding with a "must reside in-Kingdom, obtain SAMA approval" remediation. To a private SaaS, it is a **high** finding with a "confirm your transfer safeguards" remediation. The scanner computes this for you.

See [`docs/entity-types.md`](docs/entity-types.md) for the full breakdown.

---

## Controls

The catalog maps each PDPL obligation to a detection mode. Highlights:

| Domain | Example controls | Mode |
|---|---|---|
| Cross-border transfer | `PDPL-CB-01` data leaving KSA (entity-aware severity) | auto |
| Security safeguards | `PDPL-SEC-01` TLS, `SEC-03` secrets, `SEC-05` hashing | auto |
| Logging & exposure | `PDPL-LOG-01` personal data in logs | auto |
| Legal basis & consent | `PDPL-LB-01` consent gate, `LB-03` pre-ticked consent | auto / assisted |
| Data subject rights | `PDPL-DSR-01` access/export, `DSR-02` real erasure | assisted |
| Sensitive data | `PDPL-SEN-01` elevated handling | assisted |
| Retention | `PDPL-RET-01` retention limits | assisted |
| Governance & records | `PDPL-GOV-02..07`, `BR-01` 72h breach | manual |

`auto` controls produce real PASS/FAIL with file:line evidence. `assisted` controls produce high-recall leads best triaged by a human or the bundled Claude skill. `manual` controls are organizational obligations surfaced for sign-off. Full machine-readable catalog: [`controls/pdpl-controls.yaml`](controls/pdpl-controls.yaml). Human-readable: [`docs/controls-catalog.md`](docs/controls-catalog.md).

---

## Configuration

`pdpl.config.yaml` (generated by `pdpl-scan init`):

```yaml
entity:
  type: financial
  data_classification: confidential   # top_secret | secret | confidential | public
  is_public_entity: false
  processes_sensitive_data: true
  processes_children_data: false
  cross_border_transfers: true
  large_scale_processing: true
  uses_ai_on_personal_data: false
scan:
  paths: ["src"]
  exclude: ["tests", "node_modules", "dist", "build"]
gate:
  fail_on: [critical]
  weights: { critical: 25, high: 10, medium: 4, low: 1 }
```

Commit it so every scan and every contributor uses the same profile.

---

## AI-enriched review (optional Claude skill)

The repo ships a Claude skill in [`skill/`](skill/). The deterministic CLI is high-recall by design; the skill adds a triage layer that opens each candidate finding in context, drops false positives, writes the bilingual report, and tailors remediation to your entity. Point Claude Code at `skill/SKILL.md`, or install the skill, then ask it to run a PDPL review on your changed paths. The CLI works fully on its own without it.

---

## Scope, accuracy, and disclaimer

PDPL's Implementing Regulations were under amendment through 2025–2026 and SDAIA issues supplementary guidance (e.g. the 2025 AI Adoption Framework). Article references in this tool are a working map, not the final legal word. This project is provided as-is under the MIT license and **does not constitute legal advice**. Verify high-stakes decisions against SDAIA's current [regulations and policies](https://sdaia.gov.sa/en/SDAIA/about/Pages/RegulationsAndPolicies.aspx) and your own counsel. Regulatory sources are listed in [`docs/regulatory-references.md`](docs/regulatory-references.md).

## Keeping the rules current

PDPL and its sector overlays change. The Implementing Regulations were under amendment through
2025–2026, and SDAIA/NDMO/CST/NCA/SAMA and the health authorities issue updates. So the scanner stamps
every report with the date its rules were last reviewed (`RULES_LAST_UPDATED` in
[`pdpl_scanner/_meta.py`](pdpl_scanner/_meta.py)) and warns when that date is overdue.

```bash
pdpl-scan update      # shows freshness status and the refresh workflow
```

Refreshing is a deliberate research step, not a silent auto-update. Ask the bundled Claude skill's
**update mode** (or ask Claude) to research the latest published changes from the regulators since that
date, apply them to the rules, cite the source for each change, and bump the date. **You are
responsible for re-verifying compliance periodically.**

This catalog is current as of its initial publish date. Treat anything after that as needing a refresh.

## Contributing

PDPL is evolving and detection rules always have room to improve. See [`CONTRIBUTING.md`](CONTRIBUTING.md). Good first contributions: new detection patterns, additional language/framework coverage, sector-overlay refinements, and false-positive fixes.

## License

MIT — see [`LICENSE`](LICENSE).

---

<div dir="rtl">

## نظرة عامة بالعربية

**فاحص امتثال لنظام حماية البيانات الشخصية السعودي (PDPL)، يدرك نوع الجهة.**

ضعه في خط التكامل المستمر (CI) لأي مشروع ليفحص الكود بحثاً عن مخالفات النظام ويمنع الدمج عند وجودها.
يلتقط ما تعجز عنه أدوات الخصوصية العامة، لأن الامتثال في المملكة ليس كتاباً واحداً: قواعد الاستضافة
والإقامة وطبقات الجهات الرقابية تختلف حسب **من هي الجهة** و**أي بيانات تعالج**. تدفّق بيانات خارج
المملكة قد يكون "صحّح ضماناتك" لشركة خاصة، لكنه **محظور فعلياً** على بنك خاضع لساما أو جهة حكومية. هذه
الأداة تفرّق بينهما.

### ماذا تفعل

تفحص الكود والإعدادات بحثاً عن: تدفّق بيانات خارج المملكة، تشفير معطّل أو غائب، أسرار مضمّنة في الكود،
بيانات شخصية في السجلات، موافقة مفعّلة افتراضياً، تجزئة ضعيفة، غياب وسائل حقوق صاحب البيانات، حذف وهمي،
وعدم وجود مدة احتفاظ. وتعرف المعرّفات السعودية: الهوية الوطنية، الإقامة، الجوال السعودي، الآيبان
السعودي، وأسماء الحقول العربية. وتفصل ما تستطيع إثباته من الكود (نجاح/فشل حقيقي) عن الالتزامات
التنظيمية (التسجيل في سدايا، مسؤول حماية البيانات، سجل المعالجة، تقييم الأثر، إجراء الإخطار خلال ٧٢
ساعة) التي تعرضها كقائمة **تحقق يدوي**، فلا يُفهَم الفحص الأخضر على أنه شهادة امتثال.

### ما ليست عليه

هذا فاحص **للطبقة الهندسية**، وليس شهادة امتثال نظامية، ولا يغني عن التسجيل في سدايا أو تقييم الأثر أو
موافقات الجهات القطاعية أو المراجعة النظامية. الفحص النظيف يعني أن كودك نظيف، لا أن جهتك ممتثلة.

### البدء السريع

```bash
pip install pdpl-scanner
pdpl-scan init        # استبيان نوع الجهة ينشئ ملف pdpl.config.yaml
pdpl-scan .           # فحص باستخدام الملف
pdpl-scan update      # حالة حداثة القواعد وكيفية تحديثها
```

أو عبر GitHub Action: أضف الإجراء في `.github/workflows` فتظهر النتائج في تبويب الأمان وعلى طلبات الدمج،
ويرسب البناء عند وجود مخالفة حرجة.

### نوع الجهة يحدّد الحكم

| الجهة | الإقامة | حكم تدفّق البيانات خارج المملكة |
|---|---|---|
| حكومية / مالية (ساما) / بنية تحتية حساسة | محظور دون موافقة | حرج |
| صحية / اتصالات / مزود سحابي | داخل المملكة افتراضاً | عالٍ |
| خاص عام / غير ربحي | مسموح بضمانات | عالٍ قابل للمعالجة |

وتصنيف بيانات NDMO يشدّد أكثر: أي شيء "سري" فأعلى يبقى داخل المملكة مهما كان نوع الجهة.

### إخلاء المسؤولية والتحديث

**هذه الأداة مساعِدة، وليست بديلاً عن التدقيق اليدوي ولا استشارة نظامية.** أكمل دائماً قائمة التحقق
اليدوي وراجع القرارات الحساسة مع مسؤول حماية البيانات والفريق النظامي. والأنظمة تتغيّر: القواعد محدّثة
حتى التاريخ المسجّل في `pdpl_scanner/_meta.py` والظاهر في كل تقرير. **مسؤوليتك إعادة التحقق دورياً** عبر
`pdpl-scan update` أو بطلب البحث والتحديث من سكيل كلود المرفق. التفاصيل في
[DISCLAIMER.md](DISCLAIMER.md).

</div>
