# PDPL Compliance Scan — `sample_app`
**Gate:** ❌ FAIL  |  **Score:** 5/100  |  **Entity:** financial  |  **Classification:** confidential  |  **Files:** 3

## Verdict
Fails the gate on 3 critical and 2 high finding(s). Address the items below, then re-run.

**Residency posture for this entity:** prohibited_without_approval. Level 2 — in-Kingdom by default; cross-border only under PDPL + CCRF conditions.

## Summary
| Severity | Findings |
|---|---|
| 🔴 Critical | 3 |
| 🟠 High | 2 |
| 🟡 Medium | 0 |
| ⚪ Low | 0 |
| Manual-verify | 9 |

## Findings (ranked)
### ❌ [CRITICAL] PDPL-CB-01 — Personal data flows to a non-KSA region/endpoint
- **Where:** `api.js:6`
- **Evidence:** `const config = { region: 'eu-west-1', db: 'patient_records' };  // cross-border`
- **PDPL:** Art. 29 + Transfer Regulations + Risk Assessment Guideline
- **Fix:** This data must remain in-Kingdom. Cross-border requires the competent regulator's approval (SAMA for financial entities / NDMO classification for government). Host in-Kingdom with a licensed provider.

### ❌ [CRITICAL] PDPL-SEC-03 — Hardcoded secret / credential in source
- **Where:** `api.js:7`
- **Evidence:** `const apiKey = "sk_live_abc123def456ghijklmnop";    // hardcoded secret`
- **PDPL:** Art. 19 (safeguards against unauthorized access)
- **Fix:** Move secrets to a managed secret store / env injection; rotate any exposed credential immediately.

### ❌ [CRITICAL] PDPL-SEC-01 — TLS verification disabled / plaintext transport of personal data
- **Where:** `api.js:8`
- **Evidence:** `axios.get(url, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });`
- **PDPL:** Art. 19 (technical & organizational measures)
- **Fix:** Enforce TLS 1.2+ on every channel carrying personal data; never disable certificate verification.

### ❌ [HIGH] PDPL-LB-03 — Pre-ticked / default-on consent
- **Where:** `signup.jsx:1`
- **Evidence:** `<input type="checkbox" name="consent" defaultChecked={true} />`
- **PDPL:** Art. 6 (free, affirmative consent)
- **Fix:** Default consent inputs to unchecked; block processing when consent is false.

### ❌ [HIGH] PDPL-LOG-01 — Personal/sensitive data written to logs
- **Where:** `api.js:4`
- **Evidence:** `console.log("login", userNationalId, user.phone);   // PII in logs`
- **PDPL:** Art. 19 + minimization
- **Fix:** Redact/mask personal data in logs; never log secrets or sensitive identifiers; scrub error payloads.

## Manual verification required (not code-detectable)
Real PDPL obligations the scanner cannot prove from code. Confirm with your DPO/legal:
- [ ] **PDPL-GOV-02** — Record of Processing Activities (RoPA) maintained and retained  _(PDPL: Art. 31 + RoPA Guideline)_
- [ ] **PDPL-GOV-07** — Privacy notice present, accessible, and complete at the point of collection  _(PDPL: Art. 12 (transparency at collection))_
- [ ] **PDPL-BR-01** — 72-hour breach notification runbook to SDAIA (and affected subjects where harm is likely)  _(PDPL: Art. 20 + Art. 24 Implementing Regs + Breach Procedural Guide)_
- [ ] **PDPL-GOV-05** — Processor agreements (DPAs) in place with breach, deletion, and audit terms  _(PDPL: Controller-processor obligations)_
- [ ] **PDPL-GOV-04** — Data Protection Officer appointed and registered where required  _(PDPL: DPO appointment rules)_
- [ ] **SAMA-CLOUD-01** — SAMA approval obtained before using cloud services; explicit approval for any cloud outside the Kingdom  _(PDPL: SAMA Cloud Computing Regulatory Framework)_
- [ ] **SAMA-RESID-01** — Highly sensitive customer/financial data resides in-Kingdom with in-Kingdom key management  _(PDPL: SAMA CCRF / Cyber Security Framework)_
- [ ] **SAMA-OUT-01** — Material outsourcing register maintained; SAMA no-objection for material outsourcing abroad  _(PDPL: SAMA Rules on Outsourcing)_
- [ ] **NCA-ECC-01** — Information hosting and storage inside the Kingdom (NCA ECC 4.2.3.3)  _(PDPL: NCA Essential Cybersecurity Controls)_

## Scope & limits
This scan covers the engineering layer of PDPL (technical and organizational safeguards detectable in code and config). It is **not a legal certification** and does not replace SDAIA registration, a DPIA, sector approvals (SAMA/CST/NCA/NDMO), or legal review.

> **Rule freshness:** Compliance rules current as of 2026-06-30 (0 days ago). Saudi data-protection rules change; re-verify periodically.

---

<div dir="rtl">

# فحص الامتثال لنظام حماية البيانات الشخصية — `sample_app`
**البوابة:** ❌ راسب  |  **الدرجة:** 5/100  |  **نوع الجهة:** financial  |  **التصنيف:** confidential

## الحكم
يرسب في البوابة بسبب 3 ملاحظة حرجة و2 عالية. عالج البنود ثم أعد الفحص.

## الملاحظات (مرتبة)
### ❌ [CRITICAL] PDPL-CB-01 — تدفّق بيانات شخصية إلى منطقة/وجهة خارج المملكة
- **الموضع:** `api.js:6`
- **المرجع النظامي:** Art. 29 + Transfer Regulations + Risk Assessment Guideline
- **الإصلاح:** هذه البيانات يجب أن تبقى داخل المملكة. النقل خارجها يتطلب موافقة الجهة الرقابية المختصة (ساما للجهات المالية / تصنيف NDMO للجهات الحكومية). استضف داخل المملكة لدى مزوّد مرخّص.

### ❌ [CRITICAL] PDPL-SEC-03 — سر أو بيانات اعتماد مضمّنة في الكود
- **الموضع:** `api.js:7`
- **المرجع النظامي:** Art. 19 (safeguards against unauthorized access)
- **الإصلاح:** انقل الأسرار إلى مخزن أسرار مُدار/حقن بيئة، وبدّل أي بيانات اعتماد مكشوفة فوراً.

### ❌ [CRITICAL] PDPL-SEC-01 — تعطيل التحقق من TLS أو نقل بيانات شخصية بدون تشفير
- **الموضع:** `api.js:8`
- **المرجع النظامي:** Art. 19 (technical & organizational measures)
- **الإصلاح:** افرض TLS 1.2 فأعلى على كل قناة تحمل بيانات شخصية، ولا تعطّل التحقق من الشهادات.

### ❌ [HIGH] PDPL-LB-03 — خانة موافقة مفعّلة افتراضياً
- **الموضع:** `signup.jsx:1`
- **المرجع النظامي:** Art. 6 (free, affirmative consent)
- **الإصلاح:** اجعل خانات الموافقة غير مفعّلة افتراضياً، وامنع المعالجة عند رفض الموافقة.

### ❌ [HIGH] PDPL-LOG-01 — تسجيل بيانات شخصية/حساسة في السجلات
- **الموضع:** `api.js:4`
- **المرجع النظامي:** Art. 19 + minimization
- **الإصلاح:** أخفِ/قنّع البيانات الشخصية في السجلات، ولا تسجّل الأسرار أو المعرفات الحساسة، ونظّف رسائل الأخطاء.

## تحقّق يدوي مطلوب (لا يُكشف من الكود)
- [ ] **PDPL-GOV-02** — سجل أنشطة المعالجة محفوظ ومحدّث
- [ ] **PDPL-GOV-07** — إشعار خصوصية واضح ومتاح وكامل عند جمع البيانات
- [ ] **PDPL-BR-01** — إجراء التبليغ عن الاختراق خلال ٧٢ ساعة لسدايا (وأصحاب البيانات عند احتمال الضرر)
- [ ] **PDPL-GOV-05** — اتفاقيات معالجة مع المعالجين تتضمن الاختراق والحذف والتدقيق
- [ ] **PDPL-GOV-04** — تعيين مسؤول حماية البيانات وتسجيله عند اللزوم
- [ ] **SAMA-CLOUD-01** — الحصول على موافقة ساما قبل استخدام الخدمات السحابية، وموافقة صريحة لأي سحابة خارج المملكة
- [ ] **SAMA-RESID-01** — بقاء بيانات العملاء/المالية الحساسة داخل المملكة مع إدارة مفاتيح داخل المملكة
- [ ] **SAMA-OUT-01** — سجل إسناد جوهري، وعدم ممانعة من ساما للإسناد الجوهري للخارج
- [ ] **NCA-ECC-01** — استضافة وتخزين المعلومات داخل المملكة (ضوابط الأمن السيبراني الأساسية 4.2.3.3)

## النطاق والحدود
يغطي هذا الفحص الطبقة الهندسية من النظام، وليس شهادة امتثال نظامية، ولا يغني عن التسجيل في سدايا أو تقييم الأثر أو موافقات الجهات القطاعية (ساما/هيئة الاتصالات/الأمن السيبراني/NDMO).

> **حداثة القواعد:** قواعد الامتثال محدّثة حتى 2026-06-30 (قبل 0 يوماً). أنظمة حماية البيانات في المملكة تتغيّر، فأعد التحقق دورياً.

</div>