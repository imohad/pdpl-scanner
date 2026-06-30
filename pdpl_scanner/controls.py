"""
controls.py — the core PDPL control catalog (single source of truth for the engine).

Each control maps a PDPL obligation to a detection mode:
  auto     -> deterministic code pattern; PASS/FAIL with file:line evidence.
  assisted -> partial signal; emitted as WARN, best triaged by the Claude skill.
  manual   -> organizational/legal control with no code signal; always MANUAL-VERIFY.

A YAML mirror of this catalog lives in /controls/pdpl-controls.yaml for humans and customization.
Article references follow the PDPL (M/19 as amended by M/148) and its Implementing Regulations;
treat them as a working map, not the final legal word (the Regulations were under amendment in 2025-26).
"""
from __future__ import annotations

# Controls the scanner asserts from code patterns (see rules.py for the matching signals).
# Fields: id, domain, severity, mode, pdpl_ref, title_en, title_ar, fix_en, fix_ar
CORE_CONTROLS = {
    # --- Legal basis & consent ---
    "PDPL-LB-01": dict(domain="Legal Basis & Consent", severity="critical", mode="assisted",
        pdpl_ref="Arts. 5–7 (lawful basis: consent Art. 5, non-consent bases Art. 6, no-precondition Art. 7)",
        title_en="Personal data written without a consent / legal-basis gate",
        title_ar="حفظ بيانات شخصية دون بوابة موافقة أو أساس نظامي",
        fix_en="Gate every personal-data write on a documented lawful basis; persist legal_basis, purpose, consent_timestamp, consent_version.",
        fix_ar="اربط كل حفظ لبيانات شخصية بأساس نظامي موثّق، واحفظ الأساس والغرض ووقت الموافقة ونسختها."),
    "PDPL-LB-03": dict(domain="Legal Basis & Consent", severity="high", mode="auto",
        pdpl_ref="Art. 5 (consent required) + Art. 7 (consent not a precondition of service)",
        title_en="Pre-ticked / default-on consent",
        title_ar="خانة موافقة مفعّلة افتراضياً",
        fix_en="Default consent inputs to unchecked; block processing when consent is false.",
        fix_ar="اجعل خانات الموافقة غير مفعّلة افتراضياً، وامنع المعالجة عند رفض الموافقة."),
    # --- Data subject rights ---
    "PDPL-DSR-01": dict(domain="Data Subject Rights", severity="high", mode="assisted",
        pdpl_ref="Arts. 4, 9 (access & portability)",
        title_en="No data-access / export path for data subjects",
        title_ar="لا توجد وسيلة وصول/تصدير لبيانات صاحب البيانات",
        fix_en="Add an authenticated self-service export returning the subject's data in JSON/CSV.",
        fix_ar="أضف تصديراً ذاتياً موثّقاً يُرجع بيانات صاحب البيانات بصيغة قابلة للقراءة آلياً."),
    "PDPL-DSR-02": dict(domain="Data Subject Rights", severity="high", mode="assisted",
        pdpl_ref="Arts. 4, 18 (erasure)",
        title_en="Erasure is soft-flag only (PII retained indefinitely)",
        title_ar="الحذف مجرد علامة منطقية مع بقاء البيانات",
        fix_en="Implement hard delete or irreversible anonymization across stores, caches, and backups policy; document lawful retention exceptions.",
        fix_ar="طبّق حذفاً فعلياً أو إخفاء هوية لا رجعة فيه عبر المخازن والكاش والنسخ، مع توثيق استثناءات الاحتفاظ."),
    # --- Cross-border (severity is overridden by entity profile at runtime) ---
    "PDPL-CB-01": dict(domain="Cross-Border Transfer", severity="critical", mode="auto",
        pdpl_ref="Art. 29 + Transfer Regulations + Risk Assessment Guideline",
        title_en="Personal data flows to a non-KSA region/endpoint",
        title_ar="تدفّق بيانات شخصية إلى منطقة/وجهة خارج المملكة",
        fix_en="Confirm a lawful transfer basis + safeguard (SCCs/adequacy/exception), run a transfer risk assessment, minimize the payload, prefer in-Kingdom hosting.",
        fix_ar="تأكد من أساس نقل وضمانة (بنود تعاقدية معيارية/كفاية/استثناء)، نفّذ تقييم مخاطر نقل، قلّل الحمولة، وفضّل الاستضافة داخل المملكة."),
    "PDPL-CB-02": dict(domain="Cross-Border Transfer", severity="critical", mode="auto",
        pdpl_ref="Art. 29 + Transfer Regulations (processors abroad)",
        title_en="Personal data sent to a foreign third-party processor (SaaS/analytics/email/AI)",
        title_ar="إرسال بيانات شخصية إلى معالِج خارجي أجنبي (خدمة سحابية/تحليلات/بريد/ذكاء اصطناعي)",
        fix_en="Treat third-party SaaS that receives personal data as a cross-border transfer: confirm a lawful basis + safeguard, sign a DPA, minimize/anonymize the payload, and prefer an in-Kingdom or adequacy-listed provider.",
        fix_ar="عامل أي خدمة خارجية تستقبل بيانات شخصية كنقل خارج المملكة: تأكد من أساس نظامي وضمانة، ووقّع اتفاقية معالجة، وقلّل أو أخفِ الحمولة، وفضّل مزوّداً داخل المملكة أو ضمن قائمة الكفاية."),
    # --- Security safeguards ---
    "PDPL-SEC-01": dict(domain="Security Safeguards", severity="critical", mode="auto",
        pdpl_ref="Art. 19 (technical & organizational measures)",
        title_en="TLS verification disabled / plaintext transport of personal data",
        title_ar="تعطيل التحقق من TLS أو نقل بيانات شخصية بدون تشفير",
        fix_en="Enforce TLS 1.2+ on every channel carrying personal data; never disable certificate verification.",
        fix_ar="افرض TLS 1.2 فأعلى على كل قناة تحمل بيانات شخصية، ولا تعطّل التحقق من الشهادات."),
    "PDPL-SEC-02": dict(domain="Security Safeguards", severity="high", mode="auto",
        pdpl_ref="Art. 19 (encryption in transit)",
        title_en="Database / transport TLS disabled (e.g. sslmode=disable)",
        title_ar="تعطيل تشفير النقل لقاعدة البيانات (مثل sslmode=disable)",
        fix_en="Enable TLS on the database/service connection (sslmode=require/verify-full) so personal data is not carried in plaintext between services.",
        fix_ar="فعّل تشفير النقل على اتصال قاعدة البيانات/الخدمة (sslmode=require/verify-full) حتى لا تُنقل البيانات الشخصية بدون تشفير بين الخدمات."),
    "PDPL-SEC-03": dict(domain="Security Safeguards", severity="critical", mode="auto",
        pdpl_ref="Art. 19 (safeguards against unauthorized access)",
        title_en="Hardcoded secret / credential in source",
        title_ar="سر أو بيانات اعتماد مضمّنة في الكود",
        fix_en="Move secrets to a managed secret store / env injection; rotate any exposed credential immediately.",
        fix_ar="انقل الأسرار إلى مخزن أسرار مُدار/حقن بيئة، وبدّل أي بيانات اعتماد مكشوفة فوراً."),
    "PDPL-SEC-05": dict(domain="Security Safeguards", severity="high", mode="auto",
        pdpl_ref="Art. 19",
        title_en="Weak hashing (MD5/SHA1) for credentials",
        title_ar="تجزئة ضعيفة (MD5/SHA1) لكلمات المرور",
        fix_en="Use bcrypt/scrypt/argon2 with a per-user salt.",
        fix_ar="استخدم bcrypt أو scrypt أو argon2 مع ملح لكل مستخدم."),
    # --- Logging & exposure ---
    "PDPL-LOG-01": dict(domain="Logging & Exposure", severity="high", mode="auto",
        pdpl_ref="Art. 19 + minimization",
        title_en="Personal/sensitive data written to logs",
        title_ar="تسجيل بيانات شخصية/حساسة في السجلات",
        fix_en="Redact/mask personal data in logs; never log secrets or sensitive identifiers; scrub error payloads.",
        fix_ar="أخفِ/قنّع البيانات الشخصية في السجلات، ولا تسجّل الأسرار أو المعرفات الحساسة، ونظّف رسائل الأخطاء."),
    # --- Sensitive data ---
    "PDPL-SEN-01": dict(domain="Sensitive Personal Data", severity="critical", mode="assisted",
        pdpl_ref="Art. 1 (definition) + elevated safeguards",
        title_en="Sensitive data without elevated handling",
        title_ar="بيانات حساسة دون معالجة مشددة",
        fix_en="Apply encryption, least-privilege access, minimization, and a documented transfer basis to every sensitive field; trigger a DPIA for large-scale/high-risk processing.",
        fix_ar="طبّق التشفير والوصول الأدنى والتقليل وأساس نقل موثّق على كل حقل حساس، وفعّل تقييم أثر للمعالجة واسعة النطاق."),
    # --- Retention ---
    "PDPL-RET-01": dict(domain="Retention & Deletion", severity="medium", mode="assisted",
        pdpl_ref="Art. 18 (destroy when purpose ends)",
        title_en="No retention limit / purge logic on personal-data stores",
        title_ar="لا توجد مدة احتفاظ أو حذف آلي لمخازن البيانات الشخصية",
        fix_en="Define a retention period per dataset and implement automated expiry/purge once the purpose ends.",
        fix_ar="حدّد مدة احتفاظ لكل مجموعة بيانات، ونفّذ حذفاً آلياً عند انتهاء الغرض."),
}

# Organizational controls the scanner cannot prove from code. Always reported as MANUAL-VERIFY.
# Some are gated on the entity profile (see scanner.py).
MANUAL_CONTROLS = {
    "PDPL-GOV-02": dict(domain="Governance & Records", severity="medium",
        pdpl_ref="Art. 31 + RoPA Guideline",
        title_en="Record of Processing Activities (RoPA) maintained and retained",
        title_ar="سجل أنشطة المعالجة محفوظ ومحدّث",
        note_en="RoPA covers purposes, data categories, recipients, cross-border arrangements, retention, and security measures; produced to SDAIA on request.",
        note_ar="يشمل السجل الأغراض وفئات البيانات والمستلمين وترتيبات النقل والاحتفاظ والتدابير الأمنية."),
    "PDPL-GOV-03": dict(domain="Governance & Records", severity="high",
        pdpl_ref="Controller registration rules",
        title_en="Controller registration on the National Data Governance Platform",
        title_ar="تسجيل جهة التحكم في منصة الحوكمة الوطنية للبيانات",
        note_en="Triggered by public entity, primary processing, sensitive data, cross-border, or data of those lacking legal capacity.",
        note_ar="يُفعّل بكون الجهة عامة أو المعالجة نشاطاً رئيسياً أو وجود بيانات حساسة أو نقل خارجي."),
    "PDPL-GOV-04": dict(domain="Governance & Records", severity="medium",
        pdpl_ref="DPO appointment rules",
        title_en="Data Protection Officer appointed and registered where required",
        title_ar="تعيين مسؤول حماية البيانات وتسجيله عند اللزوم",
        note_en="Required for public entities, large-scale sensitive processing, cross-border, or processing children/vulnerable data.",
        note_ar="مطلوب للجهات العامة والمعالجة الحساسة واسعة النطاق والنقل الخارجي وبيانات الأطفال."),
    "PDPL-GOV-05": dict(domain="Governance & Records", severity="medium",
        pdpl_ref="Controller-processor obligations",
        title_en="Processor agreements (DPAs) in place with breach, deletion, and audit terms",
        title_ar="اتفاقيات معالجة مع المعالجين تتضمن الاختراق والحذف والتدقيق",
        note_en="Controllers remain liable for processors; contracts must reflect breach notice and sub-processing controls.",
        note_ar="تبقى مسؤولية جهة التحكم قائمة، وتعكس العقود التبليغ عن الاختراق وضوابط المعالجة الفرعية."),
    "PDPL-GOV-06": dict(domain="Governance & Records", severity="medium",
        pdpl_ref="Implementing Regs (impact assessment)",
        title_en="DPIA completed for high-risk / large-scale / sensitive processing",
        title_ar="تقييم أثر حماية البيانات للمعالجة عالية الخطورة",
        note_en="Documents risks and mitigations before processing begins.",
        note_ar="يوثّق المخاطر والتدابير قبل بدء المعالجة."),
    "PDPL-BR-01": dict(domain="Breach Notification", severity="high",
        pdpl_ref="Art. 20 + Art. 24 Implementing Regs + Breach Procedural Guide",
        title_en="72-hour breach notification runbook to SDAIA (and affected subjects where harm is likely)",
        title_ar="إجراء التبليغ عن الاختراق خلال ٧٢ ساعة لسدايا (وأصحاب البيانات عند احتمال الضرر)",
        note_en="No materiality threshold: notify SDAIA within 72 hours of awareness, with details and mitigations.",
        note_ar="لا يوجد حد أدنى: بلّغ سدايا خلال ٧٢ ساعة من العلم مع التفاصيل والتدابير."),
    "PDPL-GOV-07": dict(domain="Transparency", severity="medium",
        pdpl_ref="Art. 12 (transparency at collection)",
        title_en="Privacy notice present, accessible, and complete at the point of collection",
        title_ar="إشعار خصوصية واضح ومتاح وكامل عند جمع البيانات",
        note_en="States purpose, legal basis, recipients, transfers, retention, and data-subject rights.",
        note_ar="يوضّح الغرض والأساس والمستلمين والنقل والاحتفاظ وحقوق صاحب البيانات."),
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DEFAULT_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1}
