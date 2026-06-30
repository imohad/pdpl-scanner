# Disclaimer / إخلاء مسؤولية

## English

**This tool is an aid, not a substitute for manual review or legal advice.**

`pdpl-scanner` helps engineering and compliance teams detect technical issues related to Saudi
Arabia's Personal Data Protection Law (PDPL) and surface the organizational obligations that apply to
an entity. It does **not**, and **cannot**:

- Certify that your organization is compliant with the PDPL or any sector regulation.
- Replace a manual review by a qualified Data Protection Officer (DPO) or legal counsel.
- Replace SDAIA registration, a Data Protection Impact Assessment (DPIA), a Record of Processing
  Activities (RoPA), or sector approvals (SAMA, CST, NCA, NDMO, health authorities).
- Detect every violation. It is high-recall on the patterns it knows and silent on everything else.

A green/passing scan means the engineering layer is clean of the issues this tool checks. It does
**not** mean your organization is compliant. Always complete the manual-verify checklist and confirm
high-stakes decisions with your DPO and legal team.

**Rules change. Keep them current.** PDPL and its sector overlays are evolving. The Implementing
Regulations were under amendment through 2025-2026, and SDAIA, NDMO, CST, NCA, SAMA, and the health
authorities issue updates. The rules in this repository were last reviewed on the date recorded in
`pdpl_scanner/_meta.py` (`RULES_LAST_UPDATED`) and shown in every report. **You are responsible for
re-verifying compliance periodically.** Run `pdpl-scan update`, or ask the bundled Claude skill to
research the latest changes and refresh the rules, then bump the date.

This software is provided "as is" under the MIT license, without warranty of any kind. The authors and
contributors accept no liability for any decision made on the basis of its output. **It does not
constitute legal advice.**

---

<div dir="rtl">

## العربية

**هذه الأداة مساعِدة، وليست بديلاً عن التدقيق اليدوي أو الاستشارة النظامية.**

تساعد `pdpl-scanner` فرق الهندسة والامتثال على اكتشاف المشكلات التقنية المتعلقة بنظام حماية البيانات
الشخصية في المملكة العربية السعودية، وإبراز الالتزامات التنظيمية التي تنطبق على الجهة. لكنها **لا**
تستطيع، و**لا** ينبغي اعتمادها على أنها:

- شهادة بأن جهتك ممتثلة للنظام أو لأي لائحة قطاعية.
- بديل عن تدقيق يدوي يجريه مسؤول حماية بيانات مؤهل أو مستشار نظامي.
- بديل عن التسجيل في سدايا، أو تقييم أثر حماية البيانات، أو سجل أنشطة المعالجة، أو موافقات الجهات
  القطاعية (ساما، هيئة الاتصالات، الأمن السيبراني، NDMO، الجهات الصحية).
- كاشفة لكل مخالفة. فهي عالية الالتقاط لما تعرفه من أنماط، وصامتة عمّا سواها.

نجاح الفحص يعني أن الطبقة الهندسية خالية من المشكلات التي تفحصها هذه الأداة، ولا يعني أن جهتك ممتثلة.
أكمل دائماً قائمة التحقق اليدوي، وتأكد من القرارات الحساسة مع مسؤول حماية البيانات والفريق النظامي.

**الأنظمة تتغيّر، فأبقِها محدّثة.** نظام حماية البيانات وأطره القطاعية في تطوّر مستمر. اللائحة التنفيذية
كانت قيد التعديل خلال 2025 و2026، وتصدر سدايا وNDMO وهيئة الاتصالات والأمن السيبراني وساما والجهات
الصحية تحديثات. القواعد في هذا المستودع روجعت آخر مرة بالتاريخ المسجّل في `pdpl_scanner/_meta.py`
والظاهر في كل تقرير. **تقع على عاتقك مسؤولية إعادة التحقق من الامتثال دورياً.** شغّل `pdpl-scan update`،
أو اطلب من سكيل كلود المرفق البحث عن آخر التغييرات وتحديث القواعد، ثم حدّث التاريخ.

يُقدَّم هذا البرنامج "كما هو" بموجب رخصة MIT دون أي ضمان. ولا يتحمّل المؤلفون والمساهمون أي مسؤولية عن
أي قرار يُتخذ بناءً على مخرجاته. **وهو لا يُعدّ استشارة نظامية.**

</div>
