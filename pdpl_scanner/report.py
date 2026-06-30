"""
report.py — output formats.

Three artifacts:
  json     -> machine-readable, for dashboards and gating.
  markdown -> bilingual (Arabic RTL + English), verdict-first human report.
  sarif    -> SARIF 2.1.0 so GitHub code scanning shows findings inline on PRs and in the Security tab.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import List

from .scanner import ScanResult
from .entity_profiles import CLASSIFICATION
from . import _meta

REG_LINE = "Saudi PDPL (Royal Decree M/19, amended by M/148) + Implementing Regulations + sector overlays"
TOOL_VERSION = "1.0.0"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_json(res: ScanResult) -> dict:
    p = res.profile
    return {
        "scan": {
            "tool": "pdpl-scanner", "version": TOOL_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": res.target, "files_scanned": res.files_scanned,
            "regulation": REG_LINE,
            "rules_last_updated": _meta.RULES_LAST_UPDATED,
            "rules_stale": _meta.is_stale(),
            "freshness_note": _meta.freshness_note_en(),
        },
        "entity": {
            "type": p.type, "data_classification": p.data_classification,
            "residency_posture": p.residency, "overlays": p.overlays,
            "dpo_required": p.dpo_required, "registration_required": p.registration_required,
            "dpia_required": p.dpia_required,
        },
        "summary": {
            "score": res.score, "gate": res.gate,
            "total_findings": len(res.findings),
            "fail": sum(1 for f in res.findings if f.status == "fail"),
            "warn": sum(1 for f in res.findings if f.status == "warn"),
            "manual": len(res.manual),
            "by_severity": res.by_severity,
        },
        "findings": [f.to_dict() for f in res.findings],
        "manual_verify": res.manual,
        "note": ("Engineering-layer scan. Not a legal certification. Manual-verify controls are real "
                 "obligations to confirm with your DPO/legal."),
    }


def to_sarif(res: ScanResult) -> dict:
    rule_ids, rules, results = set(), [], []
    for f in res.findings:
        d = f.to_dict()
        if f.control not in rule_ids:
            rule_ids.add(f.control)
            rules.append({
                "id": f.control,
                "name": f.control.replace("-", ""),
                "shortDescription": {"text": d["title_en"] or f.control},
                "fullDescription": {"text": f"{d['title_en']} | PDPL: {d['pdpl_ref']}"},
                "helpUri": "https://sdaia.gov.sa/en/SDAIA/about/Pages/RegulationsAndPolicies.aspx",
                "properties": {"severity": f.severity, "pdpl_ref": d["pdpl_ref"]},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(f.severity, "warning")},
            })
        results.append({
            "ruleId": f.control,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"[{f.severity.upper()}] {d['title_en']}. Fix: {d['fix_en']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(1, f.line),
                               "snippet": {"text": f.snippet}},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pdpl-scanner", "version": TOOL_VERSION,
                "informationUri": "https://github.com/imohad/pdpl-scanner",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def _sev_emoji(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}.get(sev, "•")


def to_markdown(res: ScanResult) -> str:
    p = res.profile
    gate_badge = "✅ PASS" if res.gate == "pass" else "❌ FAIL"
    bs = res.by_severity
    L: List[str] = []

    # English section
    L.append(f"# PDPL Compliance Scan — `{res.target.split('/')[-1] or res.target}`")
    L.append(f"**Gate:** {gate_badge}  |  **Score:** {res.score}/100  |  "
             f"**Entity:** {p.type}  |  **Classification:** {p.data_classification}  |  "
             f"**Files:** {res.files_scanned}")
    L.append("")
    fails = [f for f in res.findings if f.status == "fail"]
    if res.gate == "pass" and not fails:
        L.append("## Verdict\nNo gate-blocking findings in the engineering layer. "
                 "Complete the manual-verify checklist below before claiming compliance.")
    else:
        crit = bs.get("critical", 0); high = bs.get("high", 0)
        L.append(f"## Verdict\nFails the gate on {crit} critical and {high} high finding(s). "
                 "Address the items below, then re-run.")
    L.append("")
    L.append(f"**Residency posture for this entity:** {p.residency}. "
             f"{CLASSIFICATION.get(p.data_classification, '')}")
    L.append("")
    L.append("## Summary")
    L.append("| Severity | Findings |")
    L.append("|---|---|")
    for sev in ("critical", "high", "medium", "low"):
        L.append(f"| {_sev_emoji(sev)} {sev.capitalize()} | {bs.get(sev, 0)} |")
    L.append(f"| Manual-verify | {len(res.manual)} |")
    L.append("")

    if res.findings:
        L.append("## Findings (ranked)")
        for f in res.findings:
            d = f.to_dict()
            mark = "❌" if f.status == "fail" else "⚠️"
            L.append(f"### {mark} [{f.severity.upper()}] {f.control} — {d['title_en']}")
            L.append(f"- **Where:** `{f.file}:{f.line}`")
            if f.snippet:
                L.append(f"- **Evidence:** `{f.snippet[:120]}`")
            L.append(f"- **PDPL:** {d['pdpl_ref']}")
            L.append(f"- **Fix:** {f.note or d['fix_en']}")
            L.append("")

    L.append("## Manual verification required (not code-detectable)")
    L.append("Real PDPL obligations the scanner cannot prove from code. Confirm with your DPO/legal:")
    for m in res.manual:
        L.append(f"- [ ] **{m['control']}** — {m['title_en']}  _(PDPL: {m['pdpl_ref']})_")
    L.append("")
    L.append("## Scope & limits")
    L.append("This scan covers the engineering layer of PDPL (technical and organizational safeguards "
             "detectable in code and config). It is **not a legal certification** and does not replace "
             "SDAIA registration, a DPIA, sector approvals (SAMA/CST/NCA/NDMO), or legal review.")
    L.append("")
    L.append(f"> **Rule freshness:** {_meta.freshness_note_en()}")
    L.append("")
    L.append("---")
    L.append("")

    # Arabic section (RTL)
    L.append("<div dir=\"rtl\">")
    L.append("")
    L.append(f"# فحص الامتثال لنظام حماية البيانات الشخصية — `{res.target.split('/')[-1] or res.target}`")
    L.append(f"**البوابة:** {'✅ ناجح' if res.gate=='pass' else '❌ راسب'}  |  "
             f"**الدرجة:** {res.score}/100  |  **نوع الجهة:** {p.type}  |  "
             f"**التصنيف:** {p.data_classification}")
    L.append("")
    if res.gate == "pass" and not fails:
        L.append("## الحكم\nلا توجد ملاحظات تكسر البوابة في الطبقة الهندسية. "
                 "أكمل قائمة التحقق اليدوي أدناه قبل ادعاء الامتثال.")
    else:
        L.append(f"## الحكم\nيرسب في البوابة بسبب {bs.get('critical',0)} ملاحظة حرجة و"
                 f"{bs.get('high',0)} عالية. عالج البنود ثم أعد الفحص.")
    L.append("")
    if res.findings:
        L.append("## الملاحظات (مرتبة)")
        for f in res.findings:
            d = f.to_dict()
            mark = "❌" if f.status == "fail" else "⚠️"
            L.append(f"### {mark} [{f.severity.upper()}] {f.control} — {d['title_ar']}")
            L.append(f"- **الموضع:** `{f.file}:{f.line}`")
            L.append(f"- **المرجع النظامي:** {d['pdpl_ref']}")
            L.append(f"- **الإصلاح:** {profile_fix_ar(f, d)}")
            L.append("")
    L.append("## تحقّق يدوي مطلوب (لا يُكشف من الكود)")
    for m in res.manual:
        L.append(f"- [ ] **{m['control']}** — {m['title_ar']}")
    L.append("")
    L.append("## النطاق والحدود")
    L.append("يغطي هذا الفحص الطبقة الهندسية من النظام، وليس شهادة امتثال نظامية، ولا يغني عن التسجيل "
             "في سدايا أو تقييم الأثر أو موافقات الجهات القطاعية (ساما/هيئة الاتصالات/الأمن السيبراني/NDMO).")
    L.append("")
    L.append(f"> **حداثة القواعد:** {_meta.freshness_note_ar()}")
    L.append("")
    L.append("</div>")
    return "\n".join(L)


def profile_fix_ar(f, d) -> str:
    # cross-border uses the entity-aware Arabic remediation when available
    if f.control == "PDPL-CB-01" and f.note_ar:
        return f.note_ar
    return d.get("fix_ar", "")
