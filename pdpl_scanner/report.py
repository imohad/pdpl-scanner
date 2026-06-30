"""
report.py — output formats.

Three artifacts:
  json     -> machine-readable, for dashboards and gating.
  markdown -> bilingual (Arabic RTL + English), verdict-first human report.
  sarif    -> SARIF 2.1.0 so GitHub code scanning shows findings inline on PRs and in the Security tab.
"""
from __future__ import annotations
import hashlib
import html as _html
import json
from datetime import datetime, timezone
from typing import List

from .scanner import ScanResult
from .entity_profiles import CLASSIFICATION
from . import _meta

REG_LINE = "Saudi PDPL (Royal Decree M/19, amended by M/148) + Implementing Regulations + sector overlays"
TOOL_VERSION = "1.1.0"
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
        "passed_controls": list(res.passed_controls),
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
        uri = f.file or ".pdpl/repository"   # repo-level leads have no file:line
        fingerprint = hashlib.sha256(
            f"{f.control}|{uri}|{f.snippet or d['title_en']}".encode("utf-8")).hexdigest()[:16]
        results.append({
            "ruleId": f.control,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"[{f.severity.upper()}] {d['title_en']}. "
                                f"Fix: {f.note or d['fix_en']}"},
            "partialFingerprints": {"pdplFindingHash/v1": fingerprint},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
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
    leads = [f for f in res.findings if f.status == "warn"]
    crit_fail = sum(1 for f in fails if f.severity == "critical")
    high_fail = sum(1 for f in fails if f.severity == "high")
    if res.gate == "pass":
        L.append("## Verdict\nNo gate-blocking findings in the engineering layer"
                 + (f" ({len(leads)} assisted lead(s) to triage)." if leads else ".")
                 + " Complete the manual-verify checklist below before claiming compliance.")
    else:
        L.append(f"## Verdict\nFails the gate on {crit_fail} critical and {high_fail} high "
                 f"confirmed finding(s)"
                 + (f", plus {len(leads)} assisted lead(s) to triage" if leads else "")
                 + ". Address the items below, then re-run.")
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
    if res.passed_controls:
        L.append(f"**Auto-checks passed ({len(res.passed_controls)}):** "
                 + ", ".join(f"`{c}`" for c in res.passed_controls))
        L.append("")

    if res.findings:
        L.append("## Findings (ranked)")
        L.append("`FAIL` = confirmed auto finding · `LEAD` = assisted, triage in context.")
        L.append("")
        for f in res.findings:
            d = f.to_dict()
            mark = "❌ FAIL" if f.status == "fail" else "⚠️ LEAD"
            L.append(f"### {mark} · [{f.severity.upper()}] {f.control} — {d['title_en']}")
            L.append(f"- **Where:** {_loc_en(f)}")
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
        L.append("`FAIL` = ملاحظة مؤكدة · `LEAD` = إشارة تحتاج مراجعة بشرية في السياق.")
        L.append("")
        for f in res.findings:
            d = f.to_dict()
            mark = "❌ FAIL" if f.status == "fail" else "⚠️ LEAD"
            L.append(f"### {mark} · [{f.severity.upper()}] {f.control} — {d['title_ar']}")
            L.append(f"- **الموضع:** {_loc_ar(f)}")
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
    # entity-aware / assisted findings carry their own Arabic remediation when available
    return f.note_ar or d.get("fix_ar", "")


def _loc_en(f) -> str:
    return f"`{f.file}:{f.line}`" if f.file else "_repository-wide_"


def _loc_ar(f) -> str:
    return f"`{f.file}:{f.line}`" if f.file else "_على مستوى المستودع_"


# --- Standalone bilingual HTML report ----------------------------------------

_HTML_STYLE = """
:root{--bg:#0f1419;--card:#1a2230;--ink:#e6edf3;--muted:#9bb0c3;--line:#26313f;
--crit:#ff5c5c;--high:#ff9f43;--med:#ffd24a;--low:#8fb4ff;--ok:#3ecf8e;--ksa:#1c7c54}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 -apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial,"Noto Sans Arabic",sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:32px 20px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.meta{color:var(--muted);font-size:13px;margin-bottom:18px}
.gate{display:inline-block;padding:5px 14px;border-radius:999px;font-weight:700}
.gate.pass{background:rgba(62,207,142,.15);color:var(--ok)}
.gate.fail{background:rgba(255,92,92,.15);color:var(--crit)}
.kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:96px}
.kpi b{display:block;font-size:22px}.kpi span{color:var(--muted);font-size:12px}
.f{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:12px 16px;margin:10px 0}
.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}
.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}
.tag{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;letter-spacing:.04em}
.tag.fail{background:rgba(255,92,92,.15);color:var(--crit)}.tag.lead{background:rgba(255,210,74,.15);color:var(--med)}
.where{color:var(--muted);font-size:13px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
code{background:#0b0f14;border:1px solid var(--line);border-radius:5px;padding:1px 6px;font-size:13px}
.ev{display:block;margin:6px 0;color:#c8d6e5;overflow-wrap:anywhere}
.manual li{margin:4px 0}.passed{color:var(--ok);font-size:13px}
.rtl{direction:rtl;text-align:right;border-top:2px solid var(--line);margin-top:36px;padding-top:8px}
.disclaimer{background:rgba(255,159,67,.08);border:1px solid rgba(255,159,67,.3);border-radius:10px;padding:12px 16px;margin:18px 0;font-size:13px;color:#ffd9b0}
"""


def _f_block(f, lang: str) -> str:
    d = f.to_dict()
    title = d["title_ar"] if lang == "ar" else d["title_en"]
    tag = ("fail", "FAIL") if f.status == "fail" else ("lead", "LEAD")
    where = (f"{_html.escape(f.file)}:{f.line}" if f.file
             else ("على مستوى المستودع" if lang == "ar" else "repository-wide"))
    fix = (f.note_ar or d["fix_ar"]) if lang == "ar" else (f.note or d["fix_en"])
    ev = f'<code class="ev">{_html.escape(f.snippet[:160])}</code>' if f.snippet else ""
    fix_lbl = "الإصلاح" if lang == "ar" else "Fix"
    return (f'<div class="f {f.severity}">'
            f'<span class="tag {tag[0]}">{tag[1]}</span> '
            f'<b>[{f.severity.upper()}] {f.control}</b> — {_html.escape(title)}<br>'
            f'<span class="where">{where} · {_html.escape(d["pdpl_ref"])}</span>{ev}'
            f'<div><b>{fix_lbl}:</b> {_html.escape(fix)}</div></div>')


def to_html(res: ScanResult) -> str:
    p = res.profile
    bs = res.by_severity
    name = _html.escape(res.target.split("/")[-1] or res.target)
    gate_cls = "pass" if res.gate == "pass" else "fail"
    gate_en = "PASS" if res.gate == "pass" else "FAIL"
    gate_ar = "ناجح" if res.gate == "pass" else "راسب"
    kpis = "".join(
        f'<div class="kpi"><b>{bs.get(s,0)}</b><span>{s.capitalize()}</span></div>'
        for s in ("critical", "high", "medium", "low"))
    kpis += f'<div class="kpi"><b>{res.score}</b><span>Score / 100</span></div>'
    kpis += f'<div class="kpi"><b>{len(res.manual)}</b><span>Manual-verify</span></div>'
    findings_en = "".join(_f_block(f, "en") for f in res.findings) or "<p>None.</p>"
    findings_ar = "".join(_f_block(f, "ar") for f in res.findings) or "<p>لا شيء.</p>"
    manual_en = "".join(
        f'<li><b>{m["control"]}</b> — {_html.escape(m["title_en"])} '
        f'<span class="where">({_html.escape(m["pdpl_ref"])})</span></li>' for m in res.manual)
    manual_ar = "".join(
        f'<li><b>{m["control"]}</b> — {_html.escape(m["title_ar"])}</li>' for m in res.manual)
    passed = (f'<p class="passed">✓ Auto-checks passed: '
              f'{", ".join(res.passed_controls)}</p>' if res.passed_controls else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PDPL Compliance Scan — {name}</title><style>{_HTML_STYLE}</style></head>
<body><div class="wrap">
<h1>PDPL Compliance Scan — {name}</h1>
<div class="meta">Entity: <b>{p.type}</b> · Classification: {p.data_classification} ·
Residency: {p.residency} · Files: {res.files_scanned} · Rules as of {_meta.RULES_LAST_UPDATED}</div>
<span class="gate {gate_cls}">Gate: {gate_en} / {gate_ar}</span>
<div class="kpis">{kpis}</div>{passed}
<div class="disclaimer">⚠️ Engineering-layer scan — <b>not a legal certification</b> and not a
substitute for SDAIA registration, a DPIA, sector approvals, or legal review. |
الأداة مساعِدة وليست شهادة امتثال نظامية ولا بديلاً عن التدقيق اليدوي.</div>
<h2>Findings</h2>{findings_en}
<h2>Manual verification required</h2><ul class="manual">{manual_en}</ul>
<div class="rtl">
<h2>فحص الامتثال لنظام حماية البيانات الشخصية — {name}</h2>
<div class="meta">نوع الجهة: <b>{p.type}</b> · التصنيف: {p.data_classification} · الإقامة: {p.residency}</div>
<h2>الملاحظات</h2>{findings_ar}
<h2>تحقّق يدوي مطلوب</h2><ul class="manual">{manual_ar}</ul>
</div>
<p class="meta">{_html.escape(_meta.freshness_note_en())}</p>
</div></body></html>"""
