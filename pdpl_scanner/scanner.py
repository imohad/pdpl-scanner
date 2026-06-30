"""
scanner.py — the scanning engine.

Walks a target tree, runs the deterministic rules, applies the entity profile to escalate
cross-border findings and select manual-verify controls, derives high-recall "assisted" leads for
controls that can't be asserted from a single line, scores the result, and decides the gate.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Dict, List, Optional

from .controls import CORE_CONTROLS, MANUAL_CONTROLS, SEVERITY_ORDER, DEFAULT_WEIGHTS
from .entity_profiles import EntityProfile, overlay_manual_controls
from . import rules as R


@dataclass
class Finding:
    control: str
    severity: str
    status: str          # fail | warn | manual
    confidence: str      # auto | assisted | manual
    file: str = ""
    line: int = 0
    snippet: str = ""
    note: str = ""
    note_ar: str = ""

    def to_dict(self) -> dict:
        meta = CORE_CONTROLS.get(self.control) or MANUAL_CONTROLS.get(self.control) or {}
        d = {
            "control": self.control,
            "domain": meta.get("domain", ""),
            "title_en": meta.get("title_en", ""),
            "title_ar": meta.get("title_ar", ""),
            "pdpl_ref": meta.get("pdpl_ref", ""),
            "severity": self.severity,
            "status": self.status,
            "confidence": self.confidence,
            "fix_en": meta.get("fix_en", meta.get("note_en", "")),
            "fix_ar": meta.get("fix_ar", meta.get("note_ar", "")),
        }
        # Repo-level assisted leads carry no file:line; only attach evidence when we have it.
        if self.status != "manual" and self.file:
            d["evidence"] = [{"file": self.file, "line": self.line, "snippet": self.snippet}]
        if self.note:
            d["note"] = self.note
        if self.note_ar:
            d["note_ar"] = self.note_ar
        return d


@dataclass
class ScanResult:
    target: str
    profile: EntityProfile
    findings: List[Finding] = field(default_factory=list)
    manual: List[dict] = field(default_factory=list)
    weights: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    fail_on: List[str] = field(default_factory=lambda: ["critical"])
    files_scanned: int = 0
    passed_controls: List[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        s = 100
        for f in self.findings:
            s -= self.weights.get(f.severity, 0) if f.status == "fail" else 1
        return max(0, s)

    @property
    def gate(self) -> str:
        # Gate fails on a fail-on-severity auto FAIL, or 2+ high auto FAILs. Assisted leads
        # (status="warn") are high-recall and need triage, so they never fail the build by themselves.
        hits = [f for f in self.findings
                if f.severity in self.fail_on and f.status == "fail"]
        highs = [f for f in self.findings if f.severity == "high" and f.status == "fail"]
        return "fail" if (hits or len(highs) >= 2) else "pass"

    @property
    def by_severity(self) -> Dict[str, int]:
        out = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def _iter_files(root: str):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in R.SKIP_DIRS]
        for f in fn:
            if any(f.endswith(e) for e in R.SKIP_EXT):
                continue
            p = os.path.join(dp, f)
            try:
                if os.path.getsize(p) > R.MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def _excluded(rel: str, exclude: List[str]) -> bool:
    """Exclude by exact path-segment (legacy) or by glob against the path / any segment / basename."""
    parts = rel.split(os.sep)
    for pat in exclude:
        if pat in parts:                                  # legacy: exact segment, e.g. "tests"
            return True
        if fnmatch(rel, pat) or fnmatch(rel, pat.rstrip("/") + "/*"):
            return True
        if any(fnmatch(part, pat) for part in parts):     # glob a segment, e.g. "*.test.js"
            return True
    return False


def _load_pdplignore(target: str) -> List[str]:
    path = os.path.join(target, ".pdplignore")
    if not os.path.isfile(path):
        return []
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip()
                if line:
                    out.append(line)
    except OSError:
        pass
    return out


def _suppressed(lines: List[str], i: int):
    """Suppression in effect for line i: 'all', a set of control ids, or None.

    A `pdpl-ignore` directive covers its own line and the line immediately below it.
    """
    ids: set = set()
    for src in (i, i - 1):
        if src < 0:
            continue
        d = R.ignore_directive(lines[src])
        if d is None:
            continue
        if d == []:
            return "all"
        ids.update(d)
    return ids or None


def _scan_file(path: str, root: str, profile: EntityProfile, agg: dict) -> List[Finding]:
    out: List[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    rel = os.path.relpath(path, root)
    pii_lines = {i for i, l in enumerate(lines)
                 if R.PII_HINT.search(l) or R.SENSITIVE_HINT.search(l) or R.PII_VALUE.search(l)}

    # --- aggregate signals for the assisted analyzer ---
    if pii_lines:
        agg["pii_files"].add(rel)
        agg["pii_hits"] += len(pii_lines)
    if any(R.EXPORT_HINT.search(l) for l in lines):
        agg["has_export"] = True
    if any(R.RETENTION_HINT.search(l) for l in lines):
        agg["has_retention"] = True
    if any(R.CONSENT_HINT.search(l) for l in lines):
        agg["has_consent"] = True
    file_has_encryption = any(R.ENCRYPTION_HINT.search(l) for l in lines)
    sd_in_file = 0
    sen_in_file = 0
    for i, line in enumerate(lines):
        if sd_in_file < 3 and R.SOFT_DELETE.search(line):
            sd_in_file += 1
            agg["soft_delete"].append((rel, i + 1, line.strip()[:200]))
        if sen_in_file < 3 and not file_has_encryption and R.SENSITIVE_HINT.search(line):
            sen_in_file += 1
            agg["sensitive_unprotected"].append((rel, i + 1, line.strip()[:200]))

    # --- deterministic auto rules ---
    for i, line in enumerate(lines):
        supp = _suppressed(lines, i)
        if supp == "all":
            continue
        for cid, sev, mode, rx, needs_pii, skip_ksa in R.RULES:
            if supp and cid in supp:
                continue
            if not rx.search(line):
                continue
            if needs_pii:
                window = set(range(max(0, i - 3), min(len(lines), i + 4)))
                if not (pii_lines & window):
                    continue
            if skip_ksa and R.KSA_REGION.search(line):
                continue

            eff_sev, status, note, note_ar = sev, ("fail" if mode == "auto" else "warn"), "", ""

            # entity-aware severity escalation for cross-border controls
            if cid in R.CROSS_BORDER_CONTROLS:
                eff_sev = profile.cross_border_severity()
                note = profile.cross_border_remediation("en")
                note_ar = profile.cross_border_remediation("ar")
            # secret triage: downgrade obvious placeholders/defaults to a WARN lead
            if cid == "PDPL-SEC-03":
                mv = R.SECRET_KV_RX.search(line)
                if mv and R.is_placeholder_secret(mv.group(1)):
                    eff_sev, status = "medium", "warn"
                    note = ("Looks like a placeholder/default value, not a live secret — verify, and "
                            "never ship default credentials to production.")
                    note_ar = ("يبدو قيمة افتراضية/مكان حجز لا سراً فعلياً — تحقق، ولا تنشر بيانات "
                               "اعتماد افتراضية في الإنتاج.")

            out.append(Finding(
                control=cid, severity=eff_sev, status=status,
                confidence=mode, file=rel, line=i + 1,
                snippet=line.strip()[:200], note=note, note_ar=note_ar,
            ))
    return out


# Concise bilingual notes for repo-level assisted leads.
_ASSISTED_NOTES = {
    "PDPL-DSR-01": ("No data-export / portability path was found anywhere in the codebase, yet "
                    "personal data is handled. Add an authenticated self-service export (JSON/CSV).",
                    "لم يُعثر على وسيلة تصدير/نقل للبيانات رغم معالجة بيانات شخصية. أضف تصديراً ذاتياً موثّقاً."),
    "PDPL-RET-01": ("No retention/expiry/purge logic was found, yet personal data is stored. Define a "
                    "retention period per dataset and automate deletion when the purpose ends.",
                    "لم يُعثر على منطق احتفاظ/حذف آلي رغم تخزين بيانات شخصية. حدّد مدة احتفاظ ونفّذ حذفاً آلياً."),
    "PDPL-LB-01": ("No consent / lawful-basis signal was found near personal-data handling. Gate writes "
                   "on a documented lawful basis and persist basis/purpose/consent metadata.",
                   "لم يُعثر على إشارة موافقة/أساس نظامي قرب معالجة البيانات. اربط الحفظ بأساس نظامي موثّق."),
}


def _assisted_findings(agg: dict) -> List[Finding]:
    """High-recall WARN leads for controls that can't be proven from a single line."""
    out: List[Finding] = []
    strong_pii = agg["pii_hits"] >= 3 or len(agg["pii_files"]) >= 2

    for rel, ln, snip in agg["soft_delete"][:10]:
        out.append(Finding(control="PDPL-DSR-02", severity="high", status="warn",
                            confidence="assisted", file=rel, line=ln, snippet=snip,
                            note="Soft-delete flag detected — confirm erasure is a real hard delete or "
                                 "irreversible anonymization, not just a status change.",
                            note_ar="رُصدت علامة حذف منطقي — تأكد أن الحذف فعلي أو إخفاء هوية لا رجعة فيه، "
                                    "لا مجرد تغيير حالة."))
    for rel, ln, snip in agg["sensitive_unprotected"][:10]:
        out.append(Finding(control="PDPL-SEN-01", severity="critical", status="warn",
                            confidence="assisted", file=rel, line=ln, snippet=snip,
                            note="Sensitive data handled in a file with no visible encryption/hashing — "
                                 "confirm elevated safeguards (encryption, least-privilege, minimization).",
                            note_ar="بيانات حساسة في ملف بلا تشفير/تجزئة ظاهرة — تأكد من ضوابط مشددة "
                                    "(تشفير، صلاحيات أدنى، تقليل)."))
    if strong_pii and not agg["has_export"]:
        en, ar = _ASSISTED_NOTES["PDPL-DSR-01"]
        out.append(Finding(control="PDPL-DSR-01", severity="high", status="warn",
                            confidence="assisted", note=en, note_ar=ar))
    if strong_pii and not agg["has_retention"]:
        en, ar = _ASSISTED_NOTES["PDPL-RET-01"]
        out.append(Finding(control="PDPL-RET-01", severity="medium", status="warn",
                            confidence="assisted", note=en, note_ar=ar))
    if strong_pii and not agg["has_consent"]:
        en, ar = _ASSISTED_NOTES["PDPL-LB-01"]
        out.append(Finding(control="PDPL-LB-01", severity="critical", status="warn",
                            confidence="assisted", note=en, note_ar=ar))
    return out


def _manual_controls(profile: EntityProfile) -> List[dict]:
    """Select base + entity-gated manual controls, plus overlay controls."""
    out: List[dict] = []
    base_ids = ["PDPL-GOV-02", "PDPL-GOV-07", "PDPL-BR-01", "PDPL-GOV-05"]
    if profile.registration_required:
        base_ids.append("PDPL-GOV-03")
    if profile.dpo_required:
        base_ids.append("PDPL-GOV-04")
    if profile.dpia_required:
        base_ids.append("PDPL-GOV-06")
    seen = set()
    for cid in base_ids:
        if cid in seen:
            continue
        seen.add(cid)
        meta = MANUAL_CONTROLS[cid]
        out.append({
            "control": cid, "domain": meta["domain"], "severity": meta["severity"],
            "title_en": meta["title_en"], "title_ar": meta["title_ar"],
            "pdpl_ref": meta["pdpl_ref"], "status": "manual", "confidence": "manual",
            "note_en": meta.get("note_en", ""), "note_ar": meta.get("note_ar", ""),
        })
    out.extend(overlay_manual_controls(profile))
    return out


# Auto controls the engine can assert as PASS when it scanned files and found no violation.
AUTO_CONTROL_IDS = ["PDPL-CB-01", "PDPL-CB-02", "PDPL-SEC-01", "PDPL-SEC-02", "PDPL-SEC-03",
                    "PDPL-SEC-05", "PDPL-LB-03", "PDPL-LOG-01"]


def scan(target: str, profile: Optional[EntityProfile] = None,
         weights: Optional[Dict[str, int]] = None,
         fail_on: Optional[List[str]] = None,
         exclude: Optional[List[str]] = None) -> ScanResult:
    profile = profile or EntityProfile()
    exclude = list(exclude or []) + _load_pdplignore(target)
    result = ScanResult(
        target=os.path.abspath(target), profile=profile,
        weights=weights or dict(DEFAULT_WEIGHTS),
        fail_on=fail_on or ["critical"],
    )
    agg = {"pii_files": set(), "pii_hits": 0, "has_export": False, "has_retention": False,
           "has_consent": False, "soft_delete": [], "sensitive_unprotected": []}

    findings: List[Finding] = []
    for p in _iter_files(target):
        rel = os.path.relpath(p, target)
        if _excluded(rel, exclude):
            continue
        result.files_scanned += 1
        findings.extend(_scan_file(p, target, profile, agg))

    findings.extend(_assisted_findings(agg))

    # de-dup by (control, file, line)
    seen, deduped = set(), []
    for f in findings:
        k = (f.control, f.file, f.line)
        if k not in seen:
            seen.add(k)
            deduped.append(f)
    deduped.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.confidence != "auto"))
    result.findings = deduped
    result.manual = _manual_controls(profile)

    # auto controls that ran clean (for --show-pass)
    flagged = {f.control for f in deduped if f.confidence == "auto"}
    result.passed_controls = [c for c in AUTO_CONTROL_IDS if c not in flagged]
    return result
