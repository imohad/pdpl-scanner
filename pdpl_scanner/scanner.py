"""
scanner.py — the scanning engine.

Walks a target tree, runs the deterministic rules, applies the entity profile to escalate
cross-border findings and select manual-verify controls, scores the result, and decides the gate.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
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
        if self.status != "manual":
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

    @property
    def score(self) -> int:
        s = 100
        for f in self.findings:
            s -= self.weights.get(f.severity, 0) if f.status == "fail" else 1
        return max(0, s)

    @property
    def gate(self) -> str:
        # Gate fails on any fail-on-severity FAIL, or 2+ high fails.
        hits = [f for f in self.findings
                if f.severity in self.fail_on and f.status in ("fail", "warn")]
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


def _scan_file(path: str, root: str, profile: EntityProfile) -> List[Finding]:
    out: List[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    rel = os.path.relpath(path, root)
    pii_lines = {i for i, l in enumerate(lines)
                 if R.PII_HINT.search(l) or R.SENSITIVE_HINT.search(l) or R.PII_VALUE.search(l)}

    for i, line in enumerate(lines):
        for cid, sev, mode, rx, needs_pii, skip_ksa in R.RULES:
            if not rx.search(line):
                continue
            if needs_pii:
                window = set(range(max(0, i - 3), min(len(lines), i + 4)))
                if not (pii_lines & window):
                    continue
            if skip_ksa and R.KSA_REGION.search(line):
                continue
            # entity-aware severity escalation for cross-border
            eff_sev = profile.cross_border_severity() if cid == "PDPL-CB-01" else sev
            note = ""
            note_ar = ""
            if cid == "PDPL-CB-01":
                note = profile.cross_border_remediation("en")
                note_ar = profile.cross_border_remediation("ar")
            out.append(Finding(
                control=cid, severity=eff_sev,
                status="fail" if mode == "auto" else "warn",
                confidence=mode, file=rel, line=i + 1,
                snippet=line.strip()[:200], note=note, note_ar=note_ar,
            ))
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


def scan(target: str, profile: Optional[EntityProfile] = None,
         weights: Optional[Dict[str, int]] = None,
         fail_on: Optional[List[str]] = None,
         exclude: Optional[List[str]] = None) -> ScanResult:
    profile = profile or EntityProfile()
    exclude = set(exclude or [])
    result = ScanResult(
        target=os.path.abspath(target), profile=profile,
        weights=weights or dict(DEFAULT_WEIGHTS),
        fail_on=fail_on or ["critical"],
    )
    findings: List[Finding] = []
    for p in _iter_files(target):
        rel = os.path.relpath(p, target)
        if any(part in exclude for part in rel.split(os.sep)):
            continue
        result.files_scanned += 1
        findings.extend(_scan_file(p, target, profile))

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
    return result
