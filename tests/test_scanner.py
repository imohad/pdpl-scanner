"""Tests for the PDPL scanner: entity-aware escalation, detection, gating, and report shapes."""
import os
import json
import pytest

from pdpl_scanner import scan, EntityProfile
from pdpl_scanner.report import to_json, to_sarif, to_markdown

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_app")


def test_detects_core_violations():
    res = scan(FIXTURE, EntityProfile(type="private_general"))
    controls = {f.control for f in res.findings}
    assert "PDPL-SEC-03" in controls   # hardcoded secret
    assert "PDPL-SEC-01" in controls   # TLS disabled
    assert "PDPL-CB-01" in controls    # cross-border
    assert "PDPL-LB-03" in controls    # pre-ticked consent
    assert res.files_scanned >= 3


def test_entity_escalation_cross_border():
    """Same flow is critical for a bank, high for a private SaaS."""
    cb_sev = lambda et: next(
        f.severity for f in scan(FIXTURE, EntityProfile(type=et)).findings
        if f.control == "PDPL-CB-01")
    assert cb_sev("financial") == "critical"
    assert cb_sev("government") == "critical"
    assert cb_sev("critical_infrastructure") == "critical"
    assert cb_sev("private_general") == "high"


def test_residency_posture():
    assert EntityProfile(type="financial").residency == "prohibited_without_approval"
    assert EntityProfile(type="health").residency == "in_kingdom_default"
    # public classification leaves a private entity at the PDPL base posture
    assert EntityProfile(type="private_general", data_classification="public").residency \
        == "allowed_with_safeguards"
    # confidential classification tightens a private entity to in-Kingdom-by-default (CST CCRF L2)
    assert EntityProfile(type="private_general", data_classification="confidential").residency \
        == "in_kingdom_default"
    # secret-and-above is in-Kingdom-mandatory regardless of entity type
    assert EntityProfile(type="private_general", data_classification="secret").residency \
        == "prohibited_without_approval"


def test_sector_overlays_surface():
    fin = scan(FIXTURE, EntityProfile(type="financial"))
    ids = {m["control"] for m in fin.manual}
    assert "SAMA-CLOUD-01" in ids
    assert "NCA-ECC-01" in ids
    health = scan(FIXTURE, EntityProfile(type="health"))
    assert "HEALTH-01" in {m["control"] for m in health.manual}


def test_dpo_and_registration_triggers():
    p = EntityProfile(type="private_general", cross_border_transfers=True)
    assert p.dpo_required is True
    assert p.registration_required is True
    p2 = EntityProfile(type="nonprofit")
    assert p2.dpo_required is False


def test_gate_fails_on_critical():
    res = scan(FIXTURE, EntityProfile(type="financial"))
    assert res.gate == "fail"
    assert res.score < 100


def test_gate_passes_on_clean_tree(tmp_path):
    clean = tmp_path / "src"
    clean.mkdir()
    (clean / "ok.py").write_text(
        'region = "me-central2"\nlogger.info("request received")\nstatus = 200\n')
    res = scan(str(clean), EntityProfile(type="private_general"))
    assert res.gate == "pass"


def test_json_report_shape():
    res = scan(FIXTURE, EntityProfile(type="financial"))
    d = to_json(res)
    assert d["entity"]["type"] == "financial"
    assert d["entity"]["residency_posture"] == "prohibited_without_approval"
    assert "SAMA" in d["entity"]["overlays"]
    assert d["summary"]["gate"] == "fail"
    assert isinstance(d["findings"], list) and d["findings"]
    assert d["summary"]["manual"] >= 1


def test_sarif_is_valid_2_1_0():
    res = scan(FIXTURE, EntityProfile(type="financial"))
    s = to_sarif(res)
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "pdpl-scanner"
    assert len(run["results"]) == len(res.findings)
    # every result references a defined rule
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for r in run["results"]:
        assert r["ruleId"] in rule_ids


def test_markdown_is_bilingual():
    res = scan(FIXTURE, EntityProfile(type="financial"))
    md = to_markdown(res)
    assert "PDPL Compliance Scan" in md
    assert 'dir="rtl"' in md
    assert "الحكم" in md           # Arabic verdict heading
    assert "not a legal certification" in md.lower()


def test_arabic_cross_border_remediation_present():
    res = scan(FIXTURE, EntityProfile(type="financial"))
    cb = next(f for f in res.findings if f.control == "PDPL-CB-01")
    assert cb.note_ar
    assert "المملكة" in cb.note_ar


def test_ksa_region_not_flagged_cross_border(tmp_path):
    f = tmp_path / "a.js"
    f.write_text('const cfg = { region: "me-central2", nationalId: x };\n')
    res = scan(str(tmp_path), EntityProfile(type="financial"))
    assert not any(fd.control == "PDPL-CB-01" for fd in res.findings)


def test_report_carries_freshness_metadata():
    from pdpl_scanner import _meta
    res = scan(FIXTURE, EntityProfile(type="financial"))
    d = to_json(res)
    assert d["scan"]["rules_last_updated"] == _meta.RULES_LAST_UPDATED
    assert "rules_stale" in d["scan"]
    assert "current as of" in d["scan"]["freshness_note"].lower()
    md = to_markdown(res)
    assert "Rule freshness" in md
    assert "حداثة القواعد" in md   # Arabic freshness heading


def test_freshness_helpers():
    from pdpl_scanner import _meta
    from datetime import date, datetime
    last = datetime.strptime(_meta.RULES_LAST_UPDATED, "%Y-%m-%d").date()
    # not stale the day after the update date
    soon = date(last.year, last.month, last.day)
    assert _meta.is_stale(soon) is False
    assert _meta.days_since_update(soon) == 0


# --- v1.1: new detection rules ------------------------------------------------

def _controls(res):
    return {f.control for f in res.findings}


def test_db_tls_disabled_detected(tmp_path):
    (tmp_path / "config.toml").write_text('[db]\npassword = "s3cr3t-Live-99x"\nssl_mode = "disable"\n')
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    f = next(f for f in res.findings if f.control == "PDPL-SEC-02")
    assert f.status == "fail" and f.severity == "high"


def test_foreign_processor_detected_and_entity_aware(tmp_path):
    (tmp_path / "track.js").write_text(
        'fetch("https://api.mixpanel.com/track", { nationalId: user.nationalId })\n')
    cb = lambda et: next(f for f in scan(str(tmp_path), EntityProfile(type=et)).findings
                         if f.control == "PDPL-CB-02")
    assert cb("financial").severity == "critical"      # prohibited-without-approval
    assert cb("private_general").severity == "high"    # allowed-with-safeguards
    assert cb("financial").note_ar                      # bilingual remediation present


def test_foreign_processor_needs_pii_nearby(tmp_path):
    # a bare dependency reference with no personal data nearby should not flag
    (tmp_path / "pkg.txt").write_text("docs: see https://api.sendgrid.com for details\n")
    res = scan(str(tmp_path), EntityProfile(type="financial"))
    assert "PDPL-CB-02" not in _controls(res)


# --- v1.1: secret triage ------------------------------------------------------

def test_placeholder_secret_downgraded(tmp_path):
    (tmp_path / "config.toml").write_text('password = "changeme"\n')
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    f = next(f for f in res.findings if f.control == "PDPL-SEC-03")
    assert f.status == "warn" and f.severity == "medium"   # not a gate-blocking critical


def test_real_secret_stays_critical(tmp_path):
    (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE0"\n')
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    f = next(f for f in res.findings if f.control == "PDPL-SEC-03")
    assert f.status == "fail" and f.severity == "critical"


def test_placeholder_picks_right_value_on_multipair_line(tmp_path):
    (tmp_path / "c.js").write_text('const o = { ssl_mode: "disable", password: "changeme" };\n')
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    sec3 = next(f for f in res.findings if f.control == "PDPL-SEC-03")
    assert sec3.status == "warn"   # downgraded on "changeme", not misled by "disable"


# --- v1.1: suppression --------------------------------------------------------

def test_inline_ignore_all(tmp_path):
    (tmp_path / "c.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE0"  # pdpl-ignore\n')
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    assert "PDPL-SEC-03" not in _controls(res)


def test_inline_ignore_specific_control(tmp_path):
    (tmp_path / "c.py").write_text(
        'aws_key = "AKIAIOSFODNN7EXAMPLE0"  # pdpl-ignore[PDPL-LOG-01]\n')
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    assert "PDPL-SEC-03" in _controls(res)   # not the suppressed one -> still fires


def test_pdplignore_file(tmp_path):
    (tmp_path / "secrets.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE0"\n')
    (tmp_path / ".pdplignore").write_text("# ignore generated\nsecrets.py\n")
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    assert "PDPL-SEC-03" not in _controls(res)


def test_glob_exclude(tmp_path):
    (tmp_path / "a.test.js").write_text('key = "AKIAIOSFODNN7EXAMPLE0"\n')
    res = scan(str(tmp_path), EntityProfile(type="private_general"), exclude=["*.test.js"])
    assert res.files_scanned == 0


# --- v1.1: assisted controls --------------------------------------------------

def test_assisted_soft_delete(tmp_path):
    (tmp_path / "m.py").write_text("national_id = '1'\ndef remove(u):\n    u.is_deleted = True\n")
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    dsr2 = next(f for f in res.findings if f.control == "PDPL-DSR-02")
    assert dsr2.status == "warn" and dsr2.confidence == "assisted" and dsr2.file


def test_assisted_repo_level_absence(tmp_path):
    (tmp_path / "a.py").write_text("national_id = ''\niqama = ''\n")
    (tmp_path / "b.py").write_text("passport = ''\ndob = ''\n")
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    ctrls = _controls(res)
    assert {"PDPL-DSR-01", "PDPL-RET-01", "PDPL-LB-01"} <= ctrls   # no export/retention/consent present


def test_assisted_absence_silenced_when_handled(tmp_path):
    (tmp_path / "a.py").write_text(
        "national_id = ''\niqama = ''\nconsent = True\nexport_data()\nttl = 30  # retention\n")
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    ctrls = _controls(res)
    assert "PDPL-DSR-01" not in ctrls and "PDPL-RET-01" not in ctrls and "PDPL-LB-01" not in ctrls


def test_assisted_leads_do_not_fail_gate(tmp_path):
    # personal data, no auto violations -> only assisted leads -> gate must still PASS
    (tmp_path / "a.py").write_text(
        "national_id = ''\niqama = ''\npassport = ''\nregion = 'me-central2'\n")
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    assert any(f.status == "warn" for f in res.findings)   # leads present
    assert not any(f.status == "fail" for f in res.findings)
    assert res.gate == "pass"


# --- v1.1: passed controls + reports -----------------------------------------

def test_passed_controls_reported(tmp_path):
    (tmp_path / "ok.py").write_text("region = 'me-central2'\nstatus = 200\n")
    res = scan(str(tmp_path), EntityProfile(type="private_general"))
    assert "PDPL-SEC-03" in res.passed_controls and "PDPL-CB-01" in res.passed_controls
    assert to_json(res)["passed_controls"]


def test_sarif_has_partial_fingerprints():
    res = scan(FIXTURE, EntityProfile(type="financial"))
    s = to_sarif(res)
    results = s["runs"][0]["results"]
    assert results and all("partialFingerprints" in r for r in results)
    # stable across two runs
    s2 = to_sarif(scan(FIXTURE, EntityProfile(type="financial")))
    fp1 = [r["partialFingerprints"] for r in results]
    fp2 = [r["partialFingerprints"] for r in s2["runs"][0]["results"]]
    assert fp1 == fp2


def test_html_report_bilingual():
    from pdpl_scanner.report import to_html
    html = to_html(scan(FIXTURE, EntityProfile(type="financial")))
    assert html.startswith("<!doctype html>")
    assert 'class="rtl"' in html
    assert "not a legal certification" in html
    assert "الملاحظات" in html   # Arabic findings heading
