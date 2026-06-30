"""
cli.py — command-line interface.

Zero hard dependencies (stdlib only). YAML config is supported when PyYAML is present; otherwise
fall back to JSON config or a minimal built-in YAML reader for the simple flat schema we emit.

Commands:
  pdpl-scan <path> [options]     run a scan
  pdpl-scan init                 interactive questionnaire -> pdpl.config.yaml
"""
from __future__ import annotations
import argparse
import json
import os
import sys

from .entity_profiles import EntityProfile
from .scanner import scan
from . import report as RPT
from . import _meta
from .questionnaire import run_questionnaire, profile_to_config


def _load_config(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    text = open(path, "r", encoding="utf-8").read()
    # Try PyYAML
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except Exception:
        pass
    # Try JSON
    try:
        return json.loads(text)
    except Exception:
        pass
    # Minimal flat YAML fallback for our own emitted schema
    return _mini_yaml(text)


def _mini_yaml(text: str) -> dict:
    """Parse the simple 2-level YAML we emit (no PyYAML needed)."""
    root: dict = {}
    section = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith(" "):
            key = line.rstrip(":").strip()
            root[key] = {}
            section = root[key]
        elif section is not None and ":" in line:
            k, v = line.strip().split(":", 1)
            section[k.strip()] = _coerce(v.strip())
    return root


def _coerce(v: str):
    if v in ("true", "false"):
        return v == "true"
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [x.strip().strip('"').strip("'") for x in inner.split(",")]
    if v.startswith("{") and v.endswith("}"):
        out = {}
        for pair in v[1:-1].split(","):
            if ":" in pair:
                pk, pv = pair.split(":", 1)
                try:
                    out[pk.strip()] = int(pv.strip())
                except ValueError:
                    out[pk.strip()] = pv.strip()
        return out
    return v.strip('"').strip("'")


def _profile_from_config(cfg: dict) -> EntityProfile:
    e = cfg.get("entity", {}) or {}
    return EntityProfile(
        type=e.get("type", "private_general"),
        is_public_entity=bool(e.get("is_public_entity", False)),
        is_foreign_entity=bool(e.get("is_foreign_entity", False)),
        processes_sensitive_data=bool(e.get("processes_sensitive_data", False)),
        processes_children_data=bool(e.get("processes_children_data", False)),
        cross_border_transfers=bool(e.get("cross_border_transfers", False)),
        large_scale_processing=bool(e.get("large_scale_processing", False)),
        uses_ai_on_personal_data=bool(e.get("uses_ai_on_personal_data", False)),
        data_classification=e.get("data_classification", "confidential"),
    )


def cmd_update(args) -> int:
    """Print the self-update workflow. PDPL changes; refreshing the rules is a research step."""
    d = _meta.days_since_update()
    stale = _meta.is_stale()
    print("=" * 70)
    print("PDPL Scanner — rule freshness & update")
    print("=" * 70)
    print(f"Rules last reviewed: {_meta.RULES_LAST_UPDATED}  ({d} days ago)")
    print(f"Status: {'OVERDUE — refresh recommended' if stale else 'within review window'}")
    print(f"Review cadence: every {_meta.RULES_REVIEW_AFTER_DAYS} days")
    print("\nWhy: Saudi data-protection rules change. The PDPL Implementing Regulations were under")
    print("amendment through 2025-2026, and these authorities issue updates:")
    for r in _meta.REGULATORS:
        print(f"  - {r}")
    print("\nHow to refresh (research step — this command does not auto-edit your rules):")
    print("  1. Ask the bundled Claude skill (skill/SKILL.md) to run its UPDATE MODE, or ask Claude")
    print("     to research the latest published changes from SDAIA, NDMO, CST, NCA, SAMA, and the")
    print("     health authorities since the date above.")
    print("  2. Apply any changes to pdpl_scanner/rules.py, controls.py, entity_profiles.py, and the")
    print("     YAML mirror in controls/pdpl-controls.yaml. Cite the source for each change.")
    print("  3. Bump RULES_LAST_UPDATED in pdpl_scanner/_meta.py to today's date.")
    print("  4. Run `pytest -q`, commit, and tag a new release.")
    print("\nReminder: this tool is an aid, not a legal certification. Always confirm high-stakes")
    print("decisions with your DPO/legal and SDAIA's current published regulations.")
    return 0


def cmd_init(args) -> int:
    profile = run_questionnaire()
    out = args.output or "pdpl.config.yaml"
    if os.path.exists(out) and not args.force:
        print(f"\n{out} already exists. Use --force to overwrite.")
        return 1
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(profile_to_config(profile, paths=["src"]))
    print(f"\nWrote {out}. Commit it and run: pdpl-scan .")
    return 0


def cmd_scan(args) -> int:
    cfg = _load_config(args.config) if args.config else {}
    if not cfg and os.path.exists("pdpl.config.yaml"):
        cfg = _load_config("pdpl.config.yaml")

    profile = _profile_from_config(cfg) if cfg else EntityProfile(type=args.entity)
    if args.entity and args.entity != "private_general":
        profile.type = args.entity

    gate_cfg = (cfg.get("gate", {}) or {})
    fail_on = args.fail_on.split(",") if args.fail_on else gate_cfg.get("fail_on", ["critical"])
    fail_on = [s.strip() for s in fail_on if s.strip()]
    weights = gate_cfg.get("weights") or None
    exclude = (cfg.get("scan", {}) or {}).get("exclude", []) + (args.exclude or [])

    res = scan(args.path, profile=profile, fail_on=fail_on, weights=weights, exclude=exclude)

    fmt = args.format
    payload_json = RPT.to_json(res)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload_json, fh, ensure_ascii=False, indent=2)
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(RPT.to_sarif(res), fh, ensure_ascii=False, indent=2)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(RPT.to_markdown(res))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(RPT.to_html(res))

    # stdout
    if fmt == "json":
        print(json.dumps(payload_json, ensure_ascii=False, indent=2))
    elif fmt == "markdown":
        print(RPT.to_markdown(res))
    else:
        _print_summary(res, show_pass=args.show_pass)

    return 1 if res.gate == "fail" else 0


def _print_summary(res, show_pass: bool = False) -> None:
    gate = "FAIL" if res.gate == "fail" else "PASS"
    bs = res.by_severity
    n_lead = sum(1 for f in res.findings if f.status == "warn")
    print(f"\nPDPL scan — entity={res.profile.type} class={res.profile.data_classification} "
          f"residency={res.profile.residency}")
    print(f"Files scanned: {res.files_scanned} | Score: {res.score}/100 | Gate: {gate}")
    print(f"Findings: critical={bs.get('critical',0)} high={bs.get('high',0)} "
          f"medium={bs.get('medium',0)} | leads={n_lead} | manual-verify={len(res.manual)}")
    if _meta.is_stale():
        print(f"  ! Rules last reviewed {_meta.RULES_LAST_UPDATED} and are overdue. "
              f"Run `pdpl-scan update`.")
    for f in res.findings[:20]:
        d = f.to_dict()
        mark = "FAIL" if f.status == "fail" else "LEAD"
        where = f"{f.file}:{f.line}" if f.file else "(repo-wide)"
        print(f"  [{f.severity.upper():8}] {mark} {f.control:12} {where:24}  {d['title_en']}")
    if len(res.findings) > 20:
        print(f"  ... +{len(res.findings)-20} more")
    if show_pass and res.passed_controls:
        print("\nAuto-checks passed (evaluated, no violation):")
        print("  " + ", ".join(res.passed_controls))
    if res.manual:
        print("\nManual-verify (confirm with DPO/legal):")
        for m in res.manual:
            print(f"  [ ] {m['control']:14} {m['title_en']}")


def build_scan_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pdpl-scan",
        description="Scan a codebase for Saudi PDPL compliance (entity-aware).")
    _add_scan_args(ap)
    return ap


def build_init_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pdpl-scan init",
                                 description="Interactive entity questionnaire.")
    ap.add_argument("-o", "--output", default="pdpl.config.yaml")
    ap.add_argument("--force", action="store_true")
    return ap


def _add_scan_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("path", nargs="?", default=".", help="Path to scan (default: current dir)")
    ap.add_argument("-c", "--config", help="Config file (default: ./pdpl.config.yaml if present)")
    ap.add_argument("--entity", default="private_general",
                    help="Entity type override (government|financial|health|telecom|"
                         "cloud_provider|critical_infrastructure|private_general|nonprofit)")
    ap.add_argument("--fail-on", help="Comma list of severities that fail the gate (default: critical)")
    ap.add_argument("--exclude", action="append",
                    help="Path segment or glob to exclude (repeatable). Also reads ./.pdplignore")
    ap.add_argument("--format", choices=["summary", "json", "markdown"], default="summary",
                    help="stdout format")
    ap.add_argument("--show-pass", action="store_true",
                    help="Also list auto controls that were evaluated and found clean")
    ap.add_argument("--json", help="Write JSON findings to this path")
    ap.add_argument("--sarif", help="Write SARIF (for GitHub code scanning) to this path")
    ap.add_argument("--markdown", help="Write bilingual markdown report to this path")
    ap.add_argument("--html", help="Write standalone bilingual HTML report to this path")


def main(argv=None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    # Manual subcommand routing to allow `pdpl-scan <path>` shorthand.
    if argv and argv[0] == "init":
        args = build_init_parser().parse_args(argv[1:])
        return cmd_init(args)
    if argv and argv[0] == "update":
        return cmd_update(None)
    if argv and argv[0] == "scan":
        argv = argv[1:]
    args = build_scan_parser().parse_args(argv)
    return cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
