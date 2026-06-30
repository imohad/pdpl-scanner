"""
_meta.py — rule freshness and self-update metadata.

PDPL and its sector overlays change. The Implementing Regulations were under amendment through
2025-2026, SAMA/NDMO/CST/NCA issue updates, and SDAIA ships new guidance (e.g. the AI Adoption
Framework). So this scanner stamps every report with the date its rules were last reviewed and warns
when that date is stale. Refreshing the rules is a deliberate research step (see `pdpl-scan update`
and the bundled Claude skill's update mode), not something that happens silently.

When you refresh the catalog, bump RULES_LAST_UPDATED to the date you completed the review.
"""
from __future__ import annotations
from datetime import date, datetime

# Date the rules were last reviewed against the regulators' current published text.
# Set to the repository's initial publish date. Bump this whenever you refresh the catalog.
RULES_LAST_UPDATED = "2026-06-30"

# Warn once the rules are older than this many days (regulation moves; re-verify).
RULES_REVIEW_AFTER_DAYS = 180

REGULATORS = ["SDAIA / PDPL", "NDMO", "CST (CCRF)", "NCA (ECC/CCC)", "SAMA", "MOH / SFDA (health)"]


def days_since_update(today: date | None = None) -> int:
    today = today or date.today()
    try:
        last = datetime.strptime(RULES_LAST_UPDATED, "%Y-%m-%d").date()
    except ValueError:
        return 0
    return (today - last).days


def is_stale(today: date | None = None) -> bool:
    return days_since_update(today) > RULES_REVIEW_AFTER_DAYS


def freshness_note_en(today: date | None = None) -> str:
    d = days_since_update(today)
    base = (f"Compliance rules current as of {RULES_LAST_UPDATED} ({d} days ago). "
            "Saudi data-protection rules change; re-verify periodically.")
    if is_stale(today):
        base += (" These rules are overdue for review. Run `pdpl-scan update` or ask the bundled "
                 "Claude skill to research the latest SDAIA/NDMO/SAMA/CST/NCA changes and refresh them.")
    return base


def freshness_note_ar(today: date | None = None) -> str:
    d = days_since_update(today)
    base = (f"قواعد الامتثال محدّثة حتى {RULES_LAST_UPDATED} (قبل {d} يوماً). "
            "أنظمة حماية البيانات في المملكة تتغيّر، فأعد التحقق دورياً.")
    if is_stale(today):
        base += (" هذه القواعد تجاوزت موعد المراجعة. شغّل `pdpl-scan update` أو اطلب من سكيل كلود "
                 "المرفق البحث عن آخر تحديثات سدايا/NDMO/ساما/هيئة الاتصالات/الأمن السيبراني وتحديثها.")
    return base
