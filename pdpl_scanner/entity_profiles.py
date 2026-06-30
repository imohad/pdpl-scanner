"""
entity_profiles.py — entity-type-aware compliance logic.

This is what separates a PDPL scan from a generic privacy linter: under Saudi law the
hosting/residency rules and the regulator overlays depend on WHO the entity is and WHAT data it
handles. A cross-border data flow that is merely "high risk, fix your safeguards" for a private SaaS
is effectively prohibited for a SAMA-regulated bank or a government entity.

Sources distilled into this module:
- PDPL (M/19 as amended by M/148) + Implementing Regulations + Transfer Regulations (SDAIA).
- NDMO National Data Management & Personal Data Protection Standards + Data Classification Policy
  (4 levels: Top Secret, Secret, Confidential, Public).
- CST Cloud Computing Regulatory Framework (CCRF): cloud levels aligned to NDMO classification;
  CSPs must not move Saudi Government content outside the Kingdom, even temporarily, unless permitted.
- NCA Essential Cybersecurity Controls (ECC 4.2.3.3: hosting/storage inside the Kingdom) + Cloud
  Cybersecurity Controls (CCC), mandatory for government, semi-government, and CNI operators.
- SAMA Cloud Computing Regulatory Framework + Cyber Security Framework + Rules on Outsourcing:
  highly sensitive financial/customer data must reside in-Kingdom; SAMA approval required before
  cloud use and explicitly before any cloud outside the Kingdom.
- Health: PDPL health-data rules + MOH / Saudi Health Council / Saudi HIE policies + SFDA MDS-G010.
- SDAIA AI Adoption Framework (five pillars) where AI processes personal data of Saudi residents.

Nothing here is legal advice. It encodes the prevailing regulatory posture so the scanner can
escalate findings correctly and surface the right manual obligations.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List

# --- Entity types -------------------------------------------------------------

ENTITY_TYPES = {
    "government": "Public / government entity (subject to NDMO standards + NCA ECC)",
    "financial": "SAMA-regulated (bank, insurance, finance co., payment provider, credit bureau, fintech)",
    "health": "Healthcare provider, hospital, health-tech, or health insurer",
    "telecom": "Telecom / CST-licensed operator",
    "cloud_provider": "Cloud service provider registered with CST/CITC",
    "critical_infrastructure": "Operator of Critical National Infrastructure (NCA scope)",
    "private_general": "Private-sector organization with no special sector overlay",
    "nonprofit": "Non-profit / third-sector organization",
}

# Residency posture for personal data that is in-scope for the entity.
# "prohibited_without_approval" => cross-border is a CRITICAL finding (escalate).
# "in_kingdom_default"          => must stay in-Kingdom by default; cross-border is HIGH+ and needs basis.
# "allowed_with_safeguards"     => cross-border allowed with lawful basis + safeguards + TRA (PDPL base).
RESIDENCY = {
    "government": "prohibited_without_approval",
    "financial": "prohibited_without_approval",
    "critical_infrastructure": "prohibited_without_approval",
    "telecom": "in_kingdom_default",
    "cloud_provider": "in_kingdom_default",
    "health": "in_kingdom_default",
    "private_general": "allowed_with_safeguards",
    "nonprofit": "allowed_with_safeguards",
}

# Regulator overlays surfaced per entity type (manual-verify controls added to the report).
OVERLAYS = {
    "government": ["NDMO", "NCA-ECC"],
    "financial": ["SAMA", "NCA-ECC"],
    "health": ["MOH-HEALTH", "SFDA-AI"],
    "telecom": ["CST-CCRF"],
    "cloud_provider": ["CST-CCRF", "NCA-CCC"],
    "critical_infrastructure": ["NCA-ECC", "NCA-CCC"],
    "private_general": [],
    "nonprofit": [],
}

# NDMO data classification levels and their cloud/residency consequence (CST CCRF alignment).
CLASSIFICATION = {
    "top_secret": "Level 4 — must be in-Kingdom, CST-licensed provider, Saudi-national operational control.",
    "secret": "Level 3 — must be hosted in-Kingdom.",
    "confidential": "Level 2 — in-Kingdom by default; cross-border only under PDPL + CCRF conditions.",
    "public": "Level 1 — may be hosted outside the Kingdom subject to PDPL and sector rules.",
}


@dataclass
class EntityProfile:
    type: str = "private_general"
    is_public_entity: bool = False
    is_foreign_entity: bool = False           # processes data of people in KSA from outside
    processes_sensitive_data: bool = False    # health, biometric, genetic, credit, criminal, religious/ethnic
    processes_children_data: bool = False
    cross_border_transfers: bool = False
    large_scale_processing: bool = False
    uses_ai_on_personal_data: bool = False
    data_classification: str = "confidential"  # top_secret | secret | confidential | public

    # ---- derived posture ----

    @property
    def residency(self) -> str:
        base = RESIDENCY.get(self.type, "allowed_with_safeguards")
        # NDMO classification can tighten residency even for otherwise-flexible entities.
        if self.data_classification in ("top_secret", "secret"):
            return "prohibited_without_approval"
        if self.data_classification == "confidential" and base == "allowed_with_safeguards":
            return "in_kingdom_default"
        return base

    @property
    def overlays(self) -> List[str]:
        ov = list(OVERLAYS.get(self.type, []))
        if self.is_public_entity and "NDMO" not in ov:
            ov.append("NDMO")
        if self.uses_ai_on_personal_data:
            ov.append("SDAIA-AI")
        return ov

    @property
    def dpo_required(self) -> bool:
        # DPO triggers: public entity, large-scale sensitive processing, cross-border, children/vulnerable.
        return (
            self.is_public_entity
            or self.type in ("government", "financial", "health")
            or (self.processes_sensitive_data and self.large_scale_processing)
            or self.cross_border_transfers
            or self.processes_children_data
        )

    @property
    def registration_required(self) -> bool:
        # National Data Governance Platform registration triggers.
        return (
            self.is_public_entity
            or self.type == "government"
            or self.processes_sensitive_data
            or self.cross_border_transfers
            or self.processes_children_data
        )

    @property
    def dpia_required(self) -> bool:
        return (
            (self.processes_sensitive_data and self.large_scale_processing)
            or self.processes_children_data
            or self.uses_ai_on_personal_data
        )

    def cross_border_severity(self) -> str:
        """How severe is an unguarded cross-border personal-data flow for THIS entity?"""
        return {
            "prohibited_without_approval": "critical",
            "in_kingdom_default": "high",
            "allowed_with_safeguards": "high",
        }[self.residency]

    def cross_border_remediation(self, lang: str = "en") -> str:
        r = self.residency
        if lang == "ar":
            return {
                "prohibited_without_approval":
                    "هذه البيانات يجب أن تبقى داخل المملكة. النقل خارجها يتطلب موافقة الجهة الرقابية "
                    "المختصة (ساما للجهات المالية / تصنيف NDMO للجهات الحكومية). استضف داخل المملكة لدى مزوّد مرخّص.",
                "in_kingdom_default":
                    "الاستضافة داخل المملكة هي الأصل. أي نقل خارجها يتطلب أساساً نظامياً وضمانة (بنود تعاقدية "
                    "معيارية/كفاية/استثناء) وتقييم مخاطر نقل، مع تقليل الحمولة لأدنى حد.",
                "allowed_with_safeguards":
                    "النقل مسموح بأساس نظامي وضمانة مناسبة (بنود تعاقدية معيارية/كفاية/استثناء) وتقييم مخاطر نقل "
                    "وتقليل البيانات، ويُفضّل الاستضافة داخل المملكة.",
            }[r]
        return {
            "prohibited_without_approval":
                "This data must remain in-Kingdom. Cross-border requires the competent regulator's approval "
                "(SAMA for financial entities / NDMO classification for government). Host in-Kingdom with a "
                "licensed provider.",
            "in_kingdom_default":
                "In-Kingdom hosting is the default. Any cross-border flow needs a lawful basis + safeguard "
                "(SCCs/adequacy/exception) + a transfer risk assessment, with the payload minimized.",
            "allowed_with_safeguards":
                "Cross-border is allowed with a lawful transfer basis + safeguard (SCCs/adequacy/exception) + "
                "a transfer risk assessment + minimization; prefer in-Kingdom hosting.",
        }[r]


# --- Overlay manual controls (surfaced based on entity overlays) ---------------
# Each is a real obligation the scanner cannot prove from code, so it is reported as MANUAL-VERIFY.

OVERLAY_CONTROLS: Dict[str, List[dict]] = {
    "NDMO": [
        {"id": "NDMO-CLASS-01", "severity": "high",
         "title_en": "NDMO data classification applied (Top Secret/Secret/Confidential/Public)",
         "title_ar": "تطبيق تصنيف بيانات NDMO (سري للغاية/سري/مقيّد/عام)",
         "ref": "NDMO Data Classification Policy"},
        {"id": "NDMO-GOV-01", "severity": "medium",
         "title_en": "Chief Data & Privacy Officer / entity data office in place; periodic compliance reports to NDMO",
         "title_ar": "تعيين رئيس بيانات وخصوصية ومكتب بيانات، ورفع تقارير امتثال دورية لـ NDMO",
         "ref": "NDMO National Data Governance Standards"},
    ],
    "NCA-ECC": [
        {"id": "NCA-ECC-01", "severity": "high",
         "title_en": "Information hosting and storage inside the Kingdom (NCA ECC 4.2.3.3)",
         "title_ar": "استضافة وتخزين المعلومات داخل المملكة (ضوابط الأمن السيبراني الأساسية 4.2.3.3)",
         "ref": "NCA Essential Cybersecurity Controls"},
    ],
    "NCA-CCC": [
        {"id": "NCA-CCC-01", "severity": "high",
         "title_en": "Cloud Cybersecurity Controls (CCC) implemented for the hosting model",
         "title_ar": "تطبيق ضوابط الأمن السيبراني للحوسبة السحابية على نموذج الاستضافة",
         "ref": "NCA Cloud Cybersecurity Controls"},
    ],
    "SAMA": [
        {"id": "SAMA-CLOUD-01", "severity": "critical",
         "title_en": "SAMA approval obtained before using cloud services; explicit approval for any cloud outside the Kingdom",
         "title_ar": "الحصول على موافقة ساما قبل استخدام الخدمات السحابية، وموافقة صريحة لأي سحابة خارج المملكة",
         "ref": "SAMA Cloud Computing Regulatory Framework"},
        {"id": "SAMA-RESID-01", "severity": "critical",
         "title_en": "Highly sensitive customer/financial data resides in-Kingdom with in-Kingdom key management",
         "title_ar": "بقاء بيانات العملاء/المالية الحساسة داخل المملكة مع إدارة مفاتيح داخل المملكة",
         "ref": "SAMA CCRF / Cyber Security Framework"},
        {"id": "SAMA-OUT-01", "severity": "high",
         "title_en": "Material outsourcing register maintained; SAMA no-objection for material outsourcing abroad",
         "title_ar": "سجل إسناد جوهري، وعدم ممانعة من ساما للإسناد الجوهري للخارج",
         "ref": "SAMA Rules on Outsourcing"},
    ],
    "CST-CCRF": [
        {"id": "CST-CCRF-01", "severity": "high",
         "title_en": "Workloads mapped to CCRF cloud level; Saudi Government content not transferred outside the Kingdom",
         "title_ar": "تصنيف الأحمال على مستويات إطار الحوسبة السحابية، وعدم نقل محتوى حكومي خارج المملكة",
         "ref": "CST Cloud Computing Regulatory Framework"},
    ],
    "MOH-HEALTH": [
        {"id": "HEALTH-01", "severity": "critical",
         "title_en": "Health data handled under elevated controls (encryption, RBAC, audit log) per MOH/Saudi HIE policies",
         "title_ar": "معالجة البيانات الصحية بضوابط مشددة (تشفير، صلاحيات حسب الدور، سجل تدقيق) وفق سياسات الصحة",
         "ref": "PDPL health-data rules + MOH / Saudi Health Council"},
    ],
    "SFDA-AI": [
        {"id": "SFDA-AI-01", "severity": "medium",
         "title_en": "AI/ML used as a medical device assessed against SFDA MDS-G010 (clinical efficacy, data integrity, cybersecurity)",
         "title_ar": "تقييم الذكاء الاصطناعي كجهاز طبي وفق دليل SFDA MDS-G010",
         "ref": "SFDA MDS-G010"},
    ],
    "SDAIA-AI": [
        {"id": "AI-ADOPT-01", "severity": "medium",
         "title_en": "AI on personal data aligned to SDAIA AI Adoption Framework: data governance, model accountability, transparency, human oversight, risk management",
         "title_ar": "مواءمة الذكاء الاصطناعي على البيانات الشخصية مع إطار سدايا لتبني الذكاء الاصطناعي (حوكمة بيانات، مساءلة نموذج، شفافية، إشراف بشري, إدارة مخاطر)",
         "ref": "SDAIA AI Adoption Framework (2025)"},
    ],
}


def overlay_manual_controls(profile: EntityProfile) -> List[dict]:
    """Return the overlay manual-verify controls that apply to this entity profile."""
    out: List[dict] = []
    seen = set()
    for ov in profile.overlays:
        for ctrl in OVERLAY_CONTROLS.get(ov, []):
            if ctrl["id"] not in seen:
                seen.add(ctrl["id"])
                out.append({
                    "control": ctrl["id"], "domain": f"{ov} overlay",
                    "severity": ctrl["severity"],
                    "title_en": ctrl["title_en"], "title_ar": ctrl["title_ar"],
                    "pdpl_ref": ctrl["ref"], "status": "manual",
                    "confidence": "manual", "overlay": ov,
                })
    return out
