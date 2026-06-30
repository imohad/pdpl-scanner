"""
rules.py — deterministic detection signals.

These are high-recall heuristics that produce CANDIDATE findings; a match is a lead, not a verdict.
The Claude skill (or a human) triages them in context. Every auto finding carries file:line evidence.

KSA-specific identifiers are first-class here, because that is where a generic privacy scanner is
blind: Saudi national ID, iqama, Saudi mobile, Saudi IBAN, plus Arabic field names.
"""
from __future__ import annotations
import re

# --- Saudi personal-data identifiers ------------------------------------------
PII_HINT = re.compile(
    r"national[_-]?id|nationalId|\biqama\b|residence[_-]?id|\bdob\b|date[_-]?of[_-]?birth|"
    r"passport|nationality|الهوية|الهويه|إقامة|اقامة|جواز|الجوال|العنوان|تاريخ.?الميلاد",
    re.I)
PII_VALUE = re.compile(r"\b[12]\d{9}\b|SA\d{22}|\+9665\d{8}|\b05\d{8}\b")
SENSITIVE_HINT = re.compile(
    r"health|medical|diagnos|blood[_-]?type|disability|religion|ethnic|biometric|fingerprint|"
    r"face[_-]?id|genetic|criminal|credit[_-]?score|\bsalary\b|card[_-]?number|\bcvv\b|\biban\b|"
    r"صحي|طبي|تشخيص|فصيلة|إعاقة|الديانة|العرق|بصمة|بنكي|راتب|بطاقة",
    re.I)

# --- Cross-border region signals ----------------------------------------------
# In-Kingdom cloud regions (positive signal). AWS Riyadh, Google Cloud Dammam, Oracle Jeddah/Riyadh,
# Azure Saudi, plus generic .sa and "me-central"/Saudi city tokens.
KSA_REGION = re.compile(
    r"me-central\d?|me-jeddah|me-riyadh|sa-(riyadh|jeddah|dammam)|riyadh|jeddah|dammam|"
    r"saudi|ksa\b|\.sa\b",
    re.I)
# Non-KSA cloud regions / generic foreign region tokens (negative signal).
NON_KSA_REGION = re.compile(
    r"\b(us-(east|west|gov)-\d|eu-(west|central|north|south)-\d|europe-(west|north|central)\d|"
    r"ap-(south|southeast|northeast)-\d|asia-[a-z]+\d|uk-south|us-central\d|"
    r"sa-east-\d|me-south-\d)\b",
    re.I)

# control_id, severity, mode, regex, requires_pii_nearby, skip_if_ksa_region
RULES = [
    ("PDPL-SEC-01", "critical", "auto",
     re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
                r"ssl[._]?verify\s*=\s*false|CURLOPT_SSL_VERIFYPEER\s*,?\s*(0|false)", re.I),
     False, False),
    ("PDPL-SEC-01", "high", "auto",
     re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)"), True, False),
    ("PDPL-SEC-03", "critical", "auto",
     re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|"
                r"(api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|auth[_-]?token)"
                r"\s*[:=]\s*['\"][^'\"\s]{8,}['\"]|"
                r"(mongodb(\+srv)?|postgres(ql)?|mysql|redis)://[^:\s/]+:[^@\s]+@", re.I),
     False, False),
    ("PDPL-SEC-05", "high", "auto",
     re.compile(r"\bmd5\s*\(|hashlib\.md5|\bsha1\s*\(|hashlib\.sha1|"
                r"MessageDigest\.getInstance\(\s*['\"](MD5|SHA-?1)['\"]", re.I),
     False, False),
    ("PDPL-LB-03", "high", "auto",
     re.compile(r"(consent|الموافقة|optin|opt[_-]?in)[^\n]{0,80}"
                r"(checked\s*[:=]?\s*\{?true|defaultChecked|value\s*=\s*['\"](true|1|yes)['\"])", re.I),
     False, False),
    ("PDPL-LOG-01", "high", "auto",
     re.compile(r"(console\.(log|info|debug|warn)|\bprint\s*\(|printf|fmt\.Print|"
                r"logger?\.(info|debug|log|warn)|System\.out\.print|log\.(Info|Debug|Print))", re.I),
     True, False),
    ("PDPL-CB-01", "critical", "auto", NON_KSA_REGION, True, True),
]

# Anti-pattern hints for assisted controls (no hard regex; the skill reads these and the code).
ASSISTED_HINTS = {
    "PDPL-DSR-02": ["is_deleted", "deleted_at", "soft delete", "status = 'inactive'", "isDeleted"],
    "PDPL-RET-01_positive": ["ttl", "expireat", "expire_at", "retention", "purge", "cleanup cron"],
    "PDPL-LB-01_consent": ["consent", "legal_basis", "purpose", "withdrawconsent", "الموافقة"],
    "PDPL-DSR-01_export": ["export", "download-data", "download_data", "/me/data", "data portability"],
}

SKIP_DIRS = {".git", "node_modules", "dist", "build", "vendor", "__pycache__", ".venv", "venv",
             ".next", "coverage", "target", ".terraform", "bin", "obj"}
SKIP_EXT = {".min.js", ".lock", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf", ".zip",
            ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".mov", ".pyc"}
MAX_FILE_BYTES = 2_000_000
