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
# Foreign third-party data processors (analytics, email, CRM, AI, observability, payments).
# When personal data is handled nearby, sending it to one of these is a cross-border transfer.
FOREIGN_PROCESSOR = re.compile(
    r"\b("
    r"sentry\.io|ingest\.[a-z0-9]+\.sentry\.io|"
    r"segment\.(com|io)|api\.segment\.io|cdn\.segment\.com|"
    r"(api\.)?mixpanel\.com|(api\.)?amplitude\.com|"
    r"google-analytics\.com|googletagmanager\.com|analytics\.google\.com|"
    r"api\.sendgrid\.com|sendgrid\.net|api\.mailgun\.(net|org)|mailgun\.org|"
    r"[a-z0-9.-]*\.list-manage\.com|api\.mailchimp\.com|"
    r"api\.twilio\.com|api\.openai\.com|api\.anthropic\.com|"
    r"api\.stripe\.com|[a-z0-9.-]*\.datadoghq\.com|[a-z0-9.-]*\.newrelic\.com|"
    r"api\.intercom\.io|api\.hubapi\.com|hooks\.slack\.com|"
    r"[a-z0-9-]+\.firebaseio\.com|fcm\.googleapis\.com|onesignal\.com|"
    r"api\.postmarkapp\.com|app\.posthog\.com|bugsnag\.com"
    r")\b",
    re.I)
# --- Transport-security signals (DB / service TLS disabled) -------------------
DB_TLS_DISABLED = re.compile(
    r"sslmode\s*=\s*disable|ssl_mode\s*[:=]\s*['\"]?disable|[?&]ssl=false|"
    r"['\"]?ssl['\"]?\s*[:=]\s*false",
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
    ("PDPL-SEC-02", "high", "auto", DB_TLS_DISABLED, False, False),
    ("PDPL-LOG-01", "high", "auto",
     re.compile(r"(console\.(log|info|debug|warn)|\bprint\s*\(|printf|fmt\.Print|"
                r"logger?\.(info|debug|log|warn)|System\.out\.print|log\.(Info|Debug|Print))", re.I),
     True, False),
    ("PDPL-CB-01", "critical", "auto", NON_KSA_REGION, True, True),
    ("PDPL-CB-02", "critical", "auto", FOREIGN_PROCESSOR, True, True),
]

# Cross-border controls whose severity is re-weighted by the entity profile at runtime.
CROSS_BORDER_CONTROLS = {"PDPL-CB-01", "PDPL-CB-02"}

# --- Assisted-control signals -------------------------------------------------
# These power high-recall WARN leads (confidence="assisted"): a positive signal means "looks
# handled", its absence near personal data means "looks unaddressed". A lead, never a verdict.
SOFT_DELETE = re.compile(
    r"is_deleted|isDeleted|deleted_at|deletedAt|soft[_-]?delete|"
    r"status\s*[:=]\s*['\"]?(inactive|deleted|archived)['\"]?",
    re.I)
ENCRYPTION_HINT = re.compile(
    r"encrypt|decrypt|cipher|\baes\b|\bgcm\b|\bkms\b|fernet|bcrypt|scrypt|argon2|"
    r"\bhash(ed|lib)?\b|vault|sealed|pgp|libsodium|crypto\.",
    re.I)
EXPORT_HINT = re.compile(
    r"export|download[_-]?data|/me/data|data[_-]?portability|gdpr.?export|subject[_-]?access|"
    r"تصدير|تنزيل.?البيانات",
    re.I)
RETENTION_HINT = re.compile(
    r"\bttl\b|expire(s|_?at)?|retention|purge|auto[_-]?delete|cleanup|prune|max[_-]?age|"
    r"احتفاظ|انتهاء.?الصلاحية",
    re.I)
CONSENT_HINT = re.compile(
    r"consent|legal[_-]?basis|lawful[_-]?basis|opt[_-]?in|withdraw[_-]?consent|"
    r"الموافقة|أساس.?نظامي|الأساس.?النظامي",
    re.I)

# Back-compat alias for the bundled Claude skill (it reads these keyword lists).
ASSISTED_HINTS = {
    "PDPL-DSR-02": ["is_deleted", "deleted_at", "soft delete", "status = 'inactive'", "isDeleted"],
    "PDPL-RET-01_positive": ["ttl", "expireat", "expire_at", "retention", "purge", "cleanup cron"],
    "PDPL-LB-01_consent": ["consent", "legal_basis", "purpose", "withdrawconsent", "الموافقة"],
    "PDPL-DSR-01_export": ["export", "download-data", "download_data", "/me/data", "data portability"],
}

# --- Secret triage: placeholders & entropy (reduce PDPL-SEC-03 false positives) ----------------
# A captured credential VALUE that is an obvious placeholder is downgraded to a WARN lead.
# Anchored to the credential keyword so multi-pair lines pick the right value.
SECRET_KV_RX = re.compile(
    r"(?:api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|"
    r"auth[_-]?token|\bsecret\b|\btoken\b)['\"]?\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]",
    re.I)
PLACEHOLDER_SECRETS = {
    "changeme", "change-me", "change_me", "changeit", "change-it", "password", "passwd",
    "secret", "secret_key", "secretkey", "example", "examplekey", "placeholder", "dummy",
    "test", "testing", "yourpassword", "your_password", "your-password", "your_secret",
    "yoursecret", "your-secret", "your_api_key", "your-api-key", "yourapikey", "12345678",
    "password123", "admin", "root", "redacted", "replace_me", "replaceme", "todo", "fixme",
    "none", "null", "supersecret", "mysecret", "hunter2",
}
PLACEHOLDER_RX = re.compile(
    r"^(change[_-]?(me|it)|your[_-]?[\w-]+|example[\w-]*|placeholder|dummy|test[\w-]*|xxx+|"
    r"<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%\([^)]+\)s|replace[_-]?me|redacted|\*+|\.+|-+|_+)$",
    re.I)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    counts: dict = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def is_placeholder_secret(value: str) -> bool:
    """True when a captured credential value looks like a placeholder, not a live secret."""
    v = value.strip()
    if not v:
        return True
    if v.lower() in PLACEHOLDER_SECRETS:
        return True
    if PLACEHOLDER_RX.match(v):
        return True
    if len(set(v)) <= 2:                       # e.g. "aaaaaa", "------", "000000"
        return True
    if len(v) <= 12 and shannon_entropy(v) < 2.5:
        return True
    return False


# --- Inline suppression -------------------------------------------------------
# `# pdpl-ignore` suppresses all controls on the line; `# pdpl-ignore[PDPL-SEC-03,PDPL-CB-01]`
# suppresses only the listed ones. A directive on a line also covers the line below it.
IGNORE_RX = re.compile(r"pdpl-ignore(?:\[\s*([A-Za-z0-9_,\- ]+)\s*\])?", re.I)


def ignore_directive(line: str):
    """Return None (no directive), [] (ignore all controls), or a list of control ids."""
    m = IGNORE_RX.search(line)
    if not m:
        return None
    if m.group(1):
        return [c.strip().upper() for c in m.group(1).split(",") if c.strip()]
    return []

SKIP_DIRS = {".git", "node_modules", "dist", "build", "vendor", "__pycache__", ".venv", "venv",
             ".next", "coverage", "target", ".terraform", "bin", "obj"}
SKIP_EXT = {".min.js", ".lock", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf", ".zip",
            ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".mov", ".pyc"}
MAX_FILE_BYTES = 2_000_000
