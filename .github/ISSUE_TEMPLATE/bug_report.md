---
name: Bug report
about: A false positive, false negative, crash, or incorrect output
title: "[bug] "
labels: bug
---

**What happened**
A clear description of the bug.

**Control / rule involved (if known)**
e.g. `PDPL-SEC-03`, `PDPL-CB-02`.

**Minimal example**
The smallest code/config snippet that reproduces it (redact real secrets):

```text
# paste here
```

**Command**
e.g. `pdpl-scan ./src --entity financial`

**Expected vs. actual**
- Expected:
- Actual:

**Environment**
- pdpl-scanner version:
- Python version:
- OS:

> For a **false positive**, remember you can suppress with `# pdpl-ignore[CONTROL]` or `.pdplignore`
> while we triage — but please still report it so we can improve the rule.
