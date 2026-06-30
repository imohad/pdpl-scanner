---
name: Feature request / new rule
about: Propose a new detection rule, language/framework coverage, or sector-overlay refinement
title: "[feature] "
labels: enhancement
---

**What should the scanner detect or do?**
Describe the PDPL obligation or pattern.

**PDPL / regulatory basis (if applicable)**
Article, Implementing Regulation, or sector guidance (SAMA/NDMO/CST/NCA/SDAIA/health) this maps to.

**Example it should catch**
```text
# paste a representative snippet
```

**Example it should NOT catch (to avoid false positives)**
```text
# paste a near-miss that must stay clean
```

**Detection mode**
- [ ] auto (deterministic FAIL)
- [ ] assisted (high-recall LEAD)
- [ ] manual (organizational checklist item)
