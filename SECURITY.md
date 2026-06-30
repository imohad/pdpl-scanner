# Security Policy

## Reporting a vulnerability

If you find a security issue in **pdpl-scanner itself** (not in a project it scans), please report it
privately rather than opening a public issue:

- Use GitHub's **[Report a vulnerability](https://github.com/imohad/pdpl-scanner/security/advisories/new)**
  (Security → Advisories), or
- Email the maintainer.

Please include reproduction steps and the scanner version (`pdpl-scan --help` / `pyproject.toml`).
We aim to acknowledge reports within a few days.

## Scope

`pdpl-scanner` is a static analyzer with **zero runtime dependencies** and does not execute the code it
scans. It only reads files. Findings it reports about *your* codebase are guidance, not a guarantee —
see [DISCLAIMER.md](DISCLAIMER.md).

## A note on secrets in findings

Reports (JSON / SARIF / Markdown / HTML) can contain snippets of matched lines, including fragments of
secrets the scanner detected. Treat scan artifacts as sensitive and avoid committing them
(`.gitignore` already excludes the default output filenames).
