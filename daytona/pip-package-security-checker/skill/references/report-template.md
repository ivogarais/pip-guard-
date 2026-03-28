# Structured Report Template

Codex should produce a compact, machine-readable verdict that the renderer can turn into a polished dossier.

## Output Contract

Return JSON only with these keys:

- `decision`: `allow`, `warn`, or `block`
- `risk_level`: `low`, `medium`, `high`, or `critical`
- `confidence`: `low`, `medium`, or `high`
- `malicious`: boolean
- `known_vulnerabilities`: boolean
- `executive_summary`: one short paragraph
- `recommended_action`: one short paragraph
- `recommended_version`: exact version target, range, or `null`
- `suspicious_behavior`: short factual bullets
- `key_evidence`: short factual bullets
- `notes`: optional short bullets

## Editorial Rules

- Treat Codex as the decision layer, not a generic summarizer.
- Distinguish maliciousness from ordinary vulnerabilities.
- Favor evidence from staged artifacts and local reports over speculation.
- If a package appears benign but outdated or vulnerable, prefer `warn`.
- Use `block` only for clearly malicious, deceptive, or dangerously abusive behavior.
- Keep bullets crisp enough to fit cleanly into the rendered HTML dossier.

## What The Renderer Will Do

- Associate advisories to resolved packages using `pypi-vulns.json`
- Render a TeX-style HTML dossier with tables and charts
- Surface the decision, risk, evidence, and recommended action for the wrapper
