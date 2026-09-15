# Contributing

Contributions that expand reliable decoding, improve explanations, or strengthen resource isolation are welcome.

1. Fork the repository and create a feature branch from `dev`.
2. Add a minimal, sanitized regression fixture for the behavior being changed.
3. Keep transformations deterministic and bounded. Never execute submitted PowerShell or JavaScript, retrieve remote payloads, or add an implicit paid/AI fallback.
4. Run `npm ci`, `npm run check`, and `npm run test:browser` after installing Chromium with `npx playwright install chromium`.
5. Open a pull request into `dev` and explain what decodes, what remains unknown, and how resource bounds are preserved.

Write public-facing copy for a general audience. Distinguish evidence from inferred behavior, and avoid unsupported malware/safety verdicts. Use inert examples and reserved domains such as `example.invalid`. Do not include credentials, personal data, live malware infrastructure, or confidential incident material in issues or fixtures.

Changes to `main` are promoted from `dev`. Required checks and resolved review conversations protect both long-lived branches. Maintainers should review source, fixtures, dependencies, and workflow changes before merging. Automated checks cannot establish semantic correctness for all PowerShell syntax.

For vulnerabilities, use the private reporting process in [SECURITY.md](SECURITY.md), not a public issue.
