# Security policy

## Supported versions

Security fixes are maintained on `main`. The `dev` branch is for integration and may contain unreleased changes.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/Smithey-Lab/powershell-deobfuscator/security/advisories/new). Include a minimal inert reproduction, affected version or commit, expected boundary, observed behavior, and any relevant browser details. Do not publish credentials or confidential samples. Response timing depends on maintainer availability; no service-level guarantee is provided.

## Security model

Submitted commands are untrusted text. Analysis must not execute submitted code, fetch extracted URLs, access a target machine's environment, or upload payloads. The UI renders evidence using text nodes. Worker termination, input/output limits, and bounded transformations constrain resource use. Local rate controls can be bypassed and are not hosting-spend controls.

Resource exhaustion, DOM injection, accidental command execution, unexpected outbound requests, and misleading decoding that crosses documented assumptions are relevant reports. Ordinary unsupported syntax is generally a feature request unless it violates a security boundary.

The development server binds to loopback and serves only `src/`. Production deployments should serve the static build with HTTPS and restrictive security headers. Repository automation uses pinned actions and scoped permissions; untrusted pull requests must not receive secrets or run on a privileged `pull_request_target` workflow.
