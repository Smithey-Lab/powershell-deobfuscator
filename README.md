# PowerShell Deobfuscator

[![CI](https://github.com/Smithey-Lab/powershell-deobfuscator/actions/workflows/ci.yml/badge.svg)](https://github.com/Smithey-Lab/powershell-deobfuscator/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Smithey-Lab/powershell-deobfuscator/actions/workflows/codeql.yml/badge.svg)](https://github.com/Smithey-Lab/powershell-deobfuscator/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A browser-local tool from **Smithey Lab** for unpacking obfuscated PowerShell and explaining behavior indicators with evidence.

**[Use the hosted tool](https://smitheylab.com/tools/powershell-deobfuscator/)** · [Report a bug](https://github.com/Smithey-Lab/powershell-deobfuscator/issues/new/choose) · [Contribute](CONTRIBUTING.md)

## What it does

- Decodes EncodedCommand, Base64, explicit text/hex wrappers, and URI escapes.
- Expands bounded gzip, raw deflate, and zlib payloads.
- Reconstructs nested literal formatting, concatenation, joins, character arrays, indexing/reversal, selected string methods, and constant bitwise expressions.
- Tracks conservative straight-line literal assignments and recognizes a constrained literal XOR pipeline.
- Reports 39 behavior-rule families, recovered invocation targets, extracted URLs, decoding candidates, and unresolved dependencies.
- Exports a JSON report on request.

## Privacy and limits

**No AI, analysis backend, command execution, or payload uploads.** Static files load from the host; analysis runs in a Web Worker on the visitor's device. Extracted URLs are inert text and are never visited. Only usage timestamps are stored locally. Exported reports can contain sensitive text.

Input is limited to 32 KiB UTF-8, total candidate text to 256 KiB, candidate count to 24, and decoding depth to 8. Analysis has a cooperative 2.5-second deadline and a 3-second worker cutoff. Browser usage limits allow one analysis at a time, a 5-second cooldown, and 60 attempts per hour. These are bypassable local resource limits, not server-side abuse protection or a hosting-spend cap.

Static analysis cannot resolve every script. Runtime environment values, custom aliases, complex control flow, encryption keys, and remote payloads can prevent reconstruction. Pattern matches can occur in comments or strings. Candidates are not guaranteed semantically equivalent to the original. **No result establishes that a command is safe.**

## Run locally

Requirements: Node.js 24 or newer and npm.

```sh
git clone https://github.com/Smithey-Lab/powershell-deobfuscator.git
cd powershell-deobfuscator
npm ci
npm run dev
```

Open http://127.0.0.1:5174. Use an HTTP server; browser module workers do not reliably work with `file://` URLs.

```sh
npm run check                 # lint, formatting, unit tests, static build
npx playwright install chromium
npm run test:browser           # browser behavior and privacy regression tests
npm run format                # apply formatting
```

## Use the engine

```js
import { analyze } from "./src/powershell-engine.js";
const report = await analyze("Write-Output ('{1}{0}' -f ' Lab','Smithey')");
console.log(report.layers);
```

Keep untrusted analysis inside a worker with an external timeout, as the included UI does. Calling the engine directly does not provide the browser's hard worker cutoff.

## Deploy

`npm run build` produces `dist/`, a standalone static site. Serve it over HTTPS. No AWS account, API keys, backend, or cloud deployment is required. The standalone UI works at a root path or under a subdirectory. Configure security headers on the hosting platform; the development server demonstrates a restrictive Content Security Policy. There is no automatic deployment to Smithey Lab from this repository.

## Project structure

- `src/powershell-engine.js`: bounded decoding and report assembly.
- `src/powershell-literals.js`: allowlisted literal-expression reader.
- `src/powershell-transforms.js`: explicit wrapper decoders.
- `src/powershell-variables.js`: conservative constant propagation.
- `src/powershell-rules.js`: additional behavior heuristics.
- `src/powershell-worker.js`, `src/powershell.js`: worker isolation and UI.
- `tests/`: decoder and browser regressions.

`main` is the stable branch; `dev` integrates contributions. Start feature branches from `dev`, open pull requests into `dev`, and promote tested changes through a `dev` → `main` pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for review expectations and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

MIT © 2026 Smithey Lab. See [LICENSE](LICENSE). The license does not grant permission to imply endorsement by Smithey Lab.
