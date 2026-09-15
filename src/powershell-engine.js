// Static evidence extraction only. Never evaluate submitted code or contact its URLs.
import { foldLiterals } from "./powershell-literals.js";
import { extraRules } from "./powershell-rules.js";
import { decodeWrappers } from "./powershell-transforms.js";
import { foldVariables } from "./powershell-variables.js";
export const LIMITS = Object.freeze({
  input: 32768,
  output: 262144,
  layers: 24,
  milliseconds: 2500,
  cooldown: 5000,
  hourly: 60,
});
const quote = (s) => "'" + s.replaceAll("'", "''") + "'";
const literal = "'(?:[^']|'')*'";
const unquote = (s) => s.slice(1, -1).replaceAll("''", "'");
function decode(value, unicode = false) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4)
    throw Error("Invalid Base64");
  const bytes = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  if (unicode && bytes.length % 2) throw Error("Invalid UTF-16LE");
  const encoding =
    unicode || (bytes.length > 3 && bytes[1] === 0 && bytes[3] === 0)
      ? "utf-16le"
      : "utf-8";
  const text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
  // eslint-disable-next-line no-control-regex -- Reject non-text decoded payloads.
  if (/[\x00-\x08\x0e-\x1f]/.test(text)) throw Error("Binary data");
  return { text, bytes };
}
const rules = [
  ...extraRules,
  [
    "Downloads content",
    /\b(?:DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer)\b/i,
    "Contains a web download or request primitive. Retrieved content is unknown; no addresses were visited.",
  ],
  [
    "Evaluates code dynamically",
    /\b(?:iex|Invoke-Expression)\b|\[scriptblock\]\s*::\s*create/i,
    "Contains a primitive that can turn text into executable PowerShell. Its input may be downloaded or constructed at runtime.",
  ],
  [
    "Starts another process",
    /\b(?:Start-Process|saps|cmd\.exe|rundll32|regsvr32|mshta|wscript|cscript)\b/i,
    "References process launch or a program that can run other code. Inspect the arguments and target.",
  ],
  [
    "Hides the PowerShell window",
    /-(?:w|wi|win|windowstyle)\s+hidden\b/i,
    "Requests a hidden window; this can reduce visible signs of execution.",
  ],
  [
    "Changes execution policy",
    /-(?:ep|exec|executionpolicy)\s+(?:bypass|unrestricted)\b|\bSet-ExecutionPolicy\b/i,
    "Requests an execution-policy change or bypass. This alone does not establish malicious intent.",
  ],
  [
    "Possible persistence",
    /\b(?:Register-ScheduledTask|New-Service|schtasks)\b|CurrentVersion\\Run(?:Once)?\b/i,
    "References scheduled tasks, services, or a startup registry key, which can be used to run again later.",
  ],
  [
    "Possible security interference",
    /\b(?:Set-MpPreference|Add-MpPreference|amsiInitFailed|AmsiUtils|EtwEventWrite)\b/i,
    "References security preferences or scanning/tracing internals. Review whether it attempts to weaken protection.",
  ],
  [
    "Writes or removes data",
    /\b(?:Set-Content|Add-Content|Out-File|Remove-Item|WriteAllBytes|WriteAllText)\b/i,
    "Contains a filesystem write or deletion primitive. Check the path and data before drawing conclusions.",
  ],
  [
    "Possible credential access",
    /\b(?:mimikatz|lsass|sekurlsa|Get-Credential|Windows\\Credentials)\b/i,
    "References credentials or credential-related processes. Legitimate credential prompts can match too.",
  ],
  [
    "Network socket access",
    /\b(?:TCPClient|UDPClient|Net\.Sockets)\b/i,
    "References direct network sockets. These may support remote communication; direction and purpose need review.",
  ],
  [
    "Loads code into memory",
    /\b(?:Reflection\.Assembly|VirtualAlloc|CreateThread|DllImport|Add-Type)\b/i,
    "References assembly loading, native APIs, or compilation. Inspect the code being loaded.",
  ],
];
export async function analyze(input) {
  if (typeof input !== "string" || !input.trim())
    throw Error("Paste a PowerShell command first.");
  if (new TextEncoder().encode(input).length > LIMITS.input)
    throw Error("Input exceeds the 32 KiB limit.");
  const layers = [],
    warnings = new Set(),
    seen = new Set([input]);
  let total = new TextEncoder().encode(input).length;
  const queue = [{ text: input, depth: 0 }],
    deadline = Date.now() + LIMITS.milliseconds;
  function add(text, method, parent) {
    if (seen.has(text)) return;
    const bytes = new TextEncoder().encode(text).length;
    if (
      layers.length >= LIMITS.layers ||
      total + bytes > LIMITS.output ||
      parent.depth >= 8
    ) {
      warnings.add("Decoding stopped at the layer, depth, or output limit.");
      return;
    }
    seen.add(text);
    total += bytes;
    const entry = { text, method, depth: parent.depth + 1 };
    layers.push(entry);
    queue.push(entry);
  }
  while (queue.length && Date.now() < deadline) {
    const item = queue.shift(),
      s = item.text;
    const variables = foldVariables(s, deadline);
    if (variables.text !== s)
      add(
        variables.text,
        "Substitute prior literal assignments in a straight-line sequence (candidate)",
        item,
      );
    const wrapped = decodeWrappers(s, deadline);
    if (wrapped.text !== s)
      add(
        wrapped.text,
        `Decode literal wrappers: ${wrapped.methods.join(", ")} (candidate)`,
        item,
      );
    const folded = foldLiterals(s, deadline);
    if (folded.text !== s)
      add(
        folded.text,
        `Reconstruct literal expressions: ${folded.methods.join(", ")} (candidate)`,
        item,
      );
    // These are candidate reconstructions, not a PowerShell parser or equivalent script.
    const normalized = s
      .replace(/`\r?\n/g, "")
      .replace(/`([a-z])/gi, (whole, c) =>
        /[0abefnrtuv]/i.test(c) ? whole : c,
      );
    if (normalized !== s)
      add(
        normalized,
        "Remove line continuations and non-special backtick escapes (candidate)",
        item,
      );
    const simpleQuotes = s.replace(/"([^"$`\r\n]*)"/g, (_, value) =>
      quote(value),
    );
    if (simpleQuotes !== s)
      add(
        simpleQuotes,
        "Normalize double-quoted literals without interpolation (candidate)",
        item,
      );
    const concat = s.replace(
      new RegExp(`(${literal})\\s*\\+\\s*(${literal})`, "g"),
      (_, a, b) => quote(unquote(a) + unquote(b)),
    );
    if (concat !== s)
      add(concat, "Join adjacent single-quoted literals (candidate)", item);
    const chars = s.replace(/\[char\]\s*(0x[\da-f]+|\d+)\b/gi, (all, n) =>
      Number(n) <= 65535 ? quote(String.fromCharCode(Number(n))) : all,
    );
    if (chars !== s)
      add(chars, "Decode literal character codes (candidate)", item);
    const formatted = s.replace(
      new RegExp(
        `\\((${literal})\\s+-f\\s+((?:${literal}\\s*,\\s*)*${literal})\\s*\\)`,
        "gi",
      ),
      (all, fmt, args) => {
        const values = args.match(new RegExp(literal, "g")).map(unquote),
          raw = unquote(fmt);
        if (!/^(?:[^{}]|\{\d+\})*$/.test(raw)) return all;
        if (
          [...raw.matchAll(/\{(\d+)\}/g)].some(
            (m) => Number(m[1]) >= values.length,
          )
        )
          return all;
        return quote(raw.replace(/\{(\d+)\}/g, (_, n) => values[Number(n)]));
      },
    );
    if (formatted !== s)
      add(
        formatted,
        "Resolve simple literal format expressions (candidate)",
        item,
      );
    const matches = [
      ...s.matchAll(
        /-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+["']?([A-Za-z0-9+/]+={0,2})/gi,
      ),
    ].map((m) => ({ value: m[1], unicode: true }));
    for (const m of s.matchAll(
      /FromBase64String\s*\(\s*['"]([A-Za-z0-9+/]+={0,2})['"]\s*\)/gi,
    ))
      matches.push({ value: m[1], unicode: false });
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(s.trim()) && s.trim().length >= 12)
      matches.push({ value: s.trim(), unicode: false });
    for (const m of matches.slice(0, 24)) {
      try {
        add(
          decode(m.value, m.unicode).text,
          m.unicode
            ? "Decode EncodedCommand as UTF-16LE"
            : "Decode literal Base64 text (encoding inferred)",
          item,
        );
      } catch {
        warnings.add(
          "Some Base64 data is binary, malformed, or not readable text.",
        );
      }
      // Only recognized compression wrappers; streamed output is capped before accumulation.
      if (
        (m.value.startsWith("H4sI") || /\bDeflateStream\b/i.test(s)) &&
        typeof DecompressionStream !== "undefined"
      ) {
        let reader;
        try {
          const bytes = Uint8Array.from(atob(m.value), (c) => c.charCodeAt(0));
          const format = m.value.startsWith("H4sI")
            ? "gzip"
            : bytes[0] === 0x78 && (bytes[0] * 256 + bytes[1]) % 31 === 0
              ? "deflate"
              : "deflate-raw";
          reader = new Blob([bytes])
            .stream()
            .pipeThrough(new DecompressionStream(format))
            .getReader();
          const chunks = [];
          let size = 0;
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.length;
            if (size > LIMITS.output - total || Date.now() > deadline)
              throw Error("Expansion limit");
            chunks.push(value);
          }
          const output = new Uint8Array(size);
          let offset = 0;
          for (const chunk of chunks) {
            output.set(chunk, offset);
            offset += chunk.length;
          }
          const encoding =
            output.length > 3 && output[1] === 0 && output[3] === 0
              ? "utf-16le"
              : "utf-8";
          add(
            new TextDecoder(encoding, { fatal: true }).decode(output),
            `Expand ${format} Base64 (${encoding} candidate)`,
            item,
          );
        } catch {
          warnings.add(
            "Compressed data could not be expanded within the safety limits.",
          );
        } finally {
          if (reader) await reader.cancel().catch(() => {});
        }
      }
    }
  }
  if (queue.length) warnings.add("Analysis stopped at the time limit.");
  const texts = [input, ...layers.map((l) => l.text)],
    findings = [];
  for (const [title, pattern, explanation] of rules) {
    for (let i = 0; i < texts.length; i++) {
      const match = pattern.exec(texts[i]);
      if (match) {
        findings.push({ title, explanation, evidence: match[0], layer: i });
        break;
      }
    }
  }
  const indicators = [
    ...new Set(
      texts.flatMap((t) => t.match(/\bhttps?:\/\/[^\s'"<>`)\];]+/gi) || []),
    ),
  ].slice(0, 100);
  warnings.add(
    "Static pattern analysis only: matches can occur in comments or strings. Candidates are not guaranteed equivalent to the original. No finding proves execution, intent, or safety.",
  );
  warnings.add(
    "Runtime variables, custom encryption, XOR loops, remote payloads, and other unsupported syntax may remain unresolved.",
  );
  const download = findings.some((f) => f.title === "Downloads content"),
    execute = findings.some((f) => f.title === "Evaluates code dynamically");
  const indirect = findings.some(
    (f) => f.title === "Indirect command invocation",
  );
  const unresolved = [];
  if (findings.some((f) => f.title === "Environment-based name construction"))
    unresolved.push(
      "Environment values are required to resolve environment-derived names. They are not inferred from this browser or a typical Windows installation.",
    );
  if (findings.some((f) => f.title === "Uses pipeline-dependent values"))
    unresolved.push(
      "Pipeline variables require the upstream command and its output. Unknown commands and aliases are not simulated.",
    );
  if (findings.some((f) => f.title === "Cryptographic transformation"))
    unresolved.push(
      "Cryptographic wrappers may require a key or runtime context that is not present in the text.",
    );
  if (findings.some((f) => f.title === "Downloads content"))
    unresolved.push(
      "Downloaded content is unavailable: this analyzer does not fetch remote payloads.",
    );
  const invoked = [
    ...new Set(
      texts.flatMap((t) =>
        [
          ...t.matchAll(/&\s*(?:\(\s*'((?:[^']|'')+)'\s*\)|'((?:[^']|'')+)')/g),
        ].map((m) => (m[1] ?? m[2]).replaceAll("''", "'")),
      ),
    ),
  ].slice(0, 20);
  return {
    version: 2,
    ruleCount: rules.length,
    invoked,
    unresolved,
    summary:
      download && execute
        ? "Possible download-and-execute behavior: both web retrieval and dynamic code evaluation appear. Their connection requires review."
        : indirect
          ? "Constructs and invokes a command indirectly. Review recovered literals below; environment and pipeline values may leave the actual command unresolved."
          : findings.length
            ? "Review the behavior indicators below; they describe capabilities visible in the text."
            : "No recognized behavior indicators found. This does not mean the command is safe.",
    findings,
    indicators,
    layers,
    warnings: [...warnings],
  };
}
