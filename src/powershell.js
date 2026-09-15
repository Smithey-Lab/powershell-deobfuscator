import { LIMITS } from "./powershell-engine.js";
const $ = (id) => document.getElementById(id),
  input = $("ps-input"),
  status = $("ps-status");
let worker = null,
  timer = null,
  report = null,
  attempts = [];
const key = "smithey-lab-powershell-attempts-v1";
function finish() {
  worker?.terminate();
  worker = null;
  clearTimeout(timer);
  $("ps-run").disabled = false;
}
function card(title, text) {
  const el = document.createElement("article");
  el.className = "checker-result-card";
  const h = document.createElement("h3");
  h.textContent = title;
  el.append(h);
  if (text) {
    const p = document.createElement("p");
    p.textContent = text;
    el.append(p);
  }
  return el;
}
function render(result) {
  report = result;
  $("ps-summary").textContent = result.summary;
  const cards = $("ps-cards");
  cards.replaceChildren();
  if (result.invoked?.length) {
    const el = card(
      "Recovered invocation targets",
      "Literal command names recovered from invocation expressions. Their definitions and availability on the target host are unknown.",
    );
    const pre = document.createElement("pre");
    pre.textContent = result.invoked.join("\n");
    el.append(pre);
    cards.append(el);
  }
  if (result.unresolved?.length) {
    const el = card("What prevents full decoding");
    for (const reason of result.unresolved) {
      const p = document.createElement("p");
      p.textContent = reason;
      el.append(p);
    }
    cards.append(el);
  }
  for (const finding of result.findings) {
    const el = card(finding.title, finding.explanation);
    const evidence = document.createElement("pre");
    evidence.textContent = `${finding.layer === 0 ? "Original input" : `Candidate ${finding.layer}`}: ${finding.evidence}`;
    el.append(evidence);
    cards.append(el);
  }
  const urls = card("Extracted URLs", "Text only. No addresses were visited.");
  const pre = document.createElement("pre");
  pre.textContent =
    result.indicators.join("\n") || "No literal HTTP(S) URLs found.";
  urls.append(pre);
  cards.append(urls);
  const caveats = card("Limits of this analysis");
  const list = document.createElement("ul");
  for (const warning of result.warnings) {
    const li = document.createElement("li");
    li.textContent = warning;
    list.append(li);
  }
  caveats.append(list);
  cards.append(caveats);
  if (!result.layers.length)
    cards.append(
      card(
        "No supported layers decoded",
        "The original text was checked for behavior indicators. Unsupported obfuscation may still be present.",
      ),
    );
  result.layers.forEach((layer, i) => {
    const el = document.createElement("details");
    el.className = "checker-result-card";
    const title = document.createElement("summary");
    title.textContent = `Candidate ${i + 1}: ${layer.method}`;
    const code = document.createElement("pre");
    code.textContent = layer.text;
    el.append(title, code);
    cards.append(el);
  });
  $("ps-results").hidden = false;
  $("ps-title").focus();
}
$("ps-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (worker) return;
  if (
    !input.value.trim() ||
    new TextEncoder().encode(input.value).length > LIMITS.input
  ) {
    status.textContent = "Paste a nonempty command no larger than 32 KiB.";
    return;
  }
  const now = Date.now();
  try {
    const saved = JSON.parse(localStorage.getItem(key) || "[]");
    if (Array.isArray(saved))
      attempts = [...new Set([...attempts, ...saved.filter(Number.isFinite)])];
  } catch {
    /* Session-only limits when storage is unavailable. */
  }
  attempts = attempts.filter((t) => t > now - 3600000).sort((a, b) => a - b);
  if (attempts.length >= LIMITS.hourly) {
    status.textContent =
      "Browser limit reached: 60 attempts per hour. Try again later.";
    return;
  }
  if (attempts.length && now - attempts.at(-1) < LIMITS.cooldown) {
    status.textContent = "Please wait 5 seconds between analyses.";
    return;
  }
  attempts.push(now);
  try {
    localStorage.setItem(key, JSON.stringify(attempts));
  } catch {}
  $("ps-results").hidden = true;
  report = null;
  $("ps-run").disabled = true;
  status.textContent = "Analyzing locally…";
  try {
    worker = new Worker(new URL("./powershell-worker.js", import.meta.url), {
      type: "module",
    });
    timer = setTimeout(() => {
      finish();
      status.textContent =
        "Stopped at the 3-second safety limit. Try a smaller portion of the command.";
    }, 3000);
    worker.onmessage = ({ data }) => {
      finish();
      if (data.error) {
        status.textContent = data.error;
        return;
      }
      render(data.result);
      status.textContent =
        "Analysis complete. Nothing was executed or uploaded.";
    };
    worker.onerror = () => {
      finish();
      status.textContent = "Analysis could not complete in this browser.";
    };
    worker.postMessage(input.value);
  } catch {
    finish();
    status.textContent =
      "This browser could not start the local analysis worker.";
  }
});
$("ps-clear").addEventListener("click", () => {
  finish();
  input.value = "";
  report = null;
  $("ps-cards").replaceChildren();
  $("ps-results").hidden = true;
  status.textContent = "Cleared. Nothing was saved by the tool.";
  input.focus();
});
$("ps-example").addEventListener("click", () => {
  if (worker) return;
  input.value =
    "Write-Output ('{1}{0}' -f ' Lab','Smithey'); Write-Output ([char]72 + [char]105)";
  status.textContent = "Harmless example loaded. Select Analyze command.";
  input.focus();
});
$("ps-download").addEventListener("click", () => {
  if (!report) return;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = "powershell-analysis.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
