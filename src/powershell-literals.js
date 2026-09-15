// An allowlisted literal-expression reader, not a PowerShell interpreter.
// No variables, commands, arbitrary methods, regex execution, or host environment access.
const MAX = 32768;
const q = (s) => "'" + s.replaceAll("'", "''") + "'";
const list = (v) => (Array.isArray(v) ? v : [v]);
const str = (v) =>
  typeof v === "string" ? v : typeof v === "number" ? String(v) : fail();
function fail() {
  throw Error("Unsupported literal expression");
}
function bound(v) {
  if (Array.isArray(v)) {
    if (v.length > 4096 || v.reduce((n, x) => n + str(x).length, 0) > MAX)
      fail();
  } else if (typeof v === "string" && v.length > MAX) fail();
  return v;
}
function join(values, separator) {
  const parts = list(values).map(str);
  if (
    parts.reduce((n, s) => n + s.length, 0) +
      Math.max(0, parts.length - 1) * separator.length >
    MAX
  )
    fail();
  return parts.join(separator);
}
const print = (v) =>
  Array.isArray(v)
    ? "@(" + v.map(print).join(",") + ")"
    : typeof v === "number"
      ? String(v)
      : q(v);
export function foldLiterals(
  source,
  deadline = Date.now() + 1000,
  whole = false,
) {
  const tokens = [];
  // Unknown strings/comments remain single opaque tokens; their contents are never parsed.
  const rx =
    /\s+|<#[\s\S]*?(?:#>|$)|#[^\r\n]*|'(?:[^']|'')*'|"(?:`[\s\S]|[^"`]|"")*"|\[(?:char\[\]|char|string)\]|@\(|0x[\da-f]+|\d+|\.[a-z]+|\.\.|-(?:join|f|bxor|band|bor|shl|shr)\b|\$[\w:]+|[\s\S]/giy;
  let m;
  while ((m = rx.exec(source))) {
    if (/^\s+$/.test(m[0]) || m[0].startsWith("#") || m[0].startsWith("<#"))
      continue;
    tokens.push({ s: m[0], start: m.index, end: rx.lastIndex });
  }
  let steps = 0;
  const methods = new Set();
  function read(start) {
    let i = start,
      ops = 0,
      depth = 0;
    const used = new Set();
    const peek = () => tokens[i]?.s.toLowerCase();
    const eat = (s) => {
      if (peek() !== s) fail();
      i++;
    };
    function expr(min = 0) {
      if (++depth > 40 || ++steps > 30000 || Date.now() > deadline) fail();
      let value;
      const t = tokens[i++]?.s;
      if (!t) fail();
      if (t === "(" || t === "@(") {
        value = expr();
        eat(")");
        if (t === "@(") value = list(value);
      } else if (t.startsWith("'"))
        value = t.slice(1, -1).replaceAll("''", "'");
      else if (t.startsWith('"')) {
        if (/[$`]/.test(t)) fail();
        value = t.slice(1, -1).replaceAll('""', '"');
      } else if (/^(?:0x[\da-f]+|\d+)$/i.test(t)) value = Number(t);
      else if (t === "-") {
        value = expr(110);
        if (typeof value !== "number") fail();
        value = -value;
      } else if (t.toLowerCase() === "-join") {
        value = join(expr(100), "");
        ops++;
        used.add("unary join");
      } else if (/^\[(?:char\[\]|char|string)\]$/i.test(t)) {
        const v = expr(110);
        if (t.toLowerCase() === "[string]")
          value =
            typeof v === "string"
              ? v
              : typeof v === "number"
                ? String(v)
                : fail();
        else if (t.toLowerCase() === "[char[]]") {
          if (typeof v === "string") value = v.split("");
          else
            value = list(v).map((n) => {
              if (!Number.isInteger(n) || n < 0 || n > 65535) fail();
              return String.fromCharCode(n);
            });
        } else {
          if (!Number.isInteger(v) || v < 0 || v > 65535) fail();
          value = String.fromCharCode(v);
        }
        ops++;
        used.add("character/string casts");
      } else fail();
      while (i < tokens.length) {
        if (peek() === "[" && 120 >= min) {
          i++;
          const indexes = list(expr());
          eat("]");
          if (typeof value !== "string" && !Array.isArray(value)) fail();
          value = indexes.map((n) => {
            if (!Number.isInteger(n)) fail();
            const pos = n < 0 ? value.length + n : n;
            if (pos < 0 || pos >= value.length) fail();
            return value[pos];
          });
          if (indexes.length === 1) value = value[0];
          ops++;
          used.add("indexing/reversal");
          continue;
        }
        if (
          /^\.(?:replace|substring|tochararray|tolower|toupper)$/.test(
            peek() || "",
          ) &&
          120 >= min
        ) {
          const name = peek();
          i++;
          eat("(");
          const args = peek() === ")" ? [] : list(expr());
          eat(")");
          if (typeof value !== "string") fail();
          if (name === ".replace") {
            if (
              args.length !== 2 ||
              typeof args[0] !== "string" ||
              !args[0] ||
              typeof args[1] !== "string"
            )
              fail();
            if (value.length * Math.max(1, args[1].length) > MAX) fail();
            value = value.split(args[0]).join(args[1]);
          } else if (name === ".substring") {
            if (
              args.length < 1 ||
              args.length > 2 ||
              args.some((n) => !Number.isInteger(n) || n < 0) ||
              args[0] > value.length ||
              (args.length === 2 && args[0] + args[1] > value.length)
            )
              fail();
            value = value.slice(
              args[0],
              args.length === 2 ? args[0] + args[1] : undefined,
            );
          } else {
            if (args.length) fail();
            if (name === ".tochararray") value = value.split("");
            else {
              // eslint-disable-next-line no-control-regex -- Only ASCII case folding is deterministic here.
              if (/[^\x00-\x7f]/.test(value)) fail();
              value =
                name === ".tolower" ? value.toLowerCase() : value.toUpperCase();
            }
          }
          ops++;
          used.add("allowlisted string methods");
          bound(value);
          continue;
        }
        const op = peek(),
          prec = {
            ",": 90,
            "..": 70,
            "-f": 60,
            "+": 50,
            "-bxor": 40,
            "-band": 40,
            "-bor": 40,
            "-shl": 40,
            "-shr": 40,
            "-join": 30,
          }[op];
        if (prec === undefined || prec < min) break;
        i++;
        const right = expr(prec + 1);
        ops++;
        if (op === ",") {
          value = [...list(value), ...list(right)];
          used.add("literal arrays");
        } else if (op === "..") {
          if (
            !Number.isInteger(value) ||
            !Number.isInteger(right) ||
            Math.abs(right - value) > 4095
          )
            fail();
          const step = value <= right ? 1 : -1;
          value = Array.from(
            { length: Math.abs(right - value) + 1 },
            (_, n) => value + n * step,
          );
          used.add("bounded ranges");
        } else if (op === "+") {
          if (typeof value === "string" && typeof right === "string")
            value += right;
          else if (typeof value === "number" && typeof right === "number")
            value += right;
          else if (Array.isArray(value)) value = [...value, ...list(right)];
          else fail();
          used.add("concatenation/addition");
        } else if (op === "-join") {
          if (typeof right !== "string") fail();
          value = join(value, right);
          used.add("join");
        } else if (op === "-f") {
          if (typeof value !== "string") fail();
          const args = list(right);
          let output = "",
            pos = 0;
          while (pos < value.length) {
            if (value.startsWith("{{", pos)) {
              output += "{";
              pos += 2;
            } else if (value.startsWith("}}", pos)) {
              output += "}";
              pos += 2;
            } else if (value[pos] === "{") {
              const match = /^\{(\d+)\}/.exec(value.slice(pos));
              if (!match || Number(match[1]) >= args.length) fail();
              output += str(args[Number(match[1])]);
              pos += match[0].length;
            } else {
              if (value[pos] === "}") fail();
              output += value[pos++];
            }
            if (output.length > MAX) fail();
          }
          value = output;
          used.add("format placeholders");
        } else {
          if (
            !Number.isInteger(value) ||
            !Number.isInteger(right) ||
            value < 0 ||
            value > 2147483647 ||
            right < 0 ||
            right > 2147483647
          )
            fail();
          if (op === "-bxor") value ^= right;
          else if (op === "-band") value &= right;
          else if (op === "-bor") value |= right;
          else {
            if (right > 30) fail();
            value = op === "-shl" ? value << right : value >> right;
          }
          used.add("literal bitwise operations");
        }
        bound(value);
      }
      depth--;
      return bound(value);
    }
    const value = expr();
    return { value, end: i, ops, used };
  }
  if (whole) {
    const result = read(0);
    if (result.end !== tokens.length) fail();
    return result.value;
  }
  let out = "",
    last = 0;
  for (
    let i = 0;
    i < tokens.length && steps < 30000 && Date.now() < deadline;
    i++
  ) {
    if (!/^(?:\(|@\(|'|"|\[char|\[string|-join\b)/i.test(tokens[i].s)) continue;
    // A binary join with an unknown left operand must not be re-read as unary join.
    if (
      tokens[i].s.toLowerCase() === "-join" &&
      i > 0 &&
      !["(", "@(", ",", "|", "{", ";", "="].includes(tokens[i - 1].s)
    )
      continue;
    try {
      const result = read(i);
      if (
        !result.ops ||
        (result.used.size === 1 && result.used.has("literal arrays"))
      )
        continue;
      const end = tokens[result.end - 1].end;
      const replacement = print(result.value);
      if (replacement === source.slice(tokens[i].start, end)) continue;
      out += source.slice(last, tokens[i].start) + replacement;
      last = end;
      i = result.end - 1;
      for (const name of result.used) methods.add(name);
    } catch {
      /* Unknown syntax remains visible; try independent inner literals. */
    }
  }
  return { text: out + source.slice(last), methods: [...methods] };
}
export function literalValue(source, deadline) {
  try {
    return foldLiterals(source, deadline, true);
  } catch {
    return undefined;
  }
}
