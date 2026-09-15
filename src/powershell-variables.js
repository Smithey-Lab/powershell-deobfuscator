import { literalValue } from "./powershell-literals.js";
const quote = (s) => "'" + s.replaceAll("'", "''") + "'";
const serialize = (v) =>
  Array.isArray(v)
    ? "@(" + v.map(serialize).join(",") + ")"
    : typeof v === "string"
      ? quote(v)
      : String(v);
// Conservative straight-line constant propagation. A command invalidates all prior
// bindings, since commands can mutate caller scope. Blocks/comments abort this pass.
export function foldVariables(source, deadline) {
  const segments = [];
  let start = 0,
    depth = 0,
    quoted = null;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (quoted) {
      if (c === "`" && quoted === '"') {
        i++;
        continue;
      }
      if (c === quoted) {
        if (source[i + 1] === quoted) {
          i++;
          continue;
        }
        quoted = null;
      }
      continue;
    }
    if (c === "`") {
      i++;
      continue;
    }
    if (c === "'" || c === '"') {
      quoted = c;
      continue;
    }
    if (c === "#" || c === "{" || c === "}") return { text: source, count: 0 };
    if (c === "(" || c === "[") depth++;
    if (c === ")" || c === "]") depth--;
    if (depth === 0 && (c === ";" || c === "\n")) {
      segments.push([source.slice(start, i), c]);
      start = i + 1;
    }
  }
  if (quoted || depth !== 0) return { text: source, count: 0 };
  segments.push([source.slice(start), ""]);
  const values = new Map();
  let count = 0,
    total = 0;
  const expand = (text) =>
    text.replace(
      /'(?:[^']|'')*'|"(?:`[\s\S]|[^"`]|"")*"|`[\s\S]|\$([a-z_]\w*)(?![\w:])/gi,
      (all, name) => {
        if (!name || !values.has(name.toLowerCase())) return all;
        count++;
        return "(" + serialize(values.get(name.toLowerCase())) + ")";
      },
    );
  const output = [];
  for (const [statement, separator] of segments) {
    if (Date.now() > deadline) return { text: source, count: 0 };
    const assignment = /^\s*\$([a-z_]\w*)\s*=\s*([\s\S]+)$/i.exec(statement);
    let transformed = statement;
    if (assignment) {
      const name = assignment[1].toLowerCase();
      if (
        /^(?:_|psitem|true|false|null|args|input|error|home|pwd|executioncontext|pshome|host|lastexitcode|matches)$/.test(
          name,
        )
      ) {
        values.clear();
      } else {
        const expression = expand(assignment[2]);
        const value = literalValue(expression, deadline);
        values.delete(name);
        if (value === undefined) values.clear();
        else if (values.size < 64) values.set(name, value);
        transformed =
          statement.slice(0, statement.length - assignment[2].length) +
          expression;
      }
    } else if (statement.trim()) {
      transformed = expand(statement);
      values.clear();
    }
    total += transformed.length + separator.length;
    if (total > 32768) return { text: source, count: 0 };
    output.push(transformed + separator);
  }
  return { text: output.join(""), count };
}
