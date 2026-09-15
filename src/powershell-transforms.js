import { literalValue } from "./powershell-literals.js";
const q = (s) => "'" + s.replaceAll("'", "''") + "'";
// Exact literal wrappers only. No submitted regular expressions or code are run.
export function decodeWrappers(source, deadline) {
  const notes = new Set();
  let text = source;
  text = text.replace(
    /\[(?:System\.)?Uri\]::UnescapeDataString\(\s*('(?:[^']|'')*')\s*\)/gi,
    (all, arg) => {
      try {
        const v = literalValue(arg, deadline);
        if (typeof v !== "string") return all;
        const out = decodeURIComponent(v);
        notes.add("URI percent decoding");
        return q(out);
      } catch {
        return all;
      }
    },
  );
  text = text.replace(
    /\[(?:System\.)?Text\.Encoding\]::(UTF8|Unicode|ASCII|BigEndianUnicode)\.GetString\(\s*\[(?:System\.)?Convert\]::From(Base64|Hex)String\(\s*'([a-z0-9+/=\s]+)'\s*\)\s*\)/gi,
    (all, encoding, kind, payload) => {
      try {
        let bytes;
        if (kind.toLowerCase() === "hex") {
          if (!/^(?:[\da-f]{2})+$/i.test(payload)) return all;
          bytes = Uint8Array.from(payload.match(/../g), (x) => parseInt(x, 16));
        } else {
          bytes = Uint8Array.from(atob(payload), (c) => c.charCodeAt(0));
        }
        if (encoding.toLowerCase() === "ascii" && bytes.some((x) => x > 127))
          return all;
        const out = new TextDecoder(
          {
            unicode: "utf-16le",
            bigendianunicode: "utf-16be",
            ascii: "utf-8",
            utf8: "utf-8",
          }[encoding.toLowerCase()],
          { fatal: true },
        ).decode(bytes);
        notes.add("explicit text encoding wrapper");
        return q(out);
      } catch {
        return all;
      }
    },
  );
  text = text.replace(
    /\(\s*\(?\s*((?:\d+\s*,\s*)+\d+)\s*\)?\s*\|\s*(?:%|ForEach-Object|foreach)\s*\{\s*\[char\]\s*\(\s*\$_\s*-bxor\s*(\d+)\s*\)\s*\}\s*\)/gi,
    (all, numbers, key) => {
      const values = numbers.split(",").map(Number);
      if (
        values.length > 4096 ||
        Number(key) > 65535 ||
        values.some((v) => v > 65535)
      )
        return all;
      notes.add("literal byte-array XOR pipeline");
      return (
        "@(" +
        values.map((n) => q(String.fromCharCode(n ^ Number(key)))).join(",") +
        ")"
      );
    },
  );
  return { text, methods: [...notes] };
}
