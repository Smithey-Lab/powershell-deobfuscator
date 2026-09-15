import { cp, mkdir, readdir, readFile } from "node:fs/promises";
await mkdir("dist", { recursive: true });
await cp("src", "dist", { recursive: true });
for (const file of await readdir("dist")) {
  if (!/\.(?:html|css|js|jpg)$/.test(file))
    throw Error(`Unexpected public file: ${file}`);
}
const html = await readFile("dist/index.html", "utf8");
for (const [, path] of html.matchAll(/(?:href|src)="\.\/([^"]+)"/g))
  await readFile(`dist/${path}`);
console.log("Built standalone static site.");
