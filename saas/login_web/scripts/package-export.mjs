import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = path.resolve(root, "../login_ui/static");
const html = await readFile(path.join(root, "out/saas/login.html"), "utf8");
// Authorize only the exact Next bootstrap scripts, never unsafe-inline.
const hashes = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)]
  .filter((match) => match[1].trim())
  .map(
    (match) =>
      "'sha256-" + createHash("sha256").update(match[1]).digest("base64") + "'",
  );
// This fixed, generated directory must not retain chunks from previous builds.
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await writeFile(path.join(output, "login.html"), html);
await writeFile(
  path.join(output, "script-hashes.json"),
  JSON.stringify([...new Set(hashes)]),
);
await cp(path.join(root, "out/_next"), path.join(output, "_next"), {
  recursive: true,
});
await cp(
  path.join(root, "node_modules/@fontsource-variable/manrope/LICENSE"),
  path.join(output, "LICENSE-Manrope.txt"),
);
console.log(
  "Packaged Next.js login export with " + hashes.length + " CSP script hashes.",
);
