import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = path.resolve(root, "../login_ui/static");
const pages = new Map([
  ["login.html", "out/saas/login.html"],
  ["signup.html", "out/signup.html"],
  ["signup-verify.html", "out/signup/verify.html"],
  ["signup-status.html", "out/signup/status.html"],
]);
const exports = new Map(
  await Promise.all(
    [...pages].map(async ([destination, source]) => [
      destination,
      await readFile(path.join(root, source), "utf8"),
    ]),
  ),
);
// Authorize only the exact Next bootstrap scripts, never unsafe-inline.
const hashes = [...exports.values()].flatMap((html) =>
  [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)]
    .filter((match) => match[1].trim())
    .map(
      (match) =>
        "'sha256-" +
        createHash("sha256").update(match[1]).digest("base64") +
        "'",
    ),
);
// This fixed, generated directory must not retain chunks from previous builds.
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await Promise.all(
  [...exports].map(([destination, html]) =>
    writeFile(path.join(output, destination), html),
  ),
);
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
  `Packaged ${exports.size} Next.js auth pages with ${hashes.length} CSP script hashes.`,
);
