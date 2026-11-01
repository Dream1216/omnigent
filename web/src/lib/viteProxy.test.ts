import path from "node:path";
import { loadConfigFromFile } from "vite";
import { expect, it, vi } from "vitest";

const origin = "http://localhost:6767";
const headers = { "X-Workspace-Id": "123" };

it.each([
  { name: "unset", setting: undefined, expected: {} },
  { name: "matching origin", setting: JSON.stringify({ [origin]: headers }), expected: headers },
  {
    name: "other origin",
    setting: JSON.stringify({ "https://example.com": headers }),
    expected: {},
  },
  ...[
    "{",
    "null",
    "[]",
    JSON.stringify({ [origin]: null }),
    JSON.stringify({ [origin]: { "X-Id": 123 } }),
    JSON.stringify({ [origin]: { "Bad Name": "123" } }),
    JSON.stringify({ [origin]: { "X-Id": "a\r\nb" } }),
  ].map((setting) => ({ name: "invalid setting", setting, expected: null })),
])("configures proxy headers: $name", async ({ setting, expected }) => {
  try {
    vi.stubEnv("OMNIGENT_URL", origin);
    vi.stubEnv("OMNIGENT_AUTH_TOKEN", "");
    vi.stubEnv("OMNIGENT_PROXY_HEADERS", setting);
    const result = loadConfigFromFile(
      { command: "serve", mode: "development" },
      path.resolve(__dirname, "../../vite.config.ts"),
    );
    if (expected === null) {
      await expect(result).rejects.toThrow();
      return;
    }
    const proxies = (await result)?.config.server?.proxy;
    expect(Object.keys(proxies ?? {})).toEqual([
      "/v1",
      "/api",
      "/auth",
      "/saas/auth",
      "/saas/login",
      "/health",
      "/.well-known",
    ]);
    for (const [route, proxy] of Object.entries(proxies ?? {})) {
      expect(typeof proxy === "object" && proxy.headers).toEqual(
        route.startsWith("/saas/") ? undefined : expected,
      );
    }
  } finally {
    vi.unstubAllEnvs();
  }
});
