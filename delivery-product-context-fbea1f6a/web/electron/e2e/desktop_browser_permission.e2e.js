"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { _electron: electron } = require("playwright");

test("native browser permission asks in a trusted child window and grants only this visit", async () => {
  const app = await electron.launch({
    args: [path.join(__dirname, "fixtures", "browserPermissionApp.cjs")],
  });
  try {
    const site = await app.firstWindow();
    await site.getByText("Permission test site").waitFor({ state: "visible" });
    const promptOpening = app.waitForEvent("window", {
      predicate: (page) => page !== site,
      timeout: 15_000,
    });
    await app.evaluate(() => globalThis.permissionFixture.request());
    const prompt = await promptOpening;
    await prompt.getByRole("heading", { name: "Allow local network access?" }).waitFor();
    const origin = await app.evaluate(() => globalThis.permissionFixture.origin);
    assert.equal(await prompt.locator("#origin").textContent(), origin);
    assert.equal(await app.evaluate(() => globalThis.permissionFixture.check()), false);
    await prompt.locator("#once").click();
    assert.equal(await app.evaluate(() => globalThis.permissionFixture.pending), true);
    assert.equal(await app.evaluate(() => globalThis.permissionFixture.check()), true);
    assert.equal(await app.evaluate(() => globalThis.permissionFixture.saved()), undefined);
  } finally {
    await app.close();
  }
});
