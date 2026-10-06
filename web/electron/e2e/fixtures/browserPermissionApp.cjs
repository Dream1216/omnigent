"use strict";

// Minimal real-Electron host for exercising the bundled local-network prompt.
// Chromium permission dispatch is covered by browserPermissions.test.js; this
// fixture carries the request through the native child window and preload IPC.
const http = require("node:http");
const path = require("node:path");
const { app, BrowserWindow, ipcMain } = require("electron");
const {
  createBrowserPermissionStore,
  registerBrowserPermissions,
} = require("../../src/browserPermissions");
const { createBrowserPermissionPrompt } = require("../../src/browserPermissionPrompt");

app.whenReady().then(async () => {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end("<!doctype html><title>Permission test site</title><h1>Permission test site</h1>");
  });
  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const parent = new BrowserWindow({ width: 900, height: 650, show: true });
  await parent.loadURL(origin);

  let settings = {};
  const store = createBrowserPermissionStore({
    loadSettings: () => structuredClone(settings),
    saveSettings: (next) => {
      settings = structuredClone(next);
    },
  });
  const prompt = createBrowserPermissionPrompt({
    BrowserWindow,
    ipcMain,
    promptPage: path.join(__dirname, "..", "..", "browser-permission", "index.html"),
    preloadPath: path.join(__dirname, "..", "..", "src", "browser_permission_preload.js"),
  });
  prompt.registerIpc();
  const permissionSession = {
    setPermissionRequestHandler(handler) {
      this.requestHandler = handler;
    },
    setPermissionCheckHandler(handler) {
      this.checkHandler = handler;
    },
  };
  const policy = registerBrowserPermissions(permissionSession, {
    canPrompt: () => parent.isVisible() && !parent.isDestroyed(),
    showPrompt: (options) =>
      prompt.show({
        parent,
        getAnchorBounds: () => ({ x: 300, y: 150 }),
        ...options,
      }),
    store,
  });
  policy.attach(parent.webContents);
  globalThis.permissionFixture = {
    origin,
    request() {
      this.pending = new Promise((resolve) => {
        permissionSession.requestHandler(
          parent.webContents,
          "loopback-network",
          resolve,
          { requestingUrl: origin, isMainFrame: true },
        );
      });
    },
    check: () =>
      permissionSession.checkHandler(parent.webContents, "loopback-network", origin, {
        isMainFrame: true,
      }),
    saved: () => store.get(origin),
  };
  parent.on("closed", () => server.close());
});
