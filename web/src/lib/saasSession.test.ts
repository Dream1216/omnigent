import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SAAS_CSRF_STORAGE_KEY, clearSaasCsrf, readSaasCsrf, storeSaasCsrf } from "./saasSession";

describe("SaaS CSRF session storage", () => {
  beforeEach(() => window.sessionStorage.clear());
  afterEach(() => vi.restoreAllMocks());

  it("stores only the trimmed token under the fixed tab-scoped key", () => {
    storeSaasCsrf("  csrf-token  ");

    expect(window.sessionStorage.getItem(SAAS_CSRF_STORAGE_KEY)).toBe("csrf-token");
    expect(readSaasCsrf()).toBe("csrf-token");
  });

  it("clears an existing token explicitly and when given an empty value", () => {
    storeSaasCsrf("csrf-token");
    clearSaasCsrf();
    expect(readSaasCsrf()).toBeNull();

    storeSaasCsrf("csrf-token");
    storeSaasCsrf("   ");
    expect(readSaasCsrf()).toBeNull();
  });

  it("fails closed when browser storage is unavailable", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("blocked");
    });
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("blocked");
    });
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => {
      throw new DOMException("blocked");
    });

    expect(() => storeSaasCsrf("csrf-token")).not.toThrow();
    expect(readSaasCsrf()).toBeNull();
    expect(() => clearSaasCsrf()).not.toThrow();
  });
});
