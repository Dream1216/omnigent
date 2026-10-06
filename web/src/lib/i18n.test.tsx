import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { I18nProvider, LOCALE_STORAGE_KEY, useI18n, type Locale } from "./i18n";

function Probe() {
  const { locale, setLocale, t } = useI18n();
  return (
    <div>
      <span data-testid="locale">{locale}</span>
      <span>{t("sidebar.newSession")}</span>
      <button type="button" onClick={() => setLocale("en-US")}>
        English
      </button>
      <button type="button" onClick={() => setLocale("zh-CN")}>
        中文
      </button>
    </div>
  );
}

function renderProbe() {
  return render(
    <I18nProvider>
      <Probe />
    </I18nProvider>,
  );
}

beforeEach(() => {
  localStorage.clear();
  document.documentElement.lang = "";
});

afterEach(() => cleanup());

describe("I18nProvider", () => {
  it("reuses the locale selected on the login page", async () => {
    localStorage.setItem(LOCALE_STORAGE_KEY, "zh-CN");

    renderProbe();

    expect(screen.getByTestId("locale")).toHaveTextContent("zh-CN");
    expect(screen.getByText("新建会话")).toBeInTheDocument();
    await waitFor(() => expect(document.documentElement.lang).toBe("zh-CN"));
  });

  it("persists a language change and updates the document language", async () => {
    localStorage.setItem(LOCALE_STORAGE_KEY, "en-US");
    renderProbe();

    fireEvent.click(screen.getByRole("button", { name: "中文" }));

    expect(screen.getByText("新建会话")).toBeInTheDocument();
    expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("zh-CN");
    await waitFor(() => expect(document.documentElement.lang).toBe("zh-CN"));
  });

  it("synchronizes language changes from another browser tab", () => {
    localStorage.setItem(LOCALE_STORAGE_KEY, "en-US");
    renderProbe();

    const nextLocale: Locale = "zh-CN";
    act(() => {
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: LOCALE_STORAGE_KEY,
          newValue: nextLocale,
        }),
      );
    });

    expect(screen.getByTestId("locale")).toHaveTextContent(nextLocale);
    expect(screen.getByText("新建会话")).toBeInTheDocument();
  });
});
