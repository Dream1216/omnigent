import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { TooltipProvider } from "@/components/ui/tooltip";
import { I18nProvider, LOCALE_STORAGE_KEY } from "@/lib/i18n";
import { LanguageMenuButton, LanguageSettingControl } from "./LanguageSwitcher";

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem(LOCALE_STORAGE_KEY, "en-US");
});

afterEach(() => cleanup());

describe("LanguageSwitcher", () => {
  it("switches language from the sidebar menu", async () => {
    const user = userEvent.setup();
    render(
      <I18nProvider>
        <TooltipProvider>
          <LanguageMenuButton />
        </TooltipProvider>
      </I18nProvider>,
    );

    await user.click(screen.getByRole("button", { name: "Change language" }));
    await user.click(screen.getByRole("menuitem", { name: /中文/ }));

    expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("zh-CN");
    expect(screen.getByRole("button", { name: "切换语言" })).toBeInTheDocument();
  });

  it("switches language from Appearance settings", async () => {
    const user = userEvent.setup();
    render(
      <I18nProvider>
        <LanguageSettingControl />
      </I18nProvider>,
    );

    await user.click(screen.getByRole("button", { name: "Chinese" }));

    expect(screen.getByRole("button", { name: "中文" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("选择 Omnigent 界面使用的语言。")).toBeInTheDocument();
  });
});
