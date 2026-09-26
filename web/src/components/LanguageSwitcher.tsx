import { CheckIcon, LanguagesIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useI18n, type Locale } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const options: readonly { value: Locale; shortLabel: string }[] = [
  { value: "zh-CN", shortLabel: "中文" },
  { value: "en-US", shortLabel: "EN" },
];

export function LanguageMenuButton({ className }: { className?: string }) {
  const { locale, setLocale, t } = useI18n();

  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={t("language.change")}
              className={cn("size-6 text-muted-foreground hover:text-foreground", className)}
              data-testid="language-menu-button"
            >
              <LanguagesIcon className="ui-icon" />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent side="bottom">{t("language.change")}</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end" className="min-w-40">
        {options.map((option) => {
          const label = option.value === "zh-CN" ? t("language.chinese") : t("language.english");
          return (
            <DropdownMenuItem
              key={option.value}
              onSelect={() => setLocale(option.value)}
              className="gap-2"
              data-testid={`language-option-${option.value}`}
            >
              <span className="w-8 text-xs font-medium text-muted-foreground">
                {option.shortLabel}
              </span>
              <span className="flex-1">{label}</span>
              {locale === option.value ? <CheckIcon className="size-4" aria-hidden="true" /> : null}
            </DropdownMenuItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function LanguageSettingControl() {
  const { locale, setLocale, t } = useI18n();

  return (
    <div className="flex flex-col gap-3" data-testid="language-setting-control">
      <div>
        <div className="text-ui font-medium">{t("language.label")}</div>
        <p className="mt-1 text-sm text-muted-foreground">{t("settings.languageDescription")}</p>
      </div>
      <div
        className="inline-flex w-fit rounded-lg border border-border bg-muted/40 p-1"
        role="group"
        aria-label={t("language.change")}
      >
        {options.map((option) => {
          const label = option.value === "zh-CN" ? t("language.chinese") : t("language.english");
          const selected = locale === option.value;
          return (
            <button
              key={option.value}
              type="button"
              onClick={() => setLocale(option.value)}
              aria-pressed={selected}
              className={cn(
                "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                selected
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
