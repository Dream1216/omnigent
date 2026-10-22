import { Languages } from "lucide-react";
import { useI18n, type Locale } from "@/lib/i18n";

const options: ReadonlyArray<{ value: Locale; label: string }> = [
  { value: "zh-CN", label: "中文" },
  { value: "en-US", label: "EN" },
];

export function LanguageSwitcher() {
  const { locale, setLocale, t } = useI18n();

  return (
    <div
      className="language-switcher"
      role="group"
      aria-label={t("language.change")}
      title={t("language.change")}
    >
      <Languages size={14} aria-hidden="true" />
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className="language-option"
          aria-pressed={locale === option.value}
          aria-label={
            option.value === "zh-CN"
              ? t("language.chinese")
              : t("language.english")
          }
          onClick={() => setLocale(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
