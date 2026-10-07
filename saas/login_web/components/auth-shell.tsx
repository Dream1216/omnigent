import { ArrowUpRight } from "lucide-react";
import type { ReactNode } from "react";
import { BrandMark, BrandPanel } from "@/components/brand-panel";
import { LanguageSwitcher } from "@/components/language-switcher";
import { useI18n } from "@/lib/i18n";

interface AuthShellProps {
  children: ReactNode;
  contentClassName?: string;
  headingId: string;
  linkHref: string;
  linkLabel: string;
  prompt: string;
  shellClassName?: string;
  skipHref: string;
  skipLabel: string;
}

export function AuthShell({
  children,
  contentClassName = "login-content",
  headingId,
  linkHref,
  linkLabel,
  prompt,
  shellClassName = "",
  skipHref,
  skipLabel,
}: AuthShellProps) {
  const { t } = useI18n();

  return (
    <>
      <a className="skip-link" href={skipHref}>
        {skipLabel}
      </a>
      <main className={`login-shell ${shellClassName}`.trim()}>
        <BrandPanel />
        <section className="login-stage" aria-labelledby={headingId}>
          <header className="stage-header">
            <BrandMark compact />
            <div className="stage-header-actions">
              <LanguageSwitcher />
              <p className="signup-link">
                {prompt}{" "}
                <a href={linkHref}>
                  {linkLabel} <ArrowUpRight size={14} aria-hidden="true" />
                </a>
              </p>
            </div>
          </header>
          <div className={contentClassName}>{children}</div>
          <footer className="stage-footer">
            <span>{t("page.copyright")}</span>
            <a href="/saas/delivery">
              {t("page.deliveryWorkspace")}{" "}
              <ArrowUpRight size={13} aria-hidden="true" />
            </a>
          </footer>
        </section>
      </main>
    </>
  );
}
