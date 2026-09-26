import { ArrowUpRight, LogIn } from "lucide-react";
import Head from "next/head";
import { BrandMark, BrandPanel } from "@/components/brand-panel";
import { LanguageSwitcher } from "@/components/language-switcher";
import { LoginForm } from "@/components/login-form";
import { useI18n } from "@/lib/i18n";

export default function LoginPage() {
  const { t } = useI18n();

  return (
    <>
      <Head>
        <title>{t("meta.title")}</title>
        <meta name="description" content={t("meta.description")} />
        <meta name="robots" content="noindex, nofollow" />
      </Head>
      <a className="skip-link" href="#email">
        {t("page.skip")}
      </a>
      <main className="login-shell">
        <BrandPanel />
        <section className="login-stage" aria-labelledby="login-title">
          <header className="stage-header">
            <BrandMark compact />
            <div className="stage-header-actions">
              <LanguageSwitcher />
              <p className="signup-link">
                {t("page.newUser")}{" "}
                <a href="/signup">
                  {t("page.createWorkspace")}{" "}
                  <ArrowUpRight size={14} aria-hidden="true" />
                </a>
              </p>
            </div>
          </header>
          <div className="login-content">
            <div className="welcome-mark" aria-hidden="true">
              <LogIn size={23} />
            </div>
            <p className="eyebrow">{t("page.eyebrow")}</p>
            <h1 id="login-title">
              {t("page.headingLead")}
              <br />
              {t("page.headingFocus")}
              <span>{t("page.headingPunctuation")}</span>
            </h1>
            <p className="login-description">{t("page.description")}</p>
            <LoginForm />
          </div>
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
