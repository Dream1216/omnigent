import { LogIn } from "lucide-react";
import Head from "next/head";
import { AuthShell } from "@/components/auth-shell";
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
      <AuthShell
        headingId="login-title"
        linkHref="/signup"
        linkLabel={t("page.createWorkspace")}
        prompt={t("page.newUser")}
        skipHref="#email"
        skipLabel={t("page.skip")}
      >
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
      </AuthShell>
    </>
  );
}
