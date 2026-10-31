import Head from "next/head";
import { ShieldCheck } from "lucide-react";
import { AuthShell } from "@/components/auth-shell";
import { IdentitySettings } from "@/components/identity-settings";
import { useI18n } from "@/lib/i18n";

export default function IdentityPage() {
  const { t } = useI18n();
  return (
    <>
      <Head>
        <title>{t("identity.title")} · 胜天半子</title>
        <meta name="robots" content="noindex, nofollow" />
      </Head>
      <AuthShell
        headingId="identity-title"
        linkHref="/settings/account"
        linkLabel={t("identity.back")}
        prompt=""
        skipHref="#identity-title"
        skipLabel={t("identity.title")}
        contentClassName="flow-content"
      >
        <div className="welcome-mark" aria-hidden="true">
          <ShieldCheck size={23} />
        </div>
        <p className="eyebrow">{t("identity.eyebrow")}</p>
        <h1 id="identity-title">
          {t("identity.title")}
          <span>.</span>
        </h1>
        <p className="login-description">{t("identity.description")}</p>
        <IdentitySettings />
      </AuthShell>
    </>
  );
}
