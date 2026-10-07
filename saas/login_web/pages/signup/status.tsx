import Head from "next/head";
import { AuthShell } from "@/components/auth-shell";
import { StatusFlow } from "@/components/status-flow";
import { useI18n } from "@/lib/i18n";

export default function StatusPage() {
  const { t } = useI18n();

  return (
    <>
      <Head>
        <title>{t("status.meta.title")}</title>
        <meta name="description" content={t("status.meta.description")} />
        <meta name="robots" content="noindex, nofollow" />
      </Head>
      <AuthShell
        contentClassName="flow-content"
        headingId="flow-title"
        linkHref="/saas/login"
        linkLabel={t("signup.signIn")}
        prompt={t("signup.existingUser")}
        skipHref="#flow-title"
        skipLabel={t("status.skip")}
      >
        <StatusFlow />
      </AuthShell>
    </>
  );
}
