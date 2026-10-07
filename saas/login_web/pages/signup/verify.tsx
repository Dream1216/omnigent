import Head from "next/head";
import { AuthShell } from "@/components/auth-shell";
import { VerificationFlow } from "@/components/verification-flow";
import { useI18n } from "@/lib/i18n";

export default function VerifyPage() {
  const { t } = useI18n();

  return (
    <>
      <Head>
        <title>{t("verify.meta.title")}</title>
        <meta name="description" content={t("verify.meta.description")} />
        <meta name="robots" content="noindex, nofollow" />
      </Head>
      <AuthShell
        contentClassName="flow-content"
        headingId="flow-title"
        linkHref="/saas/login"
        linkLabel={t("signup.signIn")}
        prompt={t("signup.existingUser")}
        skipHref="#flow-title"
        skipLabel={t("verify.skip")}
      >
        <VerificationFlow />
      </AuthShell>
    </>
  );
}
