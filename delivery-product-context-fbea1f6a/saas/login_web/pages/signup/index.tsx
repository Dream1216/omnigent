import { UserPlus } from "lucide-react";
import Head from "next/head";
import { AuthShell } from "@/components/auth-shell";
import { FlowIntro } from "@/components/flow-intro";
import { SignupForm } from "@/components/signup-form";
import { useI18n } from "@/lib/i18n";

export default function SignupPage() {
  const { t } = useI18n();

  return (
    <>
      <Head>
        <title>{t("signup.meta.title")}</title>
        <meta name="description" content={t("signup.meta.description")} />
        <meta name="robots" content="noindex, nofollow" />
      </Head>
      <AuthShell
        contentClassName="signup-content"
        headingId="flow-title"
        linkHref="/saas/login"
        linkLabel={t("signup.signIn")}
        prompt={t("signup.existingUser")}
        shellClassName="signup-shell"
        skipHref="#signup"
        skipLabel={t("signup.skip")}
      >
        <FlowIntro
          step={1}
          icon={<UserPlus size={23} />}
          eyebrow={t("signup.eyebrow")}
          heading={t("signup.heading")}
          description={t("signup.description")}
        />
        <SignupForm />
      </AuthShell>
    </>
  );
}
