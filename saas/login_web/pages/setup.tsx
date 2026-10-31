import Head from "next/head";
import { FolderPlus } from "lucide-react";
import { AuthShell } from "@/components/auth-shell";
import { FlowIntro } from "@/components/flow-intro";
import { WorkspaceSetup } from "@/components/workspace-setup";
import { useI18n } from "@/lib/i18n";

export default function SetupPage() {
  const { t } = useI18n();
  return (
    <>
      <Head>
        <title>{t("setup.title")} · 胜天半子</title>
        <meta name="robots" content="noindex, nofollow" />
      </Head>
      <AuthShell
        headingId="flow-title"
        contentClassName="flow-content"
        skipHref="#flow-title"
        skipLabel={t("setup.title")}
        linkHref="/saas/account/identities"
        linkLabel={t("identity.title")}
        prompt=""
      >
        <FlowIntro
          step={3}
          icon={<FolderPlus size={23} />}
          eyebrow={t("setup.eyebrow")}
          heading={t("setup.title")}
          description={t("setup.description")}
        />
        <WorkspaceSetup />
        <noscript>
          <p className="login-error">{t("form.noScript")}</p>
        </noscript>
      </AuthShell>
    </>
  );
}
