import { ArrowUpRight, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { providerStart, type IdentityProvider } from "@/lib/identity";
import { useI18n } from "@/lib/i18n";

export function FederatedSignIn({
  providers,
  destination,
  reauthenticate = false,
  kind = "login",
}: {
  providers: IdentityProvider[];
  destination: string;
  reauthenticate?: boolean;
  kind?: "login" | "signup";
}) {
  const { locale, t } = useI18n();
  return (
    <div className="federated-entry">
      <p className="identity-caption">{t("identity.centralDescription")}</p>
      {providers
        .filter((provider) => kind !== "signup" || provider.signup_path)
        .map((provider) => (
          <Button asChild key={provider.name} className="h-[52px] w-full">
            <a
              href={providerStart(
                provider,
                destination,
                locale,
                kind,
                reauthenticate,
              )}
            >
              <ShieldCheck size={18} aria-hidden="true" />
              {t(
                kind === "signup"
                  ? "identity.createAccount"
                  : "identity.continue",
              )}
              <ArrowUpRight size={18} aria-hidden="true" />
            </a>
          </Button>
        ))}
    </div>
  );
}
