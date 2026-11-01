import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  ArrowRight,
  Check,
  ChevronDown,
  FolderPlus,
  LoaderCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { identityJson, IdentityError } from "@/lib/identity";
import { safeReturnTarget } from "@/lib/auth";
import { useI18n, type MessageKey } from "@/lib/i18n";

interface Scope {
  tenant_id: string;
  space_id: string;
  tenant_name: string;
  space_name: string;
}
interface Bootstrap {
  authenticated: boolean;
  scopes: Scope[];
}
interface Intent {
  id: string;
  name: string;
}
interface Catalog {
  plans: { key: string; trial_days: number }[];
  regions: string[];
}
interface Status {
  state:
    | "pending"
    | "provisioning"
    | "ready_for_first_run"
    | "complete"
    | "recovering"
    | "support_required";
  stage: string;
  tenant_id?: string;
  space_id?: string;
  support_reference?: string;
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const requestKey = "omnigent.saas.workspace-request";

async function rememberRequest(name: string): Promise<string> {
  try {
    const stored = JSON.parse(sessionStorage.getItem(requestKey) || "null");
    // Persist no workspace name: the fingerprint only identifies an unchanged retry.
    const fingerprint = Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(name)),
      ),
    )
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    if (stored?.fingerprint === fingerprint && typeof stored.key === "string")
      return stored.key;
    const key = crypto.randomUUID();
    sessionStorage.setItem(requestKey, JSON.stringify({ fingerprint, key }));
    return key;
  } catch {
    throw new IdentityError("browser_storage_unavailable");
  }
}

function errorKey(error: unknown): MessageKey {
  const code = error instanceof IdentityError ? error.code : "request_failed";
  if (code === "verified_email_required") return "setup.verifyEmail";
  if (code === "verified_contact_required") return "setup.verifyContact";
  if (code === "identity_verification_pending") return "setup.checkingContact";
  if (code === "workspace_creation_limited") return "setup.limited";
  if (code === "browser_storage_unavailable") return "identity.storageError";
  if (code.startsWith("invitation")) return "setup.invitationError";
  if (code === "idempotency_conflict") return "setup.changedRequest";
  if (code === "network_unavailable") return "error.network";
  if (code === "request_timeout") return "error.timeout";
  return "error.unavailable";
}

export function WorkspaceSetup() {
  const { t } = useI18n();
  const [account, setAccount] = useState<Bootstrap | null>(null);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [intents, setIntents] = useState<Intent[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [name, setName] = useState("");
  const [invitation, setInvitation] = useState("");
  const [invitationOpen, setInvitationOpen] = useState(false);
  const [invitationAccepted, setInvitationAccepted] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const pending = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    setLoading(true);
    setCatalog(null);
    async function load() {
      try {
        const value = await identityJson<Bootstrap>("/saas/auth/bootstrap", {
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        if (
          typeof value.authenticated !== "boolean" ||
          !Array.isArray(value.scopes)
        )
          throw new IdentityError("invalid_response");
        setAccount(value);
        if (!value.authenticated) return;
        const [requests, catalogResult] = await Promise.allSettled([
          identityJson<Intent[]>("/saas/onboarding/workspaces", {
            signal: controller.signal,
          }),
          identityJson<Catalog>("/saas/onboarding/catalog", {
            signal: controller.signal,
          }),
        ]);
        if (controller.signal.aborted) return;
        if (
          catalogResult.status === "fulfilled" &&
          Array.isArray(catalogResult.value.plans) &&
          catalogResult.value.plans.length &&
          Array.isArray(catalogResult.value.regions) &&
          catalogResult.value.regions.length
        )
          setCatalog(catalogResult.value);
        else
          setError(
            catalogResult.status === "rejected"
              ? catalogResult.reason
              : new IdentityError("invalid_response"),
          );
        if (requests.status === "fulfilled" && Array.isArray(requests.value)) {
          const valid = requests.value.filter(
            (row) => uuid.test(row.id) && typeof row.name === "string",
          );
          setIntents(valid);
          const params = new URLSearchParams(window.location.search);
          const target = params.get("intent");
          setSelected(
            target && uuid.test(target)
              ? target
              : params.get("new") === "1"
                ? null
                : valid[0]?.id || null,
          );
        } else
          setError(
            requests.status === "rejected"
              ? requests.reason
              : new IdentityError("invalid_response"),
          );
      } catch (cause) {
        if (!controller.signal.aborted) setError(cause);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [attempt]);

  useEffect(() => {
    const refresh = (event: StorageEvent) => {
      if (event.key === "omnigent.saas.csrf") setAttempt((value) => value + 1);
    };
    window.addEventListener("storage", refresh);
    return () => window.removeEventListener("storage", refresh);
  }, []);

  useEffect(() => {
    if (!selected) {
      setStatus(null);
      return;
    }
    const controller = new AbortController();
    let timer = 0;
    setStatus(null);
    async function read() {
      try {
        const value = await identityJson<Status>(
          `/saas/onboarding/workspaces/${selected}/status`,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        if (
          ![
            "pending",
            "provisioning",
            "ready_for_first_run",
            "complete",
            "recovering",
            "support_required",
          ].includes(value.state)
        )
          throw new IdentityError("invalid_response");
        setStatus(value);
        if (["pending", "provisioning", "recovering"].includes(value.state))
          timer = window.setTimeout(read, 2000);
      } catch (cause) {
        if (!controller.signal.aborted) setError(cause);
      }
    }
    void read();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [selected, attempt]);

  function chooseIntent(id: string | null) {
    const url = new URL(window.location.href);
    if (id) {
      url.searchParams.set("intent", id);
      url.searchParams.delete("new");
    } else {
      url.searchParams.delete("intent");
      url.searchParams.set("new", "1");
    }
    window.history.replaceState(
      window.history.state,
      "",
      url.pathname + url.search,
    );
    setError(null);
    setSelected(id);
  }

  async function mutate(action: () => Promise<void>) {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (cause) {
      setError(cause);
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }

  function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void mutate(async () => {
      const cleaned = name.trim();
      if (!cleaned) return;
      const result = await identityJson<Intent>("/saas/onboarding/workspaces", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": await rememberRequest(cleaned),
        },
        body: JSON.stringify({ tenant_name: cleaned }),
      });
      if (!uuid.test(result.id) || typeof result.name !== "string")
        throw new IdentityError("invalid_response");
      chooseIntent(result.id);
      setIntents((current) => [
        result,
        ...current.filter((row) => row.id !== result.id),
      ]);
      try {
        sessionStorage.removeItem(requestKey);
      } catch {}
    });
  }

  function openScope(tenant_id: string, space_id: string) {
    void mutate(async () => {
      await identityJson("/saas/auth/active-scope", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_id, space_id }),
      });
      const target = safeReturnTarget(
        new URLSearchParams(window.location.search).get("return_to"),
        window.location.origin,
      );
      window.location.assign(
        ["/setup", "/signup", "/saas/login", "/saas/auth/"].some((path) =>
          target.startsWith(path),
        )
          ? "/"
          : target,
      );
    });
  }

  const stages: [string, MessageKey][] = [
    ["workspace", "setup.accepted"],
    ["billing", "status.billing"],
    ["runtime", "status.runtime"],
    ["project", "status.project"],
    ["activation", "status.activation"],
  ];
  const ready =
    status?.state === "ready_for_first_run" || status?.state === "complete";
  return (
    <div className="workspace-setup">
      {!account && !error && <p role="status">{t("identity.loading")}</p>}
      {account && !account.authenticated && (
        <div className="identity-callout">
          <h2>{t("identity.signInFirst")}</h2>
          <p>{t("setup.signInDescription")}</p>
          <Button asChild>
            <a href="/saas/login?return_to=%2Fsetup">
              {t("identity.signInAgain")}
            </a>
          </Button>
        </div>
      )}
      {account?.authenticated && (
        <>
          {account.scopes.length > 0 && (
            <section aria-labelledby="available-workspaces">
              <h2 id="available-workspaces">{t("setup.available")}</h2>
              <div className="workspace-options">
                {account.scopes.map((scope) => (
                  <button
                    type="button"
                    className="workspace-option"
                    disabled={busy || loading}
                    key={scope.tenant_id + scope.space_id}
                    onClick={() => openScope(scope.tenant_id, scope.space_id)}
                  >
                    <span>
                      <strong>{scope.tenant_name}</strong>
                      <small>{scope.space_name}</small>
                    </span>
                    <ArrowRight size={18} aria-hidden="true" />
                  </button>
                ))}
              </div>
            </section>
          )}
          {selected ? (
            <section aria-labelledby="workspace-progress">
              <h2 id="workspace-progress">
                {t(
                  ready
                    ? "setup.ready"
                    : status?.state === "support_required"
                      ? "setup.support"
                      : "setup.preparing",
                )}
              </h2>
              {!status ? (
                <p role="status">
                  <LoaderCircle
                    size={18}
                    className="motion-safe:animate-spin"
                  />
                  {t("status.reading")}
                </p>
              ) : (
                <>
                  {status.state === "support_required" ? (
                    <p>
                      {t("setup.supportDescription")}{" "}
                      {status.support_reference && (
                        <code>{status.support_reference}</code>
                      )}
                    </p>
                  ) : (
                    <>
                      <p className="identity-caption" role="status">
                        {t(
                          ready
                            ? "setup.readyDescription"
                            : status.state === "recovering"
                              ? "setup.recovering"
                              : "setup.continuing",
                        )}
                      </p>
                      <ol className="setup-progress">
                        {stages.map(([key, label], index) => (
                          <li
                            key={key}
                            className={
                              ready ||
                              index <
                                Math.max(
                                  0,
                                  stages.findIndex(
                                    ([stage]) => stage === status.stage,
                                  ),
                                )
                                ? "done"
                                : key === status.stage
                                  ? "active"
                                  : ""
                            }
                          >
                            <span>
                              {ready ? <Check size={15} /> : index + 1}
                            </span>
                            {t(label)}
                          </li>
                        ))}
                      </ol>
                      {ready && status.tenant_id && status.space_id && (
                        <Button
                          className="w-full"
                          disabled={busy}
                          onClick={() =>
                            openScope(status.tenant_id!, status.space_id!)
                          }
                        >
                          {t("setup.open")}
                          <ArrowRight size={18} />
                        </Button>
                      )}
                    </>
                  )}
                </>
              )}
              <Button
                variant="ghost"
                disabled={busy}
                onClick={() => chooseIntent(null)}
              >
                {t("setup.another")}
              </Button>
            </section>
          ) : (
            <section aria-labelledby="create-workspace">
              <h2 id="create-workspace">{t("setup.create")}</h2>
              {catalog && (
                <form onSubmit={create} className="workspace-create-form">
                  <Label htmlFor="workspace-name">{t("setup.name")}</Label>
                  <Input
                    id="workspace-name"
                    name="tenant_name"
                    autoComplete="organization"
                    required
                    maxLength={256}
                    value={name}
                    disabled={busy}
                    onChange={(event) => setName(event.target.value)}
                    placeholder={t("setup.placeholder")}
                  />
                  <p className="identity-caption">
                    {t("setup.defaults", { days: catalog.plans[0].trial_days })}
                  </p>
                  <Button type="submit" className="w-full" disabled={busy}>
                    {busy ? (
                      <LoaderCircle
                        size={18}
                        className="motion-safe:animate-spin"
                      />
                    ) : (
                      <FolderPlus size={18} />
                    )}
                    {t(busy ? "setup.creating" : "setup.create")}
                  </Button>
                </form>
              )}
              {intents.length > 0 && (
                <div className="workspace-resume">
                  <h3>{t("setup.previous")}</h3>
                  {intents.map((row) => (
                    <button
                      type="button"
                      disabled={busy}
                      key={row.id}
                      onClick={() => chooseIntent(row.id)}
                    >
                      {row.name}
                      <ArrowRight size={16} />
                    </button>
                  ))}
                </div>
              )}
            </section>
          )}
          <section
            className="workspace-invitation"
            aria-label={t("setup.invitation")}
          >
            <button
              type="button"
              className="workspace-invitation-toggle"
              onClick={() => setInvitationOpen((value) => !value)}
              aria-expanded={invitationOpen}
            >
              {t("setup.invitation")}
              <ChevronDown size={16} />
            </button>
            {invitationOpen && (
              <form
                className="workspace-create-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void mutate(async () => {
                    await identityJson("/saas/membership-invitations/accept", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ token: invitation.trim() }),
                    });
                    setInvitation("");
                    setInvitationAccepted(true);
                    setAttempt((value) => value + 1);
                  });
                }}
              >
                <Label htmlFor="invitation-token">
                  {t("setup.invitationCode")}
                </Label>
                <Input
                  id="invitation-token"
                  type="password"
                  autoComplete="off"
                  required
                  minLength={32}
                  maxLength={256}
                  value={invitation}
                  disabled={busy}
                  onChange={(event) => setInvitation(event.target.value)}
                />
                <Button type="submit" disabled={busy}>
                  {t("setup.join")}
                </Button>
              </form>
            )}
            {invitationAccepted && <p role="status">{t("setup.joined")}</p>}
          </section>
        </>
      )}
      {error !== null && (
        <div
          className="identity-error"
          role="alert"
          aria-label={t("setup.error")}
        >
          <p>{t(errorKey(error))}</p>
          <Button
            variant="ghost"
            onClick={() => {
              setError(null);
              setAttempt((value) => value + 1);
            }}
          >
            {t("identity.retry")}
          </Button>
          {error instanceof IdentityError &&
            ["verified_email_required", "verified_contact_required"].includes(
              error.code,
            ) && (
              <a href="/saas/login?return_to=%2Fsetup">
                {t("identity.signInAgain")}
              </a>
            )}
        </div>
      )}
    </div>
  );
}
