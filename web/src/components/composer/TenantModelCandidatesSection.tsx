import { useQuery } from "@tanstack/react-query";
import { authenticatedFetch, getCurrentUserId } from "@/lib/identity";
import { getCachedServerInfo } from "@/lib/capabilities";
import { DropdownMenuCheckboxItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { PickerSectionHeader } from "./HarnessMenuRow";

export interface TenantModelCandidate {
  model_id: string;
  display_name: string;
  provider_id: "deepseek";
  channel_id: "deepseek";
  transport: "litellm";
  wire_api: "openai_chat_completions" | "openai_responses";
  generation: number;
  configuration_revision: string;
  available: boolean;
  unavailable_reason: keyof typeof unavailableReasons | null;
}

export interface ManagedModelSelection {
  target: string;
  selectedRevision?: string;
  onSelect?: (model: TenantModelCandidate) => void;
  onClear?: () => void;
}

const unavailableReasons = {
  runtime_not_enabled: "Not enabled for runtime use",
  runtime_unavailable: "Execution service is temporarily unavailable",
  project_required: "Choose a project first",
  project_not_accessible: "Model execution is not allowed in this project",
  model_harness_unsupported: "Not available for this Agent SDK",
  host_unavailable: "Select an available Host",
  sandbox_unavailable: "Not available in this Sandbox",
  pricing_unavailable: "Customer pricing is not available",
};

async function loadCandidates(
  signal: AbortSignal,
  target?: string,
): Promise<TenantModelCandidate[] | null> {
  const response = await authenticatedFetch(
    `/v1/managed-model-catalog${target ? `?${target}` : ""}`,
    {
      signal,
      cache: "no-store",
    },
  );
  // An ordinary OSS server does not mount the downstream SaaS router.
  if (response.status === 404) return null;
  if (!response.ok) throw new Error("Platform model catalog is temporarily unavailable.");
  const body: unknown = await response.json();
  if (
    !body ||
    typeof body !== "object" ||
    !("runtime_enabled" in body) ||
    typeof body.runtime_enabled !== "boolean" ||
    !("models" in body) ||
    !Array.isArray(body.models) ||
    body.models.length > 100
  )
    throw new Error("Platform model catalog is temporarily unavailable.");
  for (const item of body.models) {
    if (
      !item ||
      typeof item !== "object" ||
      typeof item.model_id !== "string" ||
      typeof item.display_name !== "string" ||
      item.provider_id !== "deepseek" ||
      item.channel_id !== "deepseek" ||
      item.transport !== "litellm" ||
      !["openai_chat_completions", "openai_responses"].includes(item.wire_api) ||
      !Number.isSafeInteger(item.generation) ||
      item.generation < 1 ||
      typeof item.configuration_revision !== "string" ||
      !new RegExp(`^managed-model:${item.wire_api}:${item.generation}:[0-9a-f]{64}$`).test(
        item.configuration_revision,
      ) ||
      typeof item.available !== "boolean" ||
      (item.available
        ? !body.runtime_enabled || item.unavailable_reason !== null
        : !Object.hasOwn(unavailableReasons, item.unavailable_reason) ||
          (body.runtime_enabled && item.unavailable_reason === "runtime_not_enabled"))
    )
      throw new Error("Platform model catalog is temporarily unavailable.");
  }
  return body.models as TenantModelCandidate[];
}

/** Candidate discovery never installs a model or makes a runtime authorization decision. */
export function TenantModelCandidatesSection({ selection }: { selection?: ManagedModelSelection }) {
  const user = getCurrentUserId();
  // The downstream auth provider advertises this realm; OSS catalogs stay host-owned.
  const saas = getCachedServerInfo()?.login_url === "/saas/login";
  const catalog = useQuery({
    queryKey: ["tenant-managed-model-candidates", user, selection?.target],
    queryFn: ({ signal }) => loadCandidates(signal, selection?.target),
    enabled: saas && user !== null && user !== "local",
    gcTime: 0,
    staleTime: 0,
    retry: false,
    refetchOnWindowFocus: false,
  });
  // Do not show a former observer's cached catalog while a fresh read is pending.
  if (!saas || !catalog.isFetchedAfterMount || (catalog.isSuccess && !catalog.data?.length))
    return null;
  return (
    <div data-testid="tenant-managed-model-candidates">
      <DropdownMenuSeparator />
      <PickerSectionHeader>Platform models</PickerSectionHeader>
      {catalog.isError ? (
        <div
          className="px-2 py-1 text-xs break-words whitespace-normal text-muted-foreground"
          role="status"
        >
          Platform model catalog is temporarily unavailable.
        </div>
      ) : (
        <>
          {catalog.data?.every((model) => model.unavailable_reason === "runtime_not_enabled") ? (
            <div
              className="px-2 py-1 text-xs break-words whitespace-normal text-muted-foreground"
              role="status"
            >
              Candidates only. Runtime access is not enabled.
            </div>
          ) : null}
          {catalog.data?.map((model) => (
            <DropdownMenuCheckboxItem
              key={`${model.model_id}:${model.wire_api}`}
              checked={selection?.selectedRevision === model.configuration_revision}
              disabled={!model.available || !selection?.onSelect}
              onSelect={(event) => event.preventDefault()}
              onCheckedChange={(checked) => {
                if (!model.available) return;
                if (!checked && selection?.onClear) selection.onClear();
                else selection?.onSelect?.(model);
              }}
              className="whitespace-normal break-words"
              data-model-id={model.model_id}
            >
              <span className="flex min-w-0 flex-col">
                <span>{model.display_name}</span>
                <span className="text-xs text-muted-foreground">
                  DeepSeek · via LiteLLM ·{" "}
                  {model.wire_api === "openai_responses" ? "Responses" : "Chat"}
                </span>
                {!model.available || !selection?.onSelect ? (
                  <span className="text-xs text-muted-foreground">
                    {model.unavailable_reason
                      ? unavailableReasons[model.unavailable_reason]
                      : "Start a new session to select this model"}
                  </span>
                ) : null}
              </span>
            </DropdownMenuCheckboxItem>
          ))}
        </>
      )}
    </div>
  );
}
