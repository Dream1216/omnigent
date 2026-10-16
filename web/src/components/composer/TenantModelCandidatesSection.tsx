import { useQuery } from "@tanstack/react-query";
import { authenticatedFetch, getCurrentUserId } from "@/lib/identity";
import { getCachedServerInfo } from "@/lib/capabilities";
import { DropdownMenuCheckboxItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { PickerSectionHeader } from "./HarnessMenuRow";

interface Candidate {
  model_id: string;
  display_name: string;
  provider_id: "deepseek";
  channel_id: "deepseek";
  transport: "litellm";
  wire_api: "openai_chat_completions" | "openai_responses";
  generation: number;
  available: false;
  unavailable_reason: "runtime_not_enabled";
}

async function loadCandidates(signal: AbortSignal): Promise<Candidate[] | null> {
  const response = await authenticatedFetch("/v1/managed-model-catalog", {
    signal,
    cache: "no-store",
  });
  // An ordinary OSS server does not mount the downstream SaaS router.
  if (response.status === 404) return null;
  if (!response.ok) throw new Error("Platform model catalog is temporarily unavailable.");
  const body: unknown = await response.json();
  if (
    !body ||
    typeof body !== "object" ||
    !("runtime_enabled" in body) ||
    body.runtime_enabled !== false ||
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
      item.available !== false ||
      item.unavailable_reason !== "runtime_not_enabled"
    )
      throw new Error("Platform model catalog is temporarily unavailable.");
  }
  return body.models as Candidate[];
}

/** Candidate discovery never installs a model or makes a runtime authorization decision. */
export function TenantModelCandidatesSection() {
  const user = getCurrentUserId();
  // The downstream auth provider advertises this realm; OSS catalogs stay host-owned.
  const saas = getCachedServerInfo()?.login_url === "/saas/login";
  const catalog = useQuery({
    queryKey: ["tenant-managed-model-candidates", user],
    queryFn: ({ signal }) => loadCandidates(signal),
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
          <div
            className="px-2 py-1 text-xs break-words whitespace-normal text-muted-foreground"
            role="status"
          >
            Candidates only. Runtime access is not enabled.
          </div>
          {catalog.data?.map((model) => (
            <DropdownMenuCheckboxItem
              key={`${model.model_id}:${model.wire_api}`}
              checked={false}
              disabled
              className="whitespace-normal break-words"
              data-model-id={model.model_id}
            >
              <span className="flex min-w-0 flex-col">
                <span>{model.display_name}</span>
                <span className="text-xs text-muted-foreground">
                  DeepSeek · via LiteLLM ·{" "}
                  {model.wire_api === "openai_responses" ? "Responses" : "Chat"}
                </span>
                <span className="text-xs text-muted-foreground">Not enabled for runtime use</span>
              </span>
            </DropdownMenuCheckboxItem>
          ))}
        </>
      )}
    </div>
  );
}
