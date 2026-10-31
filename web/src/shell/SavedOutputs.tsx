import { useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import {
  ChevronDownIcon,
  DownloadIcon,
  FolderIcon,
  ChevronRightIcon,
  RefreshCwIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { downloadAuthenticatedFile } from "@/hooks/useFileContent";
import { authenticatedFetch } from "@/lib/identity";
import { isTempConvId } from "@/lib/tempConversationId";
import { formatBytes } from "./fileStatusUtils";

interface SavedOutput {
  path: string;
  name: string;
  type: "file" | "directory";
  bytes: number | null;
  etag: string | null;
}

interface OutputPage {
  object: "session.artifacts";
  data: SavedOutput[];
  next_cursor: string | null;
}

function baseUrl(sessionId: string) {
  return `/v1/sessions/${encodeURIComponent(sessionId)}/artifacts`;
}

async function availability(sessionId: string, signal: AbortSignal) {
  const response = await authenticatedFetch(`${baseUrl(sessionId)}/availability`, { signal });
  if ([401, 403, 404, 422, 501].includes(response.status)) return null;
  if (!response.ok) throw new Error("Saved outputs are temporarily unavailable.");
  if (!response.headers.get("content-type")?.includes("application/json")) return null;
  const data: unknown = await response.json();
  if (
    typeof data !== "object" ||
    data === null ||
    !("object" in data) ||
    data.object !== "session.artifacts.availability" ||
    !("available" in data) ||
    data.available !== true ||
    !("scope_key" in data) ||
    typeof data.scope_key !== "string" ||
    !/^[0-9a-f]{64}$/.test(data.scope_key) ||
    !("tenant_id" in data) ||
    typeof data.tenant_id !== "string" ||
    !("space_id" in data) ||
    typeof data.space_id !== "string" ||
    !/^[0-9a-f-]{36}$/.test(data.tenant_id) ||
    !/^[0-9a-f-]{36}$/.test(data.space_id)
  )
    return null;
  return { scope: data.scope_key, tenant: data.tenant_id, space: data.space_id };
}

async function fetchOutputs(
  sessionId: string,
  scope: string,
  prefix: string,
  cursor: string | null,
  signal: AbortSignal,
): Promise<OutputPage> {
  const params = new URLSearchParams({ scope, prefix, limit: "50" });
  if (cursor) params.set("cursor", cursor);
  const response = await authenticatedFetch(`${baseUrl(sessionId)}?${params}`, { signal });
  if (!response.ok) {
    if ([401, 403].includes(response.status))
      throw new Error("You no longer have access to these outputs.");
    throw new Error("Saved outputs are temporarily unavailable. Try again.");
  }
  const data = (await response.json()) as OutputPage;
  if (
    data.object !== "session.artifacts" ||
    !Array.isArray(data.data) ||
    data.data.length > 200 ||
    !data.data.every(
      (entry) =>
        typeof entry.path === "string" &&
        typeof entry.name === "string" &&
        ["file", "directory"].includes(entry.type) &&
        (entry.bytes === null || (Number.isSafeInteger(entry.bytes) && entry.bytes >= 0)) &&
        (entry.etag === null || typeof entry.etag === "string"),
    ) ||
    (data.next_cursor !== null && typeof data.next_cursor !== "string")
  ) {
    throw new Error("Saved outputs are temporarily unavailable. Try again.");
  }
  return data;
}

/** Persisted output browsing does not depend on Runner or Host liveness. */
export function SavedOutputs({ sessionId }: { sessionId: string | undefined }) {
  const [expanded, setExpanded] = useState(false);
  const [prefix, setPrefix] = useState("");
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const capability = useQuery({
    queryKey: ["saved-outputs-availability", sessionId],
    queryFn: ({ signal }) => availability(sessionId!, signal),
    enabled: !!sessionId && !isTempConvId(sessionId),
    staleTime: 0,
    gcTime: 0,
    retry: false,
    refetchOnMount: "always",
  });
  const scope = capability.data?.scope;
  const files = useInfiniteQuery({
    queryKey: ["saved-outputs", sessionId, scope, prefix],
    queryFn: ({ pageParam, signal }) => fetchOutputs(sessionId!, scope!, prefix, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    enabled: expanded && !!scope && capability.isFetchedAfterMount,
    staleTime: 0,
    gcTime: 0,
    retry: false,
  });

  if (!scope || !capability.isFetchedAfterMount) return null;
  const entries = files.error
    ? []
    : [
        ...new Map(
          (files.data?.pages.flatMap((page) => page.data) ?? []).map((entry) => [
            `${entry.type}:${entry.path}`,
            entry,
          ]),
        ).values(),
      ];
  const parts = prefix ? prefix.split("/") : [];

  async function download(entry: SavedOutput) {
    if (!sessionId || !entry.etag || !scope || !capability.data) return;
    setDownloadError(null);
    const params = new URLSearchParams({
      path: entry.path,
      etag: entry.etag,
      scope,
      tenant_id: capability.data.tenant,
      space_id: capability.data.space,
    });
    try {
      await downloadAuthenticatedFile(`${baseUrl(sessionId)}/content?${params}`, entry.name);
    } catch {
      setDownloadError("The download could not start. Refresh outputs and try again.");
    }
  }

  return (
    <section aria-label="Saved outputs" className="shrink-0 border-b border-border">
      <div className="flex items-center gap-1 px-2 py-1">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="min-w-0 flex-1 justify-start gap-1.5"
          aria-expanded={expanded}
          onClick={() => setExpanded((value) => !value)}
        >
          {expanded ? <ChevronDownIcon /> : <ChevronRightIcon />}
          Saved outputs
        </Button>
        {expanded ? (
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            aria-label="Refresh saved outputs"
            disabled={files.isFetching}
            onClick={() => {
              void capability.refetch();
              void files.refetch();
            }}
          >
            <RefreshCwIcon className={files.isFetching ? "animate-spin" : undefined} />
          </Button>
        ) : null}
      </div>
      {expanded ? (
        <div className="max-h-[min(18rem,40vh)] overflow-auto px-3 pb-2">
          <p className="mb-2 text-xs text-muted-foreground">
            Saved files remain available when the agent is offline.
          </p>
          <nav
            aria-label="Output folder"
            className="mb-1 flex flex-wrap items-center gap-1 text-xs"
          >
            <button
              type="button"
              className="cursor-pointer hover:underline"
              onClick={() => setPrefix("")}
            >
              Outputs
            </button>
            {parts.map((part, index) => (
              <span
                key={parts.slice(0, index + 1).join("/")}
                className="inline-flex items-center gap-1"
              >
                <ChevronRightIcon className="size-3" />
                <button
                  type="button"
                  className="max-w-40 truncate cursor-pointer hover:underline"
                  onClick={() => setPrefix(parts.slice(0, index + 1).join("/"))}
                >
                  {part}
                </button>
              </span>
            ))}
          </nav>
          {files.isPending ? (
            <p role="status" className="py-2 text-xs text-muted-foreground">
              Loading outputs…
            </p>
          ) : null}
          {files.error ? (
            <p role="alert" className="py-2 text-xs text-destructive">
              {files.error.message}
            </p>
          ) : null}
          {!files.isPending && !files.error && entries.length === 0 ? (
            <p className="py-2 text-xs text-muted-foreground">No saved outputs yet.</p>
          ) : null}
          <ul>
            {entries.map((entry) => (
              <li
                key={`${entry.type}:${entry.path}`}
                className="flex min-w-0 items-center gap-2 py-1"
              >
                {entry.type === "directory" ? (
                  <button
                    type="button"
                    className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left text-sm hover:underline"
                    onClick={() => {
                      setPrefix(entry.path);
                      setDownloadError(null);
                    }}
                  >
                    <FolderIcon className="size-3.5 shrink-0 text-muted-foreground" />
                    <span className="truncate">{entry.name}</span>
                  </button>
                ) : (
                  <>
                    <span className="min-w-0 flex-1 truncate text-sm" title={entry.name}>
                      {entry.name}
                    </span>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      {entry.bytes === null ? "" : formatBytes(entry.bytes)}
                    </span>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Download ${entry.name}`}
                      onClick={() => void download(entry)}
                    >
                      <DownloadIcon />
                    </Button>
                  </>
                )}
              </li>
            ))}
          </ul>
          {files.hasNextPage ? (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={files.isFetchingNextPage}
              onClick={() => void files.fetchNextPage()}
            >
              Load more outputs
            </Button>
          ) : null}
          {downloadError ? (
            <p role="alert" className="py-2 text-xs text-destructive">
              {downloadError}
            </p>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
