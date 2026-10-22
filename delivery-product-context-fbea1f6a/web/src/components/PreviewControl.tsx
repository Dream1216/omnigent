import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLinkIcon, LoaderCircleIcon, MonitorPlayIcon, SquareIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { authenticatedFetch } from "@/lib/identity";

interface SourceRun {
  id: string;
  project_id: string;
  tenant_id: string;
  space_id: string;
}
interface SessionDelivery {
  runs: SourceRun[];
  preview_enabled: boolean;
  preview: string | null;
}
interface PreviewState {
  preview_id: string;
  status: string;
  url?: string;
  expires_at: string;
}

async function read<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await authenticatedFetch(path, init);
  const value = await response.json();
  if (!response.ok) throw new Error(value.detail?.code ?? "预览暂时不可用");
  return value as T;
}

export function PreviewControl({ sessionId, enabled }: { sessionId: string; enabled: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const client = useQueryClient();
  const source = useQuery({
    queryKey: ["delivery-session", sessionId],
    queryFn: () =>
      read<SessionDelivery>(`/saas/delivery/sessions/${encodeURIComponent(sessionId)}`),
    enabled,
    staleTime: 5000,
    refetchInterval: 5000,
    retry: false,
  });
  const run = source.data?.runs[0];
  const base = run
    ? `/saas/tenants/${run.tenant_id}/spaces/${run.space_id}/projects/${run.project_id}/previews`
    : "";
  const previewId = selected ?? source.data?.preview;
  const preview = useQuery({
    queryKey: ["session-preview", sessionId, previewId],
    queryFn: () => read<PreviewState>(`${base}/${previewId}`),
    enabled: enabled && !!base && !!previewId,
    refetchInterval: (query) =>
      ["stopped", "failed", "revoked", "expired"].includes(query.state.data?.status ?? "")
        ? false
        : 3000,
    retry: false,
  });
  const action = useMutation({
    mutationFn: async (stop: boolean) => {
      if (!run) throw new Error("当前会话还没有可预览的已完成运行");
      const operation = stop ? `stop:${previewId}` : `start:${run.id}`;
      const storage = `omnigent.preview-command:${sessionId}:${operation}`;
      const key = sessionStorage.getItem(storage) ?? crypto.randomUUID();
      sessionStorage.setItem(storage, key);
      const result = await read<PreviewState>(stop ? `${base}/${previewId}` : base, {
        method: stop ? "DELETE" : "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        ...(stop
          ? {}
          : { body: JSON.stringify({ run_id: run.id, preview_kind: "static_web_v1" }) }),
      });
      sessionStorage.removeItem(storage);
      return result;
    },
    onSuccess: (value) => {
      setSelected(value.preview_id);
      client.setQueryData(["session-preview", sessionId, value.preview_id], value);
      void client.invalidateQueries({ queryKey: ["delivery-session", sessionId] });
    },
  });
  if (!enabled) return null;
  const state = preview.data;
  const ready =
    !preview.error &&
    !source.error &&
    state?.status === "ready" &&
    Date.parse(state.expires_at) > Date.now();
  const active = !!state && !["stopped", "failed", "revoked", "expired"].includes(state.status);
  const error = action.error ?? preview.error ?? source.error;
  return (
    <div className="relative" data-testid="preview-control">
      <Button
        variant="ghost"
        size="sm"
        aria-expanded={expanded}
        onClick={() => setExpanded(!expanded)}
      >
        <MonitorPlayIcon className="size-4" /> 会话预览
      </Button>
      {expanded && (
        <section
          aria-label="会话预览"
          className="absolute bottom-full right-0 z-40 mb-2 w-72 space-y-3 rounded-lg border border-border bg-popover p-4 text-sm shadow-lg"
        >
          <p className="font-medium">当前会话预览</p>
          <p className="text-xs text-muted-foreground">从已完成运行的检查点打开独立预览。</p>
          {error && <p role="alert">{error.message}</p>}
          {!run && !source.isLoading && <p>当前会话还没有可预览的已完成运行。</p>}
          {state && <p role="status">{ready ? "已就绪" : state.status}</p>}
          {ready && state.url && (
            <a
              href={state.url}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-2 underline"
            >
              <ExternalLinkIcon className="size-4" /> 打开预览
            </a>
          )}
          <div className="flex gap-2">
            <Button
              size="sm"
              disabled={
                action.isPending ||
                (!!previewId && preview.isLoading) ||
                !!preview.error ||
                !run ||
                !source.data?.preview_enabled
              }
              onClick={() => action.mutate(!!active)}
            >
              {action.isPending ? (
                <LoaderCircleIcon className="size-4 animate-spin" />
              ) : active ? (
                <SquareIcon className="size-4" />
              ) : (
                <MonitorPlayIcon className="size-4" />
              )}
              {active ? "停止预览" : "启动预览"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                void source.refetch();
                if (previewId) void preview.refetch();
              }}
            >
              刷新
            </Button>
          </div>
          <a
            className="block text-xs underline"
            href={`/saas/delivery?session_id=${encodeURIComponent(sessionId)}`}
          >
            构建与发布此会话
          </a>
        </section>
      )}
    </div>
  );
}
