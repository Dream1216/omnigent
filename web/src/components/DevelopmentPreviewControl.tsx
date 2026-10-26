import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { authenticatedFetch } from "@/lib/identity";

interface Service {
  id: string;
  port: number;
  status: string;
  kind: string;
}

interface Handoff {
  preview_id: string;
  url: string;
  token: string;
  expires_at: string;
}

interface OpenPreview {
  preview_id: string;
  url: string;
  expires_at: string;
  port: number;
}

async function read<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await authenticatedFetch(path, init);
  if (!response.ok) throw new Error("无法连接开发预览，请检查会话运行环境后重试。");
  return response.json() as Promise<T>;
}

export function DevelopmentPreviewControl({ sessionId }: { sessionId: string }) {
  const base = `/v1/sessions/${encodeURIComponent(sessionId)}`;
  const [opened, setOpened] = useState<Record<string, OpenPreview>>({});
  const [popupError, setPopupError] = useState<string | null>(null);
  const services = useQuery({
    queryKey: ["development-preview-services", sessionId],
    queryFn: () =>
      read<{ services: Service[]; preview_enabled: boolean }>(`${base}/preview-services`),
    refetchInterval: 3000,
    retry: false,
  });
  const launch = useMutation({
    mutationFn: async ({
      service,
      popup,
      target,
    }: {
      service: Service;
      popup: Window;
      target: string;
    }) => {
      try {
        const handoff = await read<Handoff>(`${base}/preview-services/${service.id}/open`, {
          method: "POST",
        });
        const url = new URL(handoff.url);
        if (
          url.protocol !== "https:" ||
          url.origin === window.location.origin ||
          url.search ||
          url.hash
        ) {
          throw new Error("预览地址不可用。");
        }
        const form = document.createElement("form");
        form.method = "POST";
        form.action = url.href;
        form.target = target;
        const token = document.createElement("input");
        token.type = "hidden";
        token.name = "token";
        token.value = handoff.token;
        form.append(token);
        document.body.append(form);
        try {
          form.submit();
        } finally {
          form.remove();
        }
        // Retain only the reusable URL; one-use credentials never enter component state.
        setOpened((previous) => ({
          ...previous,
          [service.id]: {
            preview_id: handoff.preview_id,
            url: url.origin + "/",
            expires_at: handoff.expires_at,
            port: service.port,
          },
        }));
      } catch (error) {
        popup.close();
        throw error;
      }
    },
  });
  const stop = useMutation({
    mutationFn: async (endpointId: string) => {
      await read(`${base}/development-previews/${opened[endpointId].preview_id}`, {
        method: "DELETE",
      });
      setOpened((previous) =>
        Object.fromEntries(Object.entries(previous).filter(([id]) => id !== endpointId)),
      );
    },
  });
  const error = launch.error ?? stop.error ?? services.error;
  return (
    <div className="space-y-2 border-b border-border pb-3" aria-label="开发服务预览">
      <p className="font-medium">实时开发预览</p>
      <p className="text-xs text-muted-foreground">自动发现当前会话的开发服务，无需先构建。</p>
      {services.isPending && <p role="status">正在检测监听端口…</p>}
      {error && <p role="alert">{error.message}</p>}
      {popupError && <p role="alert">{popupError}</p>}
      {services.data?.services.length === 0 && <p>尚未发现服务，请先在当前会话启动开发服务。</p>}
      {services.data && !services.data.preview_enabled && services.data.services.length > 0 && (
        <p role="status">已发现服务，预览网关尚未就绪。</p>
      )}
      {services.data?.services.map((service) => {
        const active = opened[service.id];
        return (
          <div key={service.id} className="flex items-center gap-2">
            <span>
              :{service.port} · {service.status === "ready" ? "已就绪" : "服务未就绪"}
            </span>
            {active && Date.parse(active.expires_at) > Date.now() ? (
              <>
                <a
                  href={active.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline"
                >
                  打开
                </a>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={stop.isPending}
                  onClick={() => stop.mutate(service.id)}
                >
                  停止预览
                </Button>
              </>
            ) : (
              <Button
                size="sm"
                disabled={
                  launch.isPending || service.status !== "ready" || !services.data.preview_enabled
                }
                onClick={() => {
                  const target = `preview-${crypto.randomUUID()}`;
                  const popup = window.open("about:blank", target);
                  if (!popup) {
                    setPopupError("浏览器阻止了预览窗口，请允许本站打开弹出窗口后重试。");
                    return;
                  }
                  setPopupError(null);
                  popup.opener = null;
                  launch.mutate({ service, popup, target });
                }}
              >
                打开开发预览
              </Button>
            )}
          </div>
        );
      })}
      {Object.entries(opened)
        .filter(([id]) => !services.data?.services.some((service) => service.id === id))
        .map(([id, active]) => (
          <div key={id} className="flex items-center gap-2">
            <span>:{active.port} · 服务已停止或不可用</span>
            <Button
              size="sm"
              variant="outline"
              disabled={stop.isPending}
              onClick={() => stop.mutate(id)}
            >
              撤销预览链接
            </Button>
          </div>
        ))}
    </div>
  );
}
