import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { authenticatedFetch } from "@/lib/identity";
import { DevelopmentPreviewControl } from "./DevelopmentPreviewControl";

vi.mock("@/lib/identity", () => ({ authenticatedFetch: vi.fn() }));
const endpoint = { id: "a".repeat(32), port: 5173, status: "ready", kind: "web" };
function show(services = [endpoint], enabled = true) {
  vi.mocked(authenticatedFetch).mockResolvedValue(
    new Response(JSON.stringify({ services, preview_enabled: enabled })),
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <DevelopmentPreviewControl sessionId="session-a" />
    </QueryClientProvider>,
  );
  return client;
}
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.mocked(authenticatedFetch).mockReset();
});

describe("development preview", () => {
  it("explains the empty and gateway unavailable states", async () => {
    show([], false);
    expect(await screen.findByText(/尚未发现服务/)).toBeTruthy();
  });
  it("discovers the ready port and prevents opening without the gateway", async () => {
    show([endpoint], false);
    expect(await screen.findByText(/:5173/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "打开开发预览" })).toBeDisabled();
    expect(screen.getByText(/预览网关尚未就绪/)).toBeTruthy();
  });
  it("reports a blocked popup instead of silently dropping the action", async () => {
    show();
    vi.spyOn(window, "open").mockReturnValue(null);
    fireEvent.click(await screen.findByRole("button", { name: "打开开发预览" }));
    expect(screen.getByRole("alert").textContent).toContain("浏览器阻止");
  });
  it("posts the one-use handoff and retains a credential-free URL for revocation", async () => {
    const client = show();
    const popup = { close: vi.fn(), opener: window };
    vi.spyOn(window, "open").mockReturnValue(popup as unknown as Window);
    let handoff = "";
    vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(function (
      this: HTMLFormElement,
    ) {
      expect(this.method).toBe("post");
      expect(this.action).toBe("https://dev-id.preview.example.test/__omnigent/authorize");
      handoff = (this.querySelector("input") as HTMLInputElement).value;
    });
    await screen.findByText(/:5173/);
    vi.mocked(authenticatedFetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          preview_id: "preview-id",
          url: "https://dev-id.preview.example.test/__omnigent/authorize",
          token: "one-use-secret",
          expires_at: new Date(Date.now() + 60000).toISOString(),
        }),
      ),
    );
    fireEvent.click(screen.getByRole("button", { name: "打开开发预览" }));
    const link = await screen.findByRole("link", { name: "打开" });
    expect(handoff).toBe("one-use-secret");
    expect(link.getAttribute("href")).toBe("https://dev-id.preview.example.test/");
    expect(document.querySelector("input[name=token]")).toBeNull();
    expect(document.body.textContent).not.toContain("one-use-secret");
    expect(popup.opener).toBeNull();
    vi.mocked(authenticatedFetch).mockResolvedValue(
      new Response(JSON.stringify({ services: [], preview_enabled: true })),
    );
    await client.invalidateQueries({ queryKey: ["development-preview-services"] });
    const revoke = await screen.findByRole("button", { name: "撤销预览链接" });
    vi.mocked(authenticatedFetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ status: "revoked" })),
    );
    fireEvent.click(revoke);
    await waitFor(() =>
      expect(authenticatedFetch).toHaveBeenCalledWith(
        "/v1/sessions/session-a/development-previews/preview-id",
        { method: "DELETE" },
      ),
    );
    await waitFor(() => expect(screen.queryByRole("button", { name: "撤销预览链接" })).toBeNull());
  });
});
