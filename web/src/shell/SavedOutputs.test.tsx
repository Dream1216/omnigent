import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SavedOutputs } from "./SavedOutputs";

const { fetchMock, downloadMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  downloadMock: vi.fn(),
}));
vi.mock("@/lib/identity", () => ({ authenticatedFetch: fetchMock }));
vi.mock("@/hooks/useFileContent", () => ({ downloadAuthenticatedFile: downloadMock }));

const scope = "1".repeat(64);
const tenant = "11111111-1111-1111-1111-111111111111";
const space = "22222222-2222-2222-2222-222222222222";
const etag = `"${"a".repeat(32)}"`;
const file = { name: "报告.html", path: "报告.html", type: "file", bytes: 12, etag };

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function capability() {
  return response({
    object: "session.artifacts.availability",
    available: true,
    scope_key: scope,
    tenant_id: tenant,
    space_id: space,
  });
}

function mount(id: string | undefined = "session-a") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <SavedOutputs key={id} sessionId={id} />
    </QueryClientProvider>,
  );
  return { ...view, client };
}

beforeEach(() => {
  fetchMock.mockReset();
  downloadMock.mockReset().mockResolvedValue(undefined);
  fetchMock.mockImplementation(async (url: string) =>
    url.endsWith("/availability")
      ? capability()
      : response({ object: "session.artifacts", data: [file], next_cursor: null }),
  );
});
afterEach(cleanup);

describe("SavedOutputs", () => {
  it("loads availability independently and waits for expansion before listing", async () => {
    mount();
    const toggle = await screen.findByRole("button", { name: "Saved outputs" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    fireEvent.click(toggle);
    expect(await screen.findByRole("button", { name: "Download 报告.html" })).toBeVisible();
    expect(String(fetchMock.mock.calls[1][0])).toContain("scope=" + scope);
  });

  it("downloads through the application with the listed ETag and verified scope", async () => {
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Saved outputs" }));
    fireEvent.click(await screen.findByRole("button", { name: "Download 报告.html" }));
    expect(downloadMock).toHaveBeenCalledOnce();
    const [url, name] = downloadMock.mock.calls[0];
    const parsed = new URL(url, "https://app.example");
    expect(parsed.pathname).toBe("/v1/sessions/session-a/artifacts/content");
    expect(Object.fromEntries(parsed.searchParams)).toEqual({
      path: file.path,
      etag,
      scope,
      tenant_id: tenant,
      space_id: space,
    });
    expect(name).toBe("报告.html");
    expect(url).not.toContain("aliyuncs.com");
  });

  it.each([401, 403, 404, 501])(
    "hides an unavailable or denied capability (%s)",
    async (status) => {
      fetchMock.mockResolvedValue(response({}, status));
      mount();
      await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
      expect(screen.queryByRole("button", { name: "Saved outputs" })).not.toBeInTheDocument();
    },
  );

  it("does not mistake a SPA fallback for a supported endpoint", async () => {
    fetchMock.mockResolvedValue(
      new Response("<html>app</html>", { headers: { "Content-Type": "text/html" } }),
    );
    mount();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    expect(screen.queryByRole("button", { name: "Saved outputs" })).not.toBeInTheDocument();
  });

  it("does not query unsaved sessions", async () => {
    mount("temp:draft");
    await new Promise((resolve) => {
      setTimeout(resolve, 10);
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows an empty state without requiring an online runner", async () => {
    fetchMock.mockImplementation(async (url: string) =>
      url.endsWith("/availability")
        ? capability()
        : response({ object: "session.artifacts", data: [], next_cursor: null }),
    );
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Saved outputs" }));
    expect(await screen.findByText("No saved outputs yet.")).toBeVisible();
  });

  it("navigates output folders and paginates without fetching file bytes", async () => {
    fetchMock.mockImplementation(async (url: string) => {
      if (url.endsWith("/availability")) return capability();
      const params = new URL(url, "https://app.example").searchParams;
      if (!params.get("prefix"))
        return response({
          object: "session.artifacts",
          data: [{ name: "reports", path: "reports", type: "directory", bytes: null, etag: null }],
          next_cursor: null,
        });
      return response({
        object: "session.artifacts",
        data: [{ ...file, path: "reports/" + file.path }],
        next_cursor: params.has("cursor") ? null : "next-page",
      });
    });
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Saved outputs" }));
    fireEvent.click(await screen.findByRole("button", { name: "reports" }));
    fireEvent.click(await screen.findByRole("button", { name: "Load more outputs" }));
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([url]) => String(url).includes("cursor=next-page"))).toBe(
        true,
      ),
    );
    expect(downloadMock).not.toHaveBeenCalled();
  });

  it("shows permission revocation without retaining stale file entries", async () => {
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Saved outputs" }));
    expect(await screen.findByRole("button", { name: "Download 报告.html" })).toBeVisible();
    fetchMock.mockImplementation(async (url: string) =>
      url.endsWith("/availability") ? capability() : response({}, 403),
    );
    fireEvent.click(screen.getByRole("button", { name: "Refresh saved outputs" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("You no longer have access");
    expect(screen.queryByRole("button", { name: "Download 报告.html" })).not.toBeInTheDocument();
  });
});
