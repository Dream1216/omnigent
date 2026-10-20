import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { authenticatedFetch } from "@/lib/identity";
import { DropdownMenu, DropdownMenuContent } from "@/components/ui/dropdown-menu";
import { ComposerConfigSections } from "./ComposerConfigSections";
import type { ManagedModelSelection } from "./TenantModelCandidatesSection";

let user: string | null = "tenant-user";
let saas = true;
vi.mock("@/lib/capabilities", () => ({
  getCachedServerInfo: () => ({ login_url: saas ? "/saas/login" : null }),
}));
vi.mock("@/lib/identity", () => ({
  authenticatedFetch: vi.fn(),
  getCurrentUserId: () => user,
}));
const fetchMock = vi.mocked(authenticatedFetch);
const candidate = {
  model_id: "deepseek-v4-pro",
  display_name: "DeepSeek V4 Pro",
  provider_id: "deepseek",
  channel_id: "deepseek",
  transport: "litellm",
  wire_api: "openai_responses",
  generation: 1,
  configuration_revision: `managed-model:openai_responses:1:${"a".repeat(64)}`,
  available: false,
  unavailable_reason: "runtime_not_enabled",
};
function mount(selection?: ManagedModelSelection) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <DropdownMenu open>
        <DropdownMenuContent>
          <ComposerConfigSections managedCandidates managedSelection={selection} />
        </DropdownMenuContent>
      </DropdownMenu>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  fetchMock.mockReset();
  user = "tenant-user";
  saas = true;
});

describe("TenantModelCandidatesSection", () => {
  it("does not probe downstream SaaS routes on an ordinary OSS server", async () => {
    saas = false;
    mount();
    await Promise.resolve();
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it("shows the concrete model and transport without offering runtime selection", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ models: [candidate], runtime_enabled: false })),
    );
    mount();
    const row = await screen.findByRole("menuitemcheckbox", { name: /DeepSeek V4 Pro/ });
    expect(row).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("DeepSeek · via LiteLLM · Responses")).toBeVisible();
    expect(screen.getByText("Not enabled for runtime use")).toBeVisible();
    fireEvent.click(row);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("/v1/managed-model-catalog");
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ cache: "no-store" });
  });

  it.each([404, 200])(
    "does not replace the ordinary model picker for an absent/empty catalog (%s)",
    async (status) => {
      fetchMock.mockResolvedValue(
        new Response(status === 404 ? "" : JSON.stringify({ models: [], runtime_enabled: false }), {
          status,
        }),
      );
      mount();
      await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
      expect(screen.queryByTestId("tenant-managed-model-candidates")).not.toBeInTheDocument();
    },
  );

  it.each([
    { models: [{ ...candidate, available: true }], runtime_enabled: false },
    { models: [candidate], runtime_enabled: true },
    { models: [{ ...candidate, wire_api: "anthropic_messages" }], runtime_enabled: false },
  ])("rejects unexpected runtime activation or protocol data", async (body) => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(body)));
    mount();
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Platform model catalog is temporarily unavailable.",
    );
    expect(screen.queryByRole("menuitemcheckbox")).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not read another user's cached metadata after remount", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ models: [candidate], runtime_enabled: false })),
    );
    const first = mount();
    await screen.findByText("DeepSeek V4 Pro");
    first.unmount();
    user = "another-tenant-user";
    fetchMock.mockImplementation(() => new Promise(() => {}));
    mount();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(screen.queryByText("DeepSeek V4 Pro")).not.toBeInTheDocument();
  });

  it.each([null, "local"])("does not query without a customer identity (%s)", async (identity) => {
    user = identity;
    mount();
    await Promise.resolve();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("selects only an available immutable model reference for the current target", async () => {
    const available = {
      ...candidate,
      available: true,
      unavailable_reason: null,
    };
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ models: [available], runtime_enabled: true })),
    );
    const onSelect = vi.fn();
    mount({ target: "project_id=project-one&harness=codex-native", onSelect });
    const row = await screen.findByRole("menuitemcheckbox", {
      name: /DeepSeek V4 Pro/,
    });
    expect(row).not.toHaveAttribute("aria-disabled", "true");
    fireEvent.click(row);
    expect(onSelect).toHaveBeenCalledExactlyOnceWith(available);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/v1/managed-model-catalog?project_id=project-one&harness=codex-native",
    );
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ cache: "no-store" });
  });

  it("keeps existing sessions read-only even when new-session execution is available", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          models: [{ ...candidate, available: true, unavailable_reason: null }],
          runtime_enabled: true,
        }),
      ),
    );
    mount();
    expect(
      await screen.findByRole("menuitemcheckbox", { name: /DeepSeek V4 Pro/ }),
    ).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("Start a new session to select this model")).toBeVisible();
  });

  it("allows clearing an explicitly selected platform model without sending inference", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          models: [{ ...candidate, available: true, unavailable_reason: null }],
          runtime_enabled: true,
        }),
      ),
    );
    const onSelect = vi.fn(),
      onClear = vi.fn();
    mount({
      target: "project_id=current",
      selectedRevision: candidate.configuration_revision,
      onSelect,
      onClear,
    });
    const row = await screen.findByRole("menuitemcheckbox", { name: /DeepSeek V4 Pro/ });
    expect(row).toHaveAttribute("aria-checked", "true");
    fireEvent.click(row);
    expect(onClear).toHaveBeenCalledTimes(1);
    expect(onSelect).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    "runtime_unavailable",
    "project_required",
    "model_harness_unsupported",
    "host_unavailable",
    "sandbox_unavailable",
    "pricing_unavailable",
  ])("does not select a model denied with %s", async (unavailable_reason) => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          models: [{ ...candidate, unavailable_reason }],
          runtime_enabled: true,
        }),
      ),
    );
    const onSelect = vi.fn();
    mount({ target: "project_id=current", onSelect });
    const row = await screen.findByRole("menuitemcheckbox", {
      name: /DeepSeek V4 Pro/,
    });
    expect(row).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(row);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it.each(["managed-model:openai_responses:2:" + "a".repeat(64), "invalid-reference"])(
    "rejects a mismatched reference %s",
    async (configuration_revision) => {
      fetchMock.mockResolvedValue(
        new Response(
          JSON.stringify({
            models: [{ ...candidate, configuration_revision }],
            runtime_enabled: false,
          }),
        ),
      );
      mount();
      expect(await screen.findByRole("status")).toHaveTextContent(
        "Platform model catalog is temporarily unavailable.",
      );
      expect(screen.queryByRole("menuitemcheckbox")).not.toBeInTheDocument();
    },
  );
});
