import type { Session } from "@/lib/types";

/**
 * Resolve the human-facing instance label for a child session.
 *
 * Spawned children encode the instance in ``{tool}:{name}``; user-added
 * children use ``ui:{agent}:{name}``. The bound agent remains the execution
 * configuration and is only a final display fallback.
 */
export function subAgentInstanceLabel(
  session: Pick<Session, "parentSessionId" | "title" | "subAgentName" | "agentName"> | null,
): string | null {
  if (!session || session.parentSessionId == null) return null;
  let title = session.title ?? null;
  if (title?.startsWith("ui:")) title = title.slice(3);
  if (title?.includes(":")) {
    const suffix = title.split(":").slice(1).join(":");
    if (suffix) return suffix;
  }
  return title ?? session.subAgentName ?? session.agentName ?? "sub-agent";
}
