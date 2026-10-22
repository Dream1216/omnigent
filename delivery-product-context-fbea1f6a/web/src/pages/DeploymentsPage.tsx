import { useEffect } from "react";

/** Preserve delivery bookmarks while using the current SaaS authority. */
export default function DeploymentsPage() {
  useEffect(() => {
    window.location.replace(`/saas/delivery${window.location.search}`);
  }, []);
  return (
    <main className="p-8">
      <a href={`/saas/delivery${window.location.search}`}>打开交付工作台</a>
    </main>
  );
}
