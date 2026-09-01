import type { ReactNode } from "react";
import { Check, Command, ShieldCheck, Sparkles } from "lucide-react";
import { useAppName } from "@/lib/branding";
import { cn } from "@/lib/utils";

interface SaasAuthShellProps {
  eyebrow: string;
  title: ReactNode;
  description: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  step?: { current: number; total: number; label: string };
  compact?: boolean;
}

const VALUE_POINTS = [
  "A private workspace for every organization",
  "Policy-aware agents and isolated runtime execution",
  "A guided trial with no infrastructure setup",
] as const;

export function SaasAuthShell({
  eyebrow,
  title,
  description,
  children,
  footer,
  step,
  compact = false,
}: SaasAuthShellProps) {
  const appName = useAppName();
  const progress = step ? Math.round((step.current / step.total) * 100) : 0;

  return (
    <main className="relative min-h-svh overflow-hidden bg-background text-foreground">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 opacity-[0.34] dark:opacity-[0.16]"
        style={{
          backgroundImage:
            "radial-gradient(circle at 1px 1px, color-mix(in oklab, var(--foreground) 18%, transparent) 1px, transparent 0)",
          backgroundSize: "28px 28px",
        }}
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -left-48 top-[-18rem] size-[42rem] rounded-full bg-[color-mix(in_oklab,var(--primary)_18%,transparent)] blur-3xl"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -bottom-64 right-[-16rem] size-[42rem] rounded-full bg-[color-mix(in_oklab,var(--chart-2)_14%,transparent)] blur-3xl"
      />

      <div className="relative mx-auto grid min-h-svh w-full max-w-[1440px] lg:grid-cols-[minmax(320px,0.86fr)_minmax(520px,1.14fr)]">
        <aside className="hidden border-r border-border/70 px-10 py-10 lg:flex lg:flex-col xl:px-16 xl:py-14">
          <div className="flex items-center gap-3 text-sm font-semibold tracking-tight">
            <span className="grid size-9 place-items-center rounded-xl border border-primary/25 bg-primary/10 text-primary shadow-sm">
              <Command className="size-4" strokeWidth={2.2} />
            </span>
            {appName}
          </div>

          <div className="my-auto max-w-lg py-16">
            <div className="mb-7 inline-flex items-center gap-2 rounded-full border border-border/80 bg-card/70 px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground shadow-sm backdrop-blur">
              <Sparkles className="size-3.5 text-primary" />
              Multi-tenant agent workspace
            </div>
            <h2 className="max-w-md text-balance text-4xl font-semibold leading-[1.04] tracking-[-0.045em] xl:text-5xl">
              From first idea to a running agent, in one secure place.
            </h2>
            <p className="mt-6 max-w-md text-pretty text-base leading-7 text-muted-foreground">
              Create your organization, invite your team, and let {appName} prepare the runtime
              around your work.
            </p>

            <ul className="mt-10 space-y-4">
              {VALUE_POINTS.map((point) => (
                <li key={point} className="flex items-start gap-3 text-sm text-foreground/85">
                  <span className="mt-0.5 grid size-5 shrink-0 place-items-center rounded-full bg-primary/10 text-primary">
                    <Check className="size-3" strokeWidth={2.4} />
                  </span>
                  <span className="leading-5">{point}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <ShieldCheck className="size-4" />
            Tenant boundaries are enforced from sign-up onward.
          </div>
        </aside>

        <section
          className="flex min-h-svh items-center justify-center px-5 py-10 sm:px-8 lg:px-12 xl:px-20"
          style={{
            paddingTop: "max(2.5rem, var(--omnigent-safe-top))",
            paddingBottom: "max(2.5rem, var(--omnigent-safe-bottom))",
          }}
        >
          <div className={cn("w-full", compact ? "max-w-md" : "max-w-2xl")}>
            <div className="mb-8 flex items-center gap-3 lg:hidden">
              <span className="grid size-9 place-items-center rounded-xl border border-primary/25 bg-primary/10 text-primary">
                <Command className="size-4" />
              </span>
              <span className="text-sm font-semibold">{appName}</span>
            </div>

            {step ? (
              <div
                className="mb-7"
                aria-label={`Step ${step.current} of ${step.total}: ${step.label}`}
              >
                <div className="mb-2 flex items-center justify-between font-mono text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
                  <span>{step.label}</span>
                  <span>
                    {step.current}/{step.total}
                  </span>
                </div>
                <div className="h-1 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary transition-[width] duration-500 ease-out motion-reduce:transition-none"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
            ) : null}

            <div className="rounded-[1.4rem] border border-border/80 bg-card/92 p-6 shadow-[0_24px_80px_-36px_color-mix(in_oklab,var(--foreground)_30%,transparent)] backdrop-blur sm:p-8">
              <div className="mb-7">
                <p className="mb-3 font-mono text-[11px] font-medium uppercase tracking-[0.16em] text-primary">
                  {eyebrow}
                </p>
                <h1 className="text-balance text-3xl font-semibold leading-tight tracking-[-0.035em]">
                  {title}
                </h1>
                <div className="mt-3 max-w-xl text-pretty text-sm leading-6 text-muted-foreground">
                  {description}
                </div>
              </div>
              {children}
            </div>
            {footer ? (
              <div className="mt-5 text-center text-sm text-muted-foreground">{footer}</div>
            ) : null}
          </div>
        </section>
      </div>
    </main>
  );
}
