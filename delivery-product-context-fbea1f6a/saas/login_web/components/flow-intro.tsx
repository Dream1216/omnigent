import type { ReactNode } from "react";
import { useI18n } from "@/lib/i18n";

interface FlowIntroProps {
  description: string;
  eyebrow: string;
  heading: string;
  icon: ReactNode;
  step: 1 | 2 | 3;
}

export function FlowIntro({
  description,
  eyebrow,
  heading,
  icon,
  step,
}: FlowIntroProps) {
  const { t } = useI18n();

  return (
    <div className="flow-intro">
      <div className="welcome-mark" aria-hidden="true">
        {icon}
      </div>
      <p className="eyebrow">{eyebrow}</p>
      <h1 id="flow-title">
        {heading}
        <span>.</span>
      </h1>
      <p className="login-description">{description}</p>
      <div className="flow-steps" aria-label={t("flow.step", { step })}>
        <b>0{step}</b>
        <span className="flow-track" aria-hidden="true">
          <span style={{ width: `${step * 33.333}%` }} />
        </span>
        <em>{t("flow.step", { step })}</em>
      </div>
    </div>
  );
}
