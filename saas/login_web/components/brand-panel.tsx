import {
  ArrowUpRight,
  Blocks,
  Check,
  Code2,
  FolderKanban,
  Sparkles,
  Users,
} from "lucide-react";
import { useI18n } from "@/lib/i18n";

export function BrandMark({ compact = false }: { compact?: boolean }) {
  const { t } = useI18n();

  return (
    <a
      href="/"
      className={compact ? "wordmark mobile-wordmark" : "wordmark"}
      aria-label={t("brand.home")}
    >
      <span className="brand-icon">
        <Blocks size={22} strokeWidth={2} aria-hidden="true" />
      </span>
      <span>
        Omnigent<span className="wordmark-dot">.</span>
      </span>
    </a>
  );
}

export function BrandPanel() {
  const { t } = useI18n();

  return (
    <aside className="brand-panel" aria-label={t("brand.about")}>
      <BrandMark />
      <div className="brand-story">
        <p className="brand-eyebrow">
          <span /> {t("brand.eyebrow")}
        </p>
        <h2>
          {t("brand.headingLead")}
          <br />
          <span>{t("brand.headingFocus")}</span>
        </h2>
        <p className="brand-description">
          {t("brand.descriptionLead")}
          <br />
          {t("brand.descriptionFocus")}
        </p>
        <div className="workspace-illustration" aria-hidden="true">
          <div className="diagram-grid" />
          <div className="diagram-halo" />
          <svg className="diagram-connectors" viewBox="0 0 480 280" fill="none">
            <path
              d="M116 87H187Q207 87 207 107V136M367 81H293Q273 81 273 101V136M370 229H290Q273 229 273 209V180M104 222H187Q207 222 207 202V180"
              stroke="#c8d9fa"
              strokeWidth="1.5"
            />
            <circle cx="116" cy="87" r="3" fill="#6697f1" />
            <circle cx="370" cy="229" r="3" fill="#6697f1" />
          </svg>
          <div className="diagram-center">
            <Blocks size={36} strokeWidth={1.7} />
            <span>Omnigent</span>
          </div>
          <div className="diagram-node node-agents">
            <span className="node-icon">
              <Sparkles size={18} />
            </span>
            <div>
              <strong>{t("brand.agentTitle")}</strong>
              <small>{t("brand.agentCaption")}</small>
            </div>
          </div>
          <div className="diagram-node node-projects">
            <span className="node-icon">
              <FolderKanban size={18} />
            </span>
            <div>
              <strong>{t("brand.projectTitle")}</strong>
              <small>{t("brand.projectCaption")}</small>
            </div>
          </div>
          <div className="diagram-node node-code">
            <span className="node-icon">
              <Code2 size={18} />
            </span>
            <div>
              <strong>{t("brand.workflowTitle")}</strong>
              <small>{t("brand.workflowCaption")}</small>
            </div>
          </div>
          <div className="diagram-node node-team">
            <span className="node-icon">
              <Users size={18} />
            </span>
            <div>
              <strong>{t("brand.teamTitle")}</strong>
              <small>{t("brand.teamCaption")}</small>
            </div>
          </div>
          <span className="diagram-spark spark-one">+</span>
          <span className="diagram-spark spark-two">+</span>
        </div>
        <div className="brand-benefits">
          <span>
            <Check size={14} /> {t("brand.benefitFocus")}
          </span>
          <span>
            <Check size={14} /> {t("brand.benefitConnected")}
          </span>
        </div>
      </div>
      <div className="brand-footer">
        <span>{t("brand.footer")}</span>
        <ArrowUpRight size={18} />
      </div>
    </aside>
  );
}
