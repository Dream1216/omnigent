import {
  ArrowUpRight,
  Blocks,
  Check,
  Code2,
  FolderKanban,
  Sparkles,
  Users,
} from "lucide-react";

export function BrandMark({ compact = false }: { compact?: boolean }) {
  return (
    <a
      href="/"
      className={compact ? "wordmark mobile-wordmark" : "wordmark"}
      aria-label="Omnigent home"
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
  return (
    <aside className="brand-panel" aria-label="About Omnigent">
      <BrandMark />
      <div className="brand-story">
        <p className="brand-eyebrow">
          <span /> YOUR NEXT IDEA STARTS HERE
        </p>
        <h2>
          One workspace.
          <br />
          <span>More possibilities.</span>
        </h2>
        <p className="brand-description">
          Bring your agents, projects, and team together.
          <br />
          Make room for your best work.
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
              <strong>AI agents</strong>
              <small>Ideas into action</small>
            </div>
          </div>
          <div className="diagram-node node-projects">
            <span className="node-icon">
              <FolderKanban size={18} />
            </span>
            <div>
              <strong>Projects</strong>
              <small>A space to build</small>
            </div>
          </div>
          <div className="diagram-node node-code">
            <span className="node-icon">
              <Code2 size={18} />
            </span>
            <div>
              <strong>Your workflow</strong>
              <small>Keep moving forward</small>
            </div>
          </div>
          <div className="diagram-node node-team">
            <span className="node-icon">
              <Users size={18} />
            </span>
            <div>
              <strong>Your team</strong>
              <small>Better, together</small>
            </div>
          </div>
          <span className="diagram-spark spark-one">+</span>
          <span className="diagram-spark spark-two">+</span>
        </div>
        <div className="brand-benefits">
          <span>
            <Check size={14} /> A focused workspace
          </span>
          <span>
            <Check size={14} /> Connected by design
          </span>
        </div>
      </div>
      <div className="brand-footer">
        <span>A little inspiration. A lot of possibility.</span>
        <ArrowUpRight size={18} />
      </div>
    </aside>
  );
}
