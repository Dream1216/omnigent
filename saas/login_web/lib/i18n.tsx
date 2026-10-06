import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

const enUS = {
  "language.label": "Language",
  "language.change": "Change language",
  "language.english": "English",
  "language.chinese": "Chinese",
  "meta.title": "Sign in · 胜天半子",
  "meta.description":
    "Sign in to 胜天半子. One focused workspace for your agents, projects, and team.",
  "page.skip": "Skip to sign in",
  "page.newUser": "New to 胜天半子?",
  "page.createWorkspace": "Create a workspace",
  "page.eyebrow": "WELCOME BACK",
  "page.headingLead": "Sign in to your",
  "page.headingFocus": "workspace",
  "page.headingPunctuation": ".",
  "page.description": "Good to see you. Let’s pick up where you left off.",
  "page.copyright": "© 胜天半子. Built for what’s next.",
  "page.deliveryWorkspace": "Delivery workspace",
  "brand.about": "About 胜天半子",
  "brand.home": "胜天半子 home",
  "brand.eyebrow": "YOUR NEXT IDEA STARTS HERE",
  "brand.headingLead": "One workspace.",
  "brand.headingFocus": "More possibilities.",
  "brand.descriptionLead": "Bring your agents, projects, and team together.",
  "brand.descriptionFocus": "Make room for your best work.",
  "brand.agentTitle": "AI agents",
  "brand.agentCaption": "Ideas into action",
  "brand.projectTitle": "Projects",
  "brand.projectCaption": "A space to build",
  "brand.workflowTitle": "Your workflow",
  "brand.workflowCaption": "Keep moving forward",
  "brand.teamTitle": "Your team",
  "brand.teamCaption": "Better, together",
  "brand.benefitFocus": "A focused workspace",
  "brand.benefitConnected": "Connected by design",
  "brand.footer": "A little inspiration. A lot of possibility.",
  "form.legend": "Sign in with your 胜天半子 account",
  "form.email": "Work email",
  "form.emailPlaceholder": "you@company.com",
  "form.password": "Password",
  "form.passwordPlaceholder": "Enter your password",
  "form.showPassword": "Show password",
  "form.hidePassword": "Hide password",
  "form.capsLock": "Caps Lock is on.",
  "form.submit": "Sign in",
  "form.submitting": "Signing in…",
  "form.noScript": "Enable JavaScript in your browser to sign in securely.",
  "form.afterSignIn": "After sign-in",
  "form.accountSettings": "Account settings",
  "form.note": "Your workspace. Your account.",
  "signup.meta.title": "Create a workspace · 胜天半子",
  "signup.meta.description":
    "Create a 胜天半子 workspace for your agents, projects, and team.",
  "signup.skip": "Skip to workspace registration",
  "signup.existingUser": "Already have a workspace?",
  "signup.signIn": "Sign in",
  "signup.eyebrow": "START YOUR TRIAL",
  "signup.heading": "Create your organization",
  "signup.description":
    "Choose the workspace boundary, plan, and home region your team will start with.",
  "signup.loading": "Loading available plans and regions…",
  "signup.account": "Your account",
  "signup.email": "Work email",
  "signup.name": "Your name",
  "signup.optional": "optional",
  "signup.workspace": "Workspace",
  "signup.organizationName": "Organization name",
  "signup.organizationUrl": "Organization URL",
  "signup.firstSpace": "First space",
  "signup.spaceUrl": "Space URL",
  "signup.placement": "Trial placement",
  "signup.homeRegion": "Home region",
  "signup.planDetails":
    "{{days}} day trial · {{runs}} runs · {{concurrency}} concurrent",
  "signup.submit": "Continue",
  "signup.submitting": "Creating registration…",
  "flow.step": "{{step}} of 3",
  "verify.meta.title": "Verify your email · 胜天半子",
  "verify.meta.description":
    "Verify your work email and secure your new 胜天半子 workspace.",
  "verify.skip": "Skip to email verification",
  "verify.missingEyebrow": "VERIFICATION",
  "verify.missingHeading": "Open your registration link",
  "verify.missingDescription":
    "The registration reference is missing. Start again to create a new workspace.",
  "verify.startAgain": "Start again",
  "verify.checkEyebrow": "CHECK YOUR INBOX",
  "verify.checkHeading": "Verify your work email",
  "verify.checkDescription":
    "Use the secure link in the verification email. If it expired, request another one.",
  "verify.resend": "Send another email",
  "verify.resending": "Sending…",
  "verify.resent": "Verification email requested.",
  "verify.secureEyebrow": "EMAIL VERIFIED",
  "verify.secureHeading": "Secure your account",
  "verify.secureDescription":
    "Choose the password you will use to sign in to this organization.",
  "verify.password": "Password",
  "verify.passwordPlaceholder": "At least 12 characters",
  "verify.confirm": "Confirm password",
  "verify.confirmPlaceholder": "Enter the password again",
  "verify.submit": "Verify and continue",
  "verify.submitting": "Verifying…",
  "verify.passwordMismatch": "Passwords do not match.",
  "status.meta.title": "Preparing your workspace · 胜天半子",
  "status.meta.description": "Follow the setup of your new 胜天半子 workspace.",
  "status.skip": "Skip to workspace status",
  "status.eyebrow": "PREPARING WORKSPACE",
  "status.readyEyebrow": "WORKSPACE READY",
  "status.heading": "Your workspace is taking shape",
  "status.readyHeading": "Your organization is ready",
  "status.description":
    "You can keep this page open. Each step comes from the provisioning service.",
  "status.readyDescription":
    "The tenant boundary, first space, and runtime are ready for your first agent run.",
  "status.reading": "Reading the latest setup state…",
  "status.billing": "Billing and trial",
  "status.runtime": "Runtime placement",
  "status.project": "First project",
  "status.activation": "Account activation",
  "status.firstRun": "Ready for first run",
  "status.open": "Open workspace",
  "status.continuing": "Setup is continuing safely…",
  "status.errorEyebrow": "SETUP STATUS",
  "status.errorHeading": "Sign in to continue",
  "status.errorDescription": "We could not read the workspace setup state.",
  "status.signIn": "Sign in to continue",
  "error.generic": "Unable to sign in. Please try again.",
  "error.timeout": "The request timed out. Please try again.",
  "error.network":
    "Could not reach the server. Check your connection and try again.",
  "error.unavailable":
    "The service is temporarily unavailable. Try again shortly.",
  "error.credentials": "Check your email and password and try again.",
  "error.invalidResponse":
    "The server returned an invalid response. Please try again.",
  "error.retryAfter": "Try again in {{seconds}} seconds.",
} as const;

export type MessageKey = keyof typeof enUS;
export type Locale = "en-US" | "zh-CN";
export type TranslationFunction = (
  key: MessageKey,
  values?: Record<string, string | number>,
) => string;

const zhCN: Record<MessageKey, string> = {
  "language.label": "语言",
  "language.change": "切换语言",
  "language.english": "英文",
  "language.chinese": "中文",
  "meta.title": "登录 · 胜天半子",
  "meta.description":
    "登录胜天半子，在同一个专注的工作空间中连接智能体、项目与团队。",
  "page.skip": "跳转到登录表单",
  "page.newUser": "第一次使用胜天半子？",
  "page.createWorkspace": "创建工作空间",
  "page.eyebrow": "欢迎回来",
  "page.headingLead": "登录您的",
  "page.headingFocus": "工作空间",
  "page.headingPunctuation": "。",
  "page.description": "很高兴再次见到您，继续上次未完成的工作吧。",
  "page.copyright": "© 胜天半子，为下一步而构建。",
  "page.deliveryWorkspace": "交付工作台",
  "brand.about": "关于胜天半子",
  "brand.home": "胜天半子首页",
  "brand.eyebrow": "下一个想法，从这里开始",
  "brand.headingLead": "一个工作空间。",
  "brand.headingFocus": "更多可能。",
  "brand.descriptionLead": "让智能体、项目和团队汇聚一处。",
  "brand.descriptionFocus": "为最出色的工作留出空间。",
  "brand.agentTitle": "AI 智能体",
  "brand.agentCaption": "让想法付诸行动",
  "brand.projectTitle": "项目",
  "brand.projectCaption": "专注构建的空间",
  "brand.workflowTitle": "工作流",
  "brand.workflowCaption": "持续向前推进",
  "brand.teamTitle": "团队",
  "brand.teamCaption": "协作成就更好",
  "brand.benefitFocus": "专注的工作空间",
  "brand.benefitConnected": "天生互联",
  "brand.footer": "一点灵感，无限可能。",
  "form.legend": "使用胜天半子账户登录",
  "form.email": "工作邮箱",
  "form.emailPlaceholder": "you@company.com",
  "form.password": "密码",
  "form.passwordPlaceholder": "请输入密码",
  "form.showPassword": "显示密码",
  "form.hidePassword": "隐藏密码",
  "form.capsLock": "大写锁定已开启。",
  "form.submit": "登录",
  "form.submitting": "正在登录…",
  "form.noScript": "请在浏览器中启用 JavaScript 以安全登录。",
  "form.afterSignIn": "登录后前往",
  "form.accountSettings": "账户设置",
  "form.note": "您的工作空间，您的账户。",
  "signup.meta.title": "创建工作空间 · 胜天半子",
  "signup.meta.description": "为您的智能体、项目和团队创建胜天半子工作空间。",
  "signup.skip": "跳转到工作空间注册表单",
  "signup.existingUser": "已有工作空间？",
  "signup.signIn": "登录",
  "signup.eyebrow": "开始免费试用",
  "signup.heading": "创建您的组织",
  "signup.description": "选择团队初始使用的工作空间边界、方案与所在区域。",
  "signup.loading": "正在加载可用方案和区域…",
  "signup.account": "您的账户",
  "signup.email": "工作邮箱",
  "signup.name": "您的姓名",
  "signup.optional": "选填",
  "signup.workspace": "工作空间",
  "signup.organizationName": "组织名称",
  "signup.organizationUrl": "组织网址",
  "signup.firstSpace": "首个空间",
  "signup.spaceUrl": "空间网址",
  "signup.placement": "试用配置",
  "signup.homeRegion": "所在区域",
  "signup.planDetails":
    "{{days}} 天试用 · {{runs}} 次运行 · {{concurrency}} 路并发",
  "signup.submit": "继续",
  "signup.submitting": "正在创建注册…",
  "flow.step": "第 {{step}} 步，共 3 步",
  "verify.meta.title": "验证邮箱 · 胜天半子",
  "verify.meta.description": "验证工作邮箱并保护您的新胜天半子工作空间。",
  "verify.skip": "跳转到邮箱验证",
  "verify.missingEyebrow": "邮箱验证",
  "verify.missingHeading": "打开您的注册链接",
  "verify.missingDescription": "缺少注册标识，请重新开始创建工作空间。",
  "verify.startAgain": "重新开始",
  "verify.checkEyebrow": "查看收件箱",
  "verify.checkHeading": "验证您的工作邮箱",
  "verify.checkDescription":
    "请使用验证邮件中的安全链接；如果链接已过期，可以重新发送。",
  "verify.resend": "重新发送邮件",
  "verify.resending": "正在发送…",
  "verify.resent": "验证邮件已重新发送。",
  "verify.secureEyebrow": "邮箱已验证",
  "verify.secureHeading": "保护您的账户",
  "verify.secureDescription": "设置用于登录该组织的密码。",
  "verify.password": "密码",
  "verify.passwordPlaceholder": "至少 12 个字符",
  "verify.confirm": "确认密码",
  "verify.confirmPlaceholder": "再次输入密码",
  "verify.submit": "验证并继续",
  "verify.submitting": "正在验证…",
  "verify.passwordMismatch": "两次输入的密码不一致。",
  "status.meta.title": "正在准备工作空间 · 胜天半子",
  "status.meta.description": "查看新胜天半子工作空间的开通进度。",
  "status.skip": "跳转到工作空间状态",
  "status.eyebrow": "正在准备工作空间",
  "status.readyEyebrow": "工作空间已就绪",
  "status.heading": "您的工作空间正在成形",
  "status.readyHeading": "您的组织已就绪",
  "status.description": "您可以保持此页面开启，每一步都来自开通服务。",
  "status.readyDescription":
    "租户边界、首个空间和运行环境均已就绪，可以开始第一次智能体运行。",
  "status.reading": "正在读取最新设置状态…",
  "status.billing": "计费与试用",
  "status.runtime": "运行环境配置",
  "status.project": "首个项目",
  "status.activation": "账户激活",
  "status.firstRun": "准备首次运行",
  "status.open": "打开工作空间",
  "status.continuing": "正在安全地继续设置…",
  "status.errorEyebrow": "设置状态",
  "status.errorHeading": "登录后继续",
  "status.errorDescription": "暂时无法读取工作空间设置状态。",
  "status.signIn": "登录后继续",
  "error.generic": "暂时无法登录，请重试。",
  "error.timeout": "请求超时，请重试。",
  "error.network": "无法连接服务器，请检查网络后重试。",
  "error.unavailable": "服务暂时不可用，请稍后重试。",
  "error.credentials": "请检查邮箱和密码后重试。",
  "error.invalidResponse": "服务器返回了无效响应，请重试。",
  "error.retryAfter": "请在 {{seconds}} 秒后重试。",
};

const messages: Record<Locale, Record<MessageKey, string>> = {
  "en-US": enUS,
  "zh-CN": zhCN,
};

export const LOCALE_STORAGE_KEY = "omnigent.locale";
export const DEFAULT_LOCALE: Locale = "en-US";

interface I18nContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: TranslationFunction;
}

const I18nContext = createContext<I18nContextValue | null>(null);

function isLocale(value: string | null): value is Locale {
  return value === "en-US" || value === "zh-CN";
}

function browserLocale(): Locale {
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (isLocale(stored)) return stored;
  } catch {
    // Language persistence is best-effort when storage is unavailable.
  }
  return window.navigator.languages.some((value) =>
    value.toLowerCase().startsWith("zh"),
  )
    ? "zh-CN"
    : DEFAULT_LOCALE;
}

function interpolate(
  message: string,
  values: Record<string, string | number> = {},
): string {
  return Object.entries(values).reduce(
    (value, [name, replacement]) =>
      value.split(`{{${name}}}`).join(String(replacement)),
    message,
  );
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);

  useEffect(() => {
    setLocaleState(browserLocale());
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  useEffect(() => {
    const syncLocale = (event: StorageEvent) => {
      if (event.key === LOCALE_STORAGE_KEY && isLocale(event.newValue)) {
        setLocaleState(event.newValue);
      }
    };
    window.addEventListener("storage", syncLocale);
    return () => window.removeEventListener("storage", syncLocale);
  }, []);

  const setLocale = useCallback((nextLocale: Locale) => {
    setLocaleState(nextLocale);
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, nextLocale);
    } catch {
      // The in-memory preference still applies for this tab.
    }
  }, []);

  const t = useCallback<TranslationFunction>(
    (key, values) => interpolate(messages[locale][key], values),
    [locale],
  );
  const value = useMemo(
    () => ({ locale, setLocale, t }),
    [locale, setLocale, t],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const value = useContext(I18nContext);
  if (!value) throw new Error("useI18n must be used inside I18nProvider");
  return value;
}
