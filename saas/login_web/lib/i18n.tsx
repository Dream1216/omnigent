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
  "meta.title": "Sign in · Omnigent",
  "meta.description":
    "Sign in to Omnigent. One focused workspace for your agents, projects, and team.",
  "page.skip": "Skip to sign in",
  "page.newUser": "New to Omnigent?",
  "page.createWorkspace": "Create a workspace",
  "page.eyebrow": "WELCOME BACK",
  "page.headingLead": "Sign in to your",
  "page.headingFocus": "workspace",
  "page.headingPunctuation": ".",
  "page.description": "Good to see you. Let’s pick up where you left off.",
  "page.copyright": "© Omnigent. Built for what’s next.",
  "page.deliveryWorkspace": "Delivery workspace",
  "brand.about": "About Omnigent",
  "brand.home": "Omnigent home",
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
  "form.legend": "Sign in with your Omnigent account",
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
  "meta.title": "登录 · Omnigent",
  "meta.description":
    "登录 Omnigent，在同一个专注的工作空间中连接智能体、项目与团队。",
  "page.skip": "跳转到登录表单",
  "page.newUser": "第一次使用 Omnigent？",
  "page.createWorkspace": "创建工作空间",
  "page.eyebrow": "欢迎回来",
  "page.headingLead": "登录您的",
  "page.headingFocus": "工作空间",
  "page.headingPunctuation": "。",
  "page.description": "很高兴再次见到您，继续上次未完成的工作吧。",
  "page.copyright": "© Omnigent，为下一步而构建。",
  "page.deliveryWorkspace": "交付工作台",
  "brand.about": "关于 Omnigent",
  "brand.home": "Omnigent 首页",
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
  "form.legend": "使用 Omnigent 账户登录",
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
