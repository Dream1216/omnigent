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
  "language.current": "Current language: {{language}}",
  "sidebar.search": "Search",
  "sidebar.settings": "Settings",
  "sidebar.open": "Open sidebar",
  "sidebar.close": "Close sidebar",
  "sidebar.collapse": "Collapse sidebar",
  "sidebar.newSession": "New session",
  "sidebar.automations": "Automations",
  "sidebar.inbox": "Inbox",
  "sidebar.projects": "Projects",
  "sidebar.sessions": "Sessions",
  "sidebar.pinned": "Pinned",
  "sidebar.inboxOne": "1 inbox item waiting",
  "sidebar.inboxMany": "{{count}} inbox items waiting",
  "landing.heading": "What should we build?",
  "landing.placeholder": "Describe a task to start a new session…",
  "landing.projectPlaceholder": "Start a new session in {{project}}",
  "landing.repository": "Repository",
  "landing.modelsUnavailable": "Models unavailable",
  "landing.noAgents": "No agents",
  "landing.noHost": "No host selected",
  "landing.default": "Default",
  "landing.permissionMode": "Permission mode",
  "landing.start": "Start session",
  "landing.starting": "Starting session",
  "landing.importSessions": "Import your recent sessions",
  "settings.appearance": "Appearance",
  "settings.appearanceDescription": "Choose how Omnigent looks on this device.",
  "settings.languageDescription": "Choose the language used throughout Omnigent.",
  "settings.back": "Back",
  "settings.group.desktop": "Desktop",
  "settings.group.general": "General",
  "settings.group.admin": "Admin",
  "settings.group.archived": "Archived",
  "settings.nav.general": "General",
  "settings.nav.git": "Git",
  "settings.nav.integrations": "Sandbox Integrations",
  "settings.nav.shortcuts": "Keyboard shortcuts",
  "settings.nav.import": "Import sessions",
  "settings.nav.account": "Account",
  "settings.nav.members": "Members",
  "settings.nav.policies": "Policies",
  "settings.nav.sharing": "Sharing",
  "settings.nav.archived": "Archived sessions",
  "settings.nav.cli": "Local CLI",
  "settings.nav.updates": "Updates",
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
  "language.current": "当前语言：{{language}}",
  "sidebar.search": "搜索",
  "sidebar.settings": "设置",
  "sidebar.open": "展开侧栏",
  "sidebar.close": "关闭侧栏",
  "sidebar.collapse": "收起侧栏",
  "sidebar.newSession": "新建会话",
  "sidebar.automations": "自动化",
  "sidebar.inbox": "收件箱",
  "sidebar.projects": "项目",
  "sidebar.sessions": "会话",
  "sidebar.pinned": "已置顶",
  "sidebar.inboxOne": "收件箱中有 1 项待处理",
  "sidebar.inboxMany": "收件箱中有 {{count}} 项待处理",
  "landing.heading": "今天想构建什么？",
  "landing.placeholder": "描述任务，开始新的会话…",
  "landing.projectPlaceholder": "在 {{project}} 中开始新会话",
  "landing.repository": "代码仓库",
  "landing.modelsUnavailable": "模型不可用",
  "landing.noAgents": "没有可用的智能体",
  "landing.noHost": "未选择主机",
  "landing.default": "默认",
  "landing.permissionMode": "权限模式",
  "landing.start": "开始会话",
  "landing.starting": "正在创建会话",
  "landing.importSessions": "导入最近的会话",
  "settings.appearance": "外观",
  "settings.appearanceDescription": "设置 Omnigent 在此设备上的显示方式。",
  "settings.languageDescription": "选择 Omnigent 界面使用的语言。",
  "settings.back": "返回",
  "settings.group.desktop": "桌面端",
  "settings.group.general": "通用",
  "settings.group.admin": "管理",
  "settings.group.archived": "归档",
  "settings.nav.general": "通用",
  "settings.nav.git": "Git",
  "settings.nav.integrations": "沙盒集成",
  "settings.nav.shortcuts": "键盘快捷键",
  "settings.nav.import": "导入会话",
  "settings.nav.account": "账户",
  "settings.nav.members": "成员",
  "settings.nav.policies": "策略",
  "settings.nav.sharing": "共享",
  "settings.nav.archived": "已归档会话",
  "settings.nav.cli": "本地 CLI",
  "settings.nav.updates": "更新",
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

function interpolate(message: string, values: Record<string, string | number> = {}): string {
  return Object.entries(values).reduce(
    (value, [name, replacement]) => value.split(`{{${name}}}`).join(String(replacement)),
    message,
  );
}

function translate(locale: Locale, key: MessageKey, values?: Record<string, string | number>) {
  return interpolate(messages[locale][key], values);
}

const fallbackContext: I18nContextValue = {
  locale: DEFAULT_LOCALE,
  setLocale: () => undefined,
  t: (key, values) => translate(DEFAULT_LOCALE, key, values),
};

const I18nContext = createContext<I18nContextValue>(fallbackContext);

function isLocale(value: string | null): value is Locale {
  return value === "en-US" || value === "zh-CN";
}

export function readLocalePreference(): Locale {
  if (typeof window === "undefined") return DEFAULT_LOCALE;
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (isLocale(stored)) return stored;
  } catch {
    // Language persistence is best-effort when storage is unavailable.
  }
  const languages = window.navigator.languages?.length
    ? window.navigator.languages
    : [window.navigator.language];
  return languages.some((value) => value.toLowerCase().startsWith("zh")) ? "zh-CN" : DEFAULT_LOCALE;
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(readLocalePreference);

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
    (key, values) => translate(locale, key, values),
    [locale],
  );
  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  return useContext(I18nContext);
}
