import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { CSRF_KEY } from "@/lib/auth";

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
  "identity.title": "Sign-in methods",
  "identity.signOut": "Sign out",
  "identity.errorTitle": "Sign-in method error",
  "identity.eyebrow": "YOUR ACCOUNT",
  "identity.description":
    "Review your connected identities and choose how you sign in.",
  "identity.back": "Back to settings",
  "identity.loading": "Loading sign-in options…",
  "identity.continue": "Continue to sign in",
  "identity.central": "Central sign-in",
  "identity.centralDescription":
    "Sign in with your verified account. You’ll return here when you’re done.",
  "identity.createAccount": "Create an account",
  "identity.registrationDescription":
    "Verify your email and create your account first. You can set up or join a workspace after signing in.",
  "identity.existingPassword": "Or use your existing password",
  "identity.otherSignIn": "Already using central sign-in?",
  "identity.retry": "Try again",
  "identity.signInFirst": "Sign in to manage your account",
  "identity.signInFirstDescription":
    "Use your existing sign-in method first. Then you can connect another identity.",
  "identity.signInAgain": "Sign in again",
  "identity.currentAccount": "Current account",
  "identity.methods": "Connected identities",
  "identity.verified": "Verified email",
  "identity.confirmationHeading": "An identity needs your confirmation",
  "identity.confirmationDescription":
    "An identity with this email tried to sign in. Connect it only if it belongs to you.",
  "identity.connectHeading": "Connect an identity",
  "identity.connectDescription":
    "You’ll sign in again with the identity you want to connect. Check the current account above before continuing.",
  "identity.consent":
    "I want to connect my identity to the account shown above.",
  "identity.connect": "Confirm and connect",
  "identity.connecting": "Opening sign-in…",
  "identity.noProviders":
    "No additional sign-in providers are available for this account.",
  "identity.reauthenticate":
    "Sign in again with your current account before connecting an identity.",
  "identity.rejected":
    "This identity cannot be connected. Contact your account administrator for help.",
  "identity.manualReview":
    "This identity needs a manual review before it can be connected.",
  "identity.wrongAccount":
    "Use a sign-in method already connected to your current account.",
  "identity.conflictHeading": "This email already has an account",
  "identity.conflictDescription":
    "Sign in with your original account, then open Sign-in methods to explicitly connect this identity. Your accounts have not been merged.",
  "identity.existingAccount": "Sign in with existing account",
  "identity.completingHeading": "Completing sign-in",
  "identity.completing": "Your verified sign-in is being completed.",
  "identity.retryHeading": "Sign-in could not complete",
  "identity.retryDescription":
    "Please try signing in again. If the problem continues, contact your account administrator.",
  "identity.storageError":
    "Browser storage is unavailable. Enable site storage and try signing in again.",
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
  "setup.title": "Your workspace starts here",
  "setup.eyebrow": "MAKE ROOM FOR YOUR NEXT IDEA",
  "setup.description":
    "Choose a workspace, accept an invitation, or create a new place for your agents and team.",
  "setup.available": "Your workspaces",
  "setup.create": "Create a workspace",
  "setup.name": "Workspace name",
  "setup.placeholder": "A name for your team or idea",
  "setup.defaults":
    "Start with a {{days}}-day trial. You can complete your profile later.",
  "setup.creating": "Creating your workspace…",
  "setup.preparing": "Your workspace is taking shape",
  "setup.accepted": "Request received",
  "setup.continuing":
    "Setup continues safely in the background. You can return to this page at any time.",
  "setup.recovering":
    "A setup step needs another attempt. Recovery is continuing automatically.",
  "setup.ready": "Your workspace is ready",
  "setup.readyDescription":
    "Your space and first project are ready. Open your workspace to start a task.",
  "setup.open": "Open workspace",
  "setup.another": "Create another workspace",
  "setup.previous": "Continue a previous setup",
  "setup.support": "Your setup needs attention",
  "setup.supportDescription":
    "Contact your administrator with this reference. Your request has been kept safely.",
  "setup.invitation": "Have an invitation?",
  "setup.invitationCode": "Invitation code",
  "setup.join": "Accept invitation",
  "setup.joined":
    "Invitation accepted. Your workspaces will appear when space access is available.",
  "setup.invitationError":
    "This invitation could not be accepted. Check the code and the account you signed in with.",
  "setup.error": "Workspace setup error",
  "setup.verifyEmail":
    "Verify your email with your sign-in provider, then sign in again to create a workspace.",
  "setup.limited":
    "You have requested several workspaces recently. Please try again later.",
  "setup.changedRequest":
    "This request was already submitted with different details. Return to your previous setup.",
  "setup.signInDescription": "Sign in to choose or create your workspace.",
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
  "identity.title": "登录方式",
  "identity.signOut": "退出登录",
  "identity.errorTitle": "登录方式错误",
  "identity.eyebrow": "您的账号",
  "identity.description": "查看已关联的身份，并管理您的登录方式。",
  "identity.back": "返回账号设置",
  "identity.loading": "正在读取登录方式…",
  "identity.continue": "继续登录",
  "identity.central": "统一登录",
  "identity.centralDescription": "使用您已验证的账号登录，完成后将返回本站。",
  "identity.createAccount": "创建账号",
  "identity.registrationDescription":
    "先验证邮箱并创建账号。登录后，再创建或加入工作空间。",
  "identity.existingPassword": "或使用已有账号的密码",
  "identity.otherSignIn": "已使用统一登录？",
  "identity.retry": "重试",
  "identity.signInFirst": "登录后管理账号",
  "identity.signInFirstDescription": "请先使用原有方式登录，再关联其他身份。",
  "identity.signInAgain": "重新登录",
  "identity.currentAccount": "当前账号",
  "identity.methods": "已关联的身份",
  "identity.verified": "邮箱已验证",
  "identity.confirmationHeading": "有身份等待您确认",
  "identity.confirmationDescription":
    "有身份尝试使用此邮箱登录。请仅在确认该身份属于您时进行关联。",
  "identity.connectHeading": "关联身份",
  "identity.connectDescription":
    "您将重新登录需要关联的身份。继续前，请核对上方的当前账号。",
  "identity.consent": "我确认将自己的身份关联到上方账号。",
  "identity.connect": "确认并关联",
  "identity.connecting": "正在打开身份登录…",
  "identity.noProviders": "当前未配置其他可关联的登录方式。",
  "identity.reauthenticate": "请先重新登录当前账号，再关联身份。",
  "identity.rejected": "此身份无法关联，请联系账号管理员协助处理。",
  "identity.manualReview": "此身份需要先完成人工审核才能关联。",
  "identity.wrongAccount": "请使用当前账号已关联的身份重新登录。",
  "identity.conflictHeading": "此邮箱已有账号",
  "identity.conflictDescription":
    "请先使用原账号登录，再前往“登录方式”明确关联此身份。系统尚未合并账号。",
  "identity.existingAccount": "使用原账号登录",
  "identity.completingHeading": "正在完成登录",
  "identity.completing": "正在完成已验证的身份登录。",
  "identity.retryHeading": "登录未完成",
  "identity.retryDescription": "请重新登录。如果问题持续，请联系账号管理员。",
  "identity.storageError": "浏览器存储不可用。请启用本站存储后重试登录。",
  "error.generic": "暂时无法登录，请重试。",
  "error.timeout": "请求超时，请重试。",
  "error.network": "无法连接服务器，请检查网络后重试。",
  "error.unavailable": "服务暂时不可用，请稍后重试。",
  "error.credentials": "请检查邮箱和密码后重试。",
  "error.invalidResponse": "服务器返回了无效响应，请重试。",
  "error.retryAfter": "请在 {{seconds}} 秒后重试。",
  "setup.title": "开启你的工作空间",
  "setup.eyebrow": "为你的下一个想法留出空间",
  "setup.description":
    "选择工作空间、接受邀请，或为智能体和团队创建一个新的协作空间。",
  "setup.available": "你的工作空间",
  "setup.create": "创建工作空间",
  "setup.name": "工作空间名称",
  "setup.placeholder": "给团队或想法起一个名字",
  "setup.defaults": "从 {{days}} 天试用开始，其他资料可以稍后完善。",
  "setup.creating": "正在创建工作空间…",
  "setup.preparing": "工作空间正在准备中",
  "setup.accepted": "已收到开通请求",
  "setup.continuing": "系统会在后台继续开通，你可以随时返回此页面查看进展。",
  "setup.recovering": "某个开通步骤需要重试，系统正在自动恢复。",
  "setup.ready": "工作空间已就绪",
  "setup.readyDescription":
    "空间和首个项目已准备好，进入工作空间即可开始任务。",
  "setup.open": "进入工作空间",
  "setup.another": "创建另一个工作空间",
  "setup.previous": "继续之前的开通",
  "setup.support": "开通需要协助处理",
  "setup.supportDescription":
    "请将此编号提供给管理员。你的开通请求已安全保留。",
  "setup.invitation": "已有工作空间邀请？",
  "setup.invitationCode": "邀请码",
  "setup.join": "接受邀请",
  "setup.joined": "邀请已接受，获得空间访问权限后即可在此选择工作空间。",
  "setup.invitationError": "此邀请未能接受，请检查邀请码和当前登录账号。",
  "setup.error": "工作空间开通错误",
  "setup.verifyEmail": "请先在身份服务中验证邮箱，再重新登录以创建工作空间。",
  "setup.limited": "你近期已提交多个工作空间开通请求，请稍后再试。",
  "setup.changedRequest": "此请求已经用其他资料提交，请继续之前的开通。",
  "setup.signInDescription": "登录后即可选择或创建工作空间。",
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
    const result = JSON.parse(
      document.getElementById("oidc-result")?.textContent || "{}",
    );
    const requested =
      result.ui_locale ||
      new URLSearchParams(window.location.search).get("ui_locale");
    if (isLocale(requested)) {
      try {
        window.localStorage.setItem(LOCALE_STORAGE_KEY, requested);
      } catch {}
      return requested;
    }
  } catch {}
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
      if (event.key === CSRF_KEY) {
        try {
          window.sessionStorage.setItem(CSRF_KEY, event.newValue || "");
        } catch {}
      }
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
