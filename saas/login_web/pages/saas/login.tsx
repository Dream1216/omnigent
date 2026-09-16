import { ArrowUpRight, LogIn } from "lucide-react";
import Head from "next/head";
import { BrandMark, BrandPanel } from "@/components/brand-panel";
import { LoginForm } from "@/components/login-form";

export default function LoginPage() {
  return (
    <>
      <Head>
        <title>Sign in · Omnigent</title>
        <meta
          name="description"
          content="Sign in to Omnigent. One focused workspace for your agents, projects, and team."
        />
        <meta name="robots" content="noindex, nofollow" />
      </Head>
      <a className="skip-link" href="#email">
        Skip to sign in
      </a>
      <main className="login-shell">
        <BrandPanel />
        <section className="login-stage" aria-labelledby="login-title">
          <header className="stage-header">
            <BrandMark compact />
            <p className="signup-link">
              New to Omnigent?{" "}
              <a href="/signup">
                Create a workspace <ArrowUpRight size={14} aria-hidden="true" />
              </a>
            </p>
          </header>
          <div className="login-content">
            <div className="welcome-mark" aria-hidden="true">
              <LogIn size={23} />
            </div>
            <p className="eyebrow">WELCOME BACK</p>
            <h1 id="login-title">
              Sign in to your
              <br />
              workspace<span>.</span>
            </h1>
            <p className="login-description">
              Good to see you. Let’s pick up where you left off.
            </p>
            <LoginForm />
          </div>
          <footer className="stage-footer">
            <span>© Omnigent. Built for what’s next.</span>
            <a href="/saas/delivery">
              交付工作台 <ArrowUpRight size={13} aria-hidden="true" />
            </a>
          </footer>
        </section>
      </main>
    </>
  );
}
