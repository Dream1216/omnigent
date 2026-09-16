"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  ArrowRight,
  Eye,
  EyeOff,
  LoaderCircle,
  LockKeyhole,
  Mail,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { safeReturnTarget, signIn } from "@/lib/auth";

export function LoginForm() {
  const emailRef = useRef<HTMLInputElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const pending = useRef(false);
  const request = useRef<AbortController | null>(null);
  const [ready, setReady] = useState(false);
  const [destination, setDestination] = useState("/");
  const [visible, setVisible] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (emailRef.current) emailRef.current.value = params.get("email") || "";
    setDestination(
      safeReturnTarget(params.get("return_to"), window.location.origin),
    );
    if (window.location.hash)
      window.history.replaceState(
        window.history.state,
        "",
        window.location.pathname + window.location.search,
      );
    setReady(true);
    return () => request.current?.abort();
  }, []);
  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || pending.current) return;
    const fields = new FormData(event.currentTarget);
    pending.current = true;
    setBusy(true);
    setError("");
    const controller = new AbortController();
    request.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 30_000);
    try {
      await signIn(
        String(fields.get("email") || ""),
        String(fields.get("password") || ""),
        controller.signal,
      );
      window.location.assign(destination);
    } catch (cause) {
      pending.current = false;
      setBusy(false);
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to sign in. Please try again.",
      );
    } finally {
      window.clearTimeout(timeout);
    }
  }

  return (
    <>
      <form
        id="login"
        onSubmit={submit}
        aria-busy={busy}
        action="/saas/auth/login"
        method="post"
      >
        <fieldset
          id="login-fields"
          disabled={!ready || busy}
          className="m-0 grid min-w-0 gap-6 border-0 p-0"
        >
          <legend className="sr-only">
            Sign in with your Omnigent account
          </legend>
          <div className="grid gap-2.5">
            <Label htmlFor="email">Work email</Label>
            <div className="relative">
              <Mail
                className="input-leading-icon"
                size={18}
                aria-hidden="true"
              />
              <Input
                ref={emailRef}
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                inputMode="email"
                autoCapitalize="none"
                spellCheck={false}
                placeholder="you@company.com"
                required
                className="pl-11"
              />
            </div>
          </div>
          <div className="grid gap-2.5">
            <Label htmlFor="password">Password</Label>
            <div className="relative">
              <LockKeyhole
                className="input-leading-icon"
                size={18}
                aria-hidden="true"
              />
              <Input
                id="password"
                name="password"
                type={visible ? "text" : "password"}
                autoComplete="current-password"
                placeholder="Enter your password"
                required
                className="pr-14 pl-11"
                onKeyDown={(event) =>
                  setCapsLock(event.getModifierState("CapsLock"))
                }
                onKeyUp={(event) =>
                  setCapsLock(event.getModifierState("CapsLock"))
                }
                onBlur={() => setCapsLock(false)}
              />
              <Button
                id="password-toggle"
                type="button"
                variant="ghost"
                size="icon"
                className="absolute top-1 right-1 rounded-lg"
                aria-label={visible ? "Hide password" : "Show password"}
                aria-controls="password"
                aria-pressed={visible}
                onClick={() => setVisible((value) => !value)}
              >
                {visible ? (
                  <EyeOff size={18} aria-hidden="true" />
                ) : (
                  <Eye size={18} aria-hidden="true" />
                )}
              </Button>
            </div>
            <p
              id="caps-lock"
              role="status"
              hidden={!capsLock}
              className="text-xs text-amber-700"
            >
              Caps Lock is on.
            </p>
          </div>
          <Button
            id="login-submit"
            type="submit"
            className="mt-1 h-[52px] w-full text-sm shadow-[0_6px_16px_-5px_#2563eb66]"
          >
            {busy ? (
              <LoaderCircle
                size={18}
                className="motion-safe:animate-spin"
                aria-hidden="true"
              />
            ) : null}
            {busy ? "Signing in…" : "Sign in"}
            {!busy ? <ArrowRight size={18} aria-hidden="true" /> : null}
          </Button>
        </fieldset>
        <p
          id="login-error"
          ref={errorRef}
          role="alert"
          tabIndex={-1}
          hidden={!error}
          className="login-error"
        >
          {error}
        </p>
      </form>
      <noscript>
        <p className="login-error">
          Enable JavaScript in your browser to sign in securely.
        </p>
      </noscript>
      <p
        id="return-context"
        hidden={destination.split(/[?#]/)[0] !== "/settings/account"}
        className="return-context"
      >
        After sign-in <span aria-hidden="true">→</span> Account settings
      </p>
      <div className="form-note">
        <ShieldCheck size={16} aria-hidden="true" />
        <span>Your workspace. Your account.</span>
      </div>
    </>
  );
}
