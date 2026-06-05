"use client";

import { useId, useState } from "react";
import { Copy, KeyRound, ShieldCheck, ShieldOff } from "lucide-react";
import {
  beginMfaEnrollment,
  disableMfa,
  enableMfa
} from "../../lib/api";
import { useAuth } from "./auth-shell";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "../ui/card";
import { Field, FormBanner, Input } from "../ui/form";

export function MfaCard() {
  const { session, refreshSession } = useAuth();
  const [secret, setSecret] = useState("");
  const [otpauthUrl, setOtpauthUrl] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("");
  const [statusTone, setStatusTone] = useState<"info" | "success" | "error">(
    "info"
  );
  const [saving, setSaving] = useState(false);

  const codeId = useId();
  const passwordId = useId();

  function info(message: string) {
    setStatus(message);
    setStatusTone("info");
  }
  function success(message: string) {
    setStatus(message);
    setStatusTone("success");
  }
  function error(message: string) {
    setStatus(message);
    setStatusTone("error");
  }

  async function startSetup() {
    setSaving(true);
    setStatus("");
    try {
      const response = await beginMfaEnrollment();
      setSecret(response.data.secret);
      setOtpauthUrl(response.data.otpauthUrl);
      info("Authenticator setup key generated.");
    } catch (err) {
      error(err instanceof Error ? err.message : "Unable to start MFA setup");
    } finally {
      setSaving(false);
    }
  }

  async function confirmSetup(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setStatus("");
    try {
      await enableMfa(code);
      setCode("");
      setSecret("");
      setOtpauthUrl("");
      await refreshSession();
      success("MFA is now enabled for your account.");
    } catch (err) {
      error(err instanceof Error ? err.message : "Unable to enable MFA");
    } finally {
      setSaving(false);
    }
  }

  async function turnOff(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setStatus("");
    try {
      await disableMfa({ password, code: code || undefined });
      setPassword("");
      setCode("");
      await refreshSession();
      success("MFA disabled.");
    } catch (err) {
      error(err instanceof Error ? err.message : "Unable to disable MFA");
    } finally {
      setSaving(false);
    }
  }

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      info("Copied to clipboard.");
    } catch {
      error("Unable to copy automatically.");
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
            Multi-factor authentication
          </CardTitle>
          <Badge variant={session?.user.mfaEnabled ? "success" : "outline"}>
            {session?.user.mfaEnabled ? "Enabled" : "Not enabled"}
          </Badge>
        </div>
        <CardDescription>
          Protect your account with an authenticator app and short-lived session
          verification.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!session?.user.mfaEnabled ? (
          <>
            <Button
              onClick={() => void startSetup()}
              disabled={saving}
              variant="outline"
            >
              <KeyRound className="h-4 w-4" />
              {secret ? "Regenerate setup key" : "Generate setup key"}
            </Button>

            {secret ? (
              <form
                onSubmit={confirmSetup}
                className="space-y-4 rounded-md border border-border bg-muted/30 p-4"
              >
                <div className="space-y-2">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Manual setup key
                  </p>
                  <div className="flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm">
                    <span className="flex-1 break-all font-mono text-xs">
                      {secret}
                    </span>
                    <button
                      type="button"
                      onClick={() => void copy(secret)}
                      className="text-muted-foreground hover:text-foreground"
                      aria-label="Copy setup key"
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => void copy(otpauthUrl)}
                    className="text-xs font-medium text-foreground underline-offset-4 hover:underline"
                  >
                    Copy authenticator URI
                  </button>
                </div>

                <Field label="Authentication code" htmlFor={codeId} required>
                  <Input
                    id={codeId}
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    placeholder="123456"
                    value={code}
                    onChange={(event) =>
                      setCode(
                        event.target.value.replace(/\D/g, "").slice(0, 6)
                      )
                    }
                    required
                  />
                </Field>
                <Button type="submit" disabled={saving || code.length !== 6}>
                  Enable MFA
                </Button>
              </form>
            ) : null}
          </>
        ) : (
          <form
            onSubmit={turnOff}
            className="space-y-4 rounded-md border border-border bg-muted/30 p-4"
          >
            <Field label="Current password" htmlFor={passwordId} required>
              <Input
                id={passwordId}
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </Field>
            <Field label="Authentication code" htmlFor={codeId} required>
              <Input
                id={codeId}
                inputMode="numeric"
                pattern="[0-9]{6}"
                placeholder="123456"
                value={code}
                onChange={(event) =>
                  setCode(event.target.value.replace(/\D/g, "").slice(0, 6))
                }
                required
              />
            </Field>
            <Button type="submit" variant="destructive" disabled={saving}>
              <ShieldOff className="h-4 w-4" />
              {saving ? "Updating…" : "Disable MFA"}
            </Button>
          </form>
        )}

        <FormBanner tone={statusTone}>{status}</FormBanner>
      </CardContent>
    </Card>
  );
}
