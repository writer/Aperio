"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useState } from "react";
import {
  createMemberResetLink,
  createTenantMember,
  fetchAuditLogs,
  fetchTenantMembers,
  fetchTenantSettings,
  updateMemberRole,
  updateTenantSettings,
  type AuditLogEntry,
  type CreateMemberPayload,
  type TenantMember,
  type TenantRole,
  type TenantSettings
} from "../../lib/api";
import { useAuth } from "../auth/auth-shell";
import { useToast } from "../ui/toast";
import { PageHeader } from "../layout/page-header";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "../ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle
} from "../ui/dialog";
import { Field, FormBanner, Input } from "../ui/form";
import { Skeleton } from "../ui/skeleton";
import { Switch } from "../ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "../ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { formatDateTime, formatRelative } from "../../lib/format";

const roles: TenantRole[] = ["OWNER", "ADMIN", "SECURITY_ANALYST", "VIEWER"];

export function OrganizationSettingsPage() {
  const { session } = useAuth();
  const { toast } = useToast();
  const canManage =
    session?.user.role === "OWNER" || session?.user.role === "ADMIN";

  const [settings, setSettings] = useState<TenantSettings | null>(null);
  const [members, setMembers] = useState<TenantMember[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [inviteOpen, setInviteOpen] = useState(false);

  const load = useCallback(async () => {
    if (!canManage) return;
    setLoading(true);
    setError("");
    try {
      const [s, m, a] = await Promise.all([
        fetchTenantSettings(),
        fetchTenantMembers(),
        fetchAuditLogs()
      ]);
      setSettings(s.data);
      setMembers(m.data);
      setAuditLogs(a.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load settings");
    } finally {
      setLoading(false);
    }
  }, [canManage]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!canManage) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader
          eyebrow="Settings"
          title="Organization settings"
          description="Only workspace owners and admins can access this section."
        />
        <Card>
          <CardContent className="p-6 text-sm text-muted-foreground">
            You don't have permission to manage organization settings.{" "}
            <Link
              href="/settings"
              className="font-medium text-foreground underline-offset-4 hover:underline"
            >
              Back to personal settings
            </Link>
            .
          </CardContent>
        </Card>
      </div>
    );
  }

  async function handleRoleChange(memberId: string, role: TenantRole) {
    try {
      await updateMemberRole(memberId, role);
      toast({ title: "Role updated", tone: "success" });
      await load();
    } catch (err) {
      toast({
        title: "Unable to update role",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    }
  }

  async function handleResetLink(memberId: string) {
    try {
      const result = await createMemberResetLink(memberId);
      const desc = result.reset.url
        ? `Reset URL: ${result.reset.url}`
        : "Reset email queued.";
      toast({
        title: "Reset link generated",
        description: desc,
        tone: "success"
      });
      await load();
    } catch (err) {
      toast({
        title: "Unable to generate reset link",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Settings"
        title="Organization settings"
        description="Configure members, alerts, and security defaults for this workspace."
        actions={
          <Button onClick={() => setInviteOpen(true)}>
            Invite member
          </Button>
        }
      />

      {error ? (
        <Card>
          <CardContent className="p-6 text-sm text-destructive">
            {error}
          </CardContent>
        </Card>
      ) : null}

      <Tabs defaultValue="members" className="w-full">
        <TabsList>
          <TabsTrigger value="members">Members</TabsTrigger>
          <TabsTrigger value="defaults">Defaults</TabsTrigger>
          <TabsTrigger value="audit">Audit log</TabsTrigger>
        </TabsList>

        <TabsContent value="members">
          <Card>
            <CardContent className="p-0">
              {loading ? (
                <div className="space-y-2 p-6">
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-full" />
                </div>
              ) : members.length === 0 ? (
                <p className="p-6 text-sm text-muted-foreground">
                  No members yet.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Member</TableHead>
                      <TableHead>Role</TableHead>
                      <TableHead>Auth state</TableHead>
                      <TableHead>MFA</TableHead>
                      <TableHead>Last login</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {members.map((member) => (
                      <TableRow key={member.id}>
                        <TableCell className="font-medium">
                          {member.displayName ?? member.email}
                          <p className="text-xs text-muted-foreground">
                            {member.email}
                          </p>
                        </TableCell>
                        <TableCell>
                          <select
                            value={member.role}
                            onChange={(event) =>
                              void handleRoleChange(
                                member.id,
                                event.target.value as TenantRole
                              )
                            }
                            className="rounded-md border border-input bg-background px-2 py-1 text-xs"
                          >
                            {roles.map((role) => (
                              <option key={role} value={role}>
                                {role}
                              </option>
                            ))}
                          </select>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              member.authState === "ACTIVE"
                                ? "success"
                                : "secondary"
                            }
                          >
                            {member.authState}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {member.mfaEnabled ? (
                            <Badge variant="success">on</Badge>
                          ) : (
                            <Badge variant="outline">off</Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {formatRelative(member.lastLoginAt)}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void handleResetLink(member.id)}
                          >
                            Reset link
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="defaults">
          {loading || !settings ? (
            <Card>
              <CardContent className="space-y-2 p-6">
                <Skeleton className="h-4 w-1/3" />
                <Skeleton className="h-4 w-1/2" />
              </CardContent>
            </Card>
          ) : (
            <SettingsForm
              settings={settings}
              onSaved={async () => {
                toast({ title: "Settings saved", tone: "success" });
                await load();
              }}
            />
          )}
        </TabsContent>

        <TabsContent value="audit">
          <Card>
            <CardContent className="p-0">
              {loading ? (
                <div className="space-y-2 p-6">
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-full" />
                </div>
              ) : auditLogs.length === 0 ? (
                <p className="p-6 text-sm text-muted-foreground">
                  No audit log entries yet.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>When</TableHead>
                      <TableHead>Actor</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Target</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {auditLogs.slice(0, 50).map((entry) => (
                      <TableRow key={entry.id}>
                        <TableCell className="text-muted-foreground">
                          {formatDateTime(entry.createdAt)}
                        </TableCell>
                        <TableCell>{entry.actor}</TableCell>
                        <TableCell>{entry.action}</TableCell>
                        <TableCell className="text-muted-foreground">
                          {entry.targetType}/{entry.targetId}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <InviteDialog
        open={inviteOpen}
        onClose={() => setInviteOpen(false)}
        onInvited={async () => {
          setInviteOpen(false);
          toast({ title: "Member invited", tone: "success" });
          await load();
        }}
      />
    </div>
  );
}

function SettingsForm({
  settings,
  onSaved
}: {
  settings: TenantSettings;
  onSaved: () => Promise<void>;
}) {
  const [name, setName] = useState(settings.name);
  const [notificationEmail, setNotificationEmail] = useState(
    settings.notificationEmail ?? ""
  );
  const [dataRetentionDays, setDataRetentionDays] = useState(
    settings.dataRetentionDays
  );
  const [criticalRiskThreshold, setCriticalRiskThreshold] = useState(
    settings.criticalRiskThreshold
  );
  const [defaultSlaHours, setDefaultSlaHours] = useState(settings.defaultSlaHours);
  const [autoResolveLow, setAutoResolveLow] = useState(
    settings.autoResolveLowSeverity
  );
  const [enforceSso, setEnforceSso] = useState(settings.enforceSsoOnly);
  const [webhookAlertUrl, setWebhookAlertUrl] = useState(
    settings.webhookAlertUrl ?? ""
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const nameId = useId();
  const emailId = useId();
  const retentionId = useId();
  const thresholdId = useId();
  const slaId = useId();
  const webhookId = useId();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      await updateTenantSettings({
        name,
        notificationEmail: notificationEmail || undefined,
        dataRetentionDays,
        criticalRiskThreshold,
        defaultSlaHours,
        autoResolveLowSeverity: autoResolveLow,
        enforceSsoOnly: enforceSso,
        webhookAlertUrl: webhookAlertUrl || undefined
      });
      await onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save settings");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Workspace defaults</CardTitle>
        <CardDescription>
          Notification email, retention, risk thresholds, and SLAs.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="grid gap-4 sm:grid-cols-2">
          <Field label="Workspace name" htmlFor={nameId} required>
            <Input
              id={nameId}
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
            />
          </Field>
          <Field label="Notification email" htmlFor={emailId}>
            <Input
              id={emailId}
              type="email"
              value={notificationEmail}
              onChange={(event) => setNotificationEmail(event.target.value)}
              placeholder="alerts@acme.com"
            />
          </Field>
          <Field label="Data retention (days)" htmlFor={retentionId} required>
            <Input
              id={retentionId}
              type="number"
              min={1}
              value={dataRetentionDays}
              onChange={(event) =>
                setDataRetentionDays(Number(event.target.value))
              }
              required
            />
          </Field>
          <Field
            label="Critical risk threshold"
            htmlFor={thresholdId}
            hint="0–100"
            required
          >
            <Input
              id={thresholdId}
              type="number"
              min={0}
              max={100}
              value={criticalRiskThreshold}
              onChange={(event) =>
                setCriticalRiskThreshold(Number(event.target.value))
              }
              required
            />
          </Field>
          <Field label="Default SLA (hours)" htmlFor={slaId} required>
            <Input
              id={slaId}
              type="number"
              min={1}
              value={defaultSlaHours}
              onChange={(event) =>
                setDefaultSlaHours(Number(event.target.value))
              }
              required
            />
          </Field>
          <Field label="Alert webhook URL" htmlFor={webhookId}>
            <Input
              id={webhookId}
              type="url"
              value={webhookAlertUrl}
              onChange={(event) => setWebhookAlertUrl(event.target.value)}
              placeholder="https://alerts.example.com/aperio"
            />
          </Field>

          <div className="sm:col-span-2 flex flex-col gap-3">
            <ToggleRow
              label="Auto-resolve low severity"
              hint="Automatically mark new LOW/INFO findings as resolved."
              checked={autoResolveLow}
              onChange={setAutoResolveLow}
            />
            <ToggleRow
              label="Enforce SSO sign-in"
              hint="Block password sign-ins for non-break-glass accounts."
              checked={enforceSso}
              onChange={setEnforceSso}
            />
          </div>

          <div className="sm:col-span-2">
            <FormBanner tone="error">{error}</FormBanner>
          </div>

          <div className="sm:col-span-2 flex justify-end">
            <Button type="submit" loading={saving} loadingText="Saving…">
              Save
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function ToggleRow({
  label,
  hint,
  checked,
  onChange
}: {
  label: string;
  hint?: string;
  checked: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <label className="flex items-start justify-between gap-4 rounded-md border border-border bg-background px-3 py-2.5">
      <div>
        <p className="text-sm font-medium text-foreground">{label}</p>
        {hint ? (
          <p className="text-xs text-muted-foreground">{hint}</p>
        ) : null}
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </label>
  );
}

function InviteDialog({
  open,
  onClose,
  onInvited
}: {
  open: boolean;
  onClose: () => void;
  onInvited: () => Promise<void>;
}) {
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState<TenantRole>("VIEWER");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const emailId = useId();
  const nameId = useId();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const payload: CreateMemberPayload = {
        email: email.trim().toLowerCase(),
        displayName: displayName.trim() || undefined,
        roleName: role
      };
      await createTenantMember(payload);
      setEmail("");
      setDisplayName("");
      setRole("VIEWER");
      await onInvited();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to invite");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(value) => !value && onClose()}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Invite member</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label="Email" htmlFor={emailId} required>
            <Input
              id={emailId}
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          </Field>
          <Field label="Display name" htmlFor={nameId}>
            <Input
              id={nameId}
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </Field>
          <Field label="Role">
            <select
              value={role}
              onChange={(event) => setRole(event.target.value as TenantRole)}
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm"
            >
              {roles.map((entry) => (
                <option key={entry} value={entry}>
                  {entry}
                </option>
              ))}
            </select>
          </Field>
          <FormBanner tone="error">{error}</FormBanner>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={saving} loadingText="Inviting…">
              Invite
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
