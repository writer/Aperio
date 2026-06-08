"use client";

import { useCallback, useEffect, useId, useMemo, useState } from "react";
import { CheckCircle2, ExternalLink, Plus, Search, Unplug } from "lucide-react";
import { cn } from "../../lib/utils";
import {
  clearIntegrationOAuthClient,
  connectIntegration,
  disconnectIntegration,
  fetchConnectorCatalog,
  fetchIntegrationOAuthClient,
  fetchIntegrations,
  saveIntegrationOAuthClient,
  startGoogleWorkspaceOAuth,
  type ConnectIntegrationPayload,
  type ConnectorDefinition,
  type IntegrationConnection,
  type IntegrationMode,
  type IntegrationOAuthClient
} from "../../lib/api";
import { useToast } from "../ui/toast";
import { PageHeader } from "../layout/page-header";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle
} from "../ui/dialog";
import { Field, FormBanner, Input } from "../ui/form";
import { Skeleton } from "../ui/skeleton";
import { formatRelative, providerLabel } from "../../lib/format";

type StatusFilter = "ALL" | IntegrationConnection["status"];
const STATUS_FILTERS: StatusFilter[] = ["ALL", "CONNECTED", "ERROR", "DISABLED"];

export function ConnectorsPage() {
  const { toast } = useToast();
  const [catalog, setCatalog] = useState<ConnectorDefinition[]>([]);
  const [integrations, setIntegrations] = useState<IntegrationConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [active, setActive] = useState<ConnectorDefinition | null>(null);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("ALL");
  const [catalogQuery, setCatalogQuery] = useState("");

  const filteredIntegrations = useMemo(() => {
    // Active integrations are searched by both display labels and provider-owned
    // tenant ids because operators often know only one of those identifiers.
    const q = query.trim().toLowerCase();
    return integrations.filter((i) => {
      if (statusFilter !== "ALL" && i.status !== statusFilter) return false;
      if (!q) return true;
      const haystack =
        `${i.displayName} ${providerLabel(i.provider)} ${i.externalAccountId}`.toLowerCase();
      return haystack.includes(q);
    });
  }, [integrations, query, statusFilter]);

  const filteredCatalog = useMemo(() => {
    const q = catalogQuery.trim().toLowerCase();
    if (!q) return catalog;
    // Catalog search intentionally excludes credential field metadata so secret
    // labels/placeholders do not affect connector discovery results.
    return catalog.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.category.toLowerCase().includes(q)
    );
  }, [catalog, catalogQuery]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [c, i] = await Promise.all([
        fetchConnectorCatalog(),
        fetchIntegrations()
      ]);
      setCatalog(c.data);
      setIntegrations(i.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load connectors");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleDisconnect(id: string) {
    try {
      await disconnectIntegration(id);
      toast({ title: "Integration disconnected", tone: "success" });
      await load();
    } catch (err) {
      toast({
        title: "Unable to disconnect",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Connectors"
        title="SaaS connectors"
        description="Connect SaaS apps to ingest audit logs and configuration drift events. Tokens are encrypted at rest."
      />

      <section className="flex flex-col gap-3">
        <div className="flex items-end justify-between gap-3">
          <h2 className="text-sm font-semibold text-foreground">
            Active integrations
          </h2>
          {integrations.length > 0 ? (
            <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
              {filteredIntegrations.length} of {integrations.length}
            </span>
          ) : null}
        </div>

        {integrations.length > 0 ? (
          <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-card/60 px-3 py-2">
            <div className="relative w-full max-w-xs">
              <Search
                className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                aria-hidden
              />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search integrations…"
                aria-label="Search integrations"
                className="h-8 pl-7 text-xs"
              />
            </div>
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Status
            </span>
            <div className="flex items-center gap-1">
              {STATUS_FILTERS.map((s) => {
                const active = statusFilter === s;
                return (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setStatusFilter(s)}
                    aria-pressed={active}
                    className={cn(
                      "rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider transition-colors",
                      active
                        ? "border-signal/40 bg-signal/15 text-signal"
                        : "border-border/80 bg-background text-muted-foreground hover:border-border hover:text-foreground"
                    )}
                  >
                    {s}
                  </button>
                );
              })}
            </div>
          </div>
        ) : null}

        {loading ? (
          <Card>
            <CardContent className="space-y-2 p-4">
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-4 w-3/4" />
            </CardContent>
          </Card>
        ) : integrations.length === 0 ? (
          <Card>
            <CardContent className="p-6 text-sm text-muted-foreground">
              No integrations yet. Pick a connector below to add one.
            </CardContent>
          </Card>
        ) : filteredIntegrations.length === 0 ? (
          <Card>
            <CardContent className="p-6 text-sm text-muted-foreground">
              No integrations match the current filters.
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {filteredIntegrations.map((integration) => (
              <Card
                key={integration.id}
                className={cn(
                  "relative overflow-hidden",
                  integration.status === "ERROR"
                    ? "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:bg-destructive"
                    : integration.status === "CONNECTED"
                      ? "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:bg-success/60"
                      : ""
                )}
              >
                <CardContent className="flex flex-col gap-3 p-5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                        {providerLabel(integration.provider)}
                      </p>
                      <p className="mt-1 truncate text-sm font-semibold text-foreground">
                        {integration.displayName}
                      </p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
                        {integration.externalAccountId}
                      </p>
                    </div>
                    <Badge
                      variant={
                        integration.status === "CONNECTED"
                          ? "success"
                          : integration.status === "ERROR"
                            ? "destructive"
                            : "secondary"
                      }
                    >
                      {integration.status}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Mode:{" "}
                    {integration.mode === "REMEDIATION"
                      ? "Read + remediate"
                      : "Read-only"}
                    {" · "}
                    <span className="font-mono tabular-nums">
                      synced {formatRelative(integration.lastSyncAt)}
                    </span>
                  </p>
                  <div className="flex justify-end">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => void handleDisconnect(integration.id)}
                    >
                      <Unplug className="h-3.5 w-3.5" />
                      Disconnect
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h2 className="text-sm font-semibold text-foreground">
            Available connectors
          </h2>
          {catalog.length > 0 ? (
            <div className="relative w-full max-w-xs">
              <Search
                className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                aria-hidden
              />
              <Input
                value={catalogQuery}
                onChange={(e) => setCatalogQuery(e.target.value)}
                placeholder="Search catalog…"
                aria-label="Search connector catalog"
                className="h-8 pl-7 text-xs"
              />
            </div>
          ) : null}
        </div>
        {error ? (
          <Card>
            <CardContent className="p-6 text-sm text-destructive">
              {error}
            </CardContent>
          </Card>
        ) : loading ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Card key={i}>
                <CardContent className="space-y-2 p-5">
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-5 w-40" />
                  <Skeleton className="h-3 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
        ) : filteredCatalog.length === 0 ? (
          <Card>
            <CardContent className="p-6 text-sm text-muted-foreground">
              No connectors match your search.
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {filteredCatalog.map((connector) => (
              <Card key={connector.provider}>
                <CardHeader>
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-base">
                      {connector.name}
                    </CardTitle>
                    <Badge variant="outline">{connector.category}</Badge>
                  </div>
                  <CardDescription>{connector.description}</CardDescription>
                </CardHeader>
                <CardContent className="flex items-center justify-between gap-2">
                  <a
                    href={connector.docsUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
                  >
                    Docs
                    <ExternalLink className="h-3 w-3" aria-hidden />
                  </a>
                  <Button size="sm" onClick={() => setActive(connector)}>
                    <Plus className="h-3.5 w-3.5" />
                    Connect
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </section>

      <ConnectDialog
        connector={active}
        onClose={() => setActive(null)}
        onConnected={async () => {
          setActive(null);
          toast({
            title: "Integration connected",
            tone: "success"
          });
          await load();
        }}
      />
    </div>
  );
}

function ConnectDialog({
  connector,
  onClose,
  onConnected
}: {
  connector: ConnectorDefinition | null;
  onClose: () => void;
  onConnected: () => Promise<void>;
}) {
  const displayNameId = useId();
  const externalAccountId = useId();
  const [displayName, setDisplayName] = useState("");
  const [externalAccount, setExternalAccount] = useState("");
  const [mode, setMode] = useState<IntegrationMode>("READ_ONLY");
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [oauthClient, setOauthClient] = useState<IntegrationOAuthClient | null>(null);
  const [oauthClientLoading, setOauthClientLoading] = useState(false);
  const [showOauthSetup, setShowOauthSetup] = useState(false);

  const isGoogleWorkspace = connector?.provider === "GOOGLE_WORKSPACE";

  useEffect(() => {
    if (connector) {
      // Reset form state whenever a new connector is selected so credential
      // values from one provider cannot bleed into another provider's dialog.
      setDisplayName(`${connector.name} workspace`);
      setExternalAccount("");
      setMode("READ_ONLY");
      setFieldValues({});
      setError("");
      setOauthClient(null);
      setShowOauthSetup(false);
    }
  }, [connector]);

  useEffect(() => {
    if (!connector || !isGoogleWorkspace) return;
    let cancelled = false;
    setOauthClientLoading(true);
    fetchIntegrationOAuthClient("GOOGLE_WORKSPACE")
      .then(({ data }) => {
        if (cancelled) return;
        setOauthClient(data);
        setShowOauthSetup(!data.configured);
      })
      .catch(() => {
        if (cancelled) return;
        setOauthClient({
          provider: "GOOGLE_WORKSPACE",
          clientId: "",
          redirectUri: "",
          defaultRedirectUri: "",
          configured: false,
          updatedAt: null
        });
        setShowOauthSetup(true);
      })
      .finally(() => {
        if (!cancelled) setOauthClientLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [connector, isGoogleWorkspace]);

  if (!connector) {
    return null;
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!connector) return;

    if (isGoogleWorkspace) {
      // Google Workspace captures the workspace domain and refresh token through
      // OAuth callback state, so manual credential fields are deliberately hidden.
      if (!oauthClient?.configured) {
        setShowOauthSetup(true);
        setError(
          "Add your Google Cloud OAuth client credentials below before continuing."
        );
        return;
      }
      setSaving(true);
      setError("");
      try {
        const response = await startGoogleWorkspaceOAuth(mode);
        if (typeof window !== "undefined") {
          window.location.assign(response.data.url);
        }
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Unable to start Google OAuth"
        );
        setSaving(false);
      }
      return;
    }

    const credentials = {
      // Connector catalog entries may name the primary secret accessToken or
      // token. Normalize both field names into the API payload.
      accessToken: fieldValues.accessToken ?? fieldValues.token ?? "",
      refreshToken: fieldValues.refreshToken,
      webhookSecret: fieldValues.webhookSecret
    };

    setSaving(true);
    setError("");
    try {
      const payload: ConnectIntegrationPayload = {
        provider: connector.provider,
        displayName: displayName.trim(),
        externalAccountId: externalAccount.trim(),
        mode,
        credentials
      };
      // Manual connectors post only after local normalization; server-side
      // validation/encryption remains authoritative.
      await connectIntegration(payload);
      await onConnected();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to connect");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog
      open={Boolean(connector)}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Connect {connector.name}</DialogTitle>
          <DialogDescription>
            {isGoogleWorkspace
              ? "You'll be redirected to Google to sign in as a super admin and authorize Aperio. The workspace domain and tokens are captured automatically."
              : "Tokens are encrypted with AES-256-GCM before being stored."}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          {isGoogleWorkspace ? null : (
            <>
              <Field label="Display name" htmlFor={displayNameId} required>
                <Input
                  id={displayNameId}
                  value={displayName}
                  onChange={(event) => setDisplayName(event.target.value)}
                  required
                />
              </Field>
              <Field
                label="External account ID"
                htmlFor={externalAccountId}
                hint="Tenant or workspace identifier from the SaaS app."
                required
              >
                <Input
                  id={externalAccountId}
                  value={externalAccount}
                  onChange={(event) => setExternalAccount(event.target.value)}
                  required
                />
              </Field>
            </>
          )}
          <Field label="Mode" hint="You can upgrade modes later.">
            <div className="flex gap-2">
              {(["READ_ONLY", "REMEDIATION"] as const).map((option) => (
                <button
                  key={option}
                  type="button"
                  onClick={() => setMode(option)}
                  className={`flex-1 rounded-md border px-3 py-2 text-xs font-medium transition-colors ${
                    mode === option
                      ? "border-foreground bg-foreground text-background"
                      : "border-border text-muted-foreground hover:bg-muted"
                  }`}
                >
                  {option === "READ_ONLY" ? "Read-only" : "Read + remediate"}
                </button>
              ))}
            </div>
          </Field>

          {isGoogleWorkspace ? (
            <GoogleOAuthClientPanel
              loading={oauthClientLoading}
              client={oauthClient}
              showSetup={showOauthSetup}
              onChange={(next) => {
                setOauthClient(next);
                setShowOauthSetup(!next.configured);
              }}
              onRequestEdit={() => setShowOauthSetup(true)}
              onCancelEdit={() => setShowOauthSetup(false)}
              onError={setError}
            />
          ) : null}

          {isGoogleWorkspace
            ? null
            : connector.fields.map((field) => (
                <Field
                  key={field.key}
                  label={field.label}
                  hint={field.helper}
                  required={field.required}
                >
                  <Input
                    type={field.type === "password" ? "password" : "text"}
                    placeholder={field.placeholder}
                    value={fieldValues[field.key] ?? ""}
                    onChange={(event) =>
                      setFieldValues((prev) => ({
                        ...prev,
                        [field.key]: event.target.value
                      }))
                    }
                    required={field.required}
                  />
                </Field>
              ))}

          <FormBanner tone="error">{error}</FormBanner>

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              loading={saving}
              loadingText={
                isGoogleWorkspace ? "Redirecting…" : "Connecting…"
              }
              disabled={
                isGoogleWorkspace &&
                (oauthClientLoading || !oauthClient?.configured)
              }
            >
              <CheckCircle2 className="h-4 w-4" />
              {isGoogleWorkspace ? "Continue with Google" : "Connect"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function GoogleOAuthClientPanel({
  loading,
  client,
  showSetup,
  onChange,
  onRequestEdit,
  onCancelEdit,
  onError
}: {
  loading: boolean;
  client: IntegrationOAuthClient | null;
  showSetup: boolean;
  onChange: (next: IntegrationOAuthClient) => void;
  onRequestEdit: () => void;
  onCancelEdit: () => void;
  onError: (message: string) => void;
}) {
  const clientIdInputId = useId();
  const clientSecretInputId = useId();
  const redirectInputId = useId();
  const [clientIdInput, setClientIdInput] = useState("");
  const [clientSecretInput, setClientSecretInput] = useState("");
  const [redirectInput, setRedirectInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    if (!client) return;
    setClientIdInput(client.clientId);
    setRedirectInput(client.redirectUri || client.defaultRedirectUri);
    setClientSecretInput("");
  }, [client]);

  if (loading) {
    return (
      <div className="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
        Loading Google OAuth client configuration…
      </div>
    );
  }

  if (!client) return null;

  async function handleSave() {
    if (!clientIdInput.trim() || !clientSecretInput.trim() || !redirectInput.trim()) {
      onError("Client ID, client secret, and redirect URI are required.");
      return;
    }
    setSaving(true);
    try {
      const { data } = await saveIntegrationOAuthClient({
        provider: "GOOGLE_WORKSPACE",
        clientId: clientIdInput.trim(),
        clientSecret: clientSecretInput.trim(),
        redirectUri: redirectInput.trim()
      });
      onChange(data);
      onError("");
    } catch (err) {
      onError(
        err instanceof Error
          ? err.message
          : "Unable to save Google OAuth client credentials"
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleClear() {
    setClearing(true);
    try {
      const { data } = await clearIntegrationOAuthClient("GOOGLE_WORKSPACE");
      onChange(data);
      setClientIdInput("");
      setClientSecretInput("");
      setRedirectInput(data.defaultRedirectUri);
      onError("");
    } catch (err) {
      onError(
        err instanceof Error
          ? err.message
          : "Unable to clear Google OAuth client credentials"
      );
    } finally {
      setClearing(false);
    }
  }

  if (client.configured && !showSetup) {
    return (
      <div className="flex items-start justify-between gap-3 rounded-md border border-border bg-muted/30 p-3 text-xs">
        <div className="space-y-0.5">
          <div className="font-medium text-foreground">
            Using your Google Cloud OAuth app
          </div>
          <div className="text-muted-foreground">Client ID: {client.clientId}</div>
          <div className="text-muted-foreground">
            Redirect URI: {client.redirectUri}
          </div>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onRequestEdit}
        >
          Edit
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-3 rounded-md border border-dashed border-border bg-muted/20 p-3 text-xs">
      <div className="space-y-1">
        <div className="text-sm font-medium text-foreground">
          Google Cloud OAuth client
        </div>
        <p className="text-muted-foreground">
          One-time setup per workspace. In Google Cloud Console open APIs &amp; Services
          → Credentials, create an OAuth client ID (type: Web application), add the
          redirect URI below to "Authorized redirect URIs", then paste the client ID
          and secret here.
        </p>
      </div>
      <Field label="Client ID" htmlFor={clientIdInputId} required>
        <Input
          id={clientIdInputId}
          value={clientIdInput}
          onChange={(event) => setClientIdInput(event.target.value)}
          placeholder="...apps.googleusercontent.com"
          required
        />
      </Field>
      <Field label="Client secret" htmlFor={clientSecretInputId} required>
        <Input
          id={clientSecretInputId}
          type="password"
          value={clientSecretInput}
          onChange={(event) => setClientSecretInput(event.target.value)}
          placeholder={client.configured ? "Re-enter the client secret to update" : ""}
          required
        />
      </Field>
      <Field
        label="Authorized redirect URI"
        htmlFor={redirectInputId}
        hint="Must match the value configured in Google Cloud Console exactly."
        required
      >
        <Input
          id={redirectInputId}
          value={redirectInput}
          onChange={(event) => setRedirectInput(event.target.value)}
          required
        />
      </Field>
      <div className="flex flex-wrap justify-end gap-2">
        {client.configured ? (
          <>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleClear}
              loading={clearing}
              loadingText="Removing…"
            >
              Remove credentials
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onCancelEdit}
            >
              Cancel
            </Button>
          </>
        ) : null}
        <Button
          type="button"
          size="sm"
          onClick={handleSave}
          loading={saving}
          loadingText="Saving…"
        >
          Save credentials
        </Button>
      </div>
    </div>
  );
}
