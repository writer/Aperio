"use client";

import { useCallback, useEffect, useId, useState } from "react";
import { CheckCircle2, Plus, Send, Trash2 } from "lucide-react";
import {
  createSiemDestination,
  deleteSiemDestination,
  fetchSiemCatalog,
  fetchSiemDestinations,
  testSiemDestination,
  type CreateSiemPayload,
  type SiemDestination,
  type SiemDestinationDefinition,
  type SiemStream
} from "../../lib/api";
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
  DialogDescription,
  DialogHeader,
  DialogTitle
} from "../ui/dialog";
import { Field, FormBanner, Input } from "../ui/form";
import { Skeleton } from "../ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "../ui/table";
import { formatRelative } from "../../lib/format";

const allStreams: SiemStream[] = ["FINDINGS", "EVENTS", "AUDIT_LOGS"];

export function SiemPage() {
  const { toast } = useToast();
  const [catalog, setCatalog] = useState<SiemDestinationDefinition[]>([]);
  const [destinations, setDestinations] = useState<SiemDestination[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [active, setActive] = useState<SiemDestinationDefinition | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [c, d] = await Promise.all([
        fetchSiemCatalog(),
        fetchSiemDestinations()
      ]);
      setCatalog(c.data);
      setDestinations(d.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load SIEM");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleTest(id: string) {
    try {
      const result = await testSiemDestination(id);
      toast({
        title: result.data.ok ? "Test delivery succeeded" : "Test delivery failed",
        description: result.data.message,
        tone: result.data.ok ? "success" : "error"
      });
    } catch (err) {
      toast({
        title: "Unable to test destination",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    }
  }

  async function handleDelete(id: string) {
    try {
      await deleteSiemDestination(id);
      toast({ title: "Destination removed", tone: "success" });
      await load();
    } catch (err) {
      toast({
        title: "Unable to remove destination",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="SIEM"
        title="SIEM destinations"
        description="Forward findings, events, and audit logs to your SIEM. Tokens are AES-256-GCM encrypted at rest."
      />

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-semibold text-foreground">
          Active destinations
        </h2>
        <Card>
          <CardContent className="p-0">
            {loading ? (
              <div className="space-y-2 p-6">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
              </div>
            ) : error ? (
              <div className="p-6 text-sm text-destructive">{error}</div>
            ) : destinations.length === 0 ? (
              <div className="p-6 text-sm text-muted-foreground">
                No SIEM destinations yet. Add one from the catalog below.
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Kind</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Deliveries</TableHead>
                    <TableHead>Last</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {destinations.map((destination) => (
                    <TableRow key={destination.id}>
                      <TableCell className="font-medium">
                        {destination.name}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {destination.kind}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            destination.status === "ACTIVE"
                              ? "success"
                              : destination.status === "ERROR"
                                ? "destructive"
                                : "secondary"
                          }
                        >
                          {destination.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {destination.deliveriesOk} ok · {destination.deliveriesFail} fail
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {formatRelative(destination.lastDeliveryAt)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="inline-flex gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void handleTest(destination.id)}
                          >
                            <Send className="h-3.5 w-3.5" />
                            Test
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void handleDelete(destination.id)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </section>

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-semibold text-foreground">Catalog</h2>
        {loading ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <Card key={i}>
                <CardContent className="space-y-2 p-5">
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-3 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {catalog.map((definition) => (
              <Card key={definition.kind}>
                <CardHeader>
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-base">
                      {definition.name}
                    </CardTitle>
                    <Badge variant="outline">{definition.category}</Badge>
                  </div>
                  <CardDescription>{definition.description}</CardDescription>
                </CardHeader>
                <CardContent>
                  <Button size="sm" onClick={() => setActive(definition)}>
                    <Plus className="h-3.5 w-3.5" />
                    Add destination
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </section>

      <SiemDialog
        definition={active}
        onClose={() => setActive(null)}
        onCreated={async () => {
          setActive(null);
          toast({ title: "Destination added", tone: "success" });
          await load();
        }}
      />
    </div>
  );
}

function SiemDialog({
  definition,
  onClose,
  onCreated
}: {
  definition: SiemDestinationDefinition | null;
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const nameId = useId();
  const [name, setName] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [streams, setStreams] = useState<SiemStream[]>(["FINDINGS"]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (definition) {
      setName(`${definition.name} destination`);
      setFields({});
      setStreams(definition.defaultStreams);
      setError("");
    }
  }, [definition]);

  if (!definition) {
    return null;
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!definition) return;
    setSaving(true);
    setError("");
    try {
      const payload: CreateSiemPayload = {
        kind: definition.kind,
        name: name.trim(),
        streams,
        endpointUrl: fields.endpointUrl,
        filePath: fields.filePath,
        index: fields.index,
        token: fields.token
      };
      await createSiemDestination(payload);
      await onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to add destination");
    } finally {
      setSaving(false);
    }
  }

  function toggleStream(stream: SiemStream) {
    setStreams((prev) =>
      prev.includes(stream)
        ? prev.filter((entry) => entry !== stream)
        : [...prev, stream]
    );
  }

  return (
    <Dialog
      open={Boolean(definition)}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add {definition.name} destination</DialogTitle>
          <DialogDescription>{definition.description}</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label="Name" htmlFor={nameId} required>
            <Input
              id={nameId}
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
            />
          </Field>

          {definition.fields.map((field) => (
            <Field
              key={field.key}
              label={field.label}
              hint={field.helper}
              required={field.required}
            >
              <Input
                type={field.type === "password" ? "password" : "text"}
                placeholder={field.placeholder}
                value={fields[field.key] ?? ""}
                onChange={(event) =>
                  setFields((prev) => ({
                    ...prev,
                    [field.key]: event.target.value
                  }))
                }
                required={field.required}
              />
            </Field>
          ))}

          <Field label="Streams">
            <div className="flex flex-wrap gap-2">
              {allStreams.map((stream) => {
                const checked = streams.includes(stream);
                return (
                  <button
                    key={stream}
                    type="button"
                    onClick={() => toggleStream(stream)}
                    className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                      checked
                        ? "border-foreground bg-foreground text-background"
                        : "border-border text-muted-foreground hover:bg-muted"
                    }`}
                  >
                    {stream.replace("_", " ").toLowerCase()}
                  </button>
                );
              })}
            </div>
          </Field>

          <FormBanner tone="error">{error}</FormBanner>

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={saving} loadingText="Adding…">
              <CheckCircle2 className="h-4 w-4" />
              Add
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
