"use client";

import Link from "next/link";
import { useAuth } from "../auth/auth-shell";
import { MfaCard } from "../auth/mfa-card";
import { PageHeader } from "../layout/page-header";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle
} from "../ui/card";
import { InfoTile } from "../ui/info-tile";

export function PersonalSettingsPage() {
  const { session } = useAuth();
  const canManageOrg =
    session?.user.role === "OWNER" || session?.user.role === "ADMIN";

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Settings"
        title="Personal settings"
        description="Account details and multi-factor authentication for your login."
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,400px)]">
        <Card>
          <CardHeader>
            <CardTitle>Profile</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <InfoTile
                label="Display name"
                value={session?.user.displayName ?? "Not set"}
              />
              <InfoTile label="Email" value={session?.user.email ?? "—"} />
              <InfoTile label="Role" value={session?.user.role ?? "—"} />
              <InfoTile
                label="Organization"
                value={session?.organization.name ?? "—"}
                hint={session?.organization.slug ?? ""}
              />
            </div>

            {canManageOrg ? (
              <p className="text-sm text-muted-foreground">
                Need to manage members, alerts, or organization controls?{" "}
                <Link
                  href="/settings/organization"
                  className="font-medium text-foreground underline-offset-4 hover:underline"
                >
                  Open organization settings
                </Link>
                .
              </p>
            ) : null}
          </CardContent>
        </Card>

        <MfaCard />
      </div>
    </div>
  );
}
