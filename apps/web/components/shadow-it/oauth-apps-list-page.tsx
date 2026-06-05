"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import {
  fetchShadowItOauthApps,
  type ShadowItOauthApp
} from "../../lib/api";
import { PageHeader } from "../layout/page-header";
import { AsyncSection } from "../ui/async-section";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { Skeleton } from "../ui/skeleton";
import { OauthAppsCard } from "./oauth-apps-card";

export function OauthAppsListPage() {
  const [apps, setApps] = useState<ShadowItOauthApp[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetchShadowItOauthApps();
      setApps(response.data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to load OAuth apps"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Shadow IT"
        title="OAuth Apps"
        description="Every third-party application authorized via user OAuth grants across connected workspaces. Click any row for scopes and users."
        actions={
          <Button variant="outline" asChild>
            <Link href="/shadow-it">
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
              Back to Shadow IT
            </Link>
          </Button>
        }
      />

      <AsyncSection
        data={apps}
        loading={loading}
        error={error}
        onRetry={() => void load()}
        errorTitle="Unable to load OAuth apps"
        skeleton={
          <Card>
            <CardContent className="space-y-2 p-6">
              <Skeleton className="h-4 w-1/3" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-2/3" />
            </CardContent>
          </Card>
        }
      >
        {(data) => (
          <OauthAppsCard
            apps={data}
            title="All OAuth Apps"
            description="Complete inventory of authorized OAuth applications."
          />
        )}
      </AsyncSection>
    </div>
  );
}
