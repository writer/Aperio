"use client";

import { useCallback, useEffect, useState } from "react";
import {
  fetchShadowItOauthApps,
  type ShadowItOauthApp
} from "../../lib/api";
import { PageHeader } from "../layout/page-header";
import { AsyncSection } from "../ui/async-section";
import { Card, CardContent } from "../ui/card";
import { Skeleton } from "../ui/skeleton";
import { OauthAppsCard } from "./oauth-apps-card";

export function ShadowItPage() {
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
        err instanceof Error ? err.message : "Unable to load shadow IT apps"
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
        title="Shadow IT"
        description="Third-party services your workforce is using outside of IT-sanctioned tooling. Start with OAuth applications users have authorized against connected workspaces."
      />

      <AsyncSection
        data={apps}
        loading={loading}
        error={error}
        onRetry={() => void load()}
        errorTitle="Unable to load shadow IT"
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
            limit={15}
            viewAllHref="/shadow-it/oauth-apps"
          />
        )}
      </AsyncSection>
    </div>
  );
}
