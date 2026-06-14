import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  buildGoogleWorkspaceBigQueryWifSetupScript,
  validateGoogleWorkspaceBigQueryWifSetupInput
} from "../packages/shared/src/google-workspace-bigquery-wif";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

test("package does not expose a standalone Google Workspace BigQuery WIF setup command", () => {
  const pkg = JSON.parse(readRepoFile("package.json")) as {
    scripts: Record<string, string>;
  };

  assert.equal(pkg.scripts["setup:gws-bigquery-wif"], undefined);
});

test("connectors UI exposes clean BigQuery WIF setup wizard", () => {
  const source = readRepoFile("apps/web/components/connectors/connectors-page.tsx");

  assert.match(source, /GoogleWorkspaceBigQuerySetupDialog/);
  assert.match(source, />\s*BigQuery\s*</);
  assert.match(source, /Google Workspace BigQuery intelligence/);
  assert.match(source, /Workload Identity Federation/);
  assert.match(source, /No service-account keys are stored in\s+Aperio/);
  assert.match(source, /Authorized views/);
  assert.match(source, /Data-owner BigQuery project/);
  assert.match(source, /Workload Identity trust/);
  assert.match(source, /Commands to run/);
  assert.match(source, /setProjectId\(""\)/);
  assert.match(source, /integration\?\.id/);
  assert.match(source, /buildGoogleWorkspaceBigQueryWifSetupScript/);
  assert.match(source, /googleWorkspaceBigQueryWifDefaults/);
  assert.doesNotMatch(source, /WriterInternal|WriterColab/);
});

test("shared WIF setup generator emits least-privilege BigQuery commands", () => {
  const script = buildGoogleWorkspaceBigQueryWifSetupScript({
    projectId: "example-project",
    rawDatasetId: "workspace_logs",
    location: "US",
    oidcIssuerUri: "https://issuer.example.com",
    oidcAudience: "aperio",
    principalSubject: "repo:example/aperio:ref:refs/heads/main",
    accessMode: "dataset"
  });

  assert.match(script, /gcloud iam workload-identity-pools create/);
  assert.match(script, /gcloud iam workload-identity-pools providers create-oidc/);
  assert.match(script, /roles\/iam\.workloadIdentityUser/);
  assert.match(script, /roles\/bigquery\.jobUser/);
  assert.match(script, /roles\/bigquery\.dataViewer/);
  assert.match(script, /bq query[\s\S]*--dry_run/);
  assert.match(script, /INFORMATION_SCHEMA\.TABLES/);
  assert.doesNotMatch(script, /bq update --source/);
  assert.doesNotMatch(script, /writer/i);
  assert.doesNotMatch(script, /WriterInternal|WriterColab/);
});

test("shared WIF setup generator supports authorized-view read datasets", () => {
  const script = buildGoogleWorkspaceBigQueryWifSetupScript({
    projectId: "example-project",
    rawDatasetId: "raw_workspace_logs",
    readDatasetId: "aperio_workspace_views",
    accessMode: "views",
    location: "EU",
    oidcIssuerUri: "https://issuer.example.com",
    oidcAudience: "aperio",
    principalAttribute: "repository",
    principalValue: "example/aperio"
  });

  assert.match(script, /WORKSPACE_LOG_DATASET='raw_workspace_logs'/);
  assert.match(script, /READ_DATASET='aperio_workspace_views'/);
  assert.match(script, /authorized view/i);
  assert.match(script, /bq mk --project_id="\$PROJECT_ID" --use_legacy_sql=false --view/);
  assert.match(script, /bq update --source "\$DATASET_ACCESS_JSON"/);
  assert.match(script, /"view": \{/);
  assert.match(
    script,
    /principalSet:\/\/iam\.googleapis\.com\/projects\/\$\{PROJECT_NUMBER\}\/locations\/global\/workloadIdentityPools\/\$\{POOL_ID\}\/attribute\.repository\/\$\{PRINCIPAL_VALUE\}/
  );
});

test("shared WIF setup generator validates required trust inputs", () => {
  assert.throws(
    () =>
      validateGoogleWorkspaceBigQueryWifSetupInput({
        projectId: "example-project",
        rawDatasetId: "workspace_logs",
        location: "US",
        accessMode: "dataset",
        oidcIssuerUri: "https://issuer.example.com",
        oidcAudience: "aperio"
      }),
    /principalSubject/
  );

  assert.throws(
    () =>
      validateGoogleWorkspaceBigQueryWifSetupInput({
        projectId: "example-project",
        rawDatasetId: "workspace_logs",
        location: "US",
        accessMode: "views",
        oidcIssuerUri: "https://issuer.example.com",
        oidcAudience: "aperio",
        principalSubject: "subject"
      }),
    /readDatasetId/
  );

  assert.throws(
    () =>
      validateGoogleWorkspaceBigQueryWifSetupInput({
        projectId: "example-project",
        rawDatasetId: "workspace_logs",
        readDatasetId: "workspace_logs",
        location: "US",
        accessMode: "views",
        oidcIssuerUri: "https://issuer.example.com",
        oidcAudience: "aperio",
        principalSubject: "subject"
      }),
    /different from rawDatasetId/
  );
});
