-- Per-integration cursor for the Google Workspace OAuth grant sync. The
-- Admin Directory tokens endpoint is queried per user, so a full sweep of
-- a tenant requires iterating saas_identities and calling tokens.list
-- for each one. The cursor row records the most recent sweep so the
-- connectors UI can surface sync health without grepping logs.
CREATE TABLE "google_workspace_oauth_sync_cursors" (
    "integration_id" TEXT NOT NULL PRIMARY KEY,
    "last_synced_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_app_count" INTEGER NOT NULL DEFAULT 0,
    "last_grant_count" INTEGER NOT NULL DEFAULT 0,
    "last_error" VARCHAR(500)
);

ALTER TABLE "google_workspace_oauth_sync_cursors"
    ADD CONSTRAINT "google_workspace_oauth_sync_cursors_integration_id_fkey"
    FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
