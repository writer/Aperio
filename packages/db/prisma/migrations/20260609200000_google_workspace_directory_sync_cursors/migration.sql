-- Per-integration cursor for the Google Workspace Directory API sync. The
-- Directory API does not expose a streaming "since" filter; the sync does a
-- full users.list page-walk on every tick and upserts into saas_identities.
-- The cursor row exists so the connectors UI can surface last_synced_at and
-- last_error per integration, and so a future incremental etag-based sync
-- can persist state here without another migration.
CREATE TABLE "google_workspace_directory_sync_cursors" (
    "integration_id" TEXT NOT NULL PRIMARY KEY,
    "last_synced_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_user_count" INTEGER NOT NULL DEFAULT 0,
    "last_error" VARCHAR(500)
);

ALTER TABLE "google_workspace_directory_sync_cursors"
    ADD CONSTRAINT "google_workspace_directory_sync_cursors_integration_id_fkey"
    FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
