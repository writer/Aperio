-- Per-integration, per-application cursor for the Google Workspace Reports
-- API poller. Google returns activity events ordered by id.time DESC with a
-- unique id.uniqueQualifier as a tiebreaker, so we persist both values and
-- only enqueue activities strictly newer than the cursor. last_polled_at
-- is informational (surfaces in the connectors UI as "last sync"), and
-- last_error stores the most recent poll failure for operator debugging
-- without crashing the whole sweep.
CREATE TABLE "google_workspace_sync_cursors" (
    "integration_id" TEXT NOT NULL,
    "application" VARCHAR(64) NOT NULL,
    "last_event_time" TIMESTAMP(3) NOT NULL,
    "last_unique_qualifier" VARCHAR(64) NOT NULL DEFAULT '',
    "last_polled_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_error" VARCHAR(500),

    CONSTRAINT "google_workspace_sync_cursors_pkey" PRIMARY KEY ("integration_id", "application")
);

ALTER TABLE "google_workspace_sync_cursors"
    ADD CONSTRAINT "google_workspace_sync_cursors_integration_id_fkey"
    FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
