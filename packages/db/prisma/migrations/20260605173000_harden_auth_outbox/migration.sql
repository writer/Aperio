-- Harden authentication replay tracking, SIEM outbox idempotency, and rate limiting.
ALTER TYPE "AuthTokenPurpose" ADD VALUE IF NOT EXISTS 'OAUTH_STATE';

ALTER TABLE "users" ADD COLUMN "mfa_last_counter" INTEGER;

ALTER TABLE "ingested_events" ADD COLUMN "ingestion_job_id" TEXT;
ALTER TABLE "ingested_events"
  ADD CONSTRAINT "ingested_events_ingestion_job_id_fkey"
  FOREIGN KEY ("ingestion_job_id") REFERENCES "ingestion_jobs"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
CREATE UNIQUE INDEX "ingested_events_ingestion_job_id_key"
  ON "ingested_events"("ingestion_job_id");

ALTER TABLE "siem_deliveries" ADD COLUMN "dedupe_key" VARCHAR(128);
CREATE UNIQUE INDEX "siem_deliveries_org_destination_stream_dedupe_key"
  ON "siem_deliveries"("organization_id", "destination_id", "stream", "dedupe_key");

CREATE INDEX "security_assets_org_provider_external_id_idx"
  ON "security_assets"("organization_id", "provider", "external_id");

CREATE TABLE "rate_limit_buckets" (
  "key" VARCHAR(128) NOT NULL,
  "count" INTEGER NOT NULL DEFAULT 0,
  "reset_at" TIMESTAMP(3) NOT NULL,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "rate_limit_buckets_pkey" PRIMARY KEY ("key")
);
CREATE INDEX "rate_limit_buckets_reset_at_idx" ON "rate_limit_buckets"("reset_at");

CREATE INDEX "agent_messages_from_agent_id_created_at_idx"
  ON "agent_messages"("from_agent_id", "created_at");
