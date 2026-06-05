-- AlterTable
ALTER TABLE "ingestion_jobs"
ADD COLUMN "lease_owner" VARCHAR(180),
ADD COLUMN "lease_expires_at" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "siem_deliveries"
ADD COLUMN "lease_owner" VARCHAR(180),
ADD COLUMN "lease_expires_at" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "ingestion_jobs_status_lease_expires_at_idx" ON "ingestion_jobs"("status", "lease_expires_at");

-- CreateIndex
CREATE INDEX "siem_deliveries_status_lease_expires_at_idx" ON "siem_deliveries"("status", "lease_expires_at");
