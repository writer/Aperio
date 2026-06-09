-- Per-integration user-defined finding rule. The operator authors rules
-- from the connector page without writing Go; the predicate is a small
-- JSON expression tree over the ingestion JobPayload that the worker
-- evaluates after the built-in rules.
CREATE TABLE "custom_finding_rules" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organization_id" TEXT NOT NULL,
    "integration_id" TEXT NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "severity" "Severity" NOT NULL DEFAULT 'MEDIUM',
    "event_type" VARCHAR(120) NOT NULL,
    "predicate" JSONB NOT NULL DEFAULT '{}',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL
);

ALTER TABLE "custom_finding_rules"
    ADD CONSTRAINT "custom_finding_rules_organization_id_fkey"
    FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "custom_finding_rules"
    ADD CONSTRAINT "custom_finding_rules_integration_id_fkey"
    FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;

CREATE INDEX "custom_finding_rules_organization_id_integration_id_idx"
    ON "custom_finding_rules"("organization_id", "integration_id");

CREATE INDEX "custom_finding_rules_integration_id_enabled_idx"
    ON "custom_finding_rules"("integration_id", "enabled");
