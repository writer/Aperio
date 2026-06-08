-- Executive reports: persisted PDF/HTML artifacts of CISO-facing posture summaries.
CREATE TYPE "ReportPeriod" AS ENUM ('WEEK', 'MONTH', 'QUARTER', 'CUSTOM');

CREATE TYPE "ExecutiveReportStatus" AS ENUM ('GENERATING', 'READY', 'FAILED');

CREATE TABLE "executive_reports" (
  "id"                    TEXT NOT NULL,
  "organization_id"       TEXT NOT NULL,
  "requested_by_user_id"  TEXT,
  "period"                "ReportPeriod" NOT NULL,
  "period_start"          TIMESTAMP(3) NOT NULL,
  "period_end"            TIMESTAMP(3) NOT NULL,
  "title"                 VARCHAR(220) NOT NULL,
  "summary"               TEXT,
  "status"                "ExecutiveReportStatus" NOT NULL DEFAULT 'GENERATING',
  "html_path"             VARCHAR(500),
  "pdf_path"              VARCHAR(500),
  "kpi_snapshot"          JSONB NOT NULL DEFAULT '{}',
  "error_message"         VARCHAR(1000),
  "generated_at"          TIMESTAMP(3),
  "created_at"            TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at"            TIMESTAMP(3) NOT NULL,
  CONSTRAINT "executive_reports_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "executive_reports"
  ADD CONSTRAINT "executive_reports_org_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE INDEX "executive_reports_org_period_end_idx"
  ON "executive_reports"("organization_id", "period_end");

CREATE INDEX "executive_reports_org_status_created_at_idx"
  ON "executive_reports"("organization_id", "status", "created_at");
