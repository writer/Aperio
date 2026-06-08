-- Report templates: distinguish the executive summary report from
-- vendor-specific assessment reports (starting with Google Workspace).
CREATE TYPE "ReportTemplate" AS ENUM (
  'EXECUTIVE_SUMMARY',
  'GOOGLE_WORKSPACE_ASSESSMENT'
);

ALTER TABLE "executive_reports"
  ADD COLUMN "template" "ReportTemplate" NOT NULL DEFAULT 'EXECUTIVE_SUMMARY';

CREATE INDEX "executive_reports_org_template_created_at_idx"
  ON "executive_reports"("organization_id", "template", "created_at");
