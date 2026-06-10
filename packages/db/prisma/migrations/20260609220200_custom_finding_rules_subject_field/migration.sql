-- subject_field is a dot-pathed reference (e.g. "payload.parameters.target_domain")
-- that the custom-rule evaluator uses as both the Finding.Target and
-- Finding.DedupeTarget. Without it, all custom findings for the same actor
-- under one rule collapse into a single security_findings row via
-- ON CONFLICT (organization_id, dedupe_key), silently merging distinct
-- subjects (e.g. multiple files shared by the same user) into one finding.
-- Empty/NULL preserves the prior actor-keyed behavior so this is a
-- safe additive change.
ALTER TABLE "custom_finding_rules"
    ADD COLUMN "subject_field" VARCHAR(200) NOT NULL DEFAULT '';
