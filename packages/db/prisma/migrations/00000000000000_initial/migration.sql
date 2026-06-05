-- CreateEnum
CREATE TYPE "RoleName" AS ENUM ('OWNER', 'ADMIN', 'SECURITY_ANALYST', 'VIEWER');

-- CreateEnum
CREATE TYPE "SaaSProvider" AS ENUM ('GITHUB', 'SLACK', 'GOOGLE_WORKSPACE', 'ONE_PASSWORD', 'OKTA', 'MICROSOFT_365', 'ATLASSIAN');

-- CreateEnum
CREATE TYPE "IntegrationStatus" AS ENUM ('CONNECTED', 'DISABLED', 'ERROR');

-- CreateEnum
CREATE TYPE "IntegrationMode" AS ENUM ('READ_ONLY', 'REMEDIATION');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('OPEN', 'RESOLVED', 'MUTED');

-- CreateEnum
CREATE TYPE "EventProcessingStatus" AS ENUM ('RECEIVED', 'PROCESSED', 'FAILED');

-- CreateEnum
CREATE TYPE "SiemKind" AS ENUM ('SPLUNK_HEC', 'PANTHER', 'PANOPTICON', 'ELASTIC', 'DATADOG', 'GENERIC_WEBHOOK', 'JSON_FILE');

-- CreateEnum
CREATE TYPE "SiemStreamType" AS ENUM ('FINDINGS', 'EVENTS', 'AUDIT_LOGS');

-- CreateEnum
CREATE TYPE "SiemStatus" AS ENUM ('ACTIVE', 'PAUSED', 'ERROR');

-- CreateEnum
CREATE TYPE "SiemDeliveryStatus" AS ENUM ('PENDING', 'PROCESSING', 'DELIVERED', 'FAILED', 'DEAD_LETTER');

-- CreateEnum
CREATE TYPE "AgentKind" AS ENUM ('MCP_BROKER', 'SSPM_SCANNER', 'SIEM_DISPATCHER', 'REMEDIATION_PLANNER', 'HUMAN_REVIEW', 'CUSTOM');

-- CreateEnum
CREATE TYPE "AgentStatus" AS ENUM ('ACTIVE', 'PAUSED', 'ERROR');

-- CreateEnum
CREATE TYPE "AgentTaskStatus" AS ENUM ('QUEUED', 'RUNNING', 'WAITING_FOR_APPROVAL', 'SUCCEEDED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "AgentMessageRole" AS ENUM ('SYSTEM', 'AGENT', 'USER', 'TOOL');

-- CreateEnum
CREATE TYPE "AgentProposalStatus" AS ENUM ('PROPOSED', 'APPROVED', 'REJECTED', 'EXECUTED', 'FAILED');

-- CreateEnum
CREATE TYPE "SecurityAssetType" AS ENUM ('APPLICATION', 'OAUTH_APP', 'SERVICE_ACCOUNT', 'DATA_RESOURCE', 'WORKSPACE', 'VAULT', 'REPOSITORY');

-- CreateEnum
CREATE TYPE "AssetCriticality" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "AssetExposureLevel" AS ENUM ('INTERNAL', 'TRUSTED_EXTERNAL', 'PUBLIC');

-- CreateEnum
CREATE TYPE "AssetOwnershipStatus" AS ENUM ('ASSIGNED', 'UNASSIGNED', 'REVIEW_REQUIRED');

-- CreateEnum
CREATE TYPE "RiskExceptionStatus" AS ENUM ('ACTIVE', 'EXPIRED', 'REVOKED');

-- CreateEnum
CREATE TYPE "SaasIdentityKind" AS ENUM ('USER', 'SERVICE_ACCOUNT', 'BOT');

-- CreateEnum
CREATE TYPE "SaasIdentityStatus" AS ENUM ('ACTIVE', 'SUSPENDED', 'DORMANT');

-- CreateEnum
CREATE TYPE "AuthTokenPurpose" AS ENUM ('INVITE', 'PASSWORD_RESET');

-- CreateTable
CREATE TABLE "organizations" (
    "id" TEXT NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "slug" VARCHAR(120) NOT NULL,
    "notification_email" VARCHAR(255),
    "data_retention_days" INTEGER NOT NULL DEFAULT 90,
    "critical_risk_threshold" INTEGER NOT NULL DEFAULT 80,
    "default_sla_hours" INTEGER NOT NULL DEFAULT 24,
    "auto_resolve_low_severity" BOOLEAN NOT NULL DEFAULT false,
    "enforce_sso_only" BOOLEAN NOT NULL DEFAULT false,
    "webhook_alert_url" VARCHAR(500),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "organizations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "roles" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "name" "RoleName" NOT NULL,
    "permissions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "roles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "role_id" TEXT NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "password_hash" VARCHAR(255),
    "display_name" VARCHAR(160),
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "mfa_enabled" BOOLEAN NOT NULL DEFAULT false,
    "mfa_secret_encrypted" TEXT,
    "last_login_at" TIMESTAMP(3),
    "is_break_glass" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "integration_connections" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "provider" "SaaSProvider" NOT NULL,
    "display_name" VARCHAR(160) NOT NULL,
    "external_account_id" VARCHAR(255) NOT NULL,
    "scopes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "disabled_checks" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "encrypted_access_token" TEXT NOT NULL,
    "encrypted_refresh_token" TEXT,
    "encrypted_webhook_secret" TEXT,
    "google_mailbox_scan_client_email" VARCHAR(255),
    "encrypted_google_mailbox_scan_private_key" TEXT,
    "token_key_version" VARCHAR(32) NOT NULL DEFAULT 'v1',
    "status" "IntegrationStatus" NOT NULL DEFAULT 'CONNECTED',
    "mode" "IntegrationMode" NOT NULL DEFAULT 'READ_ONLY',
    "last_sync_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "integration_connections_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ingested_events" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "integration_id" TEXT NOT NULL,
    "provider" "SaaSProvider" NOT NULL,
    "event_type" VARCHAR(180) NOT NULL,
    "source" VARCHAR(180) NOT NULL,
    "actor" VARCHAR(255),
    "severity" "Severity" NOT NULL DEFAULT 'INFO',
    "payload" JSONB NOT NULL,
    "processing_status" "EventProcessingStatus" NOT NULL DEFAULT 'RECEIVED',
    "occurred_at" TIMESTAMP(3) NOT NULL,
    "processed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ingested_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_findings" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "integration_id" TEXT NOT NULL,
    "event_id" TEXT,
    "dedupe_key" VARCHAR(128) NOT NULL,
    "title" VARCHAR(220) NOT NULL,
    "description" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "status" "FindingStatus" NOT NULL DEFAULT 'OPEN',
    "risk_score" INTEGER NOT NULL,
    "remediation_steps" TEXT[],
    "evidence" JSONB NOT NULL,
    "detected_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolved_at" TIMESTAMP(3),
    "resolved_by_id" TEXT,
    "asset_id" TEXT,

    CONSTRAINT "security_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_assets" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "integration_id" TEXT,
    "owner_user_id" TEXT,
    "business_owner_user_id" TEXT,
    "type" "SecurityAssetType" NOT NULL,
    "provider" "SaaSProvider",
    "name" VARCHAR(180) NOT NULL,
    "summary" VARCHAR(500),
    "external_id" VARCHAR(255),
    "labels" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "criticality" "AssetCriticality" NOT NULL DEFAULT 'MEDIUM',
    "exposure_level" "AssetExposureLevel" NOT NULL DEFAULT 'INTERNAL',
    "ownership_status" "AssetOwnershipStatus" NOT NULL DEFAULT 'UNASSIGNED',
    "contains_sensitive_data" BOOLEAN NOT NULL DEFAULT false,
    "is_privileged" BOOLEAN NOT NULL DEFAULT false,
    "risk_score" INTEGER NOT NULL DEFAULT 0,
    "last_observed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_assets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "saas_identities" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "integration_id" TEXT,
    "provider" "SaaSProvider" NOT NULL,
    "external_id" VARCHAR(255) NOT NULL,
    "email" VARCHAR(255),
    "display_name" VARCHAR(160),
    "kind" "SaasIdentityKind" NOT NULL DEFAULT 'USER',
    "status" "SaasIdentityStatus" NOT NULL DEFAULT 'ACTIVE',
    "role" VARCHAR(120),
    "groups" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "scope_hints" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "linked_asset_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "mfa_enabled" BOOLEAN,
    "is_privileged" BOOLEAN NOT NULL DEFAULT false,
    "is_external" BOOLEAN NOT NULL DEFAULT false,
    "last_observed_at" TIMESTAMP(3),
    "risk_score" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "saas_identities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "auth_tokens" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "created_by_user_id" TEXT,
    "purpose" "AuthTokenPurpose" NOT NULL,
    "token_hash" VARCHAR(128) NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "consumed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auth_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_sessions" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "token_hash" VARCHAR(128) NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "last_seen_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "mfa_verified_at" TIMESTAMP(3),
    "last_ip_address" VARCHAR(64),
    "last_user_agent" VARCHAR(255),
    "revoked_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "siem_destinations" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "kind" "SiemKind" NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "endpoint_url" VARCHAR(500),
    "file_path" VARCHAR(500),
    "index" VARCHAR(120),
    "encrypted_token" TEXT,
    "token_key_version" VARCHAR(32) NOT NULL DEFAULT 'v1',
    "streams" "SiemStreamType"[] DEFAULT ARRAY['FINDINGS']::"SiemStreamType"[],
    "status" "SiemStatus" NOT NULL DEFAULT 'ACTIVE',
    "last_delivery_at" TIMESTAMP(3),
    "last_error" VARCHAR(500),
    "deliveries_ok" INTEGER NOT NULL DEFAULT 0,
    "deliveries_fail" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "siem_destinations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "siem_deliveries" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "destination_id" TEXT,
    "stream" "SiemStreamType" NOT NULL,
    "payload" JSONB NOT NULL,
    "status" "SiemDeliveryStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "max_attempts" INTEGER NOT NULL DEFAULT 5,
    "next_attempt_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_error" VARCHAR(500),
    "delivered_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "siem_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agents" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "key" VARCHAR(120) NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "kind" "AgentKind" NOT NULL,
    "capabilities" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "endpoint_url" VARCHAR(500),
    "mcp_server_url" VARCHAR(500),
    "status" "AgentStatus" NOT NULL DEFAULT 'ACTIVE',
    "last_seen_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_tasks" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "task_type" VARCHAR(120) NOT NULL,
    "title" VARCHAR(220) NOT NULL,
    "status" "AgentTaskStatus" NOT NULL DEFAULT 'QUEUED',
    "input" JSONB NOT NULL,
    "output" JSONB,
    "error" VARCHAR(1000),
    "created_by_agent_id" TEXT,
    "assigned_agent_id" TEXT,
    "parent_task_id" TEXT,
    "lease_expires_at" TIMESTAMP(3),
    "started_at" TIMESTAMP(3),
    "completed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agent_tasks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_messages" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "task_id" TEXT,
    "from_agent_id" TEXT,
    "to_agent_id" TEXT,
    "role" "AgentMessageRole" NOT NULL DEFAULT 'AGENT',
    "message_type" VARCHAR(120) NOT NULL DEFAULT 'a2a.message.v1',
    "correlation_id" VARCHAR(160),
    "content" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_messages_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_proposals" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "task_id" TEXT,
    "finding_id" TEXT,
    "proposed_by_agent_id" TEXT,
    "approved_by_user_id" TEXT,
    "action" VARCHAR(160) NOT NULL,
    "rationale" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "status" "AgentProposalStatus" NOT NULL DEFAULT 'PROPOSED',
    "approved_at" TIMESTAMP(3),
    "executed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agent_proposals_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "risk_exceptions" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "asset_id" TEXT,
    "finding_id" TEXT,
    "created_by_user_id" TEXT,
    "approved_by_user_id" TEXT,
    "title" VARCHAR(180) NOT NULL,
    "rationale" TEXT NOT NULL,
    "compensating_controls" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "status" "RiskExceptionStatus" NOT NULL DEFAULT 'ACTIVE',
    "expires_at" TIMESTAMP(3),
    "approved_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "risk_exceptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oauth_app_grants" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "integration_id" TEXT NOT NULL,
    "asset_id" TEXT,
    "provider" "SaaSProvider" NOT NULL,
    "external_app_id" VARCHAR(255) NOT NULL,
    "app_display_name" VARCHAR(255),
    "user_email" VARCHAR(255) NOT NULL,
    "user_external_id" VARCHAR(255),
    "user_display_name" VARCHAR(255),
    "scopes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "anonymous" BOOLEAN NOT NULL DEFAULT false,
    "native_app" BOOLEAN NOT NULL DEFAULT false,
    "last_observed_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "oauth_app_grants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tenant_audit_logs" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "actor_user_id" TEXT,
    "action" VARCHAR(180) NOT NULL,
    "target_type" VARCHAR(120) NOT NULL,
    "target_id" VARCHAR(180) NOT NULL,
    "ip_address" VARCHAR(64),
    "metadata" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tenant_audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "organizations_slug_key" ON "organizations"("slug");

-- CreateIndex
CREATE INDEX "roles_organization_id_idx" ON "roles"("organization_id");

-- CreateIndex
CREATE UNIQUE INDEX "roles_organization_id_name_key" ON "roles"("organization_id", "name");

-- CreateIndex
CREATE INDEX "users_organization_id_idx" ON "users"("organization_id");

-- CreateIndex
CREATE INDEX "users_organization_id_role_id_idx" ON "users"("organization_id", "role_id");

-- CreateIndex
CREATE UNIQUE INDEX "users_organization_id_email_key" ON "users"("organization_id", "email");

-- CreateIndex
CREATE INDEX "integration_connections_organization_id_idx" ON "integration_connections"("organization_id");

-- CreateIndex
CREATE INDEX "integration_connections_organization_id_provider_status_idx" ON "integration_connections"("organization_id", "provider", "status");

-- CreateIndex
CREATE UNIQUE INDEX "integration_connections_organization_id_provider_external_a_key" ON "integration_connections"("organization_id", "provider", "external_account_id");

-- CreateIndex
CREATE INDEX "ingested_events_organization_id_idx" ON "ingested_events"("organization_id");

-- CreateIndex
CREATE INDEX "ingested_events_organization_id_provider_event_type_idx" ON "ingested_events"("organization_id", "provider", "event_type");

-- CreateIndex
CREATE INDEX "ingested_events_organization_id_occurred_at_idx" ON "ingested_events"("organization_id", "occurred_at");

-- CreateIndex
CREATE INDEX "security_findings_organization_id_idx" ON "security_findings"("organization_id");

-- CreateIndex
CREATE INDEX "security_findings_organization_id_status_severity_idx" ON "security_findings"("organization_id", "status", "severity");

-- CreateIndex
CREATE INDEX "security_findings_organization_id_integration_id_idx" ON "security_findings"("organization_id", "integration_id");

-- CreateIndex
CREATE INDEX "security_findings_organization_id_detected_at_idx" ON "security_findings"("organization_id", "detected_at");

-- CreateIndex
CREATE INDEX "security_findings_organization_id_asset_id_idx" ON "security_findings"("organization_id", "asset_id");

-- CreateIndex
CREATE UNIQUE INDEX "security_findings_organization_id_dedupe_key_key" ON "security_findings"("organization_id", "dedupe_key");

-- CreateIndex
CREATE INDEX "security_assets_organization_id_type_idx" ON "security_assets"("organization_id", "type");

-- CreateIndex
CREATE INDEX "security_assets_organization_id_ownership_status_idx" ON "security_assets"("organization_id", "ownership_status");

-- CreateIndex
CREATE INDEX "security_assets_organization_id_exposure_level_idx" ON "security_assets"("organization_id", "exposure_level");

-- CreateIndex
CREATE INDEX "security_assets_integration_id_idx" ON "security_assets"("integration_id");

-- CreateIndex
CREATE INDEX "security_assets_owner_user_id_idx" ON "security_assets"("owner_user_id");

-- CreateIndex
CREATE INDEX "saas_identities_organization_id_provider_status_idx" ON "saas_identities"("organization_id", "provider", "status");

-- CreateIndex
CREATE INDEX "saas_identities_integration_id_status_idx" ON "saas_identities"("integration_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "saas_identities_organization_id_provider_external_id_key" ON "saas_identities"("organization_id", "provider", "external_id");

-- CreateIndex
CREATE UNIQUE INDEX "auth_tokens_token_hash_key" ON "auth_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "auth_tokens_organization_id_purpose_expires_at_idx" ON "auth_tokens"("organization_id", "purpose", "expires_at");

-- CreateIndex
CREATE INDEX "auth_tokens_user_id_purpose_consumed_at_idx" ON "auth_tokens"("user_id", "purpose", "consumed_at");

-- CreateIndex
CREATE UNIQUE INDEX "user_sessions_token_hash_key" ON "user_sessions"("token_hash");

-- CreateIndex
CREATE INDEX "user_sessions_organization_id_expires_at_idx" ON "user_sessions"("organization_id", "expires_at");

-- CreateIndex
CREATE INDEX "user_sessions_user_id_revoked_at_idx" ON "user_sessions"("user_id", "revoked_at");

-- CreateIndex
CREATE INDEX "siem_destinations_organization_id_idx" ON "siem_destinations"("organization_id");

-- CreateIndex
CREATE INDEX "siem_destinations_organization_id_kind_idx" ON "siem_destinations"("organization_id", "kind");

-- CreateIndex
CREATE INDEX "siem_deliveries_organization_id_status_next_attempt_at_idx" ON "siem_deliveries"("organization_id", "status", "next_attempt_at");

-- CreateIndex
CREATE INDEX "siem_deliveries_destination_id_status_idx" ON "siem_deliveries"("destination_id", "status");

-- CreateIndex
CREATE INDEX "agents_organization_id_kind_status_idx" ON "agents"("organization_id", "kind", "status");

-- CreateIndex
CREATE UNIQUE INDEX "agents_organization_id_key_key" ON "agents"("organization_id", "key");

-- CreateIndex
CREATE INDEX "agent_tasks_organization_id_status_created_at_idx" ON "agent_tasks"("organization_id", "status", "created_at");

-- CreateIndex
CREATE INDEX "agent_tasks_assigned_agent_id_status_idx" ON "agent_tasks"("assigned_agent_id", "status");

-- CreateIndex
CREATE INDEX "agent_tasks_parent_task_id_idx" ON "agent_tasks"("parent_task_id");

-- CreateIndex
CREATE INDEX "agent_messages_organization_id_created_at_idx" ON "agent_messages"("organization_id", "created_at");

-- CreateIndex
CREATE INDEX "agent_messages_task_id_created_at_idx" ON "agent_messages"("task_id", "created_at");

-- CreateIndex
CREATE INDEX "agent_messages_to_agent_id_created_at_idx" ON "agent_messages"("to_agent_id", "created_at");

-- CreateIndex
CREATE INDEX "agent_proposals_organization_id_status_created_at_idx" ON "agent_proposals"("organization_id", "status", "created_at");

-- CreateIndex
CREATE INDEX "agent_proposals_task_id_idx" ON "agent_proposals"("task_id");

-- CreateIndex
CREATE INDEX "agent_proposals_finding_id_idx" ON "agent_proposals"("finding_id");

-- CreateIndex
CREATE INDEX "risk_exceptions_organization_id_status_created_at_idx" ON "risk_exceptions"("organization_id", "status", "created_at");

-- CreateIndex
CREATE INDEX "risk_exceptions_asset_id_idx" ON "risk_exceptions"("asset_id");

-- CreateIndex
CREATE INDEX "risk_exceptions_finding_id_idx" ON "risk_exceptions"("finding_id");

-- CreateIndex
CREATE INDEX "oauth_app_grants_organization_id_external_app_id_idx" ON "oauth_app_grants"("organization_id", "external_app_id");

-- CreateIndex
CREATE INDEX "oauth_app_grants_organization_id_integration_id_idx" ON "oauth_app_grants"("organization_id", "integration_id");

-- CreateIndex
CREATE INDEX "oauth_app_grants_asset_id_idx" ON "oauth_app_grants"("asset_id");

-- CreateIndex
CREATE UNIQUE INDEX "oauth_app_grants_organization_id_integration_id_external_ap_key" ON "oauth_app_grants"("organization_id", "integration_id", "external_app_id", "user_email");

-- CreateIndex
CREATE INDEX "tenant_audit_logs_organization_id_idx" ON "tenant_audit_logs"("organization_id");

-- CreateIndex
CREATE INDEX "tenant_audit_logs_organization_id_actor_user_id_idx" ON "tenant_audit_logs"("organization_id", "actor_user_id");

-- CreateIndex
CREATE INDEX "tenant_audit_logs_organization_id_created_at_idx" ON "tenant_audit_logs"("organization_id", "created_at");

-- AddForeignKey
ALTER TABLE "roles" ADD CONSTRAINT "roles_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "integration_connections" ADD CONSTRAINT "integration_connections_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ingested_events" ADD CONSTRAINT "ingested_events_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ingested_events" ADD CONSTRAINT "ingested_events_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_findings" ADD CONSTRAINT "security_findings_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_findings" ADD CONSTRAINT "security_findings_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_findings" ADD CONSTRAINT "security_findings_event_id_fkey" FOREIGN KEY ("event_id") REFERENCES "ingested_events"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_findings" ADD CONSTRAINT "security_findings_resolved_by_id_fkey" FOREIGN KEY ("resolved_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_findings" ADD CONSTRAINT "security_findings_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "security_assets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_assets" ADD CONSTRAINT "security_assets_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_assets" ADD CONSTRAINT "security_assets_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_assets" ADD CONSTRAINT "security_assets_owner_user_id_fkey" FOREIGN KEY ("owner_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_assets" ADD CONSTRAINT "security_assets_business_owner_user_id_fkey" FOREIGN KEY ("business_owner_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_identities" ADD CONSTRAINT "saas_identities_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_identities" ADD CONSTRAINT "saas_identities_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auth_tokens" ADD CONSTRAINT "auth_tokens_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auth_tokens" ADD CONSTRAINT "auth_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auth_tokens" ADD CONSTRAINT "auth_tokens_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "siem_destinations" ADD CONSTRAINT "siem_destinations_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "siem_deliveries" ADD CONSTRAINT "siem_deliveries_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "siem_deliveries" ADD CONSTRAINT "siem_deliveries_destination_id_fkey" FOREIGN KEY ("destination_id") REFERENCES "siem_destinations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agents" ADD CONSTRAINT "agents_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_tasks" ADD CONSTRAINT "agent_tasks_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_tasks" ADD CONSTRAINT "agent_tasks_created_by_agent_id_fkey" FOREIGN KEY ("created_by_agent_id") REFERENCES "agents"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_tasks" ADD CONSTRAINT "agent_tasks_assigned_agent_id_fkey" FOREIGN KEY ("assigned_agent_id") REFERENCES "agents"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_tasks" ADD CONSTRAINT "agent_tasks_parent_task_id_fkey" FOREIGN KEY ("parent_task_id") REFERENCES "agent_tasks"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_messages" ADD CONSTRAINT "agent_messages_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_messages" ADD CONSTRAINT "agent_messages_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "agent_tasks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_messages" ADD CONSTRAINT "agent_messages_from_agent_id_fkey" FOREIGN KEY ("from_agent_id") REFERENCES "agents"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_messages" ADD CONSTRAINT "agent_messages_to_agent_id_fkey" FOREIGN KEY ("to_agent_id") REFERENCES "agents"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_proposals" ADD CONSTRAINT "agent_proposals_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_proposals" ADD CONSTRAINT "agent_proposals_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "agent_tasks"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_proposals" ADD CONSTRAINT "agent_proposals_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "security_findings"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_proposals" ADD CONSTRAINT "agent_proposals_proposed_by_agent_id_fkey" FOREIGN KEY ("proposed_by_agent_id") REFERENCES "agents"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_proposals" ADD CONSTRAINT "agent_proposals_approved_by_user_id_fkey" FOREIGN KEY ("approved_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_exceptions" ADD CONSTRAINT "risk_exceptions_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_exceptions" ADD CONSTRAINT "risk_exceptions_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "security_assets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_exceptions" ADD CONSTRAINT "risk_exceptions_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "security_findings"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_exceptions" ADD CONSTRAINT "risk_exceptions_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_exceptions" ADD CONSTRAINT "risk_exceptions_approved_by_user_id_fkey" FOREIGN KEY ("approved_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_app_grants" ADD CONSTRAINT "oauth_app_grants_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_app_grants" ADD CONSTRAINT "oauth_app_grants_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_app_grants" ADD CONSTRAINT "oauth_app_grants_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "security_assets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tenant_audit_logs" ADD CONSTRAINT "tenant_audit_logs_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tenant_audit_logs" ADD CONSTRAINT "tenant_audit_logs_actor_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
