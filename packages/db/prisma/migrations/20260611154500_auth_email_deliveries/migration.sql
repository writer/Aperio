CREATE TABLE "auth_email_deliveries" (
  "id" TEXT NOT NULL,
  "organization_id" TEXT NOT NULL,
  "user_id" TEXT NOT NULL,
  "auth_token_id" TEXT NOT NULL,
  "purpose" "AuthTokenPurpose" NOT NULL,
  "recipient_email" VARCHAR(255) NOT NULL,
  "subject" VARCHAR(255) NOT NULL,
  "payload" JSONB NOT NULL,
  "status" VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  "sent_at" TIMESTAMP(3),
  "expires_at" TIMESTAMP(3) NOT NULL,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "auth_email_deliveries_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "auth_email_deliveries"
  ADD CONSTRAINT "auth_email_deliveries_organization_id_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "auth_email_deliveries"
  ADD CONSTRAINT "auth_email_deliveries_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "users"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "auth_email_deliveries"
  ADD CONSTRAINT "auth_email_deliveries_auth_token_id_fkey"
  FOREIGN KEY ("auth_token_id") REFERENCES "auth_tokens"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE INDEX "auth_email_deliveries_org_status_created_at_idx"
  ON "auth_email_deliveries"("organization_id", "status", "created_at");

CREATE INDEX "auth_email_deliveries_user_purpose_status_idx"
  ON "auth_email_deliveries"("user_id", "purpose", "status");

CREATE UNIQUE INDEX "auth_email_deliveries_auth_token_id_key"
  ON "auth_email_deliveries"("auth_token_id");
