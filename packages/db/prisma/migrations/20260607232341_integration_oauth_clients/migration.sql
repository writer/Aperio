-- Per-organization OAuth client credentials for SaaS connectors. Lets each
-- tenant register their own Google/Microsoft/etc. OAuth app from the admin
-- UI without touching the Aperio operator's .env file. The client secret is
-- encrypted with APERIO_ENCRYPTION_KEY; client id and redirect URI are stored
-- in plaintext because both are public values returned to browsers during
-- the OAuth redirect.
CREATE TABLE "integration_oauth_clients" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "provider" "SaaSProvider" NOT NULL,
    "client_id" VARCHAR(500) NOT NULL,
    "encrypted_client_secret" TEXT NOT NULL,
    "redirect_uri" VARCHAR(500) NOT NULL,
    "token_key_version" VARCHAR(32) NOT NULL DEFAULT 'v1',
    "created_by_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "integration_oauth_clients_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "integration_oauth_clients_organization_id_provider_key"
    ON "integration_oauth_clients"("organization_id", "provider");

CREATE INDEX "integration_oauth_clients_organization_id_idx"
    ON "integration_oauth_clients"("organization_id");

ALTER TABLE "integration_oauth_clients"
    ADD CONSTRAINT "integration_oauth_clients_organization_id_fkey"
    FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "integration_oauth_clients"
    ADD CONSTRAINT "integration_oauth_clients_created_by_id_fkey"
    FOREIGN KEY ("created_by_id") REFERENCES "users"("id")
    ON DELETE SET NULL ON UPDATE CASCADE;
