import { prisma } from "@aperio/db";
import { sendEmail, isEmailDeliveryConfigured } from "./email";
import { logger } from "./logger";

export async function sendTenantOperationalAlert(input: {
  organizationId: string;
  title: string;
  details: string;
  metadata?: Record<string, unknown>;
}) {
  const organization = await prisma.organization.findUnique({
    where: { id: input.organizationId },
    select: {
      name: true,
      notificationEmail: true,
      webhookAlertUrl: true
    }
  });

  if (!organization) {
    return;
  }

  const payload = {
    source: "aperio",
    title: input.title,
    details: input.details,
    organizationName: organization.name,
    metadata: input.metadata ?? {},
    timestamp: new Date().toISOString()
  };

  if (organization.webhookAlertUrl) {
    try {
      const response = await fetch(organization.webhookAlertUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        logger.warn("alert.webhook_delivery_failed", {
          organizationId: input.organizationId,
          status: response.status
        });
      }
    } catch (error) {
      logger.warn("alert.webhook_delivery_failed", {
        organizationId: input.organizationId,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  if (organization.notificationEmail && isEmailDeliveryConfigured()) {
    try {
      await sendEmail({
        to: organization.notificationEmail,
        subject: `[Aperio] ${input.title}`,
        text: `${input.details}\n\n${JSON.stringify(payload.metadata, null, 2)}`
      });
    } catch (error) {
      logger.warn("alert.email_delivery_failed", {
        organizationId: input.organizationId,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
}
