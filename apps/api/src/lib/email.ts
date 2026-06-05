import { logger } from "./logger";

export type EmailDeliveryMode = "email" | "manual_link";

type SendEmailInput = {
  to: string;
  subject: string;
  text: string;
  html?: string;
  replyTo?: string;
};

type AuthEmailInput = {
  kind: "invite" | "password_reset";
  organizationName: string;
  recipientEmail: string;
  recipientName?: string | null;
  link: string;
  expiresAt: Date;
};

function emailProvider() {
  return (process.env.APERIO_EMAIL_PROVIDER ?? "").trim().toLowerCase();
}

export function authLinksCanBeExposedManually() {
  return (
    process.env.NODE_ENV !== "production" ||
    process.env.APERIO_EXPOSE_AUTH_LINKS === "true"
  );
}

export function isEmailDeliveryConfigured() {
  return (
    emailProvider() === "resend" &&
    !!process.env.APERIO_RESEND_API_KEY &&
    !!process.env.APERIO_EMAIL_FROM
  );
}

export async function sendEmail(input: SendEmailInput) {
  if (!isEmailDeliveryConfigured()) {
    throw new Error("Email delivery is not configured");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${process.env.APERIO_RESEND_API_KEY}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      from: process.env.APERIO_EMAIL_FROM,
      to: [input.to],
      subject: input.subject,
      text: input.text,
      html: input.html,
      reply_to: input.replyTo
    })
  });

  if (!response.ok) {
    const body = await response.text();
    logger.error("email.delivery_failed", {
      provider: emailProvider(),
      status: response.status,
      body
    });
    throw new Error("Email delivery failed");
  }

  return response.json().catch(() => null);
}

export async function deliverAuthLinkEmail(
  input: AuthEmailInput
): Promise<{
  delivery: EmailDeliveryMode;
  url?: string;
}> {
  const greeting = input.recipientName?.trim() || input.recipientEmail;
  const expiresAt = input.expiresAt.toUTCString().replace("GMT", "UTC");
  const subject =
    input.kind === "invite"
      ? `You're invited to ${input.organizationName} on Aperio`
      : `Reset your ${input.organizationName} Aperio password`;
  const actionLabel =
    input.kind === "invite" ? "Accept invitation" : "Reset password";
  const intro =
    input.kind === "invite"
      ? `You've been invited to join ${input.organizationName} in Aperio.`
      : `A password reset was requested for your ${input.organizationName} workspace in Aperio.`;
  const text = [
    `Hello ${greeting},`,
    "",
    intro,
    `${actionLabel}: ${input.link}`,
    `Expires: ${expiresAt}`,
    "",
    "If you did not expect this email, you can ignore it."
  ].join("\n");

  const html = `<p>Hello ${greeting},</p><p>${intro}</p><p><a href="${input.link}">${actionLabel}</a></p><p>Expires: ${expiresAt}</p><p>If you did not expect this email, you can ignore it.</p>`;

  if (isEmailDeliveryConfigured()) {
    await sendEmail({
      to: input.recipientEmail,
      subject,
      text,
      html
    });

    return { delivery: "email" };
  }

  if (authLinksCanBeExposedManually()) {
    logger.warn("email.manual_link_fallback", {
      kind: input.kind,
      recipientEmail: input.recipientEmail
    });
    return {
      delivery: "manual_link",
      url: input.link
    };
  }

  throw new Error("Email delivery is not configured");
}
