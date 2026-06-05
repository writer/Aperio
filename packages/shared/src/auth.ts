import { z } from "zod";

const workspaceSlugSchema = z
  .string()
  .trim()
  .min(3)
  .max(120)
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, {
    message: "Workspace slug must use lowercase letters, numbers, and hyphens"
  });

const passwordSchema = z
  .string()
  .min(12)
  .max(128)
  .regex(/[A-Z]/, { message: "Password must include an uppercase letter" })
  .regex(/[a-z]/, { message: "Password must include a lowercase letter" })
  .regex(/[0-9]/, { message: "Password must include a number" });

const totpCodeSchema = z
  .string()
  .trim()
  .regex(/^\d{6}$/, {
    message: "Authentication code must be 6 digits"
  });

export const signupSchema = z
  .object({
    organizationName: z.string().trim().min(1).max(160),
    organizationSlug: workspaceSlugSchema,
    notificationEmail: z
      .union([z.string().trim().email().max(255), z.literal("")])
      .optional(),
    ownerEmail: z.string().trim().email().max(255).toLowerCase(),
    ownerDisplayName: z
      .union([z.string().trim().min(1).max(160), z.literal("")])
      .optional(),
    password: passwordSchema
  })
  .strict();

export const loginSchema = z
  .object({
    organizationSlug: workspaceSlugSchema,
    email: z.string().trim().email().max(255).toLowerCase(),
    password: z.string().min(1).max(128),
    totpCode: totpCodeSchema.optional()
  })
  .strict();

export const inviteMemberSchema = z
  .object({
    email: z.string().trim().email().max(255).toLowerCase(),
    displayName: z.string().trim().min(1).max(160).optional(),
    roleName: z.enum(["OWNER", "ADMIN", "SECURITY_ANALYST", "VIEWER"])
  })
  .strict();

export const requestPasswordResetSchema = z
  .object({
    organizationSlug: workspaceSlugSchema,
    email: z.string().trim().email().max(255).toLowerCase()
  })
  .strict();

export const completePasswordResetSchema = z
  .object({
    token: z.string().trim().min(32).max(255),
    password: passwordSchema
  })
  .strict();

export const acceptInviteSchema = z
  .object({
    token: z.string().trim().min(32).max(255),
    displayName: z.string().trim().min(1).max(160).optional(),
    password: passwordSchema
  })
  .strict();

export const verifyMfaEnrollmentSchema = z
  .object({
    code: totpCodeSchema
  })
  .strict();

export const disableMfaSchema = z
  .object({
    password: z.string().min(1).max(128),
    code: totpCodeSchema.optional()
  })
  .strict();

export type SignupInput = z.infer<typeof signupSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type InviteMemberInput = z.infer<typeof inviteMemberSchema>;
export type VerifyMfaEnrollmentInput = z.infer<typeof verifyMfaEnrollmentSchema>;
export type DisableMfaInput = z.infer<typeof disableMfaSchema>;
