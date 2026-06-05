import { z } from "zod";
import { providerSchema } from "./types";

export const securityAssetTypes = [
  "APPLICATION",
  "OAUTH_APP",
  "SERVICE_ACCOUNT",
  "DATA_RESOURCE",
  "WORKSPACE",
  "VAULT",
  "REPOSITORY"
] as const;

export const assetCriticalities = [
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL"
] as const;

export const assetExposureLevels = [
  "INTERNAL",
  "TRUSTED_EXTERNAL",
  "PUBLIC"
] as const;

export const assetOwnershipStatuses = [
  "ASSIGNED",
  "UNASSIGNED",
  "REVIEW_REQUIRED"
] as const;

export const riskExceptionStatuses = [
  "ACTIVE",
  "EXPIRED",
  "REVOKED"
] as const;

export const securityAssetTypeSchema = z.enum(securityAssetTypes);
export const assetCriticalitySchema = z.enum(assetCriticalities);
export const assetExposureLevelSchema = z.enum(assetExposureLevels);
export const assetOwnershipStatusSchema = z.enum(assetOwnershipStatuses);
export const riskExceptionStatusSchema = z.enum(riskExceptionStatuses);

const optionalIdSchema = z.union([z.string().trim().min(1), z.literal("")]).optional();
const optionalDateSchema = z
  .union([z.string().datetime(), z.literal("")])
  .optional();

const baseSecurityAssetSchema = z.object({
  integrationId: optionalIdSchema,
  ownerUserId: optionalIdSchema,
  businessOwnerUserId: optionalIdSchema,
  type: securityAssetTypeSchema,
  provider: providerSchema.optional(),
  name: z.string().trim().min(1).max(180),
  summary: z.union([z.string().trim().max(500), z.literal("")]).optional(),
  externalId: z.union([z.string().trim().max(255), z.literal("")]).optional(),
  labels: z.array(z.string().trim().min(1).max(80)).max(12).default([]),
  criticality: assetCriticalitySchema.default("MEDIUM"),
  exposureLevel: assetExposureLevelSchema.default("INTERNAL"),
  ownershipStatus: assetOwnershipStatusSchema.optional(),
  containsSensitiveData: z.boolean().default(false),
  isPrivileged: z.boolean().default(false),
  riskScore: z.coerce.number().int().min(0).max(100).default(0),
  lastObservedAt: optionalDateSchema
});

export const createSecurityAssetSchema = baseSecurityAssetSchema.transform((value) => ({
  ...value,
  integrationId: value.integrationId || undefined,
  ownerUserId: value.ownerUserId || undefined,
  businessOwnerUserId: value.businessOwnerUserId || undefined,
  summary: value.summary || undefined,
  externalId: value.externalId || undefined,
  lastObservedAt: value.lastObservedAt || undefined
}));

export const updateSecurityAssetSchema = baseSecurityAssetSchema
  .partial()
  .transform((value) => ({
    ...value,
    integrationId: value.integrationId === "" ? null : value.integrationId,
    ownerUserId: value.ownerUserId === "" ? null : value.ownerUserId,
    businessOwnerUserId:
      value.businessOwnerUserId === "" ? null : value.businessOwnerUserId,
    summary: value.summary === "" ? null : value.summary,
    externalId: value.externalId === "" ? null : value.externalId,
    lastObservedAt: value.lastObservedAt === "" ? null : value.lastObservedAt
  }));

export const securityAssetsQuerySchema = z.object({
  type: securityAssetTypeSchema.optional(),
  ownershipStatus: assetOwnershipStatusSchema.optional(),
  integrationId: z.string().trim().min(1).optional()
});

export const createRiskExceptionSchema = z
  .object({
    assetId: optionalIdSchema,
    findingId: optionalIdSchema,
    title: z.string().trim().min(1).max(180),
    rationale: z.string().trim().min(1).max(4000),
    compensatingControls: z
      .array(z.string().trim().min(1).max(300))
      .max(8)
      .default([]),
    expiresAt: optionalDateSchema
  })
  .transform((value) => ({
    ...value,
    assetId: value.assetId || undefined,
    findingId: value.findingId || undefined,
    expiresAt: value.expiresAt || undefined
  }))
  .refine((value) => !!value.assetId || !!value.findingId, {
    message: "An exception must reference an asset or finding",
    path: ["assetId"]
  });

export const updateRiskExceptionSchema = z
  .object({
    title: z.string().trim().min(1).max(180).optional(),
    rationale: z.string().trim().min(1).max(4000).optional(),
    compensatingControls: z
      .array(z.string().trim().min(1).max(300))
      .max(8)
      .optional(),
    status: riskExceptionStatusSchema.optional(),
    expiresAt: optionalDateSchema
  })
  .transform((value) => ({
    ...value,
    expiresAt: value.expiresAt === "" ? null : value.expiresAt
  }));

export type SecurityAssetType = (typeof securityAssetTypes)[number];
export type AssetCriticality = (typeof assetCriticalities)[number];
export type AssetExposureLevel = (typeof assetExposureLevels)[number];
export type AssetOwnershipStatus = (typeof assetOwnershipStatuses)[number];
export type RiskExceptionStatus = (typeof riskExceptionStatuses)[number];
export type CreateSecurityAssetInput = z.infer<typeof createSecurityAssetSchema>;
export type UpdateSecurityAssetInput = z.infer<typeof updateSecurityAssetSchema>;
export type CreateRiskExceptionInput = z.infer<typeof createRiskExceptionSchema>;
export type UpdateRiskExceptionInput = z.infer<typeof updateRiskExceptionSchema>;
