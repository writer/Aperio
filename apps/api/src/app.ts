import { randomUUID } from "node:crypto";
import compression from "compression";
import cors from "cors";
import express, {
  type ErrorRequestHandler,
  type Request,
  type Response
} from "express";
import helmet from "helmet";
import { prisma } from "@aperio/db";
import { isEmailDeliveryConfigured } from "./lib/email";
import { logger } from "./lib/logger";
import { requireAuth, requireTenant } from "./middleware/security";
import { adminRouter } from "./routes/admin";
import { agentsRouter } from "./routes/agents";
import { authRouter } from "./routes/auth";
import { dashboardRouter } from "./routes/dashboard";
import { findingsRouter } from "./routes/findings";
import { ingestionRouter } from "./routes/ingestion";
import {
  integrationsRouter,
  publicIntegrationsRouter
} from "./routes/integrations";
import { remediationsRouter } from "./routes/remediations";
import { securityRouter } from "./routes/security";
import { shadowItRouter } from "./routes/shadow-it";
import { siemRouter } from "./routes/siem";

type RequestWithId = Request & { requestId?: string };

function backupCheck() {
  return {
    storageConfigured: Boolean(process.env.APERIO_BACKUP_STORAGE_URL),
    scheduleConfigured: Boolean(process.env.APERIO_BACKUP_SCHEDULE),
    retentionDays: Number(process.env.APERIO_BACKUP_RETENTION_DAYS ?? 0)
  };
}

export function createApp() {
  const app = express();
  const allowedOrigins = (process.env.APERIO_WEB_ORIGIN ?? "http://localhost:3000")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

  app.disable("x-powered-by");
  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginResourcePolicy: { policy: "same-site" }
    })
  );
  app.use(
    cors({
      origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
          return callback(null, true);
        }

        return callback(new Error("Origin not allowed by CORS"));
      },
      credentials: true
    })
  );
  app.use(compression());
  app.use(express.json({ limit: "1mb", strict: true }));
  app.use((req, res, next) => {
    const requestId = req.header("x-request-id") || randomUUID();
    (req as RequestWithId).requestId = requestId;
    res.setHeader("x-request-id", requestId);
    const startedAt = Date.now();

    res.on("finish", () => {
      logger.info("http.request", {
        requestId,
        method: req.method,
        path: req.originalUrl,
        statusCode: res.statusCode,
        durationMs: Date.now() - startedAt
      });
    });

    next();
  });

  app.get("/healthz", (_req: Request, res: Response) => {
    res.json({ status: "ok" });
  });

  app.get("/readyz", async (_req: Request, res: Response) => {
    const checks = {
      database: false,
      emailDelivery: isEmailDeliveryConfigured(),
      backup: backupCheck()
    };

    try {
      await prisma.$queryRawUnsafe("SELECT 1");
      checks.database = true;
      return res.json({
        status: "ok",
        checks
      });
    } catch (error) {
      logger.error("readiness.failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      return res.status(503).json({
        status: "error",
        checks
      });
    }
  });

  app.use("/api/v1/auth", authRouter);
  app.use("/api/v1/integrations", publicIntegrationsRouter);

  const apiV1 = express.Router();
  apiV1.use(requireAuth, requireTenant);
  apiV1.use("/dashboard", dashboardRouter);
  apiV1.use("/findings", findingsRouter);
  apiV1.use("/findings", remediationsRouter);
  apiV1.use("/ingestion", ingestionRouter);
  apiV1.use("/integrations", integrationsRouter);
  apiV1.use("/siem", siemRouter);
  apiV1.use("/admin", adminRouter);
  apiV1.use("/agents", agentsRouter);
  apiV1.use("/security", securityRouter);
  apiV1.use("/shadow-it", shadowItRouter);
  app.use("/api/v1", apiV1);

  const errorHandler: ErrorRequestHandler = (error, req, res, _next) => {
    const requestId = (req as RequestWithId).requestId;
    logger.error("http.error", {
      requestId,
      method: req.method,
      path: req.originalUrl,
      error: error instanceof Error ? error.message : String(error)
    });

    const message =
      process.env.NODE_ENV === "production"
        ? "Internal server error"
        : error instanceof Error
          ? error.message
          : "Internal server error";

    res.status(500).json({
      error: message,
      requestId
    });
  };

  app.use(errorHandler);
  return app;
}
