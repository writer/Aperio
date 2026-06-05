import { prisma } from "@aperio/db";
import { logger } from "./lib/logger";
import { createApp } from "./app";
import { startSiemDispatcher } from "../../../workers/siem-dispatcher";

const app = createApp();
const port = Number(process.env.PORT ?? 4000);

const server = app.listen(port, () => {
  logger.info("server.started", {
    port,
    url: `http://localhost:${port}`
  });
});
const siemDispatcher = startSiemDispatcher();

async function shutdown(signal: string) {
  logger.info("server.stopping", { signal });
  clearInterval(siemDispatcher);
  server.close(async () => {
    await prisma.$disconnect();
    process.exit(0);
  });
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
