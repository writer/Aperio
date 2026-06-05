import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { prisma } from "@aperio/db";

const execFileAsync = promisify(execFile);

async function hasBinary(command: string) {
  try {
    const { stdout, stderr } = await execFileAsync(command, ["--version"]);
    return {
      ok: true,
      version: (stdout || stderr).trim()
    };
  } catch {
    return {
      ok: false,
      version: null
    };
  }
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL ?? "";
  const backupStorageUrl = process.env.APERIO_BACKUP_STORAGE_URL ?? "";
  const backupSchedule = process.env.APERIO_BACKUP_SCHEDULE ?? "";
  const backupRetentionDays = Number(
    process.env.APERIO_BACKUP_RETENTION_DAYS ?? 0
  );

  let databaseReachable = false;

  try {
    await prisma.$queryRawUnsafe("SELECT 1");
    databaseReachable = true;
  } finally {
    await prisma.$disconnect();
  }

  const result = {
    ok: databaseReachable,
    checks: {
      databaseUrlConfigured: databaseUrl.startsWith("postgres"),
      databaseReachable,
      backupStorageConfigured: Boolean(backupStorageUrl),
      backupScheduleConfigured: Boolean(backupSchedule),
      backupRetentionDays,
      pgDump: await hasBinary("pg_dump"),
      pgRestore: await hasBinary("pg_restore")
    },
    warnings: [] as string[]
  };

  if (!result.checks.backupStorageConfigured) {
    result.warnings.push("APERIO_BACKUP_STORAGE_URL is not configured");
  }
  if (!result.checks.backupScheduleConfigured) {
    result.warnings.push("APERIO_BACKUP_SCHEDULE is not configured");
  }
  if (backupRetentionDays < 7) {
    result.warnings.push("APERIO_BACKUP_RETENTION_DAYS should be at least 7");
  }
  if (!result.checks.pgDump.ok) {
    result.warnings.push("pg_dump is not available in PATH");
  }
  if (!result.checks.pgRestore.ok) {
    result.warnings.push("pg_restore is not available in PATH");
  }

  console.log(JSON.stringify(result, null, 2));
}

void main().catch(async (error) => {
  await prisma.$disconnect();
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: error instanceof Error ? error.message : String(error)
      },
      null,
      2
    )
  );
  process.exit(1);
});
