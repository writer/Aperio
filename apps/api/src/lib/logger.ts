type LogLevel = "info" | "warn" | "error";

function writeLog(level: LogLevel, message: string, metadata?: Record<string, unknown>) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...(metadata ?? {})
  };
  const line = JSON.stringify(entry);

  if (level === "error") {
    console.error(line);
    return;
  }

  if (level === "warn") {
    console.warn(line);
    return;
  }

  console.log(line);
}

export const logger = {
  info(message: string, metadata?: Record<string, unknown>) {
    writeLog("info", message, metadata);
  },
  warn(message: string, metadata?: Record<string, unknown>) {
    writeLog("warn", message, metadata);
  },
  error(message: string, metadata?: Record<string, unknown>) {
    writeLog("error", message, metadata);
  }
};
