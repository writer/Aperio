import fs from "node:fs";

const envFile = process.argv[2] ?? ".env";

function parseEnvLine(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) {
    return null;
  }
  const withoutExport = trimmed.startsWith("export ") ? trimmed.slice("export ".length).trim() : trimmed;
  const equals = withoutExport.indexOf("=");
  if (equals <= 0) {
    return null;
  }
  const key = withoutExport.slice(0, equals).trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    return null;
  }
  let value = withoutExport.slice(equals + 1).trim();
  if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }
  return { key, value };
}

function shellQuote(value) {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, "utf8").split(/\r?\n/)) {
    const parsed = parseEnvLine(line);
    if (!parsed || process.env[parsed.key] !== undefined) {
      continue;
    }
    process.stdout.write(`export ${parsed.key}=${shellQuote(parsed.value)};\n`);
  }
}
