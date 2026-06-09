import { readFileSync } from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

// These tests pin the contract that an exiting auxiliary worker (ingestion,
// siem, google) must NOT tear down the essential dev stack (connect, web).
// A regression that, for example, drops the `essential` flag or makes all
// children call shutdown() on exit would break developer flow: a compile
// error in one worker package would kill the web + API dev loop, blocking
// all unrelated UI/backend work in the monorepo.

test("dev orchestrator marks connect + web as essential", () => {
  const source = readRepoFile("scripts/dev.mjs");
  assert.match(
    source,
    /start\("connect",\s*"go",\s*\[[^\]]*"\.\/cmd\/aperio"\][^)]*\{\s*essential:\s*true\s*\}\s*\)/,
    "connect must be started with { essential: true }"
  );
  assert.match(
    source,
    /start\("web",\s*"npx",\s*\[[^\]]*"next"[^\]]*\][^)]*\{\s*essential:\s*true\s*\}\s*\)/,
    "web must be started with { essential: true }"
  );
});

test("dev orchestrator marks workers as non-essential", () => {
  const source = readRepoFile("scripts/dev.mjs");
  // startWorker() is the only path that should produce non-essential children
  // so the auxiliary classification lives in exactly one place.
  assert.match(
    source,
    /return start\(label,\s*"go",\s*\["run",\s*pkg\],\s*\{\s*essential:\s*false[\s\S]*?\}\s*\)/,
    "startWorker must pass essential: false so a worker exit does not tear down web + API"
  );
  for (const worker of ["ingestion", "siem", "google"]) {
    const pattern = new RegExp(`startWorker\\("${worker}",\\s*"\\./cmd/[^"]+"\\)`);
    assert.match(source, pattern, `${worker} worker must be started via startWorker()`);
  }
});

test("dev orchestrator only calls shutdown() from the essential branch", () => {
  const source = readRepoFile("scripts/dev.mjs");
  // The exit handler MUST branch on `essential` before deciding to shutdown,
  // otherwise auxiliary worker exits will tear down web + connect. The two
  // shutdown sites for the user-signal handler (SIGINT/SIGTERM) and the
  // explicit shutdown(0) call there are intentional and outside the child
  // exit path.
  assert.match(
    source,
    /if\s*\(essential\)\s*\{\s*[\s\S]*?shutdown\(code\s*\?\?\s*1\)/,
    "essential children must shutdown on exit"
  );
  assert.match(
    source,
    /Restart\s+#\$\{slot\.restartCount\}/,
    "auxiliary worker exits must schedule a restart with the bookkeeping slot, not shutdown"
  );
  // Belt-and-suspenders: ensure the auxiliary branch logs the worker-only
  // disclaimer so the developer sees that web + API are still up.
  assert.match(
    source,
    /worker only;\s*web \+ API unaffected/,
    "auxiliary worker exit must surface a 'web + API unaffected' notice so the developer is not misled"
  );
});

test("dev orchestrator caps auxiliary restart backoff", () => {
  const source = readRepoFile("scripts/dev.mjs");
  // A permanently broken worker must not spin tight; cap is read from the
  // named constant so a future tweak shows up in a single grep.
  assert.match(
    source,
    /const\s+MAX_WORKER_RESTART_DELAY\s*=\s*\d+/,
    "the restart-delay cap must be a named constant"
  );
  assert.match(
    source,
    /Math\.min\(MAX_WORKER_RESTART_DELAY,/,
    "auxiliary restart delay must be bounded by MAX_WORKER_RESTART_DELAY"
  );
});

test("dev orchestrator restarts auxiliary worker on both exit and spawn-error paths", () => {
  const source = readRepoFile("scripts/dev.mjs");
  // Node emits 'error' WITHOUT a following 'exit' when the process cannot
  // be spawned (EAGAIN/EMFILE/ENOENT). The restart helper MUST be reachable
  // from both child.on("exit", ...) and child.on("error", ...) for an
  // auxiliary child, otherwise a single transient spawn failure silently
  // leaves the worker permanently dead for the rest of the dev session.
  // The shared scheduleAuxiliaryRestart helper makes both paths converge,
  // so we assert (a) it is defined exactly once, (b) it is invoked from
  // both handler bodies, and (c) the spawn-failure branch is auxiliary-
  // only (essential children still tear the stack down on spawn error).
  assert.match(
    source,
    /function\s+scheduleAuxiliaryRestart\s*\(/,
    "auxiliary restart must be a named helper so both event handlers can share it"
  );
  // Narrow to the long-lived child handlers inside start() — distinguished
  // from the throwaway run() handler by their (code, signal) / (error)
  // signature plus the essential branch — so we don't accidentally match
  // the helper used for blocking subcommands like prisma migrate.
  const exitHandler = source.match(/child\.on\("exit",\s*\(code,\s*signal\)[\s\S]*?\}\);/);
  assert.ok(exitHandler, "expected start()'s child.on(\"exit\", ...) handler");
  assert.match(
    exitHandler![0],
    /scheduleAuxiliaryRestart\(/,
    "exit handler must call scheduleAuxiliaryRestart for auxiliary children"
  );
  const errorHandler = source.match(/child\.on\("error",\s*\(error\)[\s\S]*?\}\);/);
  assert.ok(errorHandler, "expected start()'s child.on(\"error\", ...) handler");
  assert.match(
    errorHandler![0],
    /scheduleAuxiliaryRestart\(/,
    "error handler must also call scheduleAuxiliaryRestart so spawn failures recover"
  );
  // Belt-and-suspenders: essential children must still take the shutdown
  // path on a spawn error (the previous behaviour); we are only adding
  // recovery for the auxiliary branch.
  assert.match(
    errorHandler![0],
    /if\s*\(essential\)\s*\{[\s\S]*?shutdown\(1\)/,
    "error handler must still tear down the stack for essential children"
  );
});
