import type { NextFunction, Request, Response } from "express";

type RateLimitOptions = {
  windowMs: number;
  max: number;
  message: string;
  maxKeys?: number;
};

type HitWindow = {
  count: number;
  resetAt: number;
};

export function createMemoryRateLimit(options: RateLimitOptions) {
  const hits = new Map<string, HitWindow>();
  const maxKeys = options.maxKeys ?? 10_000;
  let nextSweepAt = Date.now() + options.windowMs;

  function sweepExpired(now: number) {
    if (now < nextSweepAt && hits.size < maxKeys) {
      return;
    }

    for (const [key, hit] of hits) {
      if (hit.resetAt <= now) {
        hits.delete(key);
      }
    }

    while (hits.size > maxKeys) {
      const oldestKey = hits.keys().next().value as string | undefined;
      if (!oldestKey) break;
      hits.delete(oldestKey);
    }

    nextSweepAt = now + options.windowMs;
  }

  function setHeaders(res: Response, hit: HitWindow) {
    res.setHeader("x-ratelimit-limit", String(options.max));
    res.setHeader("x-ratelimit-remaining", String(Math.max(options.max - hit.count, 0)));
    res.setHeader("x-ratelimit-reset", String(Math.ceil(hit.resetAt / 1000)));
  }

  return (req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    sweepExpired(now);

    const key = `${req.ip}:${req.path}`;
    const existing = hits.get(key);

    if (!existing || existing.resetAt <= now) {
      const fresh = {
        count: 1,
        resetAt: now + options.windowMs
      };
      hits.set(key, fresh);
      setHeaders(res, fresh);
      return next();
    }

    if (existing.count >= options.max) {
      setHeaders(res, existing);
      res.setHeader("retry-after", String(Math.ceil((existing.resetAt - now) / 1000)));
      return res.status(429).json({ error: options.message });
    }

    existing.count += 1;
    hits.set(key, existing);
    setHeaders(res, existing);
    return next();
  };
}
