import type { NextFunction, Request, Response } from "express";

type RateLimitOptions = {
  windowMs: number;
  max: number;
  message: string;
};

type HitWindow = {
  count: number;
  resetAt: number;
};

export function createMemoryRateLimit(options: RateLimitOptions) {
  const hits = new Map<string, HitWindow>();

  return (req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    const key = `${req.ip}:${req.path}`;
    const existing = hits.get(key);

    if (!existing || existing.resetAt <= now) {
      hits.set(key, {
        count: 1,
        resetAt: now + options.windowMs
      });
      return next();
    }

    if (existing.count >= options.max) {
      res.setHeader("retry-after", String(Math.ceil((existing.resetAt - now) / 1000)));
      return res.status(429).json({ error: options.message });
    }

    existing.count += 1;
    hits.set(key, existing);
    return next();
  };
}
