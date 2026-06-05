import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  typedRoutes: false,
  turbopack: {
    root: path.resolve(__dirname, "../..")
  },
  transpilePackages: ["@aperio/shared"]
};

export default nextConfig;
