import type { NextConfig } from "next";
import path from "node:path";

// Backend URL — defaults to localhost for `npm run dev`, overridden in
// Docker via VIPER_API_URL=http://viper-api:8080 so the Next.js server
// forwards /api/* to the API container.
const API_URL = process.env.VIPER_API_URL ?? "http://localhost:8080";

const nextConfig: NextConfig = {
  // Emit a minimal `.next/standalone` for the Docker image
  output: "standalone",

  turbopack: {
    root: path.resolve(__dirname),
  },

  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${API_URL}/api/:path*`,
      },
      {
        source: "/ws",
        destination: `${API_URL}/ws`,
      },
    ];
  },
};

export default nextConfig;
