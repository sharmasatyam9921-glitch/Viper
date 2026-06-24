import type { NextConfig } from "next";
import path from "node:path";

// Backend URL — defaults to the IPv4 loopback for `npm run dev`, overridden in
// Docker via VIPER_API_URL=http://viper-api:8080 so the Next.js server
// forwards /api/* to the API container.
// NB: use 127.0.0.1, NOT "localhost" — Node resolves "localhost" to IPv6 ::1
// first, but the API server binds IPv4 127.0.0.1 only, so a "localhost" proxy
// target fails with ECONNREFUSED ::1:8080 and every dashboard API call breaks.
const API_URL = process.env.VIPER_API_URL ?? "http://127.0.0.1:8080";

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
