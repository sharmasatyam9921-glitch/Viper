# syntax=docker/dockerfile:1.7
# ──────────────────────────────────────────────────────────────────────────
# VIPER 6.0 — Next.js dashboard image
#
# Three stages so the runtime image stays small:
#   deps     — npm install (cached against package.json + lockfile)
#   builder  — next build → emits .next/standalone
#   runner   — only the standalone server.js + .next/static + public
# ──────────────────────────────────────────────────────────────────────────

# ── deps ──────────────────────────────────────────────────────────────────
FROM node:20-alpine AS deps

RUN apk add --no-cache libc6-compat

WORKDIR /app

COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# ── builder ───────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1 \
    NODE_ENV=production

RUN npm run build

# ── runner ────────────────────────────────────────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Non-root user
RUN addgroup --system --gid 1001 nodejs \
 && adduser --system --uid 1001 nextjs

# Copy public assets + standalone build
# (Next.js standalone packs server.js + node_modules subset)
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

# Liveness — the Next.js server starts even if the API is down
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --quiet --spider http://localhost:3000/ || exit 1

CMD ["node", "server.js"]
