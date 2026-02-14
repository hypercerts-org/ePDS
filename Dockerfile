# Multi-stage Dockerfile for Magic PDS

# -- Base --
FROM node:20-alpine AS base
RUN corepack enable && corepack prepare pnpm@8.15.9 --activate
RUN addgroup -g 1001 appuser && adduser -u 1001 -G appuser -D appuser
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* ./
COPY packages/shared/package.json packages/shared/
COPY packages/auth-service/package.json packages/auth-service/
COPY packages/pds-core/package.json packages/pds-core/

# -- Dependencies --
FROM base AS deps
RUN pnpm install --frozen-lockfile

# -- Build --
FROM deps AS build
COPY packages/ packages/
COPY tsconfig.json ./
RUN pnpm build

# -- PDS Core --
FROM node:20-alpine AS pds-core
RUN corepack enable && corepack prepare pnpm@8.15.9 --activate
RUN addgroup -g 1001 appuser && adduser -u 1001 -G appuser -D appuser
RUN apk add --no-cache wget
WORKDIR /app
# Copy the full workspace structure so pnpm symlinks resolve
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=build /app/packages/pds-core/node_modules ./packages/pds-core/node_modules
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/pds-core/dist ./packages/pds-core/dist
COPY --from=build /app/packages/pds-core/package.json ./packages/pds-core/
COPY --from=build /app/package.json ./
COPY --from=build /app/pnpm-workspace.yaml ./
RUN mkdir -p /data && chown appuser:appuser /data
ENV PDS_DATA_DIR=/data
USER appuser
CMD ["node", "packages/pds-core/dist/index.js"]

# -- Auth Service --
FROM node:20-alpine AS auth-service
RUN corepack enable && corepack prepare pnpm@8.15.9 --activate
RUN addgroup -g 1001 appuser && adduser -u 1001 -G appuser -D appuser
RUN apk add --no-cache wget
WORKDIR /app
# Copy the full workspace structure so pnpm symlinks resolve
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=build /app/packages/auth-service/node_modules ./packages/auth-service/node_modules
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/auth-service/dist ./packages/auth-service/dist
COPY --from=build /app/packages/auth-service/package.json ./packages/auth-service/
COPY packages/auth-service/public ./packages/auth-service/public
COPY --from=build /app/package.json ./
COPY --from=build /app/pnpm-workspace.yaml ./
RUN mkdir -p /data && chown appuser:appuser /data
ENV DB_LOCATION=/data/magic-pds.sqlite
USER appuser
CMD ["node", "packages/auth-service/dist/index.js"]
