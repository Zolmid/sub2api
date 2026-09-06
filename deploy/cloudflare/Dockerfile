# syntax=docker/dockerfile:1.7
# Build context is the repository root: docker build -f deploy/cloudflare/Dockerfile .
FROM node:24-alpine AS frontend-builder
WORKDIR /src/frontend

# Keep the frontend lockfile authoritative, matching the root image build.
RUN corepack enable && corepack prepare pnpm@9 --activate
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN --mount=type=cache,id=sub2api-cloudflare-pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --prefer-offline

# LegalDocumentView imports these documents at build time.
COPY frontend/ ./
COPY docs/legal/ /src/docs/legal/
RUN pnpm run build

FROM golang:1.27.0-alpine AS build
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=cache,id=sub2api-cloudflare-gomod,target=/go/pkg/mod go mod download
COPY backend/ ./
COPY --from=frontend-builder /src/backend/internal/web/dist ./internal/web/dist
RUN --mount=type=cache,id=sub2api-cloudflare-gomod,target=/go/pkg/mod \
    --mount=type=cache,id=sub2api-cloudflare-gobuild,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -tags embed -trimpath -ldflags='-s -w' -o /out/sub2api ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sub2api /sub2api
EXPOSE 8080
ENV SUB2API_DEPLOYMENT_MODE=cloudflare \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=8080 \
    SUB2API_CF_CONTROL_PLANE_URL=http://sub2api.internal \
    SUB2API_CF_LEASE_TTL_SECONDS=90
USER nonroot:nonroot
ENTRYPOINT ["/sub2api"]
