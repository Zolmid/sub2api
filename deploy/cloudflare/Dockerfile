# Build context is the repository root: docker build -f deploy/cloudflare/Dockerfile .
FROM golang:1.27.0-alpine AS build
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/sub2api ./cmd/server

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
