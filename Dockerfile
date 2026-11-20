# Stage 1: Node builds the SvelteKit UI
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# Stage 2: Go builds the single binary with the UI embedded
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/build ./web/build
ARG VERSION=dev
RUN mkdir -p /out/work && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/yourcve ./cmd/yourcve

# Stage 3: distroless runtime (~30 MB), no shell, runs as nonroot
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/yourcve /yourcve
# writable scratch dir for import archives (TMPDIR), owned by nonroot
COPY --from=build --chown=65532:65532 /out/work /work
ENV TMPDIR=/work
ENV LISTEN_ADDR=:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/yourcve", "healthcheck"]
ENTRYPOINT ["/yourcve"]
