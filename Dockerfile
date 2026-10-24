# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache module downloads separately from source
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build with all optional features; CGO disabled for pure-Go SQLite
RUN CGO_ENABLED=0 go build -tags "ion,saml,ldap" \
    -ldflags="-s -w" \
    -o /out/tpt-identity \
    ./cmd/tpt-identity

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /out/tpt-identity /usr/local/bin/tpt-identity

# Directories for config, keys, and database
RUN mkdir -p /app/keys /app/data

EXPOSE 8080

# Run as a non-root user
RUN addgroup -S tpt && adduser -S -G tpt tpt
USER tpt

ENTRYPOINT ["tpt-identity"]
CMD ["serve", "--config", "/app/config.yaml"]
