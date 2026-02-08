# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod ./

# Download dependencies (if any)
RUN go mod download || true

# Copy source code
COPY . .

# Build the application from cmd/baseline
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o baseline ./cmd/baseline

# Final stage
FROM alpine:3.19

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S baseline && \
    adduser -u 1001 -S baseline -G baseline

# Use app directory instead of /root
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/baseline .

# Change ownership to non-root user
RUN chown baseline:baseline baseline

# Switch to non-root user
USER baseline

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ./baseline version || exit 1

# Run the binary
CMD ["./baseline"]
