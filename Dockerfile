# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o s3scanner ./cmd/s3scanner

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S s3scanner && \
    adduser -u 1001 -S s3scanner -G s3scanner

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/s3scanner .

# Copy rules directory
COPY --from=builder /app/rules ./rules

# Change ownership to non-root user
RUN chown -R s3scanner:s3scanner /app

# Switch to non-root user
USER s3scanner

# Expose port (if needed for health checks)
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["./s3scanner"]
