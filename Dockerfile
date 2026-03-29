# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN go build -o demo .

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/demo .
COPY --from=builder /app/templates ./templates

# Create a directory for the database and persist it via volumes
VOLUME ["/app/db"]

# Set environment variables
ENV APP_DOMAIN=localhost
ENV PORT=8000

EXPOSE 8000

CMD ["./demo"]
