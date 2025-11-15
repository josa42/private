# Build stage
FROM golang:1.24.2-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o grandstream-telephonebook .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Copy the binary from builder
COPY --from=builder /app/grandstream-telephonebook .

# Expose port 8081
EXPOSE 8081

# Run the application
CMD ["./grandstream-telephonebook"]
