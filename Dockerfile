# Stage 1: Build the application
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy dependency files first (better caching)
COPY go.mod ./

COPY . .
RUN go build -o react2shell-honeypot main.go

# Stage 2: Run the application
FROM alpine:latest

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/react2shell-honeypot .

# Create the log directory inside the container
RUN mkdir -p /var/log/react2shell-honeypot

# Expose the volume (tells Docker this directory holds persistent data)
VOLUME ["/var/log/react2shell-honeypot"]

# Run the binary
CMD ["./react2shell-honeypot"]
