# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o image-api .

# Final runner stage
FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/image-api /app/image-api
COPY --from=builder /app/paperback-extensions/bundles /app/paperback-extensions/bundles

EXPOSE 8000

ENV PORT=8000

ENTRYPOINT ["/app/image-api"]
