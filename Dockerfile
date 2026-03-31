# Pre-built ghostpsy binary image: build with `docker build -t ghostpsy-agent -f agent-linux/Dockerfile agent-linux`
# Other Dockerfiles copy with: COPY --from=ghostpsy-agent /ghostpsy /usr/local/bin/ghostpsy

FROM    golang:1.24-bookworm AS builder
WORKDIR /src
COPY    go.mod go.sum ./
RUN     go mod download
COPY    . .
RUN     CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ghostpsy ./cmd/ghostpsy

FROM    scratch
COPY    --from=builder /ghostpsy /ghostpsy
