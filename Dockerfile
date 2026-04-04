# Pre-built ghostpsy binary image: build with `docker build -t ghostpsy-agent -f agent-linux/Dockerfile agent-linux`
# Other Dockerfiles copy with: COPY --from=ghostpsy-agent /ghostpsy /usr/local/bin/ghostpsy

FROM    golang:1.24-bookworm AS builder
WORKDIR /src
COPY    go.mod go.sum ./
RUN     go mod download
COPY    . .
RUN     VERSION=$(tr -d '[:space:]' < VERSION) && \
        RELEASE_DATE=$(date -u +%Y-%m-%d) && \
        VP=github.com/ghostpsy/agent-linux/internal/version && \
        CGO_ENABLED=0 go build -trimpath \
        -ldflags="-s -w -X ${VP}.Version=${VERSION} -X ${VP}.ReleaseDate=${RELEASE_DATE}" \
        -o /ghostpsy ./cmd/ghostpsy

FROM    scratch
COPY    --from=builder /ghostpsy /ghostpsy
