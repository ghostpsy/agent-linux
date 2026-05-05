# Pre-built ghostpsy binary image: build with `docker build -t ghostpsy-agent -f agent-linux/Dockerfile agent-linux`
# Other Dockerfiles copy with: COPY --from=ghostpsy-agent /ghostpsy /usr/local/bin/ghostpsy

FROM    golang:1.26-alpine AS builder
WORKDIR /src
COPY    go.mod go.sum ./
RUN     go mod download
COPY    . .

ARG     GOOS=linux CGO_ENABLED=0 VP=github.com/ghostpsy/agent-linux/internal/version
RUN     VERSION=$(tr -d '[:space:]' < VERSION) \
        RELEASE_DATE=$(date -u +%Y-%m-%d) \
        go build -trimpath \
            -ldflags="-s -w -X ${VP}.Version=${VERSION} -X ${VP}.ReleaseDate=${RELEASE_DATE}" \
            -o /ghostpsy ./cmd/ghostpsy

FROM    scratch
COPY    --from=builder /ghostpsy /ghostpsy
