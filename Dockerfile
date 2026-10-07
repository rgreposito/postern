FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /postern ./cmd/postern \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /posternctl ./cmd/posternctl

FROM alpine:3.21
RUN adduser -D -H -u 65532 nonroot \
 && apk add --no-cache ca-certificates
COPY --from=build /postern /usr/local/bin/postern
COPY --from=build /posternctl /usr/local/bin/posternctl
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/postern"]
