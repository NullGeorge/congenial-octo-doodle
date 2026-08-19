FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Declared after the dependency layers so a new stamp does not re-download
# modules, only re-links the binaries.
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ENV STAMP="-s -w \
 -X github.com/NullGeorge/congenial-octo-doodle/internal/version.Version=${VERSION} \
 -X github.com/NullGeorge/congenial-octo-doodle/internal/version.Commit=${COMMIT} \
 -X github.com/NullGeorge/congenial-octo-doodle/internal/version.Date=${DATE}"

RUN CGO_ENABLED=0 go build -trimpath -ldflags="$STAMP" -o /out/knockd-agent ./cmd/agent
RUN CGO_ENABLED=0 go build -trimpath -ldflags="$STAMP" -o /out/knock-helper ./cmd/knock-helper
RUN CGO_ENABLED=0 go build -trimpath -ldflags="$STAMP" -o /out/knock-watch ./cmd/knock-watch

FROM scratch AS export
COPY --from=build /out/knockd-agent /out/knock-helper /out/knock-watch /

FROM alpine:3.22
COPY --from=build /out/knockd-agent /usr/local/bin/knockd-agent
COPY --from=build /out/knock-helper /usr/local/sbin/knock-helper
COPY --from=build /out/knock-watch /usr/local/bin/knock-watch
ENTRYPOINT ["/usr/local/bin/knockd-agent"]
