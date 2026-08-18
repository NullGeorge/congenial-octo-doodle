FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/knockd-agent ./cmd/agent

FROM scratch AS export
COPY --from=build /out/knockd-agent /

FROM alpine:3.22
COPY --from=build /out/knockd-agent /usr/local/bin/knockd-agent
ENTRYPOINT ["/usr/local/bin/knockd-agent"]
