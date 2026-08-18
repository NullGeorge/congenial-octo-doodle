.PHONY: build test docker-build docker-test clean version

IMAGE ?= knockd-agent:dev
DIST ?= dist

# Identity of the build. The date is the commit date rather than "now", so
# rebuilding the same commit produces the same binary and does not bust the
# Docker layer cache.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
STAMP = --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE)

build:
	docker build $(STAMP) --target export --output type=local,dest=$(DIST) .

version:
	@echo "$(VERSION) (commit $(COMMIT), $(DATE))"

# Run the Go test suite inside the same Docker toolchain.
test:
	docker run --rm -v "$(PWD):/src" -w /src golang:1.24-alpine go test ./...

docker-build:
	docker build $(STAMP) -t $(IMAGE) .

docker-test:
	docker build --target build -t $(IMAGE)-build .
	docker run --rm $(IMAGE)-build go test ./...

clean:
	rm -rf $(DIST)
