.PHONY: build test docker-build docker-test clean

IMAGE ?= knockd-agent:dev
DIST ?= dist

build:
	docker build --target export --output type=local,dest=$(DIST) .

# Run the Go test suite inside the same Docker toolchain.
test:
	docker run --rm -v "$(PWD):/src" -w /src golang:1.24-alpine go test ./...

docker-build:
	docker build -t $(IMAGE) .

docker-test:
	docker build --target build -t $(IMAGE)-build .
	docker run --rm $(IMAGE)-build go test ./...

clean:
	rm -rf $(DIST)
