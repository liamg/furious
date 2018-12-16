SHELL := /bin/bash
BINARY := furious

.PHONY: build
build: 
	./build.sh `git describe --tags`

.PHONY: test
test:
	go test -v ./...
	go vet -v

.PHONY: install
install: build
	go install -ldflags "-X github.com/liamg/furious/version.Version=`git describe --tags`"

.PHONY: update-ports
install-tools:
	go run tools/update-ports.go
