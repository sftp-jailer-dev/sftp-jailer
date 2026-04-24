.PHONY: all build test lint vuln logo run clean

VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PROJECT_URL := https://sftp-jailer.com
LDFLAGS     := -s -w \
               -X main.buildVersion=$(VERSION) \
               -X main.buildProjectURL=$(PROJECT_URL)

BIN := bin/sftp-jailer

all: build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/sftp-jailer

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run

vuln:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

logo:
	bash scripts/render-logo.sh

run: build
	@echo "Run with: sudo $(BIN)"

clean:
	rm -rf bin/
