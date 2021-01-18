# Most of this file is borrowed from the Makefile of Influxdb

VERSION := $(shell git describe --exact-match --tags 2>/dev/null)
COMMIT := $(shell git rev-parse --short HEAD)

LDFLAGS := $(LDFLAGS) -X main.commit=$(COMMIT)
ifdef VERSION
	LDFLAGS += -X main.version=$(VERSION)
endif

export GOOS=$(shell go env GOOS)
export GO_BUILD_SM=env GO111MODULE=on go build -ldflags "-s -w $(LDFLAGS)"

SOURCES := $(shell find . -name '*.go' -not -name '*_test.go') go.mod go.sum

CMDS := \
	bin/$(GOOS)/gosfv

all: $(CMDS)

bin/$(GOOS)/gosfv: $(SOURCES)
	$(GO_BUILD_SM) -o $@ ./cmd/$(shell basename "$@")

gosfv: bin/$(GOOS)/gosfv

.PHONY: all