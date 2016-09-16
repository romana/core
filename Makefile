#
# test: run unit tests with coverage turned on.
# vet: run go vet for catching subtle errors.
# lint: run golint.
#

services = $$GOPATH/bin/root\
		   $$GOPATH/bin/agent\
		   $$GOPATH/bin/tenant\
		   $$GOPATH/bin/ipam\
		   $$GOPATH/bin/romana\
		   $$GOPATH/bin/policy\
		   $$GOPATH/bin/listener\
		   $$GOPATH/bin/doc\
		   $$GOPATH/bin/topology

UPX_VERSION := $(shell upx --version 2>/dev/null)

install:
	go install -ldflags \
		"-X github.com/romana/core/common.buildInfo=`git describe --always` \
		-X github.com/romana/core/common.buildTimeStamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'`" \
		"./..."

all: install fmt test lint vet

test:
	go list -f '{{.ImportPath}}' "./..." | \
		grep -v /vendor/ | xargs go test -v -timeout=30s -cover

vet:
	go list -f '{{.ImportPath}}' "./..." | \
		grep -v /vendor/ | xargs go vet

fmt:
	go list -f '{{.ImportPath}}' "./..." | \
		grep -v /vendor/ | xargs go fmt

lint:
	go list -f '{{.Dir}}' "./..." | \
		grep -v /vendor/ | xargs -n 1 golint

upx:
ifndef UPX_VERSION
	$(error "No upx in $(PATH), consider doing apt-get install upx")
endif
	upx $(services)

clean:
	rm $(services)

.PHONY: test vet lint all install clean fmt upx
