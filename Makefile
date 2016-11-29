#
# test: run unit tests with coverage turned on.
# vet: run go vet for catching subtle errors.
# lint: run golint.
#

services = $$GOPATH/bin/watchnodes\
		   $$GOPATH/bin/listener

UPX_VERSION := $(shell upx --version 2>/dev/null)

install:
	go list -f '{{.ImportPath}}' "./..." | \
		grep -v /vendor/ | xargs go install -ldflags \
		"-X github.com/romana/kube/common.buildInfo=`git describe --always` \
		-X github.com/romana/kube/common.buildTimeStamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'`"

all: install upx fmt vet test lint

test:
	go list -f '{{.ImportPath}}' "./..." | \
		grep -v /vendor/ | xargs go test -timeout=30s -cover

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
