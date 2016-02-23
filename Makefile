#
# test: run unit tests with coverage turned on.
# vet: run go vet for catching subtle errors.
# lint: run golint.
#

services = $$GOPATH/bin/root $$GOPATH/bin/agent $$GOPATH/bin/tenant $$GOPATH/bin/ipam $$GOPATH/bin/topology

install:
	go install -ldflags "-X main.buildInfo=`git describe --always` -X main.buildTimeStamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'`" "./..."

all: install fmt test lint vet

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

clean:
	rm $(services)

.PHONY: test vet lint all install clean fmt
