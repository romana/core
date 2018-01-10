#
# test: run unit tests with coverage turned on.
# vet: run go vet for catching subtle errors.
# lint: run golint.
#

services = $$GOPATH/bin/romanad\
		   $$GOPATH/bin/romana\
		   $$GOPATH/bin/romana_agent\
		   $$GOPATH/bin/romana_cni\
		   $$GOPATH/bin/romana_aws\
		   $$GOPATH/bin/romana_listener\
		   $$GOPATH/bin/romana_route_publisher\
		   $$GOPATH/bin/romana_doc

UPX_VERSION := $(shell upx --version 2>/dev/null)

all: fmt vet install

buildbranch := $(shell git describe --all --abbrev=7 --always)
buildcommit := $(shell git log --pretty=format:"%h" | head -n 1)
buildinfo := ${buildbranch}-${buildcommit}
install:
	go list -f '{{.ImportPath}}' "./..." | \
		grep -v /vendor/ | xargs go install -race -ldflags \
		"-X github.com/romana/core/common.buildInfo=$(buildinfo) \
		-X github.com/romana/core/common.buildTimeStamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'`"

test:
	go list -f '{{.ImportPath}}' "./..." | \
		grep -v /vendor/ | xargs go test -timeout=30s -cover

testv:
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

doc_main_file = $(shell go list -f '{{.Dir}}' "./..." |fgrep github.com/romana/core/tools/doc)/doc.go
root_dir = $(shell go list -f '{{.Root}}' "./..." | head -1)
swagger_dir_tmp = $(shell mktemp -d)
index=$(shell for svc in agent ipam root tenant topology policy; do echo '<li><a href=\"../index.html?url=/romana/'$$svc/$$svc.yaml'\">'$$svc'</a></li>'; echo; done)

swagger:	
	cd $(swagger_dir_tmp)
	echo In `pwd`
	go run $(doc_main_file) $(root_dir) > swagger.out 2>&1
	# If the above succeeded, we do not need to keep the output,
	# so remove it.
	rm swagger.out
	echo '<html><body><h1>Romana services</h1>' > doc/index.html
	echo '<ul>' >> doc/index.html
	echo "$(index)" >> doc/index.html
	echo '</ul>' >> doc/index.html	
	echo '</body></html>' >> doc/index.html
	cat index.html
	aws s3 sync --acl public-read doc s3://swagger.romana.io/romana
	echo Latest doc uploaded to http://swagger.romana.io.s3-website-us-west-1.amazonaws.com/romana/index.html
	rm -rf $(swagger_dir_tmp)

.PHONY: test vet lint all install clean fmt upx testv
