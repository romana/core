#
# test: run unit tests with coverage turned on.
# vet: run go vet for catching subtle errors.
# lint: run golint.
#

all: test lint vet

test:
	go list -f '{{.ImportPath}}' "./..." | \
		grep -v /vendor/ | xargs go test -timeout=30s -cover

vet:
	go list -f '{{.ImportPath}}' "./..." | \
		grep -v /vendor/ | xargs go vet

lint:
	go list -f '{{.Dir}}' "./..." | \
		grep -v /vendor/ | xargs -n 1 golint

.PHONY: test vet lint all
