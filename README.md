# Core

Core components of the Romana system.

## Getting started

 1. Prepare a Go workspace with the path src/github.com/romana
 2. Inside of that directory, clone the repo: `git clone git@github.com:romana/core.git`
 3. Make sure to define and export `GOPATH` (and possibly `GOROOT`) as needed.
 4. Define and export `GO15VENDOREXPERIMENT=1`
 5. Change into the 'src' directory of your workspace and install all the
    dependencies with: `go install github.com/romana/core/...` (note that there
    may be some warnings about "no buildable Go source files" in some
    directories. Those warnings can be ignored.
 6. Run some unit tests, like so: `go test -v github.com/romana/core/root`

