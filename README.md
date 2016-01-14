# Romana Core Components

Romana is a new Software Defined Network (SDN) solution specifically designed
for the Cloud Native architectural style. The result of this focus is that
Romana cloud networks are less expensive to build, easier to operate and
deliver higher performance than cloud networks built using alternative SDN
designs.

## What's in this repository

This repository contains the core components of the Romana system: A series of
cooperating micro services written in Go. These services currently are:

* *Root*: Used as the starting point for services to discover each other. Also
holds the configuration and serves relevant parts to the other services.
* *Tenant*: Manages tenants in the Romana system, interfaces with environments
such as OpenStack, to map their tenants to Romana tenants.
* *Topology*: Understands the network topology in which we are deployed, knows
about hosts, racks, spines, etc.
* *IPAM*: Generates and manages the IP addresses Romana assigns to network
endpoints.
* *Agent*: Lives on hosts and there performs actions on behalf of Romana, such
as creating interfaces, setting routes or iptables rules.

Planned for the near future:

* *Auth*: Serves authentication tokens to tenants and services.
* *Routes*: Manages special routes for VM migration and service insertion.

## Getting started

 1. Install Go, at least version 1.5.1, as described here: https://golang.org/doc/install
    Remember to set `GOPATH` and possibly also `GOROOT` as needed.
 2. Define and export `GO15VENDOREXPERIMENT=1`
 3. Prepare a Go workspace, as described here: https://golang.org/doc/code.html#Workspaces
 4. Inside of the workspace's `src/` directory, create the path
    `github.com/romana`
 5. Inside of that directory, clone this repo: `git clone git@github.com:romana/core.git`
 6. Change into the `src/` directory of your workspace and install all the
    dependencies with: `go install github.com/romana/core/...` (note that there
    may be some warnings about "no buildable Go source files" in some
    directories. Those warnings can be ignored.
 7. Run some unit tests, like so: `go test -v github.com/romana/core/root`

