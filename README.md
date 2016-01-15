# Romana Core Components
  		  
Romana is a new Software Defined Network (SDN) solution specifically designed
for the Cloud Native architectural style. The result of this focus is that
Romana cloud networks are less expensive to build, easier to operate and
deliver higher performance than cloud networks built using alternative SDN
designs.

## What's in this repository

This repository contains the core components of the Romana system: A series of
cooperating microservices written in Go. These services currently are:

* *Root*: Used as the starting point for services to discover each other. Also
holds the configuration and serves relevant parts to the other services.
* *Tenant*: Manages tenants in the Romana system, interfaces with environments
such as OpenStack, to map their tenants to Romana tenants.
* *Topology*: Keeps track of the network topology in which we are deployed,
knows about hosts, racks, spines, etc. This information is the used by the IPAM
service.
* *IPAM*: Generates and manages the IP addresses Romana assigns to network
endpoints. Uses the topology service to be able to create topology aware
addresses.
* *Agent*: Lives on hosts and there performs actions on behalf of Romana, such
as creating interfaces, setting routes or iptables rules.
* *Auth*: Serves authentication tokens to tenants and services.

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

