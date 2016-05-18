# Romana Core Components

[![License][License-Image]][License-Url] [![ReportCard][ReportCard-Image]][ReportCard-Url] [![Release][Release-Image]][Release-Url] [![GoDoc][GoDoc-Image]][GoDoc-Url]

Romana is a new Software Defined Network (SDN) solution specifically designed
for the Cloud Native architectural style. The result of this focus is that
Romana cloud networks are less expensive to build, easier to operate and
deliver higher performance than cloud networks built using alternative SDN
designs.

## What's in this repository

This repository contains the core components of the Romana system: A series of
cooperating microservices written in Go. These services currently are:

* *[Root](https://godoc.org/github.com/romana/core/root)*: Used as the starting point for services to discover each other. Also
holds the configuration and serves relevant parts to the other services.
* *[Tenant](https://godoc.org/github.com/romana/core/tenant)*: Manages tenants in the Romana system, interfaces with environments
such as OpenStack, to map their tenants to Romana tenants.
* *[Topology](https://godoc.org/github.com/romana/core/topology)*: Keeps track of the network topology in which we are deployed,
knows about hosts, racks, spines, etc. This information is the used by the IPAM
service.
* *[IPAM](https://godoc.org/github.com/romana/core/ipam))*: Generates and manages the IP addresses Romana assigns to network
endpoints. Uses the topology service to be able to create topology aware
addresses.
* *[Agent](https://godoc.org/github.com/romana/core/agent)*: Lives on hosts and there performs actions on behalf of Romana, such
as creating interfaces, setting routes or iptables rules.
* *Auth*: Serves authentication tokens to tenants and services.

## Getting started

### Setup the Go development environment

First, you need to setup a Go development environment. You can skip this if
you have a development environment already.

Option A: Using binary distribution

  * Download https://storage.googleapis.com/golang/go1.5.3.linux-amd64.tar.gz
  * Unpack to /usr/local/go: sudo tar -C /usr/local -xzf go1.5.3.linux-amd64.tar.gz
  * Update your profile to include:

      ```
      if [ -d /usr/local/go/bin ]; then
        PATH="$PATH:/usr/local/go/bin"
        export GOPATH="$HOME/go"
        export GO15VENDOREXPERIMENT=1
      fi
      ```

Option B: Installing from source

   * Follow the instructions here: https://golang.org/doc/install/source

### Download, build and test the Romana core source code

Once you have your Go environment, follow these steps to download, build and
test the Romana core components:

 1. Prepare a Go workspace.
 2. Ensure your `PATH` is set to find your Go installation and binaries.
 3. Ensure the `GOPATH` environment variable is set to point at the root of your
    workspace.
 4. Define and export `GO15VENDOREXPERIMENT=1`
 5. Inside of the workspace directory run: `go get github.com/romana/core/...`
    (the three dots at the end are part of the command).
 6. You may see an error at this point, complaining about `No submodule mapping found in .gitmodules...`. This is due to a known bug in "go get". You can fix that by running `cd $GOPATH/src/github.com/romana/core ; git submodule update --init --recursive`.
 7. If you wish to work with a specific branch or tag you need to run: `git checkout <branchname> ; git submodule update --init --recursive`.
 8. To run unit test for a specific Romana service run: `go test -v github.com/romana/core/<name>`, where `<name>` might be `agent`, `root`, `ipam`, `tenant` or `topology`.

### Update a running cluster with your modified code

If you use the 'romana-setup' script (provided in the https://github.com/romana/romana
repository), you get an OpenStack DevStack cluster running on some EC2
instances. It installs a standard version of the Romana core components.

Let's say you have made changes to the core services and wish to test them on a running
cluster. Here are the instructions describing how to replace the binaries on
the cluster and how to restart the services:

 1. After successfully compiling your code locally, you will find the binaries
    in `$GOPATH/bin` as `agent`, `root`, `ipam`, `tenant` and `topology`.
 2. Upload these binaries to every host in the cluster (every EC2 instance)
    with this command: `rsync -e 'ssh -i <absolute path to your SSH key .ssh/ec2_id_rsa>' -azu --existing "$GOPATH/bin/" ubuntu@<ec2-ip-address>:~/romana/bin/`. This command needs to be executed for every EC2 instance in the cluster. Please remember to specify the correct IP address of the EC2 instance and the absolute path to your SSH key where indicated.
 3. Log into the controller host and restart the services with these commands
    (note that only root and agent need to be re-started manually, other
    services will re-start on their own):

    ```
    for i in ipam tenant topology root agent; do
        sudo service romana-$i stop
    done
    sudo service romana-root start
    sudo service romana-agent start
    ```

 4. On the compute host(s), restart the services with these commands:

    ```
    sudo service romana-agent stop
    sudo service romana-agent start
    ```    

### Previous Releases
Previous Releases can be found [here][github-release].

[License-Url]: LICENSE
[License-Image]: https://img.shields.io/badge/license-Apache--2-blue.svg
[Release-Url]: https://github.com/romana/core/releases/tag/v0.8.3
[Release-image]: https://img.shields.io/badge/release-0.8.3-blue.svg
[ReportCard-Url]: https://goreportcard.com/report/romana/core
[ReportCard-Image]: https://goreportcard.com/badge/romana/core
[github-release]: https://github.com/romana/core/releases/
[GoDoc-Image]: https://godoc.org/github.com/romana/core?status.png
[GoDoc-Url]: https://godoc.org/github.com/romana/core
