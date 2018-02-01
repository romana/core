# Romana Command Line Tools

Romana command line tools provide a romana API reference implementation.
They provide a simple command line interface to interact with Romana services.

## Setting up CLI

**./romana** CLI uses a configuration file ~/.romana.yaml which contains
various parameters for connecting to root service and root service port.
A sample ~/.romana.yaml file looks as follows:

```yaml
$ cat ~/.romana.yaml 
#
# Default romana configuration file.
# please move it to ~/.romana.yaml
#
RootURL: "http://192.168.99.10:9600"
LogFile: "/var/tmp/romana.log"
Format: "table" # options are table/json 
Platform: "kubernetes"
Verbose: false
```

## Basic Usage

Once a configuration is setup (by default the romana installer will
populate the ~/.romana.yaml with a valid configuration), running the
*romana* command will display details about commands supported by
romana.

```bash
Usage:
  romana [flags]
  romana [command]

Available Commands:
  host        Add, Remove or Show hosts for romana services.
  tenant      Create, Delete, Show or List Tenant Details.
  segment     Add or Remove a segment.
  policy      Add, Remove or List a policy.

Flags:
  -c, --config string     config file (default is $HOME/.romana.yaml)
  -f, --format string     enable formatting options like [json|table], etc.
  -h, --help              help for romana
  -P, --platform string   Use platforms like [openstack|kubernetes], etc.
  -r, --rootURL string    root service url, e.g. http://192.168.0.1:9600
  -v, --verbose           Verbose output.
      --version           Build and Versioning Information.
```

## Getting started

### Host sub-commands

#### Adding a new host to romana cluster
Adding a new host to romana cluster should be done
using using [static hosts](https://github.com/romana/romana/blob/master/static_hosts.md)
and this feature is only avaiable here for debugging assistance.
```
romana host add [hostname][hostip][romana cidr][(optional)agent port] [flags]
```

#### Removing a host from romana cluster
```
romana host remove [hostname|hostip] [flags]
```

#### Listing hosts in a romana cluster
```
romana host list [flags]
```

#### Showing details about specific hosts in a romana cluster
```
romana host show [hostname1][hostname2]... [flags]
```

### Tenant sub-commands

#### Create a new tenant in romana cluster
Creating a new tenant is only necessary on certain platforms
like openstack (where the tenant has to exist previously on
that platform), for platforms like kubernetes, tenants are
created automatically and no command line interaction is
needed in those cases.
```
romana tenant create [tenantname] [flags]
```

#### Delete a specific tenant in romana cluster
```
romana tenant delete [tenantname] [flags]
```

#### Listing tenants in a romana cluster
```
romana tenant list [flags]
```

#### Showing details about specific tenant in a romana cluster
```
romana tenant show [tenantname1][tenantname2]... [flags]
```

### Segment sub-commands

#### Add a new segment to a specific tenant in romana cluster
Adding a new segment to a specific tenant is only necessary on
certain platforms like openstack, for platforms like kubernetes,
segments are created automatically and no command line interaction
is needed in those cases.
```
romana segment add [tenantName][segmentName] [flags]
```

#### Remove a segment for a specific tenant in romana cluster
```
romana segment remove [tenantName][segmentName] [flags]
```

#### Listing all segments for given tenants in a romana cluster
```
romana segment list [tenantName][tenantName]... [flags]
```

### Policy sub-commands

#### Sample Romana Policy
A sample romana policy is shown [here](../policy/policy.sample.json).

#### Add a new policy to romana cluster
Adding policies to romana cluster involves them being applied
to various backends like openstack VMs, Kubernetes Pods, etc
for various platforms supported by romana.
```
romana policy add [policyFile] [flags]
```
Alternatively policies can be added using standard input.
```
cat policy.json | romana policy add
```

#### Remove a specific policy from romana cluster
```
romana policy remove [policyName] [flags]
Local Flags:
    -i, --policyid uint   Policy ID
```

#### Listing all policies in a romana cluster
```
romana policy list [flags]
```
