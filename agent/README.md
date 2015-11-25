#POC agent
### golang version

This is prototype implemetation for pani agent in golang

### How to read
```
+---------------------+       +-------------------+
| main.go#main        |       | agent.go#NewAgent |
|                     |       |                   |
++--------------------+       +^------------------+
 |                             |
 |                             |
 |   +---------------------+   |
 +--->  init.go#Init       +---+
 |   |                     |
 |   +---------------------+
 |
 |   +---------------------+
 +--->  serve-api.go#Serve |
     |                     |
     +-----+---------------+
           |
           |http serve
           |
        +--v-----------------------------+
        |  serve-api.go#interfaceHandler |
        |                                |
        +------+-------------------------+
               |
               |goroutine (aka thread)
               |
            +--v-------------------------+
            |  angent.go#interfaceHandle |
            |                            |
            +----------------------------+
```


### Dependencies
* `go get gopkg.in/yaml.v2`

### Tests
Run them from project dir or it will fail to locate `test-poc-conf.yaml` required for some tests.
``` 
void@53dfd5849e82:~/go/src/github.com/romana/agent$ go test -v
=== RUN   TestNewChains
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
2015/10/29 23:20:25 Testing chain0
2015/10/29 23:20:25 >> Testing chain success0
2015/10/29 23:20:25 Testing chain1
2015/10/29 23:20:25 >> Testing chain success1
2015/10/29 23:20:25 Testing chain2
2015/10/29 23:20:25 >> Testing chain success2
--- PASS: TestNewChains (0.00s)
=== RUN   TestCreateChains
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
--- PASS: TestCreateChains (0.00s)
=== RUN   TestDivertTraffic
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
2015/10/29 23:20:25 Diverting traffic in0
2015/10/29 23:20:25 Diverting traffic success0
--- PASS: TestDivertTraffic (0.00s)
=== RUN   TestCreateRules
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
2015/10/29 23:20:25 Creating firewall rules for chain0
2015/10/29 23:20:25 Creating firewall rules success
--- PASS: TestCreateRules (0.00s)
=== RUN   TestCreateU32Rules
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
2015/10/29 23:20:25 Creating U32 firewall rules for chain0
2015/10/29 23:20:25 Creating U32 firewall rules failed for chain0
--- PASS: TestCreateU32Rules (0.00s)
=== RUN   TestAppendLineToFile
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
--- PASS: TestAppendLineToFile (0.00s)
=== RUN   TestIsLineInFile
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
--- PASS: TestIsLineInFile (0.00s)
=== RUN   TestDhcpPid
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
--- PASS: TestDhcpPid (0.00s)
=== RUN   TestIsRouteExist
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
--- PASS: TestIsRouteExist (0.00s)
=== RUN   TestCreateRoute
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
2015/10/29 23:20:25 Helper: creating route
--- PASS: TestCreateRoute (0.00s)
=== RUN   TestCreateInterhostRoutes
2015/10/29 23:20:25 Init:IdentifyCurrentHost 127.0.0.0/8 belongs to 127.0.0.1 %!s(bool=true)
2015/10/29 23:20:25 Helper: creating route
--- PASS: TestCreateInterhostRoutes (0.00s)
PASS
ok  	github.com/romana/agent	0.031s
```

### Run it on POC infrastructure
1. Setup POC infrastructure, wait for it to finish
2. Login and stop pani-agent `sudo sv stop pani-agent-svc`
3. Build golang agent `go build agent/main.go`
4. Copy golang agent e.g. `scp main ubuntu@52.8.128.133:`
5. Login and start golang agent with sudo `ssh ubuntu@52.8.128.133 "sudo ./main  -config poc-conf.yaml"`
6. Launch new instance

Expected output
```
ubuntu@ip-192-168-0-10:~$ sudo ./main -config poc-conf.yaml
2015/10/29 23:19:52 Init:IdentifyCurrentHost 10.0.0.0/16 belongs to 127.0.0.1 %!s(bool=false)
2015/10/29 23:19:52 Init:IdentifyCurrentHost 10.1.0.0/16 belongs to 127.0.0.1 %!s(bool=false)
2015/10/29 23:19:52 Init:IdentifyCurrentHost 10.0.0.0/16 belongs to 192.168.0.10 %!s(bool=false)
2015/10/29 23:19:52 Init:IdentifyCurrentHost 10.1.0.0/16 belongs to 192.168.0.10 %!s(bool=false)
2015/10/29 23:19:52 Init:IdentifyCurrentHost 10.0.0.0/16 belongs to 192.168.122.1 %!s(bool=false)
2015/10/29 23:19:52 Init:IdentifyCurrentHost 10.1.0.0/16 belongs to 192.168.122.1 %!s(bool=false)
2015/10/29 23:19:52 Init:IdentifyCurrentHost 10.0.0.0/16 belongs to 10.0.0.1 %!s(bool=true)





2015/10/29 23:20:08 Handler: parsing netif
2015/10/29 23:20:08 Handler: calling agent
2015/10/29 23:20:08 Agent: processing mech request
2015/10/29 23:20:08 Helper: Waiting for interface tape2645735-9f, 0 attempt
2015/10/29 23:20:18 Helper: Waiting for interface tape2645735-9f, 1 attempt
2015/10/29 23:20:18 Agent: ensuring interhost routes exist
2015/10/29 23:20:18 Helper.Executor: executing command: /sbin/ip [ro show 10.1.0.0/16]
2015/10/29 23:20:18 Agent: checking if dhcp is running
2015/10/29 23:20:18 Helper.Executor: executing command: ps [-C dnsmasq-calico -o pid --no-headers]
2015/10/29 23:20:18 Agent: creating endpoint routes
2015/10/29 23:20:18 Ensuring routes for 10.0.1.12 tape2645735-9f
2015/10/29 23:20:18 Helper.Executor: executing command: /sbin/ip [ro show 10.0.1.12/32]
2015/10/29 23:20:18 Helper: creating route
2015/10/29 23:20:18 Helper.Executor: executing command: /sbin/ip [ro add 10.0.1.12/32 dev tape2645735-9f]
2015/10/29 23:20:18 Agent: provisioning dhcp
2015/10/29 23:20:18 Helper.Executor: executing command: ps [-C dnsmasq-calico -o pid --no-headers]
2015/10/29 23:20:18 Agent: provisioning firewall
2015/10/29 23:20:18 Firewall: Initializing
2015/10/29 23:20:18 Testing chain0
2015/10/29 23:20:18 Helper.Executor: executing command: /sbin/iptables [-L pani-T0S1-INPUT]
2015/10/29 23:20:18 Testing chain1
2015/10/29 23:20:18 Helper.Executor: executing command: /sbin/iptables [-L pani-T0S1-OUTPUT]
2015/10/29 23:20:18 Testing chain2
2015/10/29 23:20:18 Helper.Executor: executing command: /sbin/iptables [-L pani-T0S1-FORWARD]
2015/10/29 23:20:18 Firewall: creating chains
2015/10/29 23:20:18 All good{tape2645735-9f fa:16:3e:2a:3b:4e 10.0.1.12}
```

### Roadmap
1. More tests
2. Thread safety // Done
3. Move orphan functions to some structs
4. Do something with init process. // Done
5. Do we need to expose library functions or agent only communicates via HTTP ?
6. Feedback welcome 

P.S. that's like my first pice of code after hello world, don't kick to much (:
