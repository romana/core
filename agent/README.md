#POC agent
### golang version

This is prototype implemetation for Romana agent in golang.

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

