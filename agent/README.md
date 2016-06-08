#Romana Agent

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
            |  agent.go#interfaceHandle  |
            |                            |
            +----------------------------+
```


### Tests

You can run tests as follows:
```
git clone https://github.com/romana/core
cd core
make test
```
