package main

import (
	"flag"
	"github.com/romana/agent"
)

// main function is entrypoint to everything.
func main() {
	var configLocation = flag.String("config", "/tmp/conf.yml", "Full path to POC config file")
	var leaseFileLocation = flag.String("leasefile", "/etc/ethers", "Full path to lease file")
	var waitForIfaceTry = flag.Int("waitForIfaceTry", 6, "Full path to lease file")
	flag.Parse()
	PaniAgent := agent.Init(configLocation, leaseFileLocation, waitForIfaceTry)
	PaniAgent.Serve()
	// agent.DryRun()
}
