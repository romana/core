package agent

import (
	"fmt"
	"log"
	"net/http"
)

// Agent provides access to configuration and helper functions, shared across
// all the threads.
// Types Config, Leasefile and Firewall are designed to be loosely coupled
// so they could later be separated into packages and used independently.
type Agent struct {
	// Configuration from config file as well as discovered run-time configuration.
	config *Config

	// Leasefile is a type that manages DHCP leases in the file
	LeaseFile *LeaseFile

	// Helper here is a type that organizes swappable interfaces for 3rd
	// party libraries (e.g. os.exec), and some functions that are using
	// those interfaces directly. Main purpose is to support unit testing.
	// Choice of having Helper as a field of an Agent is made to
	// support multiple instances of an Agent running at same time.
	// We like this approach, since it gives us flexibility as the agent evolves in the future.
	// Should this flexibility not be required, a suitable alternative is to re-implement the
	// Agent structure as a set of global variables.
	Helper *Helper
}

// NewAgent returns Agent structure with all fields initialized.
func NewAgent(config *Config) Agent {
	// new agent
	agent := new(Agent)

	// plug helper
	h := NewAgentHelper(agent)
	agent.Helper = &h

	// plug config
	agent.config = config

	// plug leasefile
	lf := NewLeaseFile(agent.config.LeaseFileLocation, agent)
	agent.LeaseFile = &lf

	return *agent
}

// interfaceHandler handles HTTP requests for endpoints provisioning.
// Currently tested with pani ML2 driver.
func (a *Agent) interfaceHandler(w http.ResponseWriter, r *http.Request) {
	// Parse out NetIf form the request
	netif := new(NetIf)
	r.ParseForm()
	log.Print("Handler: parsing netif")
	if err := netif.ParseNetIf(r.Form); err != nil {
		log.Print("Handler: parsing netif failed", w, r)
	}
	log.Print("Handler: calling agent")

	// Spawn new thread to process the request

	// TODO don't know if fork-bombs are possible in go but if they are this
	// need to be refactored as buffered channel with fixed pool of workers
	go a.interfaceHandle(*netif)
	w.Write([]byte("OK"))

}

// interfaceHandle does a number of opertaions on given endpoint to ensure
// it's connected:
// 1. Ensures interface is ready
// 2. Ensures interhost routes are in place
// 3. Checks if DHCP is running
// 4. Creates ip route pointing new interface
// 5. Provisions static DHCP lease for new interface
// 6. Provisions firewall rules
func (a *Agent) interfaceHandle(netif NetIf) error {
	log.Print("Agent: processing request to provision new interface")
	if !a.Helper.waitForIface(netif.name) {
		// TODO should we resubmit failed interface in queue for later
		// retry ? ... considering oenstack will give up as well after
		// timeout
		return agentErrorString(fmt.Sprintf("Requested interface not available in time - %s", netif.name))
	}

	// Ensure we have all the routes to our neighbours
	log.Print("Agent: ensuring interhost routes exist")
	if err := a.Helper.ensureInterHostRoutes(); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}
	// dhcpPid is only needed here for fail fast check
	// will try to poll the pid again in provisionLease
	log.Print("Agent: checking if DHCP is running")
	_, err := a.Helper.DhcpPid()
	if err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}
	log.Print("Agent: creating endpoint routes")
	if err := a.Helper.ensureRouteToEndpoint(&netif); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}
	log.Print("Agent: provisioning DHCP")
	if err := a.LeaseFile.provisionLease(&netif); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}
	log.Print("Agent: provisioning firewall")
	if err := provisionFirewallRules(netif, a); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}

	log.Print("All good", netif)
	return nil
}

/* development code
func DryRun() {
	tif := NetIf{"eth0", "B", "10.0.0.1"}
	firewall, _ := NewFirewall(tif)
	err := firewall.ParseNetIf(tif)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(firewall.u32Filter)
	// for chain := range firewall.chains {
	// 	fmt.Println(firewall.chains[chain])
	// }
	firewall.CreateChains([]int{1, 2, 3})
	a.Helper.ensureInterHostRoutes()
	if _, err := a.Helper.DhcpPid(); err != nil {
		fmt.Println(err)
	}
}
*/
