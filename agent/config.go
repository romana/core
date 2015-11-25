package agent

import (
	"github.com/romana/IPAM/src/romana/config"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net"
	"os"
)

// PocConfig is used in ParsePocConfig to receive parsed POC config file.
// TODO This can be done without global variable now.
var PocConfig = config.PocConfig{}

// Config holds the agent's current configuration.
// This consists of data parsed from the config file as well as
// runtime or discovered configuration, such as the network
// config of the current host.
type Config struct {
	// Originally parsed config file
	PocConfig config.PocConfig

	// Current host network configuration
	CurrentHostIP        net.IP
	CurrentHostGW        net.IP
	CurrentHostGWNet     net.IPNet
	CurrentHostGWNetSize int
	// index of the current host in POC config file
	CurrentHostIndex int

	// Command line flags and other defaults
	waitForIfaceTry   int // how long to wait for interface before giving up
	LeaseFileLocation string
	// etc
}

// EndpointNetmask returns integer value (aka size) of endpoint netmask.
func (c *Config) EndpointNetmask() int {
	return 32 - int(c.PocConfig.DC.PseudoNet.EndpointSpaceBits)
}

// PNetCIDR returns pseudo net cidr in net.IPNet format.
func (c *Config) PNetCIDR() (cidr *net.IPNet, err error) {
	_, cidr, err = net.ParseCIDR(c.PocConfig.DC.PseudoNet.Cidr)
	return
}

// TenantBits returns tenant bits value from POC config.
func (c *Config) TenantBits() uint64 {
	return c.PocConfig.DC.PseudoNet.TenantBits
}

// SegmentBits returns segment bits value from POC config.
func (c *Config) SegmentBits() uint64 {
	return c.PocConfig.DC.PseudoNet.SegmentBits
}

// EndpointBits returns endpoint bits value from POC config.
func (c *Config) EndpointBits() uint64 {
	return c.PocConfig.DC.PseudoNet.EndpointBits
}

// ParsePocConfig reads POC config file from disk.
func ParsePocConfig(path *string, config *config.PocConfig) error {
	if _, err := os.Stat(*path); err != nil {
		log.Fatal("Can not read config file")
	}
	data, err := ioutil.ReadFile(*path)
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal([]byte(data), config)
	if err != nil {
		panic(err)
	}
	return nil
}

// IdentifyCurrentHost is a function that discovers network configuration
// of the host we are running at.
// We need to know public IP and pani gateway IP of the current host.
// This is done by matching current host IP addresses against config file.
// If no match found we assume we are running on host which is not
// the part of pani setup and spit error out.
func IdentifyCurrentHost(config *Config) error {
	addrs, _ := net.InterfaceAddrs()
	hosts := config.PocConfig.DC.Leaves[0].Hosts
	// Yeah, nested loop. Can't think anything better.
	for i := range addrs {
		// TODO This condition required to break from outer loop
		// when inner one *broken*. Don't look pretty,
		// but do we justify use of labels for that case ?
		if config.CurrentHostGW != nil {
			break
		}

		RomanaIP, _, err := net.ParseCIDR(addrs[i].String())
		if err != nil {
			log.Printf("Failed to parse %s", addrs[i].String())
			return err
		}
		for j := range hosts {

			_, romanaNet, err := net.ParseCIDR(hosts[j].RomanaIp)
			if err != nil {
				log.Printf("Failed to parse %s", hosts[j].RomanaIp)
				return err
			}
			log.Printf("Init:IdentifyCurrentHost %s belongs to %s %s",
				romanaNet,
				RomanaIP,
				romanaNet.Contains(RomanaIP))

			if romanaNet.Contains(RomanaIP) {
				config.CurrentHostIP = net.ParseIP(hosts[j].Ip)
				config.CurrentHostGW = RomanaIP
				config.CurrentHostGWNet = *romanaNet
				config.CurrentHostGWNetSize, _ = romanaNet.Mask.Size()
				config.CurrentHostIndex = j
				break
			}
		}
	}
	if config.CurrentHostGW == nil {
		return wrongHostError()
	}
	return nil
}

// Init initializes Config structure and uses it to initialize Agent.
// Returns fully initialized Agent.
func Init(configLocation *string,
	leasefileLocation *string,
	waitForIfaceTry *int) Agent { // signature ends

	// new config
	config := new(Config)

	// read POC config file
	if err := ParsePocConfig(configLocation, &config.PocConfig); err != nil {
		panic(err)
	}

	// discover our network config
	if err := IdentifyCurrentHost(config); err != nil {
		panic(err)
	}

	// propagate flags
	config.waitForIfaceTry = *waitForIfaceTry // *10 sec
	config.LeaseFileLocation = *leasefileLocation

	// initialize config
	agent := NewAgent(config)
	return agent
}
