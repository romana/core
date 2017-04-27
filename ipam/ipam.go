// Copyright (c) 2017 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or	 implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package ipam

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	"github.com/romana/core/pkg/api"
	log "github.com/romana/rlog"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync"
)

// This provides an implementation of an IPAM that can allocate
// blocks of IPs for tenant/segment pair. It assumes IPv4.
//
// Address blocks may be taken out of more than one pre-configured
// address range (Networks).

const (
	msgNoAvailableIP = "No available IP."
)

var (
	err              error
	tenantNameRegexp = regexp.MustCompile("^[a-zA-Z0-9_]*$")
)

// makeOwner makes an "owner" string -- which is "<tenant>:<segment>".
func makeOwner(tenant string, segment string) string {
	return fmt.Sprintf("%s:%s", tenant, segment)
}

// parseOwner splits the owner string into tenant and segment.
func parseOwner(owner string) (string, string) {
	tenSeg := strings.SplitN("tenant", ":", 2)
	if len(tenSeg) == 1 {
		return tenSeg[0], ""
	}
	return tenSeg[0], tenSeg[1]
}

// CIDR represents a CIDR (net.IPNet, effectively) with some
// extra functionality for convenience.
type CIDR struct {
	// Represents the IPNet object corresponding to this CIDR.
	*net.IPNet
	StartIP    net.IP `json:"start_ip"`
	StartIPInt uint64 `json:"start_ip_int"`
	EndIP      net.IP `json:"end_ip"`
	EndIPInt   uint64 `json:"end_ip_int"`
}

// NewCIDR creates a CIDR object from a string.
func NewCIDR(s string) (*CIDR, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	cidr := &CIDR{IPNet: ipNet}
	cidr.StartIP = ip
	cidr.StartIPInt = common.IPv4ToInt(ip)
	ones, bits := ipNet.Mask.Size()
	ipCount := 1 << uint(bits-ones)
	cidr.EndIPInt = cidr.StartIPInt + uint64(ipCount) - 1
	cidr.EndIP = common.IntToIPv4(cidr.EndIPInt)
	return cidr, nil
}

// Contains returns true if this CIDR fully contains (is equivalent to or a superset
// of) the provided CIDR.
func (c *CIDR) Contains(c2 *CIDR) bool {
	log.Tracef(trace.Private, "%d<=%d && %d>=%d: %t", c.StartIPInt,
		c2.StartIPInt, c.EndIPInt,
		c2.EndIPInt,
		(c.StartIPInt <= c2.StartIPInt && c.EndIPInt >= c2.EndIPInt))
	return c.StartIPInt <= c2.StartIPInt && c.EndIPInt >= c2.EndIPInt
}

func (c CIDR) toString() string {
	return c.IPNet.String() + " (" + (c.StartIP.String()) + "-" + string(c.EndIP.String()) + ")"
}

func (c CIDR) String() string {
	return c.toString()
}

func (c CIDR) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", c.toString())), nil
}

func (cidr *CIDR) UnmarshalJSON(data []byte) error {
	_, ipNet, err := net.ParseCIDR(string(data))
	if err != nil {
		return err
	}
	cidr.IP = ipNet.IP
	cidr.Mask = ipNet.Mask
	return nil
}

// Host represents a host in Romana topology.
type Host struct {
	Name string `json:"name"`
	CIDR *CIDR  `json:"cidr"`

	BlockToOwner  map[int]string   `json:"block_to_owner"`
	OwnerToBlocks map[string][]int `json:"owner_to_block"`

	Blocks         []*Block `json:"blocks"`
	ReusableBlocks []int    `json:"reusable_blocks"`

	ipam *IPAM
}

func (host *Host) deallocateIP(ip net.IP) error {
	for blockID, block := range host.Blocks {
		if block.CIDR.IPNet.Contains(ip) {
			log.Tracef(trace.Private, "IP to deallocate %s belongs to block %s", ip, block.CIDR)
			err := block.deallocateIP(ip)
			if err != nil {
				return err
			}
			if block.isEmpty() {
				tenant := host.BlockToOwner[blockID]
				log.Tracef(trace.Private, "Block %d for tenant %s is empty, reclaiming it for reuse", blockID, tenant)
				host.ReusableBlocks = append(host.ReusableBlocks, blockID)
				tenantBlocks := host.OwnerToBlocks[tenant]
				host.OwnerToBlocks[tenant] = append(tenantBlocks[:blockID], tenantBlocks[blockID+1:]...)
			}
		}
	}
	return nil
}

func (host *Host) allocateIP(network *Network, tenant string, segment string) net.IP {
	owner := makeOwner(tenant, segment)
	ownedBlockIDs := host.OwnerToBlocks[owner]
	var ip net.IP
	if len(ownedBlockIDs) > 0 {
		for _, blockID := range ownedBlockIDs {
			block := host.Blocks[blockID]
			ip = block.allocateIP(network)
			if ip != nil {
				return ip
			}
		}
		log.Tracef(trace.Private, "All blocks on host %s (network %s) for owner %s are exhausted, will try to reuse a block", host.Name, network.Name, owner)
	} else {
		log.Tracef(trace.Private, "Host %s (network %s) has no blocks for owner %s, will try to reuse a block", host.Name, network.Name, owner)
	}
	// If we are here then all blocks are exhausted. Need to allocate a new block.
	// First let's see if there are blocks on this host to be reused.
	if len(host.ReusableBlocks) > 0 {
		for _, blockID := range host.ReusableBlocks {
			block := host.Blocks[blockID]
			ip = block.allocateIP(network)
			if ip != nil {
				// We can now remove this block from reusables.
				log.Tracef(trace.Private, "Reusing block %d for owner %s", blockID, owner)
				host.ReusableBlocks = append(host.ReusableBlocks[:blockID], host.ReusableBlocks[blockID+1:]...)
				host.OwnerToBlocks[owner] = append(host.OwnerToBlocks[owner], blockID)
				host.BlockToOwner[blockID] = owner
				return ip
			}
		}
		log.Tracef(trace.Private, "Host %s has no blocks to reuse for %s, creating new block", host.Name, tenant)
	} else {
		log.Tracef(trace.Private, "Host %s has no blocks to reuse for %s, creating new block", host.Name, tenant)
	}

	for {
		var newBlockStartIPInt uint64
		if len(host.Blocks) > 0 {
			lastBlock := host.Blocks[len(host.Blocks)-1]
			newBlockStartIPInt = lastBlock.CIDR.EndIPInt + 1
		} else {
			newBlockStartIPInt = host.CIDR.StartIPInt
		}
		if newBlockStartIPInt > host.CIDR.EndIPInt {
			// Cannot allocate any more blocks for this network, move on to another.
			log.Tracef(trace.Private, "Cannot allocate any more blocks from network %s", host.CIDR)
			return nil
		}

		newBlockEndIPInt := newBlockStartIPInt + (1 << (32 - network.BlockMask)) - 1
		if newBlockEndIPInt > network.CIDR.EndIPInt {
			// Cannot allocate any more blocks for this network, move on to another.
			// TODO: Or should we allocate as much as possible?
			log.Tracef(trace.Private, "Cannot allocate any more blocks from network %s", host.CIDR)
			return nil
		}

		newBlockCIDRStr := fmt.Sprintf("%s/%d", common.IntToIPv4(newBlockStartIPInt), network.BlockMask)
		newBlockCIDR, err := NewCIDR(newBlockCIDRStr)
		if err != nil {
			// This should not really happen...
			log.Errorf("Error occurred allocating IP for %s in network %s: %s", owner, host.CIDR, err)
			return nil
		}
		newBlock := newBlock(newBlockCIDR, host)
		host.Blocks = append(host.Blocks, newBlock)
		host.OwnerToBlocks[owner] = append(host.OwnerToBlocks[owner], len(host.Blocks)-1)
		host.BlockToOwner[len(host.Blocks)-1] = owner
		log.Tracef(trace.Private, "New block created in %s: %s", host.CIDR, newBlockCIDR)
		ip := newBlock.allocateIP(network)
		if ip == nil {
			// This could happen if this is a new block but happens to be completely
			// blacked out. Try allocating another.
			log.Tracef(trace.Private, "Cannot allocate any IPs from block %s", newBlock.CIDR)
			continue
		}
		return ip
	}
}

// HostsGroups holds either a list of hosts at a given level
type HostsGroups struct {
	Hosts  []*Host        `json:"hosts"`
	Groups []*HostsGroups `json:"groups"`
	ipam   *IPAM
}

func (hg *HostsGroups) listHosts() []*Host {
	list := hg.Hosts
	for _, group := range hg.Groups {
		list2 := group.listHosts()
		list = append(list, list2...)
	}
	return list
}

func (hg *HostsGroups) findHostByName(name string) *Host {
	for _, h := range hg.Hosts {
		if h.Name == name {
			return h
		}
	}
	for _, group := range hg.Groups {
		return group.findHostByName(name)
	}
	return nil
}

func (hg *HostsGroups) String() string {
	if len(hg.Hosts) > 0 {
		return fmt.Sprintf("%v", hg.Hosts)
	} else {
		s := ""
		for _, hg2 := range hg.Groups {
			if s != "" {
				s += ", \n"
			}
			s += "\t" + hg2.String()
		}
		s = "[\n" + s + "\n]"
		return s
	}
}

// parse parses simple JSON representing host groups, such as
// this one:
//                     [
//                        [ "A", "B", "C" ],
//                        [ "D" ],
//                        [
//                          [ "E", "F" ],
//                          [ "G", "H" ]
//                        ],
//                        [
//                          [ "I", "J", "K" ],
//                          [
//                            [ "N", "O", "P", "Q" ],
//                            [ "R", "S" ]
//                          ],
//                          [ "T" ]
//                        ]
//                    ]
// into the HostsOrHostGroups structure.
func (hg *HostsGroups) parse(arr []interface{}, cidr *CIDR) error {
	kind := ""
	// Figure out in the given array, what would be the size per
	// element.
	ones, bits := cidr.Mask.Size()
	free := bits - ones
	if len(arr) == 0 {
		return common.NewError("Zero length array")
	}
	if free%len(arr) != 0 {
		return common.NewError("Cannot allocate CIDR %s amoung %d hosts", cidr, len(arr))
	}
	bitsPerElement := free / len(arr)

	for i, elt := range arr {
		eltVal := reflect.ValueOf(elt)
		if eltVal.Kind() != reflect.Slice && eltVal.Kind() != reflect.String {
			return errors.New(fmt.Sprintf("Unknown type %s", eltVal.Kind()))
		} else if kind == "" {
			kind = eltVal.Kind().String()
			if kind == "string" {
				hg.Hosts = make([]*Host, len(arr))
			} else {
				hg.Groups = make([]*HostsGroups, len(arr))
			}
		} else if eltVal.Kind().String() != kind {
			return errors.New(fmt.Sprintf("Mixed types"))
		}
		// Calculate CIDR for the current element

		elementCIDRIP := common.IntToIPv4(cidr.StartIPInt + uint64(bitsPerElement*i))
		elementCIDRString := fmt.Sprintf("%s/%d", elementCIDRIP, bitsPerElement)
		elementCIDR, err := NewCIDR(elementCIDRString)
		if err != nil {
			return err
		}
		if kind == "string" {
			hg.Hosts[i] = &Host{Name: elt.(string), CIDR: elementCIDR}
			hg.Hosts[i].BlockToOwner = make(map[int]string)
			hg.Hosts[i].Blocks = make([]*Block, 0)
			hg.Hosts[i].OwnerToBlocks = make(map[string][]int)
			hg.Hosts[i].ReusableBlocks = make([]int, 0)
		} else {
			hg.Groups[i] = &HostsGroups{}
			newArr := elt.([]interface{})
			err := hg.Groups[i].parse(newArr, elementCIDR)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Block represents a CIDR that is owned by an Owner,
// and thus can have addresses allocated in it it.
type Block struct {
	CIDR     *CIDR          `json:"cidr"`
	Pool     *common.IDRing `json:"pool"`
	ipam     *IPAM
	Revision int `json:"revision"`
}

// newBlock creates a new Block on the given host.
func newBlock(cidr *CIDR, host *Host) *Block {
	eb := &Block{CIDR: cidr,
		ipam: host.ipam,
		Pool: common.NewIDRing(cidr.StartIPInt, cidr.EndIPInt),
	}
	return eb
}

// hasIPInCIDR checks whether it has any allocated IPs that
// belong to provided CIDR.
func (b Block) hasIPInCIDR(cidr CIDR) bool {
	allocated := b.Pool.Invert()
	for _, r := range allocated.Ranges {
		if r.Min >= cidr.StartIPInt && r.Max <= cidr.EndIPInt {
			return true
		}
	}
	return false
}

// Returns true if there is nothing allocated.
func (b *Block) isEmpty() bool {
	return b.Pool.IsEmpty()
}

// allocateIP allocates an IP from the block. Returns nil if
// exhausted.
func (b *Block) allocateIP(network *Network) net.IP {
	var ip net.IP
	blackedOutIPInts := make([]uint64, 0)
	for {
		ipInt, err := b.Pool.GetID()
		if err == nil {
			ip = common.IntToIPv4(ipInt)
			blackedOutBy := network.blackedOutBy(ip)
			log.Tracef(trace.Private, "IP %s is blacked out by %s", ip, blackedOutBy)
			if blackedOutBy == nil {
				break
			} else {
				blackedOutIPInts = append(blackedOutIPInts, ipInt)
				ip = nil
			}
		} else {
			// Exhausted
			break
		}
	}
	if len(blackedOutIPInts) > 0 {
		log.Tracef(trace.Private, "Could not allocate these, as they are blacked out: %v", blackedOutIPInts)
		err, _ := b.Pool.ReclaimIDs(blackedOutIPInts)
		if err != nil {
			// Nothing much to do here...
			log.Errorf("Could not reclaim IDs: %s", err)
		}
	}
	log.Tracef(trace.Private, "Allocated %s from %s", ip, b.CIDR)

	b.Revision += 1
	return ip
}

// deallocateIP deallocates the specified IP within the block.
func (b *Block) deallocateIP(ip net.IP) error {
	if !b.CIDR.IPNet.Contains(ip) {
		return common.NewError("IP %s not in this block %s", ip, b.CIDR)
	}
	ipInt := common.IPv4ToInt(ip)
	err := b.Pool.ReclaimID(ipInt)
	if err != nil {
		return err
	}
	b.Revision += 1
	return nil

}

// Network is the main structure managing allocation of IP addresses in the
// provided CIDR.
type Network struct {
	Name string `json:"name"`

	// CIDR of the network (likely 10/8).
	CIDR *CIDR `json:"cidr"`

	// Size of tenant/segment block to allocate, in bits as mask
	// (specify 32 for size 1, e.g.)
	BlockMask uint `json:"block_mask"`

	BlackedOut []*CIDR `json:"blacked_out"`

	HostsGroups *HostsGroups `json:"host_groups"`

	Revison int `json:"revision"`

	ipam *IPAM
}

func newNetwork(name string, cidr *CIDR, blockMask uint) *Network {
	network := &Network{
		CIDR:      cidr,
		Name:      name,
		BlockMask: blockMask,
	}
	network.BlackedOut = make([]*CIDR, 0)
	return network
}

// deallocateIP attempts to deallocate an IP from the network. If the block
// an IP is deallocated from is empty, it is returned to an empty pool.
func (network *Network) deallocateIP(ip net.IP) error {
	hosts := network.HostsGroups.listHosts()
	for _, host := range hosts {
		if host.CIDR.IPNet.Contains(ip) {
			err := host.deallocateIP(ip)
			if err == nil {
				network.Revison += 1
			}
			return err
		}
	}
	// This is unlikely to happen...
	return common.NewError("Cannot find IP %s", ip)
}

// allocateIP attempts to allocate an IP from one of the existing blocks for the tenant; and
// if not, reuse a block that belongs to no tenant. Finally, it will try to allocate a
// new block.
func (network *Network) allocateIP(hostName string, tenant string, segment string) net.IP {
	host := network.HostsGroups.findHostByName(hostName)
	if host == nil {
		log.Errorf("Host %s not found on network %s", hostName, network.Name)
		return nil
	}
	ip := host.allocateIP(network, tenant, segment)
	if ip == nil {
		return nil
	} else {
		network.Revison += 1
		return ip
	}
}

// blackedOutBy returns the CIDR that blacks out this IP,
// nil if IP is not blocked.
func (network *Network) blackedOutBy(ip net.IP) *CIDR {
	for _, cidr := range network.BlackedOut {
		if cidr.IPNet.Contains(ip) {
			return cidr
		}
	}
	return nil
}

type IPAM struct {
	Networks map[string]*Network `json:"networks"`
	Revision int
	// Map of endpoint ID to IP
	AddressNameToIP map[string]net.IP `json:"address_name_to_ip"`
	save            Saver
	locker          sync.Locker
}

// Saver defines a function that can save the state of the BlockIPAM
// to a persistent store. Saver is allowed to assume the BlockIPAM
// can be successfully marshaled to JSON.
type Saver func(ipam *IPAM) error

// ParseIPAM restores IPAM from JSON.
func ParseIPAM(j string, saver Saver, locker sync.Locker) (*IPAM, error) {
	ipam := &IPAM{}
	err := json.Unmarshal([]byte(j), ipam)
	if err != nil {
		return nil, err
	}
	ipam.save = saver
	if locker == nil {
		ipam.locker = &sync.Mutex{}
	} else {
		ipam.locker = locker
	}

	for _, network := range ipam.Networks {
		network.ipam = ipam
		ipam.setIPAMForHostGroups(network.HostsGroups)
	}

	return ipam, nil
}

func (ipam *IPAM) setIPAMForHostGroups(hg *HostsGroups) {
	for _, host := range hg.Hosts {
		host.ipam = ipam
		for _, block := range host.Blocks {
			block.ipam = ipam
		}
	}
	for _, group := range hg.Groups {
		ipam.setIPAMForHostGroups(group)
	}
}

// NewIPAM creates a new IPAM object. If locker is not provided,
// sync.Mutex is used. If an HA deployment is expected, then the locker
// based on some external resource, e.g., a DB, should be provided.
func NewIPAM(saver Saver, locker sync.Locker) (*IPAM, error) {
	ipam := &IPAM{}
	//	ipam.TenantToNetwork = make(map[string][]int)
	ipam.Networks = make(map[string]*Network)
	ipam.AddressNameToIP = make(map[string]net.IP)

	if locker == nil {
		ipam.locker = &sync.Mutex{}
	} else {
		ipam.locker = locker
	}

	ipam.save = saver
	err := ipam.save(ipam)
	if err != nil {
		return nil, err
	}
	return ipam, nil
}

// AllocateIP allocates an IP for the provided tenant and segment.
// It will first attempt to allocate an IP from an existing block,
// and if all are exhausted, will try to allocate a new block for
// this tenant/segment pair. Will return nil as IP if the entire
// network is exhausted.
func (ipam *IPAM) AllocateIP(addressName string, host string, tenant string, segment string) (net.IP, error) {
	ipam.locker.Lock()
	defer ipam.locker.Unlock()

	//	networks, err := ipam.getNetworksForTenant(tenant)
	//	if err != nil {
	//		return nil, err
	//	}
	for _, network := range ipam.Networks {
		ip := network.allocateIP(host, tenant, segment)
		if ip != nil {
			ipam.AddressNameToIP[addressName] = ip
			err = ipam.save(ipam)
			if err != nil {
				return nil, err
			}
			return ip, nil
		}
	}
	return nil, errors.New(msgNoAvailableIP)
}

// DeallocateIP will deallocate the provided IP (returning an
// error if it never was allocated in the first place).
func (ipam *IPAM) DeallocateIP(addressName string) error {

	ipam.locker.Lock()
	defer ipam.locker.Unlock()

	log.Tracef(trace.Private, "Request to deallocate %s", addressName)
	if ip, ok := ipam.AddressNameToIP[addressName]; ok {
		for _, network := range ipam.Networks {
			if network.CIDR.IPNet.Contains(ip) {
				return network.deallocateIP(ip)
			}
		}
		return common.NewError404("IP", ip.String())
	}
	return common.NewError404("addressName", addressName)
}

func (ipam *IPAM) updateTopology(req api.TopologyUpdateRequest) error {
	// TODO
	if len(ipam.Networks) > 0 {
		return errors.New("Updating topology after it has been initally set up currently not implemented.")
	}
	for _, netDef := range req.Networks {
		if _, ok := ipam.Networks[netDef.Name]; ok {
			return common.NewError("Network with name %s already defined", netDef.Name)
		}
		netDefCIDR, err := NewCIDR(netDef.CIDR)
		if err != nil {
			return err
		}
		//		for _, network := range ipam.Networks {
		//			if network.CIDR.Contains(netDefCIDR) {
		//				return common.NewError("CIDR %s already is contained in CIDR %s of network %s", netDefCIDR, network.CIDR, network.Name)
		//			}
		//			if netDefCIDR.Contains(network.CIDR) {
		//				return common.NewError("CIDR %s  contains already existing CIDR %s of network %s", netDefCIDR, network.CIDR, network.Name)
		//			}
		//		}
		network := newNetwork(netDef.Name, netDefCIDR, netDef.BlockMask)
		ipam.Networks[netDef.Name] = network
	}

	for _, topoDef := range req.Topologies {
		for _, netName := range topoDef.Networks {
			if network, ok := ipam.Networks[netName]; ok {
				hg := &HostsGroups{}
				err := hg.parse(topoDef.Map, network.CIDR)
				if err != nil {
					return err
				}
				network.HostsGroups = hg
			} else {
				return common.NewError("Network with name %s not defined", netName)
			}
		}
	}
	return nil
}

// BlackOut removes a CIDR from consideration. It is an error if CIDR
// is within any of the exising allocated blocks. Fragmentation may
// result if CIDRs smaller than ipam. Blocks are blacked out and then
// un-blacked out.
func (ipam *IPAM) BlackOut(cidrStr string) error {
	ipam.locker.Lock()
	defer ipam.locker.Unlock()
	log.Tracef(trace.Private, "Black out request for %s", cidrStr)
	cidr, err := NewCIDR(cidrStr)
	if err != nil {
		return err
	}
	var network *Network
	found := false
	for _, network = range ipam.Networks {
		if network.CIDR.Contains(cidr) {
			// We found the network...
			found = true
			break
		}
	}
	if !found {
		return common.NewError("No network found for %s", cidrStr)
	}
	// Do a bit of a sanity check
	if cidr.Contains(network.CIDR) {
		return common.NewError("Cannot black out the entire network (%s vs %s)", cidr, network.CIDR)
	}

	for i, blackedOut := range network.BlackedOut {
		if blackedOut.Contains(cidr) {
			// We already have a bigger CIDR in the list. Do nothing.
			log.Tracef(trace.Private, "Already have a CIDR equivalent or bigger to requested %s: %s", cidr, blackedOut)
			return nil
		}
		if cidr.Contains(blackedOut) {
			// Replace existing one with this one as it is bigger. But first check
			// if it has allocated IPs.
			hosts := network.HostsGroups.listHosts()
			for _, host := range hosts {
				for _, block := range host.Blocks {
					if block.hasIPInCIDR(*cidr) {
						return errors.New("Blackout block contains already allocated IPs.")
					}
				}
			}
			network.BlackedOut[i] = cidr
			err := ipam.save(ipam)
			if err != nil {
				return err
			}
			log.Tracef(trace.Private, "Blacked out %s; current list of blacked out CIDRs for %s: %s", cidr, network.CIDR, network.BlackedOut)
			return nil
		}
	}

	network.BlackedOut = append(network.BlackedOut, cidr)
	err = ipam.save(ipam)
	if err != nil {
		return err
	}
	log.Tracef(trace.Private, "Blacked out %s; current list of blacked out CIDRs for %s: %s", cidr, network.CIDR, network.BlackedOut)
	return nil
}

// UnBlackOut adds CIDR backs into the pool for consideration.
func (ipam *IPAM) UnBlackOut(cidrStr string) error {
	// TODO it is possible for this to leave fragmentation - if a block was previously
	// completely blacked out.
	// To defragment - defragment the list of allocated IPs in every block.
	ipam.locker.Lock()
	defer ipam.locker.Unlock()

	cidr, err := NewCIDR(cidrStr)
	if err != nil {
		return err
	}
	var network *Network
	found := false
	for _, network = range ipam.Networks {
		if network.CIDR.Contains(cidr) {
			// We found the network...
			found = true
			break
		}
	}
	if !found {
		return common.NewError("No network found for %s", cidrStr)
	}

	var i int
	var blackedOut *CIDR
	found = false
	for i, blackedOut = range network.BlackedOut {
		if blackedOut.String() == cidr.String() {
			found = true
			break
		}
	}
	if !found {
		return common.NewError("No such CIDR %s found in the blackout list: %s ", cidrStr, network.BlackedOut)
	}
	network.BlackedOut = append(network.BlackedOut[:i], network.BlackedOut[i+1:]...)
	return ipam.save(ipam)
}

// getNetworksForTenant gets all available networks for the
// specified tenant, with networks specfically allowed for the
// tenant by its ID first, followed by wildcard networks.
//func (ipam *IPAM) getNetworksForTenant(tenant string) ([]*Network, error) {
//	// We want to prioritize the networks on which this tenant
//	// is allowed explicitly and only after go to the available to all.
//	networks := make([]*Network, 0)
//	tenantNetworkIDs := ipam.TenantToNetwork[tenant]
//	if tenantNetworkIDs != nil && len(tenantNetworkIDs) > 0 {
//		for _, id := range tenantNetworkIDs {
//			networks = append(networks, ipam.Networks[id])
//		}
//	}
//	wildcardNetworkIDs := ipam.TenantToNetwork["*"]
//	if wildcardNetworkIDs != nil && len(wildcardNetworkIDs) > 0 {
//		for _, id := range wildcardNetworkIDs {
//			networks = append(networks, ipam.Networks[id])
//		}
//	}
//	if len(networks) == 0 {
//		return nil, common.NewError("No networks found for tenant %s.", tenant)
//	}
//	return networks, nil
//}
