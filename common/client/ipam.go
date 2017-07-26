// Copyright (c) 2016-2017 Pani Networks
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

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client/idring"
	"github.com/romana/core/common/log/trace"

	log "github.com/romana/rlog"
)

// This provides an implementation of an IPAM that can allocate
// blocks of IPs for tenant/segment pair. It assumes IPv4.
//
// Address blocks may be taken outÂ of more than one pre-configured
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

func initCIDR(s string, cidr *CIDR) error {
	ip, ipNet, err := net.ParseCIDR(s)
	log.Tracef(trace.Inside, "In initCIDR(\"%s\") got %s, %s, %v", s, ip, ipNet, err)
	if err != nil {
		return err
	}
	cidr.IPNet = ipNet
	if ip != nil {
		cidr.StartIP = ip
		cidr.StartIPInt = common.IPv4ToInt(ip)
		ones, bits := ipNet.Mask.Size()
		ipCount := 1 << uint(bits-ones)
		cidr.EndIPInt = cidr.StartIPInt + uint64(ipCount) - 1
		cidr.EndIP = common.IntToIPv4(cidr.EndIPInt)
	}
	return nil
}

// NewCIDR creates a CIDR object from a string.
func NewCIDR(s string) (CIDR, error) {
	cidr := &CIDR{}
	err := initCIDR(s, cidr)
	return *cidr, err
}

// Contains returns true if this CIDR fully contains (is equivalent to or a superset
// of) the provided CIDR.
func (c CIDR) Contains(c2 CIDR) bool {
	log.Tracef(trace.Private, "%d<=%d && %d>=%d: %t", c.StartIPInt,
		c2.StartIPInt, c.EndIPInt,
		c2.EndIPInt,
		(c.StartIPInt <= c2.StartIPInt && c.EndIPInt >= c2.EndIPInt))
	return c.StartIPInt <= c2.StartIPInt && c.EndIPInt >= c2.EndIPInt
}

func (c CIDR) DebugString() string {
	if c.IPNet == nil {
		return ""
	}
	return c.IPNet.String() + " (" + (c.StartIP.String()) + "-" + string(c.EndIP.String()) + ")"
}

func (c CIDR) String() string {
	if c.IPNet == nil {
		return ""
	}
	return c.IPNet.String()
}

func (c CIDR) MarshalText() ([]byte, error) {
	if c.IPNet == nil {
		return nil, nil
	}
	return []byte(c.IPNet.String()), nil
}

func (cidr *CIDR) UnmarshalText(data []byte) error {
	s := string(data)
	err := initCIDR(s, cidr)
	if err != nil && s != "" {
		log.Tracef(trace.Inside, "Unmarshaling CIDR from \"%s\": %v", s, err)
		return err
	}
	return nil
}

// Host represents a host in Romana topology.
type Host struct {
	IP        net.IP `json:"ip"`
	Name      string `json:"name"`
	AgentPort int    `json:"agent_port"`
	group     *HostsGroups
}

func (h Host) String() string {
	return h.IP.String()
}

// HostsGroups holds either a list of hosts at a given level; it cannot
// be a mix. In other words, the invariant is:
//   - Either Hosts or Groups field is nil
type HostsGroups struct {
	Routing string         `json:"routing"`
	Hosts   []*Host        `json:"hosts"`
	Groups  []*HostsGroups `json:"groups"`
	// CIDR which is to be subdivided among hosts or sub-groups of this group.
	CIDR CIDR `json:"cidr"`

	BlockToOwner  map[int]string   `json:"block_to_owner"`
	OwnerToBlocks map[string][]int `json:"owner_to_block"`

	BlockToHost map[int]string `json:"block_to_host"`

	Blocks         []*Block `json:"blocks"`
	ReusableBlocks []int    `json:"reusable_blocks"`

	network *Network
}

func (hg *HostsGroups) String() string {
	s := ""
	if hg.Hosts != nil {
		return fmt.Sprintf("Hosts: %s; CIDR: %v", hg.Hosts, hg.CIDR)
	} else {
		for _, group := range hg.Groups {
			if len(s) > 0 {
				s += ", "
			}
			s += group.String()
		}
		cidrStr := ""
		s = fmt.Sprintf("[%s]; CIDR: %s, Blocks: %s", s, cidrStr, hg.Blocks)
		return s
	}
}

// AddHost adds hosts to this group. If the group contains
// other groups, it is an error.
func (hg *HostsGroups) AddHost(host api.Host) error {
	// TODO this should be happening in IPAM, not here (locking and saving, below)
	// but we only expose this method for now
	hg.network.ipam.locker.Lock()
	defer hg.network.ipam.locker.Unlock()

	if hg.Hosts == nil {
		return errors.New("Cannot add host to this group, group contains only other groups.")
	}

	if host.IP == nil {
		return common.NewError("Host IP is required.")
	}
	if host.Name == "" {
		return common.NewError("Host name is required.")
	}
	if hg.findHostByName(host.Name) != nil {
		return common.NewError("Host with name %s already exists.", host.Name)
	}
	if host.IP != nil && hg.findHostByIP(host.IP.String()) != nil {
		return common.NewError("Host with IP %s already exists in this host group", host.IP)
	}

	newHost := &Host{IP: host.IP, Name: host.Name, AgentPort: host.AgentPort, group: hg}
	hg.Hosts = append(hg.Hosts, newHost)
	hg.network.ipam.TopologyRevision++
	//TODO move this to IPAM
	return hg.network.ipam.save(hg.network.ipam)
}

func (hg *HostsGroups) allocateIP(network *Network, hostName string, owner string) net.IP {
	ownedBlockIDs := hg.OwnerToBlocks[owner]
	var ip net.IP
	if len(ownedBlockIDs) > 0 {
		for _, blockID := range ownedBlockIDs {
			block := hg.Blocks[blockID]
			hostForCurBlock := hg.BlockToHost[blockID]
			log.Tracef(trace.Inside, "Host for block %d: %s", blockID, hostForCurBlock)
			if hostName == hostForCurBlock {
				ip = block.allocateIP(network)
				if ip != nil {
					return ip
				}
			}
		}
		log.Tracef(trace.Inside, "All blocks on network %s for owner %s and host %s are exhausted, will try to reuse a block", network.Name, owner, hostName)
	} else {
		log.Tracef(trace.Inside, "Network %s has no blocks for owner %s, will try to reuse a block", network.Name, owner)
	}
	// If we are here then all blocks are exhausted. Need to allocate a new block.
	// First let's see if there are blocks on this host to be reused.
	for _, blockID := range hg.ReusableBlocks {
		block := hg.Blocks[blockID]
		ip = block.allocateIP(network)
		if ip != nil {
			// We can now remove this block from reusables.
			log.Tracef(trace.Inside, "Reusing block %d for owner %s", blockID, owner)
			hg.ReusableBlocks = append(hg.ReusableBlocks[:blockID], hg.ReusableBlocks[blockID+1:]...)
			hg.OwnerToBlocks[owner] = append(hg.OwnerToBlocks[owner], blockID)
			hg.BlockToOwner[blockID] = owner
			hg.BlockToHost[blockID] = hostName
			return ip
		}
	}
	log.Tracef(trace.Inside, "Network %s has no blocks to reuse for %s, creating new block", network.Name, owner)

	for {
		var newBlockStartIPInt uint64
		if len(hg.Blocks) > 0 {
			lastBlock := hg.Blocks[len(hg.Blocks)-1]
			newBlockStartIPInt = lastBlock.CIDR.EndIPInt + 1
		} else {
			newBlockStartIPInt = hg.CIDR.StartIPInt
		}
		if newBlockStartIPInt > hg.CIDR.EndIPInt {
			// Cannot allocate any more blocks for this network, move on to another.
			log.Tracef(trace.Inside, "Cannot allocate any more blocks from network %s", hg.CIDR)
			return nil
		}

		newBlockEndIPInt := newBlockStartIPInt + (1 << (32 - network.BlockMask)) - 1
		if newBlockEndIPInt > network.CIDR.EndIPInt {
			// Cannot allocate any more blocks for this network, move on to another.
			// TODO: Or should we allocate as much as possible?
			log.Tracef(trace.Inside, "Cannot allocate any more blocks from network %s", hg.CIDR)
			return nil
		}

		newBlockCIDRStr := fmt.Sprintf("%s/%d", common.IntToIPv4(newBlockStartIPInt), network.BlockMask)
		newBlockCIDR, err := NewCIDR(newBlockCIDRStr)
		if err != nil {
			// This should not really happen...
			log.Errorf("Error occurred allocating IP for %s in network %s: %s", owner, hg.CIDR, err)
			return nil
		}
		newBlock := newBlock(newBlockCIDR)
		hg.Blocks = append(hg.Blocks, newBlock)
		newBlockID := len(hg.Blocks) - 1
		hg.OwnerToBlocks[owner] = append(hg.OwnerToBlocks[owner], newBlockID)
		hg.BlockToOwner[newBlockID] = owner
		hg.BlockToHost[newBlockID] = hostName
		log.Tracef(trace.Inside, "New block created in %s for owner %s and host %s: %s", hg.CIDR, owner, hostName, newBlockCIDR)
		ip := newBlock.allocateIP(network)
		if ip == nil {
			// This could happen if this is a new block but happens to be completely
			// blacked out. Try allocating another.
			log.Tracef(trace.Inside, "Cannot allocate any IPs from block %s", newBlock.CIDR)
			continue
		}
		return ip
	}
}

func (hg *HostsGroups) deallocateIP(ip net.IP) error {
	if hg.Hosts != nil {
		// This is the right group
		for blockID, block := range hg.Blocks {
			if block.CIDR.IPNet.Contains(ip) {
				log.Tracef(trace.Private, "HostsGroups.deallocateIP: IP to deallocate %s belongs to block %s", ip, block.CIDR)
				err := block.deallocateIP(ip)
				if err != nil {
					return err
				}
				if block.isEmpty() {
					owner := hg.BlockToOwner[blockID]
					log.Tracef(trace.Private, "Block %d for tenant %s is empty, reclaiming it for reuse", blockID, owner)
					hg.ReusableBlocks = append(hg.ReusableBlocks, blockID)
					ownerBlocks := hg.OwnerToBlocks[owner]
					hg.OwnerToBlocks[owner] = append(ownerBlocks[:blockID], ownerBlocks[blockID+1:]...)
					delete(hg.BlockToHost, blockID)
				}
				return nil
			}
		}
	} else {
		for _, group := range hg.Groups {
			if group.CIDR.IPNet.Contains(ip) {
				return group.deallocateIP(ip)
			}
		}
	}
	// This is unlikely to happen...
	return common.NewError("Cannot find IP %s", ip)
}

// See ipam.injectParents.
func (hg *HostsGroups) injectParents(network *Network) {
	hg.network = network
	for i, _ := range hg.Hosts {
		hg.Hosts[i].group = hg
	}
	for i, _ := range hg.Groups {
		hg.Groups[i].injectParents(network)
	}

}

// listHosts lists all hosts in this group.
func (hg *HostsGroups) ListHosts() []*Host {
	list := hg.Hosts
	for _, group := range hg.Groups {
		list2 := group.ListHosts()
		list = append(list, list2...)
	}
	return list
}

func (hg *HostsGroups) ListBlocks() []*Block {
	blocks := make([]*Block, 0)
	if hg.Blocks != nil {
		blocks = append(blocks, hg.Blocks...)
	}
	for _, group := range hg.Groups {
		blocks2 := group.ListBlocks()
		if blocks2 != nil {
			blocks = append(blocks, blocks2...)
		}
	}
	return blocks
}

// GetBlocks returns list of blocks for the provided group
// including extra information about a block (host, tenant/segment, etc.)
// - corresponding to api.IPAMBlockResponse.
func (hg *HostsGroups) GetBlocks() []api.IPAMBlockResponse {
	retval := make([]api.IPAMBlockResponse, 0)
	if hg.Blocks != nil {
		for blockID, block := range hg.Blocks {
			owner := hg.BlockToOwner[blockID]
			tenant, segment := parseOwner(owner)
			br := api.IPAMBlockResponse{
				CIDR:     api.IPNet{IPNet: *block.CIDR.IPNet},
				Host:     hg.BlockToHost[blockID],
				Revision: block.Revision,
				Tenant:   tenant,
				Segment:  segment,
			}
			retval = append(retval, br)
		}
	}
	for _, group := range hg.Groups {
		br := group.GetBlocks()
		retval = append(retval, br...)
	}
	return retval
}

func (hg *HostsGroups) findHostByIP(ip string) *Host {
	for _, h := range hg.Hosts {
		if h.IP.String() == ip {
			return h
		}
	}
	for _, group := range hg.Groups {
		return group.findHostByIP(ip)
	}
	return nil
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

// parseMap parses the Map part of the GroupSpec, that may contain
// groups or hosts.
func (hg *HostsGroups) parseMap(groupSpecs []api.GroupSpec, cidr CIDR, network *Network) error {

	// Figure out  what would be the size per
	// element.
	ones, bits := cidr.Mask.Size()
	free := bits - ones
	if len(groupSpecs) == 0 {
		// Just do nothing for now...
		return nil
	}

	if len(groupSpecs) == 1 {
		hg.Routing = groupSpecs[0].Routing
		return hg.parse(groupSpecs[0].Groups, cidr, network)

	}
	hg.Groups = make([]*HostsGroups, len(groupSpecs))

	// Pad the array to the next power of 2
	rem := free % len(groupSpecs)
	if rem != 0 {
		// Let's allocate a few more empty slots to complete the power of 2
		remArr := make([]api.GroupSpec, rem)
		groupSpecs = append(groupSpecs, remArr...)
	}
	bitsPerElement := free / len(groupSpecs)

	for i, elt := range groupSpecs {
		// Calculate CIDR for the current group
		incr := uint64(i << uint(bitsPerElement))
		elementCIDRIP := common.IntToIPv4(cidr.StartIPInt + incr)
		elementCIDRString := fmt.Sprintf("%s/%d", elementCIDRIP, (32 - bitsPerElement))
		log.Tracef(trace.Inside, "CIDR String for %s %d: %s", elementCIDRIP, bitsPerElement, elementCIDRString)
		elementCIDR, err := NewCIDR(elementCIDRString)
		if err != nil {
			return err
		}

		hg.Groups[i] = &HostsGroups{network: network, Routing: elt.Routing}
		err = hg.Groups[i].parse(elt.Groups, elementCIDR, network)
		if err != nil {
			return err
		}
	}
	return nil
}

// parse parses
func (hg *HostsGroups) parse(arr []interface{}, cidr CIDR, network *Network) error {

	if hg.BlockToOwner == nil {
		hg.BlockToOwner = make(map[int]string)
	}
	if hg.BlockToHost == nil {
		hg.BlockToHost = make(map[int]string)
	}

	if hg.OwnerToBlocks == nil {
		hg.OwnerToBlocks = make(map[string][]int)
	}
	if hg.Blocks == nil {
		hg.Blocks = make([]*Block, 0)
	}
	if hg.ReusableBlocks == nil {
		hg.ReusableBlocks = make([]int, 0)
	}

	// Figure out in the given array, what would be the size per
	// element.
	ones, bits := cidr.Mask.Size()
	free := bits - ones
	if len(arr) == 0 {
		// Just do nothing for now...
		return nil
	}

	// First we see what kind of elements we have here - groups or hosts
	eltVal := reflect.ValueOf(arr[0])
	eltValKind := eltVal.Kind()

	if eltValKind != reflect.Slice && eltValKind != reflect.Map {
		return errors.New(fmt.Sprintf("Unknown type %s: %v", eltVal.Kind(), eltVal.Interface()))
	}
	// Just started parsing this entity.
	if eltValKind == reflect.Map {
		hg.Hosts = make([]*Host, len(arr))
		hg.CIDR = cidr
		hg.BlockToOwner = make(map[int]string)
		hg.Blocks = make([]*Block, 0)
		hg.OwnerToBlocks = make(map[string][]int)
		hg.ReusableBlocks = make([]int, 0)
	} else {
		hg.Groups = make([]*HostsGroups, len(arr))

		// Pad the array to the next power of 2
		rem := free % len(arr)
		if rem != 0 {
			// Let's allocate a few more empty slots to complete the power of 2
			remArr := make([]interface{}, rem)
			arr = append(arr, remArr...)
		}
	}

	bitsPerElement := free / len(arr)
	for i, elt := range arr {
		if i > 0 {
			// Sanity check - whether element types are mixed here. It would be an error
			// if they are.
			eltVal = reflect.ValueOf(elt)
			curKind := eltVal.Kind()
			if eltValKind != curKind {
				return common.NewError("Mixed types")
			}
		}
		if eltValKind == reflect.Map {
			// This is host, we inherit the CIDR
			hostData := elt.(map[string]interface{})
			if hostData["ip"] == nil || hostData["name"] == nil {
				return common.NewError("Both name and IP are required for hosts: %v", hostData)
			}
			host := &Host{Name: hostData["name"].(string)}
			ipStr := hostData["ip"].(string)
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return common.NewError("Cannot parse IP: %s", ipStr)
			}
			host.IP = ip
			host.group = hg
			hg.Hosts[i] = host
		} else {
			// Calculate CIDR for the current group
			incr := uint64(i << uint(bitsPerElement))
			elementCIDRIP := common.IntToIPv4(cidr.StartIPInt + incr)
			elementCIDRString := fmt.Sprintf("%s/%d", elementCIDRIP, (32 - bitsPerElement))
			elementCIDR, err := NewCIDR(elementCIDRString)
			if err != nil {
				return err
			}

			hg.Groups[i] = &HostsGroups{network: network}
			newArr := elt.([]interface{})
			err = hg.Groups[i].parse(newArr, elementCIDR, network)
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
	CIDR     CIDR           `json:"cidr"`
	Pool     *idring.IDRing `json:"pool"`
	Revision int            `json:"revision"`
}

func (b Block) String() string {
	return fmt.Sprintf("Block %s (rev. %d): %s", b.CIDR, b.Revision, b.Pool)
}

// newBlock creates a new Block on the given host.
func newBlock(cidr CIDR) *Block {
	eb := &Block{CIDR: cidr,
		Pool: idring.NewIDRing(cidr.StartIPInt, cidr.EndIPInt, nil),
	}
	return eb
}

func (b Block) ListAddresses() []string {
	retval := make([]string, 0)
	for _, r := range b.Pool.Ranges {
		for i := r.Min; i <= r.Max; i++ {
			ip := common.IntToIPv4(i)
			retval = append(retval, ip.String())
		}
	}
	return retval
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
			if blackedOutBy == nil {
				break
			} else {
				log.Tracef(trace.Private, "IP %s is blacked out by %s", ip, blackedOutBy)
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

	b.Revision++
	return ip
}

// deallocateIP deallocates the specified IP within the block.
func (b *Block) deallocateIP(ip net.IP) error {
	log.Tracef(trace.Inside, "Block.deallocateIP: Deallocating IP %s from block %s", ip, b)
	if !b.CIDR.IPNet.Contains(ip) {
		return common.NewError("Block.deallocateIP: IP %s not in this block %s", ip, b.CIDR)
	}
	ipInt := common.IPv4ToInt(ip)
	err := b.Pool.ReclaimID(ipInt)
	if err != nil {
		return err
	}
	b.Revision++
	return nil

}

// Network is the main structure managing allocation of IP addresses in the
// provided CIDR.
type Network struct {
	Name string `json:"name"`

	// CIDR of the network (likely 10/8).
	CIDR CIDR `json:"cidr"`

	// Size of tenant/segment block to allocate, in bits as mask
	// (specify 32 for size 1, e.g.)
	BlockMask uint `json:"block_mask"`

	BlackedOut []CIDR `json:"blacked_out"`

	HostsGroups *HostsGroups `json:"groups"`

	Revison int `json:"revision"`

	ipam *IPAM
}

func newNetwork(name string, cidr CIDR, blockMask uint) *Network {
	network := &Network{
		CIDR:      cidr,
		Name:      name,
		BlockMask: blockMask,
	}
	network.BlackedOut = make([]CIDR, 0)
	return network
}

// deallocateIP attempts to deallocate an IP from the network. If the block
// an IP is deallocated from is empty, it is returned to an empty pool.
func (network *Network) deallocateIP(ip net.IP) error {
	err := network.HostsGroups.deallocateIP(ip)
	if err == nil {
		network.Revison++
	}
	return err
}

// allocateIP attempts to allocate an IP from one of the existing blocks for the tenant; and
// if not, reuse a block that belongs to no tenant. Finally, it will try to allocate a
// new block.
func (network *Network) allocateIP(hostName string, owner string) (net.IP, error) {
	host := network.HostsGroups.findHostByName(hostName)
	if host == nil {
		return nil, common.NewError("Host %s not found", hostName)
	}
	ip := host.group.allocateIP(network, hostName, owner)
	if ip == nil {
		return nil, nil
	}
	network.Revison++
	return ip, nil
}

// blackedOutBy returns the CIDR that blacks out this IP,
// nil if IP is not blocked.
func (network *Network) blackedOutBy(ip net.IP) *CIDR {
	for _, cidr := range network.BlackedOut {
		if cidr.IPNet.Contains(ip) {
			return &cidr
		}
	}
	return nil
}

// Saver defines a function that can save the state of the BlockIPAM
// to a persistent store. Saver is allowed to assume the BlockIPAM
// can be successfully marshaled to JSON.
type Saver func(ipam *IPAM) error

// ParseIPAM restores IPAM from JSON as stored in the KV store.
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
	log.Tracef(trace.Inside, "ParseIPAM(): Set locker to %v", ipam.locker)
	ipam.injectParents()
	return ipam, nil
}

type IPAM struct {
	Networks map[string]*Network `json:"networks"`

	// Revision of the state of allocations
	AllocationRevision int
	// Revision of topology information (only changes if hosts are added)
	TopologyRevision int

	// Map of address name to IP
	AddressNameToIP map[string]net.IP `json:"address_name_to_ip"`
	save            Saver
	locker          sync.Locker

	TenantToNetwork map[string][]string `json:"tenant_to_network"`

	//	OwnerToIP map[string][]string
	//	IPToOwner map[string]string
}

// injectParents is intended to add references to parent objects where appropriate
// after parsing the IPAM object from JSON.
func (ipam *IPAM) injectParents() {
	for _, network := range ipam.Networks {
		network.HostsGroups.injectParents(network)
		network.ipam = ipam
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
	ipam.TenantToNetwork = make(map[string][]string)

	//	ipam.OwnerToIP = make(map[string][]string)
	//	ipam.IPToOwner = make(map[string]string)

	if locker == nil {
		ipam.locker = &sync.Mutex{}
	} else {
		ipam.locker = locker
	}
	log.Tracef(trace.Inside, "NewIPAM(): Set locker to %v", ipam.locker)

	ipam.save = saver
	err := ipam.save(ipam)
	if err != nil {
		return nil, err
	}
	return ipam, nil
}

func (ipam *IPAM) ListHosts() api.HostList {
	list := make([]api.Host, 0)
	for _, network := range ipam.Networks {
		for _, host := range network.HostsGroups.ListHosts() {
			list = append(list, api.Host{IP: host.IP, Name: host.Name})
		}
	}
	retval := api.HostList{Hosts: list,
		Revision: ipam.TopologyRevision,
	}
	return retval
}

// GetGroupsForNetwork retrieves HostsGroups for the network
// with the provided name, or nil if not found.
func (ipam *IPAM) GetGroupsForNetwork(netName string) *HostsGroups {
	if network, ok := ipam.Networks[netName]; ok {
		return network.HostsGroups
	} else {
		return nil
	}
}

// AllocateIP allocates an IP for the provided tenant and segment,
// and associates the provided name with it. That name can afterwards
// be used for deallocation.
// It will first attempt to allocate an IP from an existing block,
// and if all are exhausted, will try to allocate a new block for
// this tenant/segment pair. Will return nil as IP if the entire
// network is exhausted.
func (ipam *IPAM) AllocateIP(addressName string, host string, tenant string, segment string) (net.IP, error) {
	ipam.locker.Lock()
	defer ipam.locker.Unlock()

	if addr, ok := ipam.AddressNameToIP[addressName]; ok {
		return nil, common.NewError("Address with name %s already allocated: %s", addressName, addr)
	}

	// Find eligible networks for the specified tenant
	networksForTenant, err := ipam.getNetworksForTenant(tenant)
	if err != nil {
		return nil, err
	}

	owner := makeOwner(tenant, segment)
	for _, network := range networksForTenant {
		ip, err := network.allocateIP(host, owner)

		if err != nil {
			return nil, err
		}
		if ip != nil {
			ipam.AddressNameToIP[addressName] = ip

			//			ipam.OwnerToIP[owner] = append(ipam.OwnerToIP[owner], ip)
			//			ipam.IPToOwner[ip] = owner

			err = ipam.save(ipam)
			if err != nil {
				return nil, err
			}
			ipam.AllocationRevision++
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

	if ip, ok := ipam.AddressNameToIP[addressName]; ok {
		log.Tracef(trace.Inside, "IPAM.DeallocateIP: Request to deallocate %s: %s", addressName, ip)
		for _, network := range ipam.Networks {
			if network.CIDR.IPNet.Contains(ip) {
				log.Tracef(trace.Inside, "IPAM.DeallocateIP: IP %s belongs to network %s", ip, network.Name)
				err := network.deallocateIP(ip)
				if err == nil {
					ipam.AllocationRevision++
				}
				return err
			}
		}
		return common.NewError404("IP", ip.String())
	}
	return common.NewError404("addressName", addressName)
}

// getNetworksForTenant gets all eligible networks for the
// specified tenant, with networks specfically allowed for the
// tenant by its ID first, followed by wildcard networks (that is,
// those for whom all tenants are allowed). If none found, an error
// is returned.
func (ipam *IPAM) getNetworksForTenant(tenant string) ([]*Network, error) {
	// We want to prioritize the networks on which this tenant
	// is allowed explicitly and only after go to the available to all.
	networks := make([]*Network, 0)
	tenantNetworkIDs := ipam.TenantToNetwork[tenant]
	if tenantNetworkIDs != nil && len(tenantNetworkIDs) > 0 {
		for _, id := range tenantNetworkIDs {
			networks = append(networks, ipam.Networks[id])
		}
	}
	wildcardNetworkIDs := ipam.TenantToNetwork["*"]
	if wildcardNetworkIDs != nil && len(wildcardNetworkIDs) > 0 {
		for _, id := range wildcardNetworkIDs {
			networks = append(networks, ipam.Networks[id])
		}
	}
	if len(networks) == 0 {
		return nil, common.NewError("No networks found for tenant %s.", tenant)
	}

	log.Tracef(trace.Inside, "Eligible networks for tenant %s: %v", tenant, networks)
	return networks, nil
}

// updateTopology updates the entire topology, returning an error if it is
// in conflict with the previous topology.
func (ipam *IPAM) UpdateTopology(req api.TopologyUpdateRequest) error {
	// TODO
	ipam.locker.Lock()
	defer ipam.locker.Unlock()

	if len(ipam.Networks) > 0 {
		return errors.New("Updating topology after it has been initally set up currently not implemented.")
	}
	for _, netDef := range req.Networks {
		if _, ok := ipam.Networks[netDef.Name]; ok {
			return common.NewError("Network with name %s already defined", netDef.Name)
		}
		if netDef.BlockMask == 0 {
			return common.NewError("Block mask %d (or unspecified) for %s is invalid, must be > 8", netDef.BlockMask, netDef.Name)
		}
		if netDef.BlockMask <= 8 {
			return common.NewError("Block mask %d for %s is invalid, must be > 8", netDef.BlockMask, netDef.Name)
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
		//

		// If empty, all tenants are allowed.
		if netDef.Tenants == nil || len(netDef.Tenants) == 0 {
			if networksForTenant, ok := ipam.TenantToNetwork["*"]; ok {
				ipam.TenantToNetwork["*"] = append(networksForTenant, netDef.Name)
			} else {
				ipam.TenantToNetwork["*"] = []string{netDef.Name}
			}
		} else {
			for _, tenantName := range netDef.Tenants {
				if !tenantNameRegexp.MatchString(tenantName) {
					return common.NewError("Bad tenant name: %s", tenantName)
				}
				if _, ok := ipam.TenantToNetwork[tenantName]; !ok {
					ipam.TenantToNetwork[tenantName] = make([]string, 0)
				}
				ipam.TenantToNetwork[tenantName] = append(ipam.TenantToNetwork[tenantName], netDef.Name)
			}
		}
		network := newNetwork(netDef.Name, netDefCIDR, netDef.BlockMask)
		network.ipam = ipam
		ipam.Networks[netDef.Name] = network
	}
	log.Tracef(trace.Inside, "Tenants to network mapping: %v", ipam.TenantToNetwork)
	for _, topoDef := range req.Topologies {
		for _, netName := range topoDef.Networks {
			if network, ok := ipam.Networks[netName]; ok {
				hg := &HostsGroups{}
				err := hg.parseMap(topoDef.Map, network.CIDR, network)
				if err != nil {
					return err
				}
				network.HostsGroups = hg
				hg.network = network
				log.Tracef(trace.Inside, "Parsed topology for network %s: %s", netName, network.HostsGroups)
			} else {
				return common.NewError("Network with name %s not defined", netName)
			}
		}
	}
	ipam.TopologyRevision++
	err = ipam.save(ipam)
	if err != nil {
		return err
	}
	return nil
}

func (ipam *IPAM) ListAllBlocks() *api.IPAMBlocksResponse {
	blocks := make([]api.IPAMBlockResponse, 0)
	for _, network := range ipam.Networks {
		netBlocks := network.HostsGroups.GetBlocks()
		blocks = append(blocks, netBlocks...)
	}
	return &api.IPAMBlocksResponse{
		Revision: ipam.AllocationRevision,
		Blocks:   blocks,
	}
}

func (ipam *IPAM) ListNetworkBlocks(netName string) *api.IPAMBlocksResponse {
	if network, ok := ipam.Networks[netName]; ok {
		resp := &api.IPAMBlocksResponse{
			Revision: network.Revison,
			Blocks:   network.HostsGroups.GetBlocks(),
		}
		return resp
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
	log.Tracef(trace.Private, "BlackOut: Black out request for %s", cidrStr)
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
		log.Tracef(trace.Inside, "BlackOut: Checking if %s contains %s in network %s", blackedOut, cidr, network.Name)
		if blackedOut.Contains(cidr) {
			// We already have a bigger CIDR in the list. Do nothing.
			log.Tracef(trace.Private, "Already have a CIDR equivalent or bigger to requested %s: %s", cidr, blackedOut)
			return nil
		}
		log.Tracef(trace.Inside, "BlackOut: Checking if %s contains %s in network %s", cidr, blackedOut, network.Name)
		if cidr.Contains(blackedOut) {
			// Replace existing one with this one as it is bigger. But first check
			// if it has allocated IPs.
			networkBlocks := network.HostsGroups.ListBlocks()
			log.Tracef(trace.Inside, "BlackOut: Checking blocks %v if they have IP in %s", networkBlocks, cidr)
			for _, block := range networkBlocks {
				if block.hasIPInCIDR(cidr) {
					return errors.New("Blackout block contains already allocated IPs.")
				}
			}
			network.BlackedOut[i] = cidr
			network.Revison++
			err := ipam.save(ipam)
			if err != nil {
				return err
			}
			log.Tracef(trace.Private, "Blacked out %s; current list of blacked out CIDRs for %s: %s", cidr, network.CIDR, network.BlackedOut)
			return nil
		}
	}

	// Check if proposed black out cidr contains allocated IPs
	// Replace existing one with this one as it is bigger. But first check
	// if it has allocated IPs.
	networkBlocks := network.HostsGroups.ListBlocks()
	log.Tracef(trace.Inside, "BlackOut: Checking blocks %v if they have IP in %s", networkBlocks, cidr)
	for _, block := range networkBlocks {
		if block.hasIPInCIDR(cidr) {
			return errors.New("Blackout block contains already allocated IPs.")
		}
	}

	network.BlackedOut = append(network.BlackedOut, cidr)
	network.Revison++
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
	var blackedOut CIDR
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
	network.Revison++
	return ipam.save(ipam)
}
