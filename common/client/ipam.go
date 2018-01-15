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
	"fmt"
	"math"
	"math/big"
	"net"
	"reflect"
	"regexp"
	"strings"

	libkvStore "github.com/docker/libkv/store"
	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/api/errors"
	"github.com/romana/core/common/client/idring"
	"github.com/romana/core/common/log/trace"

	"github.com/mohae/deepcopy"

	log "github.com/romana/rlog"
)

// This provides an implementation of an IPAM that can allocate
// blocks of IPs for tenant/segment pair. It assumes IPv4.
//
// Address blocks may be taken out more then one pre-configured
// address range (Networks).

const (
	msgNoAvailableIP = "No available IP."
	DefaultAgentPort = 9604
	DefaultBlockMask = 29
)

var (
	tenantNameRegexp = regexp.MustCompile("^[a-zA-Z0-9_-]*$")
)

func deleteElementInt(arr []int, i int) []int {
	retval := make([]int, i)
	copy(retval, arr[:i])
	retval = append(retval, arr[i+1:]...)
	return retval
}

func deleteElementHost(arr []*Host, i int) []*Host {
	retval := make([]*Host, i)
	copy(retval, arr[:i])
	retval = append(retval, arr[i+1:]...)
	return retval
}

func deleteElementCIDR(arr []CIDR, i int) []CIDR {
	retval := make([]CIDR, i)
	copy(retval, arr[:i])
	retval = append(retval, arr[i+1:]...)
	return retval
}

// makeOwner makes an "owner" string -- which is "<tenant>:<segment>".
func makeOwner(tenant string, segment string) string {
	return fmt.Sprintf("%s:%s", tenant, segment)
}

// parseOwner splits the owner string into tenant and segment.
func parseOwner(owner string) (string, string) {
	tenSeg := strings.SplitN(owner, ":", 2)
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
	//	log.Tracef(trace.Inside, "In initCIDR(\"%s\") got %s, %s, %v", s, ip, ipNet, err)
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

func (c CIDR) ContainsIP(ip net.IP) bool {
	ipInt := common.IPv4ToInt(ip)
	log.Tracef(trace.Private, "%d<=%d && %d>=%d: %t", c.StartIPInt,
		ipInt, c.EndIPInt,
		ipInt,
		(c.StartIPInt <= ipInt && c.EndIPInt >= ipInt))
	return c.StartIPInt <= ipInt && c.EndIPInt >= ipInt
}

func (c CIDR) DebugString() string {
	if c.IPNet == nil {
		return ""
	}
	return c.IPNet.String() + " (" + (c.StartIP.String()) + "-" + c.EndIP.String() + ")"
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
	Name      string                 `json:"name"`
	IP        net.IP                 `json:"ip"`
	AgentPort uint                   `json:"agent_port"`
	Tags      map[string]string      `json:"tags"`
	K8SInfo   map[string]interface{} `json:"k8s_info"`
	group     *Group
}

func (h Host) String() string {
	val := fmt.Sprintf("%s (%s)", h.IP, h.Name)
	if h.Tags != nil && len(h.Tags) > 0 {
		val += fmt.Sprintf(" Tags: %s", h.Tags)
	}
	if h.K8SInfo != nil && len(h.K8SInfo) > 0 {
		val += fmt.Sprintf(" Kubernetes info: %s", h.K8SInfo)
	}
	return val
}

// Group holds either a list of hosts at a given level; it cannot
// be a mix. In other words, the invariant is:
//   - Either Hosts or Groups field is nil
type Group struct {
	Name   string   `json:"name"`
	Hosts  []*Host  `json:"hosts"`
	Groups []*Group `json:"groups"`
	// CIDR which is to be subdivided among hosts or sub-groups of this group.
	CIDR CIDR `json:"cidr"`

	BlockToOwner  map[int]string   `json:"block_to_owner"`
	OwnerToBlocks map[string][]int `json:"owner_to_block"`

	BlockToHost map[int]string `json:"block_to_host"`

	Blocks         []*Block          `json:"blocks"`
	ReusableBlocks []int             `json:"reusable_blocks"`
	Assignment     map[string]string `json:"assignment"`
	Routing        string            `json:"routing"`
	network        *Network

	Dummy bool `json:"dummy"`
}

func (hg *Group) String() string {
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

// isHostEligible checks if the host can be added to this group.
func (hg *Group) isHostEligible(host *Host) bool {
	log.Tracef(trace.Inside, "Checking eligibility of %s in group %s", host, hg.Name)
	if hg.Dummy {
		return false
	}
	// Check assignment
	if hg.Assignment != nil {
		for k, v := range hg.Assignment {
			if host.Tags == nil {
				log.Tracef(trace.Inside, "Group %s has %v requirements, host %s has no tags, skipping", hg.Name, hg.Assignment, host)
				return false
			}
			if host.Tags[k] != v {
				log.Tracef(trace.Inside, "Group %s requires %s=%s, host has %s", hg.Name, k, v, host.Tags[k])
				return false
			}
		}
	}
	return true
}

// findSmallestGroup finds the group with fewest hosts
func (hg *Group) findSmallestEligibleGroup(host *Host) *Group {
	if !hg.isHostEligible(host) {
		log.Tracef(trace.Inside, "Host %s not eligible for group %s", host, hg.Name)
		return nil
	}
	log.Tracef(trace.Inside, "Looking for smallest group in %s", hg.Name)
	if hg.Groups == nil {
		return nil
	}
	var g *Group
	var curSmallest *Group
	minHosts := math.MaxInt32
	for _, g = range hg.Groups {
		ok := g.isHostEligible(host)
		if !ok {
			log.Tracef(trace.Inside, "Host %s not eligible for group %v", host, hg.Name)
			continue
		}
		log.Tracef(trace.Inside, "In %s, considering %s", hg.Name, g.Name)
		if g.Hosts != nil {
			log.Tracef(trace.Inside, "In %s, considering %s with %d hosts (vs current smallest %d)", hg.Name, g.Name, len(g.Hosts), minHosts)
			if minHosts > len(g.Hosts) {
				minHosts = len(g.Hosts)
				curSmallest = g
			}
		} else {
			smallestCandidate := g.findSmallestEligibleGroup(host)
			if smallestCandidate != nil {
				if len(smallestCandidate.Hosts) < minHosts {
					minHosts = len(smallestCandidate.Hosts)
					curSmallest = smallestCandidate
				}
			}
		}
	}
	if curSmallest == nil {
		log.Tracef(trace.Inside, "Could not find eligible group for host %s", host)
		return nil
	}

	log.Tracef(trace.Inside, "Group with fewest hosts has %d hosts", len(curSmallest.Hosts))
	return curSmallest
}

func (hg *Group) addHost(host *Host) (bool, error) {
	log.Tracef(trace.Inside, "Calling addHost(%s) on group %s", host.Name, hg.Name)
	if hg.findHostByName(host.Name) != nil {
		return false, errors.NewRomanaExistsError(*host, "host", fmt.Sprintf("name=%s", host.Name))
	}

	if hg.findHostByIP(host.IP.String()) != nil {
		err := errors.NewRomanaExistsError(*host, "host", fmt.Sprintf("IP=%s", host.IP))
		return false, err
	}

	if host.AgentPort == 0 {
		host.AgentPort = DefaultAgentPort
	}

	if hg.Hosts == nil {
		// Try to add to one of the subgroups.
		smallest := hg.findSmallestEligibleGroup(host)
		if smallest == nil {
			return false, nil
		}
		return smallest.addHost(host)
	}

	if !hg.isHostEligible(host) {
		return false, nil
	}
	hg.Hosts = append(hg.Hosts, host)
	host.group = hg
	log.Infof("Added host %s with tags %s to group %s", host, host.Tags, hg.Name)
	return true, nil
}

// allocateSpecificIP will attempt to allocate specified IP in the given group.
// The algorithm is as follows:
// 1. Go through all blocks owned by owner
// 2. If the IP belongs in any of these blocks, check the host
//    - If the block belongs to a host different than specified, return error
//    - Otherwise allocate the IP in the block
// 3. If not, sequentially allocate a new block for given host and owner
//    - If the IP belongs to this block, allocate it
//    - Otherwise, add the block to reusable list and go to 3
//
// While an alternative may be to calculate the block (if any) to contain the IP,
// going through all possible blocks is not a huge operation, is easy to follow,
// and results in a list of reusable blocks for later reuse. Given that this operation
// is only useful (for now) in case of updating topology -- that is, a relatively rare
// operation -- and that iterating over all blocks is not a hugely expensive proposition,
// it is good enough for now.
func (hg *Group) allocateSpecificIP(ip net.IP, network *Network, hostName string, owner string) error {
	if !hg.CIDR.ContainsIP(ip) {
		return fmt.Errorf("Cannot allocate IP %s in group %s (%s)", ip, hg.Name, hg.CIDR)
	}
	ownedBlockIDs := hg.OwnerToBlocks[owner]
	if len(ownedBlockIDs) > 0 {
		for _, blockID := range ownedBlockIDs {
			block := hg.Blocks[blockID]
			if block.CIDR.ContainsIP(ip) {
				hostForCurBlock := hg.BlockToHost[blockID]
				log.Tracef(trace.Inside, "Host for block %d: %s", blockID, hostForCurBlock)
				if hostName != hostForCurBlock {
					return fmt.Errorf("Cannot allocate IP %s on host %s: block belongs to %s", ip, hostName, hostForCurBlock)
				}
				return block.allocateSpecificIP(ip, network)
			}
		}
		log.Tracef(trace.Inside, "IP %s not found on any block in network %s for owner %s and host %s", ip, network.Name, owner, hostName)
	} else {
		log.Tracef(trace.Inside, "IP %s not found on any block in network %s for owner %s and host %s", ip, network.Name, owner, hostName)
	}
	var err error
	// If we are here then all blocks are exhausted. Need to allocate a new block.
	// First let's see if there are blocks on this group to be reused.
	for blockIdx, blockID := range hg.ReusableBlocks {
		block := hg.Blocks[blockID]
		if block.CIDR.ContainsIP(ip) {
			err = block.allocateSpecificIP(ip, network)
			if err != nil {
				hg.ReusableBlocks = deleteElementInt(hg.ReusableBlocks, blockIdx)
				hg.OwnerToBlocks[owner] = append(hg.OwnerToBlocks[owner], blockID)
				hg.BlockToOwner[blockID] = owner
				hg.BlockToHost[blockID] = hostName
			}
			return err
		}
	}
	log.Tracef(trace.Inside, "Network %s has no blocks to reuse for <%s>, creating new block", network.Name, owner)

	for {
		var newBlockStartIPInt uint64
		if len(hg.Blocks) > 0 {
			lastBlock := hg.Blocks[len(hg.Blocks)-1]
			newBlockStartIPInt = lastBlock.CIDR.EndIPInt + 1
		} else {
			newBlockStartIPInt = hg.CIDR.StartIPInt
		}
		if newBlockStartIPInt > hg.CIDR.EndIPInt {
			return fmt.Errorf("No more blocks can be allocated in %s", network.Name)
		}

		newBlockEndIPInt := newBlockStartIPInt + (1 << (32 - network.BlockMask)) - 1
		if newBlockEndIPInt > network.CIDR.EndIPInt {
			return fmt.Errorf("No more blocks can be allocated in %s", network.Name)
		}

		newBlockCIDRStr := fmt.Sprintf("%s/%d", common.IntToIPv4(newBlockStartIPInt), network.BlockMask)
		newBlockCIDR, err := NewCIDR(newBlockCIDRStr)
		if err != nil {
			return err
		}
		newBlock := newBlock(newBlockCIDR)
		hg.Blocks = append(hg.Blocks, newBlock)
		newBlockID := len(hg.Blocks) - 1
		if newBlock.CIDR.ContainsIP(ip) {
			err = newBlock.allocateSpecificIP(ip, network)
			if err == nil {
				hg.OwnerToBlocks[owner] = append(hg.OwnerToBlocks[owner], newBlockID)
				hg.BlockToOwner[newBlockID] = owner
				hg.BlockToHost[newBlockID] = hostName
			}
			return err
		} else {
			// A newly created block may not yet be the one to contain the
			// IP we wish to allocate. So just add it to the reusable blocks
			// for the group.
			hg.ReusableBlocks = append(hg.ReusableBlocks, newBlockID)
		}
	}
}

func (hg *Group) allocateIP(network *Network, hostName string, owner string) net.IP {
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
		log.Tracef(trace.Inside, "Network %s has no blocks for owner <%s>, will try to reuse a block", network.Name, owner)
	}
	// If we are here then all blocks are exhausted. Need to allocate a new block.
	// First let's see if there are blocks on this group to be reused.
	for blockIdx, blockID := range hg.ReusableBlocks {
		block := hg.Blocks[blockID]
		ip = block.allocateIP(network)
		if ip != nil {
			// We can now remove this block from reusables.
			log.Tracef(trace.Inside, "Reusing block %d for owner %s", blockID, owner)
			hg.ReusableBlocks = deleteElementInt(hg.ReusableBlocks, blockIdx)
			hg.OwnerToBlocks[owner] = append(hg.OwnerToBlocks[owner], blockID)
			hg.BlockToOwner[blockID] = owner
			hg.BlockToHost[blockID] = hostName
			return ip
		}
	}
	log.Tracef(trace.Inside, "Network %s has no blocks to reuse for <%s>, creating new block", network.Name, owner)

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
		log.Tracef(trace.Inside, "Group %s BlockToOwner: %v, BlockToHost: %v", hg.CIDR, hg.BlockToOwner, hg.BlockToHost)
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

func (hg *Group) findIPInfo(ip net.IP) (string, string) {
	log.Tracef(trace.Inside, "group.findIPInfo(): Looking for %s in %s (%s)", ip, hg.Name, hg.CIDR)
	if hg.Hosts != nil {
		log.Tracef(trace.Inside, "group.findIPInfo(): Looking for %s in %d blocks", ip, len(hg.Blocks))
		var block *Block
		var blockID int
		for blockID, block = range hg.Blocks {
			if block.CIDR.IPNet.Contains(ip) {
				log.Tracef(trace.Inside, "group.findIPInfo(): Found %s in %s: %d", ip, block.CIDR, blockID)
				log.Tracef(trace.Inside, "BTW %v %v", hg.BlockToHost[blockID], hg.BlockToOwner[blockID])
				return hg.BlockToHost[blockID], hg.BlockToOwner[blockID]
			}
		}
		return "", ""
	} else {
		for _, group := range hg.Groups {
			if group.CIDR.IPNet.Contains(ip) {
				return group.findIPInfo(ip)
			}
		}
	}
	return "", ""
}

func (hg *Group) deallocateIP(ip net.IP) error {
	if hg.Hosts != nil {
		// This is the right group
		reclaimBlock := false
		var block *Block
		var blockID int
		for blockID, block = range hg.Blocks {
			//			log.Tracef(trace.Inside, "Checking if block %d (%s) contains %s: %v", blockID, block.CIDR, ip, block.CIDR.IPNet.Contains(ip))
			if block.CIDR.IPNet.Contains(ip) {
				log.Tracef(trace.Private, "Group.deallocateIP: IP to deallocate %s belongs to block %s", ip, block.CIDR)
				err := block.deallocateIP(ip)
				if err != nil {
					return err
				}
				if block.isEmpty() {
					reclaimBlock = true
				}
				break
			}
		}
		if reclaimBlock {
			owner := hg.BlockToOwner[blockID]
			log.Tracef(trace.Private, "Block %d for tenant %s is empty, reclaiming it for reuse", blockID, owner)
			hg.ReusableBlocks = append(hg.ReusableBlocks, blockID)
			ownerBlocks := hg.OwnerToBlocks[owner]
			delete(hg.BlockToOwner, blockID)

			ownerBlockToDelete := -1
			for i, _ := range hg.OwnerToBlocks[owner] {
				if blockID == hg.OwnerToBlocks[owner][i] {
					ownerBlockToDelete = i
					break
				}
			}
			if ownerBlockToDelete == -1 {
				return common.NewError("Could not find block to reclaim (%d) in blocks owned by %s: %v", blockID, owner, hg.OwnerToBlocks[owner])
			}
			hg.OwnerToBlocks[owner] = deleteElementInt(ownerBlocks, ownerBlockToDelete)
			delete(hg.BlockToHost, blockID)
		}
		return nil
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
func (hg *Group) injectParents(network *Network) {
	hg.network = network
	for i, _ := range hg.Hosts {
		hg.Hosts[i].group = hg
	}
	for i, _ := range hg.Groups {
		hg.Groups[i].injectParents(network)
	}
}

// listHosts lists all hosts in this group.
func (hg *Group) ListHosts() []*Host {
	list := hg.Hosts
	for _, group := range hg.Groups {
		list2 := group.ListHosts()
		list = append(list, list2...)
	}
	return list
}

func (hg *Group) ListBlocks() []*Block {
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
func (hg *Group) GetBlocks() []api.IPAMBlockResponse {
	retval := make([]api.IPAMBlockResponse, 0)
	if hg.Blocks != nil {
		for blockID, block := range hg.Blocks {
			owner := hg.BlockToOwner[blockID]
			tenant, segment := parseOwner(owner)
			count := 0
			if block.ListAllocatedAddresses() != nil {
				count = len(block.ListAllocatedAddresses())
			}
			br := api.IPAMBlockResponse{
				CIDR:             api.IPNet{IPNet: *block.CIDR.IPNet},
				Host:             hg.BlockToHost[blockID],
				Revision:         block.Revision,
				Tenant:           tenant,
				Segment:          segment,
				AllocatedIPCount: count,
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

func (hg *Group) findHostByIP(ip string) *Host {
	if ip == "" {
		return nil
	}
	for _, h := range hg.Hosts {
		if h.IP.String() == ip {
			return h
		}
	}
	for _, group := range hg.Groups {
		if host := group.findHostByIP(ip); host != nil {
			return host
		}
	}
	return nil
}

func (hg *Group) findHostByName(name string) *Host {
	if name == "" {
		return nil
	}
	if hg.Hosts != nil {
		for _, h := range hg.Hosts {
			if h.Name == name {
				return h
			}
		}
	}
	if hg.Groups != nil {
		for _, group := range hg.Groups {
			h := group.findHostByName(name)
			if h != nil {
				return h
			}
		}
	}
	return nil
}

// padGroupToPow2Size adds more elements to the group-or-host array, if we have
// the bits for it. For example, if 3 groups were requested, we need 2 bits to
// encode those and therefore, we have space for one more group. We may just as
// well create it now and leave it empty in that case, since it might be useful
// later on.
func (hg *Group) padGroupToPow2Size(groupOrHosts []api.GroupOrHost) []api.GroupOrHost {
	largestIndex := len(groupOrHosts) - 1
	bitsToEncodeGroups := uint(big.NewInt(int64(largestIndex)).BitLen())
	pow2numGroups := 1 << bitsToEncodeGroups
	// Pad the array to the next power of 2
	rem := pow2numGroups - len(groupOrHosts)
	if rem != 0 {
		// Let's allocate a few more empty slots to complete the power of 2
		remArr := make([]api.GroupOrHost, rem)
		for _, g := range remArr {
			g.Dummy = true
		}
		groupOrHosts = append(groupOrHosts, remArr...)
	}
	return groupOrHosts
}

// bitsForGroupElements calculates how many bits we have available for the
// encoding of endpoints. For example, with a 10.0.0.0/24 CIDR and four groups,
// we lose 2 bits for the encoding of groups. Thus, the function should return
// 6 in this case: We have 6 bits left for elements within the groups.
func (hg *Group) bitsForGroupElements(numGroups int, cidr CIDR) int {
	// Number of free bits in the CIDR
	ones, bits := cidr.Mask.Size()
	free := bits - ones

	var n int
	if numGroups == 0 {
		// No groups is weird bit say we give full cidr in that case.
		n = free
	} else {
		// Calculate how many bits we need to encode the various groups, then
		// subtract from the free bits in the CIDR.
		// Note: if numGroups==1 then we get free - 0 which means
		// allocate entire cidr to this one group.
		n = free - big.NewInt(int64(numGroups-1)).BitLen()
	}
	return n
}

// cidrForCurrentGroup calculates the CIDR for the nth group in a list of
// groups. This can be calculated off the 'index' of the group, the CIDR above
// this group and the number of bits we need to reserve for elements within the
// group.
func (hg *Group) cidrForCurrentGroup(groupIndex int, bitsPerElement int, cidr CIDR) (CIDR, error) {
	// Calculate CIDR for the current group
	incr := uint64(groupIndex << uint(bitsPerElement))
	elementCIDRIP := common.IntToIPv4(cidr.StartIPInt + incr)
	elementCIDRString := fmt.Sprintf("%s/%d", elementCIDRIP, (32 - bitsPerElement))
	log.Tracef(trace.Inside, "CIDR String for %s %d: %s", elementCIDRIP, bitsPerElement, elementCIDRString)
	elementCidr, err := NewCIDR(elementCIDRString)
	if err != nil {
		return elementCidr, err
	}
	return elementCidr, nil
}

func (hg *Group) parseMap(groupOrHosts []api.GroupOrHost, cidr CIDR, network *Network) error {
	var err error
	if len(groupOrHosts) == 0 {
		// Just do nothing for now...
		return nil
	}

	if len(groupOrHosts) == 1 {
		log.Tracef(trace.Inside, "parseMap of size 1")
		hg.Name = groupOrHosts[0].Name
		hg.Assignment = groupOrHosts[0].Assignment
		log.Tracef(trace.Inside, "Assignment for group %s: %s", hg.Name, hg.Assignment)
		hg.Routing = groupOrHosts[0].Routing
		hg.Dummy = groupOrHosts[0].Dummy
		err = hg.parse(groupOrHosts[0].Groups, cidr, network)
		if err != nil {
			return err
		}
		return nil
	}

	hg.Name = "/"
	groupOrHosts = hg.padGroupToPow2Size(groupOrHosts)
	bitsPerElement := hg.bitsForGroupElements(len(groupOrHosts), cidr)

	hg.Groups = make([]*Group, len(groupOrHosts))
	for i, elt := range groupOrHosts {
		log.Tracef(trace.Inside, "parseMap: parsing %s", elt.Name)
		elementCIDR, err := hg.cidrForCurrentGroup(i, bitsPerElement, cidr)
		if err != nil {
			return err
		}
		hg.Groups[i] = &Group{}
		hg.Groups[i].Name = elt.Name
		hg.Groups[i].Assignment = elt.Assignment
		hg.Groups[i].Routing = elt.Routing
		log.Tracef(trace.Inside, "Assignment for group %s: %s", hg.Groups[i].Name, hg.Groups[i].Assignment)

		hg.Groups[i].Dummy = elt.Dummy
		//		log.Tracef(trace.Inside, "Calling parse() on %v with %v", hg.Groups[i], elt.Groups)
		err = hg.Groups[i].parse(elt.Groups, elementCIDR, network)
		if err != nil {
			return err
		}
	}

	return nil
}

// groupStructuresInit initializes a number of storage structures in a group.
// If the forceInit parameter is true then it will re-initialize them, even if
// they already had values.
func (hg *Group) groupStructuresInit(forceInit bool) {
	if hg.BlockToOwner == nil || forceInit {
		hg.BlockToOwner = make(map[int]string)
	}
	if hg.BlockToHost == nil || forceInit {
		hg.BlockToHost = make(map[int]string)
	}

	if hg.OwnerToBlocks == nil || forceInit {
		hg.OwnerToBlocks = make(map[string][]int)
	}
	if hg.Blocks == nil || forceInit {
		hg.Blocks = make([]*Block, 0)
	}
	if hg.ReusableBlocks == nil || forceInit {
		hg.ReusableBlocks = make([]int, 0)
	}
}

func (hg *Group) parse(arr []api.GroupOrHost, cidr CIDR, network *Network) error {
	hg.groupStructuresInit(false)

	// Every group - no matter what type - gets a CIDR
	hg.CIDR = cidr

	// First we see what kind of elements we have here - groups or hosts
	if len(arr) == 0 {
		log.Tracef(trace.Inside, "Received empty array in group %s, assuming this is a host group", hg.Name)
		// This is an empty group
		hg.Hosts = make([]*Host, 0)
		hg.groupStructuresInit(true)
		return nil
	}

	var isHostList bool
	if arr[0].IP != nil {
		// This is a group with hosts
		isHostList = true
		hg.Hosts = make([]*Host, len(arr))
		hg.groupStructuresInit(true)
	} else {
		// This is a group that contains more groups
		arr = hg.padGroupToPow2Size(arr)
		hg.Groups = make([]*Group, len(arr))
	}

	bitsPerElement := hg.bitsForGroupElements(len(arr), cidr)
	for i, elt := range arr {
		if isHostList {
			if elt.IP != nil && elt.Name == "" {
				return common.NewError("Both name and IP are required for hosts: %+v (%T)", elt, elt)
			}
			// This is host, we inherit the CIDR
			host := &Host{Name: elt.Name, IP: elt.IP}
			host.group = hg
			hg.Hosts[i] = host
		} else {
			elementCIDR, err := hg.cidrForCurrentGroup(i, bitsPerElement, cidr)
			if err != nil {
				return err
			}

			hg.Groups[i] = &Group{}
			hg.Groups[i].Assignment = elt.Assignment
			hg.Groups[i].Routing = elt.Routing
			err = hg.Groups[i].parse(elt.Groups, elementCIDR, network)
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

func (b *Block) clear() {
	b.Pool.Clear()
}

// newBlock creates a new Block on the given host.
func newBlock(cidr CIDR) *Block {
	eb := &Block{CIDR: cidr,
		Pool: idring.NewIDRing(cidr.StartIPInt, cidr.EndIPInt, nil),
	}
	return eb
}

// ListAvailableAddresses lists all available adresses in the block
func (b Block) ListAvailableAddresses() []string {
	retval := make([]string, 0)
	for _, r := range b.Pool.Ranges {
		for i := r.Min; i <= r.Max; i++ {
			ip := common.IntToIPv4(i)
			retval = append(retval, ip.String())
		}
	}
	return retval
}

// ListAllocatedAddresses lists all allocated adresses in the block
func (b Block) ListAllocatedAddresses() []string {
	allocated := b.Pool.Invert()
	retval := make([]string, 0)
	for _, r := range allocated.Ranges {
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

func (b *Block) allocateSpecificIP(ip net.IP, network *Network) error {
	var err error
	blackedOutBy := network.blackedOutBy(ip)
	if blackedOutBy != nil {
		return fmt.Errorf("Cannot allocate %s: blacked out by %s", ip, blackedOutBy)
	}
	id := common.IPv4ToInt(ip)
	err = b.Pool.GetSpecificID(id)
	if err != nil {
		log.Errorf("Cannot allocate IP %s in block %s: %s", ip, b.CIDR, err)
	}
	return err
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

	Group *Group `json:"host_groups"`

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
	err := network.Group.deallocateIP(ip)
	if err == nil {
		network.Revison++
	}
	return err
}

func (network *Network) findIPInfo(ip net.IP) (hostName string, owner string) {

	log.Tracef(trace.Inside, "network.findIPInfo(): Looking for %s in %s (%s)", ip, network.Name, network.CIDR)
	if network.Group == nil {
		log.Tracef(trace.Inside, "network.findIPInfo(): Not found.")
		return "", ""
	}
	return network.Group.findIPInfo(ip)
}

func (network *Network) allocateSpecificIP(ip net.IP, hostName string, owner string) error {
	if network.Group == nil {
		return errors.NewRomanaNotFoundError("No groups found in network",
			"group",
			fmt.Sprintf("network=%s", network.Name))
	}

	host := network.Group.findHostByName(hostName)
	if host == nil {
		return errors.NewRomanaNotFoundError(fmt.Sprintf("Host %s not found", hostName),
			"host",
			fmt.Sprintf("hostname=%s", hostName))
	}

	return host.group.allocateSpecificIP(ip, network, hostName, owner)
}

// allocateIP attempts to allocate an IP from one of the existing blocks for the tenant; and
// if not, reuse a block that belongs to no tenant. Finally, it will try to allocate a
// new block.
func (network *Network) allocateIP(hostName string, owner string) (net.IP, error) {
	if network.Group == nil {
		return nil, nil
	}
	host := network.Group.findHostByName(hostName)
	if host == nil {
		return nil, errors.NewRomanaNotFoundError(fmt.Sprintf("Host %s not found", hostName),
			"host",
			fmt.Sprintf("hostname=%s", hostName))
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

// Loader is a function for loading IPAM data from a store
type Loader func(ipam *IPAM, ch <-chan struct{}) error

// Saver defines a function that can save the state of the BlockIPAM
// to a persistent store. Saver is allowed to assume the BlockIPAM
// can be successfully marshaled to JSON.
type Saver func(ipam *IPAM, ch <-chan struct{}) error

// NewIPAM creates a new IPAM object. If locker is not provided,
// mutexLocker is used. If an HA deployment is expected, then the locker
// based on some external resource, e.g., a DB, should be provided.
func NewIPAM(saver Saver, locker Locker) (*IPAM, error) {
	ipam := &IPAM{}
	if locker == nil {
		ipam.locker = newMutexLocker()
	} else {
		ipam.locker = locker
	}
	ch, err := ipam.locker.Lock()
	if err != nil {
		return nil, err
	}
	defer ipam.locker.Unlock()
	ipam.clearIPAM()

	log.Tracef(trace.Inside, "NewIPAM(): Set locker to %v", ipam.locker)

	ipam.save = saver
	err = ipam.save(ipam, ch)
	if err != nil {
		return nil, err
	}
	return ipam, nil
}

// parseIPAM restores IPAM from JSON
func parseIPAM(j string) (*IPAM, error) {
	ipam := &IPAM{}
	err := json.Unmarshal([]byte(j), ipam)
	if err != nil {
		return nil, err
	}
	ipam.injectParents()
	ipam.locker = newMutexLocker()
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
	load            Loader
	save            Saver
	locker          Locker

	TenantToNetwork map[string][]string `json:"tenant_to_network"`

	//	OwnerToIP map[string][]string
	//	IPToOwner map[string]string
	prevKVPair *libkvStore.KVPair
}

func (ipam *IPAM) GetPrevKVPair() *libkvStore.KVPair {
	return ipam.prevKVPair
}

func (ipam *IPAM) SetPrevKVPair(kvp *libkvStore.KVPair) {
	ipam.prevKVPair = kvp
}

// injectParents is intended to add references to parent objects where appropriate
// after parsing the IPAM object from JSON.
func (ipam *IPAM) injectParents() {
	for _, network := range ipam.Networks {
		if network.Group != nil {
			network.Group.injectParents(network)
		}
		network.ipam = ipam
	}
}

// clearIPAM clears IPAM.
func (ipam *IPAM) clearIPAM() {
	ipam.Networks = make(map[string]*Network)
	ipam.AddressNameToIP = make(map[string]net.IP)
	ipam.TenantToNetwork = make(map[string][]string)
}

func (ipam *IPAM) ListHosts() api.HostList {
	list := make([]api.Host, 0)
	for _, network := range ipam.Networks {
		for _, host := range network.Group.ListHosts() {
			if host.AgentPort == 0 {
				host.AgentPort = DefaultAgentPort
			}
			list = append(list, api.Host{
				IP:        host.IP,
				Name:      host.Name,
				AgentPort: host.AgentPort,
			})
		}
	}
	retval := api.HostList{Hosts: list,
		Revision: ipam.TopologyRevision,
	}
	return retval
}

// GetGroupsForNetwork retrieves Group for the network
// with the provided name, or nil if not found.
func (ipam *IPAM) GetGroupsForNetwork(netName string) *Group {
	if network, ok := ipam.Networks[netName]; ok {
		return network.Group
	} else {
		return nil
	}
}

// allocateSpecificIP tries to allocate a specific IP. If the specific IP cannot be
// allocated in the given host/tenant/segment combination, an error is returned.
func (ipam *IPAM) allocateSpecificIP(addressName string, ip net.IP, host string, tenant string, segment string) error {
	// Find eligible networks for the specified tenant
	var err error
	msg := fmt.Sprintf("%s: %s (Host %s, tenant %s, segment %s)", addressName, ip, host, tenant, segment)
	log.Debugf("Attempting to allocate %s", msg)
	networksForTenant, err := ipam.getNetworksForTenant(tenant)
	if err != nil {
		return err
	}

	owner := makeOwner(tenant, segment)
	for _, network := range networksForTenant {
		if network.CIDR.ContainsIP(ip) {
			err = network.allocateSpecificIP(ip, host, owner)
			if err != nil {
				return err
			}
			ipam.AddressNameToIP[addressName] = ip
			return nil
		}
	}
	return fmt.Errorf("No suitable network found to allocate %s", msg)
}

// AllocateIP allocates an IP for the provided tenant and segment,
// and associates the provided name with it. That name can afterwards
// be used for deallocation.
// It will first attempt to allocate an IP from an existing block,
// and if all are exhausted, will try to allocate a new block for
// this tenant/segment pair. Will return nil as IP if the entire
// network is exhausted.
func (ipam *IPAM) AllocateIP(addressName string, host string, tenant string, segment string) (net.IP, error) {
	log.Tracef(trace.Inside, "Entering IPAM.AllocateIP()")
	ch, err := ipam.locker.Lock()
	if err != nil {
		log.Error("IPAM.AllocateIP: error acquiring a lock")
		return nil, err
	}
	//	log.Tracef(trace.Inside, "IPAM.AllocateIP: got a lock")
	defer ipam.locker.Unlock()

	latestIPAM := &IPAM{}
	err = ipam.load(latestIPAM, ch)
	if err != nil {
		return nil, err
	}

	if addr, ok := latestIPAM.AddressNameToIP[addressName]; ok {
		err := errors.NewRomanaExistsErrorWithMessage(
			fmt.Sprintf("Address with name %s already allocated: %s", addressName, addr),
			fmt.Sprintf("Address: %s", addressName),
			"IP",
			fmt.Sprintf("name=%s", addressName),
			fmt.Sprintf("IP=%s", addr))

		return nil, err

	}

	// Find eligible networks for the specified tenant
	networksForTenant, err := latestIPAM.getNetworksForTenant(tenant)
	if err != nil {
		return nil, err
	}

	owner := makeOwner(tenant, segment)
	for _, network := range networksForTenant {
		log.Tracef(trace.Inside, "Trying to allocate IP for host %s on network %s.", host, network.Name)
		ip, err := network.allocateIP(host, owner)
		if err != nil {
			switch err := err.(type) {
			case errors.RomanaNotFoundError:
				if err.Type == "host" {
					// This is for when the host is not within the currently examined network.
					// In such a case, we should just carry on examining other networks.
					// Any other error so far is a legitimate error and we fail fast.
					log.Infof("Network %s does not have host %s defined, skipping.", network.Name, host)
					continue
				} else {
					return nil, err
				}
			default:
				return nil, err
			}
		}

		if ip != nil {
			latestIPAM.AddressNameToIP[addressName] = ip
			latestIPAM.AllocationRevision++
			log.Tracef(trace.Inside, "Updated AllocationRevision to %d", latestIPAM.AllocationRevision)
			err = ipam.save(latestIPAM, ch)
			if err != nil {
				return nil, err
			}
			return ip, nil
		}
	}
	return nil, common.NewError(msgNoAvailableIP)
}

// DeallocateIP will deallocate the provided IP (returning an
// error if it never was allocated in the first place).
func (ipam *IPAM) DeallocateIP(addressName string) error {
	ch, err := ipam.locker.Lock()
	if err != nil {
		return err
	}
	defer ipam.locker.Unlock()

	latestIPAM := &IPAM{}
	latestIPAM.clearIPAM()
	err = ipam.load(latestIPAM, ch)
	if err != nil {
		return err
	}

	if ip, ok := latestIPAM.AddressNameToIP[addressName]; ok {
		log.Tracef(trace.Inside, "IPAM.DeallocateIP: Request to deallocate %s: %s", addressName, ip)
		for _, network := range latestIPAM.Networks {
			if network.CIDR.IPNet.Contains(ip) {
				log.Tracef(trace.Inside, "IPAM.DeallocateIP: IP %s belongs to network %s", ip, network.Name)
				err := network.deallocateIP(ip)
				if err == nil {
					delete(latestIPAM.AddressNameToIP, addressName)
					latestIPAM.AllocationRevision++
					err = ipam.save(latestIPAM, ch)
					if err != nil {
						return err
					}
				}
				return err
			}
		}
		return errors.NewRomanaNotFoundError("", "IP", fmt.Sprintf("IP=%s", ip))
	}
	// find by IPAddress instead of name, so that all
	// platforms are supported.
	for name, ip := range latestIPAM.AddressNameToIP {
		if ip.String() == addressName {
			for _, network := range latestIPAM.Networks {
				if network.CIDR.IPNet.Contains(ip) {
					log.Tracef(trace.Inside,
						"IPAM.DeallocateIP: IP %s belongs to network %s",
						ip, network.Name)
					err := network.deallocateIP(ip)
					if err == nil {
						delete(latestIPAM.AddressNameToIP, name)
						latestIPAM.AllocationRevision++
						err = ipam.save(latestIPAM, ch)
						if err != nil {
							return err
						}
					}
					return err
				}
			}
			return common.NewError404("IP", ip.String())
		}
	}

	return errors.NewRomanaNotFoundError("", "address", fmt.Sprintf("name=%s", addressName))
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

// setTopology clears IPAM and sets existing topology in it.
func (ipam *IPAM) setTopology(req api.TopologyUpdateRequest) error {
	ipam.clearIPAM()
	var netDef api.NetworkDefinition
	for _, netDef = range req.Networks {
		log.Infof("Parsing network %s", netDef.Name)
		if _, ok := ipam.Networks[netDef.Name]; ok {
			return common.NewError("Network with name %s already defined", netDef.Name)
		}
		netDefCIDR, err := NewCIDR(netDef.CIDR)
		if err != nil {
			return err
		}
		blockMaskMin, blockMaskMax := netDefCIDR.Mask.Size()

		if netDef.BlockMask == 0 {
			if DefaultBlockMask < uint(blockMaskMin) {
				netDef.BlockMask = uint(blockMaskMin)
			} else {
				netDef.BlockMask = DefaultBlockMask
			}
		}
		if netDef.BlockMask < uint(blockMaskMin) || netDef.BlockMask > uint(blockMaskMax) {
			return common.NewError(
				"invalid blockmask(%d) for network(%s), must be %d <= blockmask <= %d",
				netDef.BlockMask, netDef.Name, blockMaskMin, blockMaskMax)
		}

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
		log.Infof("Adding network %s: %v", netDef.Name, network)
		ipam.Networks[netDef.Name] = network
	}

	// Now check if we got any overlapping CIDRs...
	// Doing it here for simplicity because we at this point have already parsed CIDR
	// strings into CIDR objects.
	// n^2 nested loop is ok - there will not be a lot of networks.
	var net1 *Network
	var net2 *Network
	for _, net1 = range ipam.Networks {
		for _, net2 = range ipam.Networks {
			if net1 == net2 {
				continue
			}
			log.Printf("Checking %s %v vs %s %v", net1.Name, net1, net2.Name, net2)
			if net2.CIDR.Contains(net1.CIDR) {
				return common.NewError("CIDR %s of network %s already is contained in CIDR %s of network %s", net1.CIDR, net1.Name, net2.CIDR, net2.Name)
			}
			if net1.CIDR.Contains(net2.CIDR) {
				return common.NewError("CIDR %s of network %s already is contained in CIDR %s of network %s", net2.CIDR, net2.Name, net1.CIDR, net1.Name)
			}
		}
	}

	processedNetworks := make(map[string]bool)
	log.Tracef(trace.Inside, "Tenants to network mapping: %v", ipam.TenantToNetwork)
	var ok bool
	var network *Network
	var err error
	for _, topoDef := range req.Topologies {
		for _, netName := range topoDef.Networks {
			if _, ok = processedNetworks[netName]; ok {
				return common.NewError("Network %s appears more than once.", netName)
			}
			if network, ok = ipam.Networks[netName]; ok {
				hg := &Group{}

				err = hg.parseMap(topoDef.Map, network.CIDR, network)
				if err != nil {
					return err
				}
				network.Group = hg
				log.Tracef(trace.Inside, "Parsed topology for network %s: %s", netName, network.Group)
			} else {
				return common.NewError("Network with name %s not defined", netName)
			}
			processedNetworks[netName] = true
		}
	}
	return nil
}

// cloneIPAM returns a copy of the current IPAM
// (except for save and locker which are copied
// by reference).
func (ipam *IPAM) cloneIPAM() (*IPAM, error) {
	b, err := json.Marshal(ipam)
	if err != nil {
		return nil, err
	}
	newIPAM, err := parseIPAM(string(b))
	if err != nil {
		return nil, err
	}
	newIPAM.save = ipam.save
	newIPAM.locker = ipam.locker
	return newIPAM, nil
}

// UpdateTopology updates the entire topology, returning an error if the
// current topology has IPs that cannot be allocated in the new one.
func (ipam *IPAM) UpdateTopology(req api.TopologyUpdateRequest, lockAndSave bool) error {
	var err error
	var ch <-chan struct{}
	if lockAndSave {
		ch, err = ipam.locker.Lock()
		if err != nil {
			return err
		}
		defer ipam.locker.Unlock()
	}

	// The algorithm is as follows:
	// - Back up IPAM
	// - Set current IPAM's topology to the provided
	// - Attempt to allocate all IPs from backed up IPAM.
	//   - If any fails, fail
	backupIPAM, err := ipam.cloneIPAM()
	backupIPAM.locker = nil
	if err != nil {
		return err
	}
	err = ipam.setTopology(req)
	if err != nil {
		return err
	}

	var ipFound bool
	for addressName, ip := range backupIPAM.AddressNameToIP {
		log.Debugf("UpdateTopology(): Attempting to allocate %s: %s", addressName, ip)
		ipFound = false
		for _, network := range backupIPAM.Networks {
			if network.CIDR.ContainsIP(ip) {
				log.Debugf("UpdateTopology(): Attempt to allocate %s in %s (%s)", ip, network.Name, network.CIDR)
				hostName, owner := network.findIPInfo(ip)
				if hostName == "" || owner == "" {
					return fmt.Errorf("Unexpected result when looking up IP %s: host %s, owner %s", ip, hostName, owner)
				}
				tenant, segment := parseOwner(owner)
				err = ipam.allocateSpecificIP(addressName, ip, hostName, tenant, segment)
				if err == nil {
					ipFound = true
				} else {
					return err
				}
			}
		}
		if !ipFound {
			return fmt.Errorf("Cannot find network for IP %s", ip)
		}
	}

	ipam.TopologyRevision++
	if lockAndSave {
		err = ipam.save(ipam, ch)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ipam *IPAM) ListAllBlocks() *api.IPAMBlocksResponse {
	blocks := make([]api.IPAMBlockResponse, 0)
	for _, network := range ipam.Networks {
		netBlocks := network.Group.GetBlocks()
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
			Blocks:   network.Group.GetBlocks(),
		}
		return resp
	}
	return nil
}

// UpdateHostLabels updates host's labels. Note that this does not check
// the new labels against label assignment and whether that breaks anything;
// that is a TODO
func (ipam *IPAM) UpdateHostLabels(host api.Host) error {
	// log.Tracef(trace.Inside, "UpdateHostLabels for %s", host)
	ch, err := ipam.locker.Lock()
	if err != nil {
		return err
	}
	defer ipam.locker.Unlock()

	if host.IP == nil && host.Name == "" {
		return common.NewError("At least one of IP, Name must be specified to update a host")
	}
	updatedHost := false
	foundHost := false
	var hostToUpdate *Host
	for _, net := range ipam.Networks {
		hostToUpdate = nil
		if host.IP == nil {
			hostToUpdate = net.Group.findHostByName(host.Name)
		} else {
			hostToUpdate = net.Group.findHostByIP(host.IP.String())
			if hostToUpdate != nil && host.Name != "" {
				if hostToUpdate.Name != host.Name {
					return fmt.Errorf("Found host with IP %s but it has name %s, not %s", host.IP, hostToUpdate.Name, host.Name)
				}
			}
		}
		if hostToUpdate == nil {
			log.Tracef(trace.Inside, "Host %v (%s) not found in net %s\n", host.IP, host.Name, net.Name)
			continue
		}
		foundHost = true
		log.Tracef(trace.Inside, "UpdateHostLabels: Checking %+v vs %+v", hostToUpdate.Tags, host.Tags)
		if !reflect.DeepEqual(hostToUpdate.Tags, host.Tags) {
			eligibilityCheckHost := &Host{Tags: host.Tags}
			if !hostToUpdate.group.isHostEligible(eligibilityCheckHost) {
				return fmt.Errorf("New tags for host %s (%+v) will result for host being ineligible for current group %s with assignment %s",
					hostToUpdate,
					host.Tags,
					hostToUpdate.group.Name,
					hostToUpdate.group.Assignment)
			}
			log.Tracef(trace.Inside, "Updating host %s Tags with %v", hostToUpdate, host.Tags)
			if host.Tags == nil {
				hostToUpdate.Tags = nil
			} else {
				hostToUpdate.Tags = deepcopy.Copy(host.Tags).(map[string]string)
			}

			updatedHost = true
		}
	}
	if updatedHost {
		ipam.TopologyRevision++
		err = ipam.save(ipam, ch)
		if err != nil {
			return err
		}
	} else if !foundHost {
		return fmt.Errorf("No host found with IP %s and/or name %s", host.IP, host.Name)
	}
	return nil
}

func (ipam *IPAM) UpdateHostK8SInfo(host api.Host) error {
	// log.Tracef(trace.Inside, "UpdateHostK8SInfo for %s", host)
	ch, err := ipam.locker.Lock()
	if err != nil {
		return err
	}
	defer ipam.locker.Unlock()

	if host.IP == nil && host.Name == "" {
		return common.NewError("At least one of IP, Name must be specified to delete a host")
	}
	updatedHost := false
	foundHost := false
	var hostToUpdate *Host
	for _, net := range ipam.Networks {
		hostToUpdate = nil
		if host.IP == nil {
			hostToUpdate = net.Group.findHostByName(host.Name)
		} else {
			hostToUpdate = net.Group.findHostByIP(host.IP.String())
			if hostToUpdate != nil && host.Name != "" {
				if hostToUpdate.Name != host.Name {
					return fmt.Errorf("Found host with IP %s but it has name %s, not %s", host.IP, hostToUpdate.Name, host.Name)
				}
			}
		}
		if hostToUpdate == nil {
			log.Tracef(trace.Inside, "Host %v (%s) not found in net %s\n", host.IP, host.Name, net.Name)
			continue
		}
		foundHost = true
		if !reflect.DeepEqual(hostToUpdate.K8SInfo, host.K8SInfo) {
			log.Tracef(trace.Inside, "Updating host %s K8S info with %v", hostToUpdate, host.K8SInfo)
			if host.K8SInfo == nil {
				hostToUpdate.K8SInfo = nil
			} else {
				hostToUpdate.K8SInfo = deepcopy.Copy(host.K8SInfo).(map[string]interface{})
			}
			updatedHost = true
		}
	}
	if updatedHost {
		ipam.TopologyRevision++
		err = ipam.save(ipam, ch)
		if err != nil {
			return err
		}
	} else if !foundHost {
		return fmt.Errorf("No host found with IP %s and/or name %s", host.IP, host.Name)
	}
	return nil
}

func (ipam *IPAM) RemoveHost(host api.Host) error {
	ch, err := ipam.locker.Lock()
	if err != nil {
		return err
	}
	defer ipam.locker.Unlock()

	if host.IP == nil && host.Name == "" {
		return common.NewError("At least one of IP, Name must be specified to delete a host")
	}
	removedHost := false
	var hostToRemove *Host
	for _, net := range ipam.Networks {
		log.Tracef(trace.Inside, "Looking for host %v (%s) to remove from net %s", host.IP, host.Name, net.Name)
		hostToRemove = nil
		if host.IP == nil {
			hostToRemove = net.Group.findHostByName(host.Name)
		} else {
			hostToRemove = net.Group.findHostByIP(host.IP.String())
		}
		if hostToRemove == nil {
			log.Tracef(trace.Inside, "Host %v (%s) not found in net %s\n", host.IP, host.Name, net.Name)
			continue
		}
		if host.Name != "" {
			if hostToRemove.Name != host.Name {
				return common.NewError("Found host with IP %s but it has name %s, not %s", host.IP, hostToRemove.Name, host.Name)
			}
		}
		var i int
		var curHost *Host

		for i, curHost = range hostToRemove.group.Hosts {
			if curHost.IP.String() == hostToRemove.IP.String() {
				log.Tracef(trace.Inside, "Net %s: removing host %s (%d) from group %s (%v)\n", net.Name, hostToRemove, i, hostToRemove.group.Name, hostToRemove.group.Hosts)
				hostToRemove.group.Hosts = deleteElementHost(hostToRemove.group.Hosts, i)
				log.Tracef(trace.Inside, "Net %s, group %s, after removal: %v", net.Name, hostToRemove.group.Name, hostToRemove.group.Hosts)
				removedHost = true
				break
			}
		}
		for k, v := range hostToRemove.group.BlockToHost {
			if v == curHost.Name {
				delete(hostToRemove.group.BlockToHost, k)
				hostToRemove.group.Blocks[k].clear()
				hostToRemove.group.ReusableBlocks = append(hostToRemove.group.ReusableBlocks, k)
			}
		}
	}
	if removedHost {
		ipam.TopologyRevision++
		err = ipam.save(ipam, ch)
		if err != nil {
			return err
		}
	} else {
		return common.NewError("No host found with IP %s and/or name %s", host.IP, host.Name)
	}
	return nil
}

// AddHost adds host to the current IPAM.
func (ipam *IPAM) AddHost(host api.Host) error {
	ch, err := ipam.locker.Lock()
	if err != nil {
		return err
	}
	defer ipam.locker.Unlock()

	if host.IP == nil {
		return common.NewError("Host IP is required.")
	}
	if host.Name == "" {
		return common.NewError("Host name is required.")
	}
	log.Tracef(trace.Inside, "Entering AddHost with %d networks\n", len(ipam.Networks))
	addedHost := false
	var myTags map[string]string
	if host.Tags != nil {
		myTags = deepcopy.Copy(host.Tags).(map[string]string)
	}
	for _, net := range ipam.Networks {
		myHost := &Host{IP: host.IP,
			Name: host.Name,
			Tags: myTags,
		}
		log.Tracef(trace.Inside, "Attempting to add host %s (%s) to network %s\n", host.Name, host.IP, net.Name)
		if net.Group == nil {
			continue
		}
		ok, err := net.Group.addHost(myHost)
		if err != nil {
			return err
		}
		if ok {
			addedHost = true
		}
	}
	if addedHost {
		ipam.TopologyRevision++
		err = ipam.save(ipam, ch)
		if err != nil {
			return err
		}
	} else {
		return common.NewError("No suitable groups to add host %s to.", host)
	}
	return nil
}

// BlackOut removes a CIDR from consideration. It is an error if CIDR
// is within any of the exising allocated blocks. Fragmentation may
// result if CIDRs smaller than ipam. Blocks are blacked out and then
// un-blacked out.
func (ipam *IPAM) BlackOut(cidrStr string) error {
	ch, err := ipam.locker.Lock()
	if err != nil {
		return err
	}
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
			networkBlocks := network.Group.ListBlocks()
			log.Tracef(trace.Inside, "BlackOut: Checking blocks %v if they have IP in %s", networkBlocks, cidr)
			for _, block := range networkBlocks {
				if block.hasIPInCIDR(cidr) {
					return common.NewError("Blackout block contains already allocated IPs.")
				}
			}
			network.BlackedOut[i] = cidr
			network.Revison++
			err := ipam.save(ipam, ch)
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
	networkBlocks := network.Group.ListBlocks()
	log.Tracef(trace.Inside, "BlackOut: Checking blocks %v if they have IP in %s", networkBlocks, cidr)
	for _, block := range networkBlocks {
		if block.hasIPInCIDR(cidr) {
			return common.NewError("Blackout block contains already allocated IPs.")
		}
	}

	network.BlackedOut = append(network.BlackedOut, cidr)
	network.Revison++
	err = ipam.save(ipam, ch)
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
	ch, err := ipam.locker.Lock()
	if err != nil {
		return err
	}
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
	network.BlackedOut = deleteElementCIDR(network.BlackedOut, i)
	network.Revison++
	return ipam.save(ipam, ch)
}
