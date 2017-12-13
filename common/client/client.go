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
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/log/trace"

	libkvStore "github.com/docker/libkv/store"
	log "github.com/romana/rlog"
)

const (
	DefaultEtcdPrefix     = "/romana"
	DefaultEtcdEndpoints  = "localhost:2379"
	ipamKey               = "/ipam"
	ipamDataKey           = ipamKey + "/data"
	PoliciesPrefix        = "/policies"
	RomanaIPPrefix        = "/romanaip"
	defaultTopologyLevels = 20
)

type Client struct {
	savingMutex *sync.RWMutex
	config      *common.Config
	Store       *Store
	ipamLocker  Locker
	IPAM        *IPAM
}

// NewClient creates a new Client object based on provided config
func NewClient(config *common.Config) (*Client, error) {
	if config.EtcdPrefix == "" {
		config.EtcdPrefix = DefaultEtcdPrefix
	}
	store, err := NewStore(config.EtcdEndpoints, config.EtcdPrefix)
	if err != nil {
		return nil, err
	}

	c := &Client{
		config:      config,
		Store:       store,
		savingMutex: &sync.RWMutex{},
	}

	err = c.initIPAM(config.InitialTopologyFile)
	if err != nil {
		return nil, err
	}
	err = c.watchIPAM()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) ListHosts() api.HostList {
	return c.IPAM.ListHosts()
}

type HostListCallback func(api.HostList)

func (c *Client) WatchHostsWithCallback(cb HostListCallback) error {
	// TODO this needs a way to remove the callback function
	// (to stop listening)
	log.Tracef(trace.Public, "Entering WatchHostsWithCallback.")
	stopCh := make(chan struct{})
	ch, err := c.WatchHosts(stopCh)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case result := <-ch:
				cb(result)
			}
		}
	}()
	return nil
}

type BlocksCallback func(api.IPAMBlocksResponse)

func (c *Client) WatchBlocksWithCallback(cb BlocksCallback) error {
	// TODO this needs a way to remove the callback function
	// (to stop listening)
	log.Tracef(trace.Public, "Entering WatchBlocksWithCallback.")
	stopCh := make(chan struct{})
	ch, err := c.WatchBlocks(stopCh)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case result := <-ch:
				cb(result)
			}
		}
	}()
	return nil
}

// WatchBlocks is similar to Watch of libkv store, but specific
// to watching for blocks.
func (c *Client) WatchBlocks(stopCh <-chan struct{}) (<-chan api.IPAMBlocksResponse, error) {
	log.Tracef(trace.Public, "Entering WatchBlocks.")
	ch, err := c.Store.ReconnectingWatch(ipamDataKey, stopCh)
	if err != nil {
		return nil, err
	}
	outCh := make(chan api.IPAMBlocksResponse)
	// Since for now everything is stored in a single blob, we are going to get
	// notification on all changes. We can filter them out by checking for
	// the revision in the block list.
	lastBlockListRevision := -1

	go func() {
		log.Tracef(trace.Inside, "WatchBlocks: Entering WatchBlocks goroutine.")
		for {
			select {
			case <-stopCh:
				log.Tracef(trace.Inside, "WatchBlocks: Stop message received")
				return
			case kv := <-ch:
				ipamJson := string(kv.Value)
				log.Tracef(trace.Inside, "WatchBlocks: got JSON [%s]", ipamJson)

				ipam, err := parseIPAM(ipamJson)
				if err != nil {
					if ipamJson == "" {
						log.Warnf("WatchBlocks: Received empty IPAM JSON from KV store")
					} else {
						log.Errorf("WatchBlocks: Error parsing IPAM JSON ```%s ```: %s", ipamJson, err)
					}
					break
				}
				blocks := ipam.ListAllBlocks()
				if blocks.Revision <= lastBlockListRevision {
					log.Debugf("WatchBlocks: Received revision %d smaller than last reported %d, ignoring.", blocks.Revision, lastBlockListRevision)
				} else {
					lastBlockListRevision = blocks.Revision
					log.Tracef(trace.Inside, "WatchBlocks: sending block list revision %d to out channel", blocks.Revision)
					outCh <- *blocks
				}
			}
		}
	}()
	return outCh, nil
}

// WatchHosts is similar to Watch of libkv store, but specific
// to watching for host list.
func (c *Client) WatchHosts(stopCh <-chan struct{}) (<-chan api.HostList, error) {
	log.Tracef(trace.Public, "Entering WatchHosts.")
	ch, err := c.Store.ReconnectingWatch(ipamDataKey, stopCh)
	if err != nil {
		return nil, err
	}
	outCh := make(chan api.HostList)
	// Since for now everything is stored in a single blob, we are going to get
	// notification on all changes. We can filter them out by checking for
	// IPAM's TopologyRevision.
	lastHostListRevision := -1

	go func() {
		log.Tracef(trace.Inside, "WatchHosts: Entering WatchHosts goroutine.")
		for {
			select {
			case <-stopCh:
				log.Tracef(trace.Inside, "WatchHosts: Stop message received")
				return
			case kv := <-ch:
				ipamJson := string(kv.Value)
				ipam, err := parseIPAM(ipamJson)
				log.Tracef(trace.Inside, "WatchHosts: got %s", ipamJson)
				if err != nil {
					log.Errorf("WatchHosts: Error parsing IPAM: %s", err)
					continue
				}
				hostList := ipam.ListHosts()
				if hostList.Revision <= lastHostListRevision {
					log.Debugf("WatchHosts: Received revision %d smaller than last reported %d, ignoring.", hostList.Revision, lastHostListRevision)
				} else {
					lastHostListRevision = hostList.Revision
					log.Tracef(trace.Inside, "WatchHosts: sending host list revision %d to out channel", hostList.Revision)
					outCh <- hostList
				}
			}
		}
	}()
	return outCh, nil
}

func (c *Client) ListPolicies() ([]api.Policy, error) {
	kvps, err := c.Store.ListObjects(PoliciesPrefix)
	if err != nil {
		return nil, err
	}
	policies := make([]api.Policy, 0, len(kvps))
	errors := []error{}
	for i, v := range kvps {
		p := api.Policy{}
		err := json.Unmarshal(v.Value, &p)
		if err != nil {
			errors = append(errors, fmt.Errorf("error decoding policy %d: %v: %v", i+1, v.Value, err))
			continue
		}
		policies = append(policies, p)
	}
	if len(errors) > 0 {
		return policies, fmt.Errorf("%d decoding errors. %v", len(errors), errors)
	}
	return policies, nil
}

// ListTenants is a temporary method to satisfy current agent cache.
func (c *Client) ListTenants() []api.Tenant {
	t := make(map[string]api.Tenant)
	blocks := c.IPAM.ListAllBlocks()
	for _, block := range blocks.Blocks {
		if tenant, ok := t[block.Tenant]; ok {
			segmentFound := false
			for _, segment := range tenant.Segments {
				if segment.ID == block.Segment {
					segmentFound = true
					segment.Blocks = append(segment.Blocks, api.IPNet{IPNet: block.CIDR.IPNet})
					break
				}
			}
			if !segmentFound {
				segmentBlock := api.IPNet{IPNet: block.CIDR.IPNet}
				segmentBlocks := []api.IPNet{segmentBlock}
				segment := api.Segment{
					ID:     block.Segment,
					Blocks: segmentBlocks,
				}
				tenant.Segments = append(tenant.Segments, segment)
			}
		} else {
			// We don't know about this tenant yet...
			segmentBlock := api.IPNet{IPNet: block.CIDR.IPNet}
			segmentBlocks := []api.IPNet{segmentBlock}
			segment := api.Segment{
				ID:     block.Segment,
				Blocks: segmentBlocks,
			}
			t[block.Tenant] = api.Tenant{
				ID:       block.Tenant,
				Segments: []api.Segment{segment},
			}

		}
	}
	tenants := make([]api.Tenant, len(t))
	i := 0
	for _, tenant := range t {
		tenants[i] = tenant
		i++
	}
	return tenants
}

// AddPolicy adds a policy (or modifies it if policy with such ID already
// exists)
func (c *Client) AddPolicy(policy api.Policy) error {
	b, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	return c.Store.PutObject(PoliciesPrefix+"/"+policy.ID, b)
}

// DeletePolicy attempts to delete policy. If the policy does
// not exist, false is returned, instead of an error.
func (c *Client) DeletePolicy(id string) (bool, error) {
	return c.Store.Delete(PoliciesPrefix + "/" + id)
}

// GetPolicy attempts to retrieve a policy.
func (c *Client) GetPolicy(id string) (api.Policy, error) {
	p := api.Policy{}
	v, err := c.Store.GetObject(id)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(v.Value, &p)
	return p, err
}

func (c *Client) initIPAM(initialTopologyFile *string) error {
	if initialTopologyFile != nil {
		log.Tracef(trace.Inside, "initIPAM(): Entered with %s", *initialTopologyFile)
	} else {
		log.Tracef(trace.Inside, "initIPAM(): Entered.")
	}
	var err error
	c.ipamLocker, err = c.Store.NewLocker(ipamKey)
	if err != nil {
		return err
	}
	log.Tracef(trace.Inside, "initIPAM(): Created locker %v", c.ipamLocker)

	ch, err := c.ipamLocker.Lock()
	if err != nil {
		return err
	}
	log.Tracef(trace.Inside, "initIPAM(): Got lock")
	defer c.ipamLocker.Unlock()

	// Check if IPAM info exists in the store
	var ipamExists bool
	ipamExists, err = c.Store.Exists(ipamDataKey)
	if err != nil {
		return err
	}
	log.Infof("IPAM exists at %s: %t", ipamDataKey, ipamExists)
	// make sure there is sane data in ipam.
	if ipamExists {
		ipamData, err := c.Store.GetString(ipamDataKey, "")
		if err != nil {
			log.Errorf("Error while fetching ipam data: %s", err)
			return err
		}
		log.Debugf("IPAM data: %s", ipamData)
		if ipamData == "" {
			log.Trace(trace.Inside, "Setting ipamExists to false because ipamData = \"\"")
			ipamExists = false
		} else {
			ipam := &IPAM{}
			err := json.Unmarshal([]byte(ipamData), ipam)
			if err != nil {
				log.Errorf("Error while un-marshalling ipam data: %s", err)
				return err
			}
			if ipam.AllocationRevision < 1 && ipam.TopologyRevision < 1 {
				log.Warnf("Allocation revision: %d, Topology revision %d, deleting", ipam.AllocationRevision, ipam.TopologyRevision)
				c.Store.Delete(ipamDataKey)
				log.Trace(trace.Inside, "Setting ipamExists to false because deleted")
				ipamExists = false
			}
		}
	}

	if ipamExists {
		if initialTopologyFile != nil && *initialTopologyFile != "" {
			log.Infof("Ignoring initial topology file %s as IPAM already exists", *initialTopologyFile)
		}
		// Load if exists
		log.Infof("Loading IPAM data from %s", c.Store.getKey(ipamDataKey))
		kv, err := c.Store.Get(ipamDataKey)
		if err != nil {
			return err
		}
		c.IPAM, err = parseIPAM(string(kv.Value))
		if err != nil {
			return err
		}
		c.IPAM.save = c.save
		c.IPAM.load = c.load
		c.IPAM.locker = c.ipamLocker
		c.IPAM.SetPrevKVPair(kv)
	} else {
		// If does not exist -- initialize with initial topology.

		log.Infof("No IPAM data found at %s, initializing", c.Store.getKey(ipamDataKey))
		c.IPAM = &IPAM{locker: c.ipamLocker,
			save: c.save,
			load: c.load,
		}

		if initialTopologyFile != nil && *initialTopologyFile != "" {
			topoData, err := ioutil.ReadFile(*initialTopologyFile)
			if err != nil {
				return err
			}
			topoReq := &api.TopologyUpdateRequest{}
			err = json.Unmarshal(topoData, topoReq)
			if err != nil {
				return fmt.Errorf("error processing %s: %s", *initialTopologyFile, err)
			}
			err = c.IPAM.UpdateTopology(*topoReq, false)
			if err != nil {
				return err
			}
			log.Infof("Initialized IPAM with %s", *initialTopologyFile)
		}
		err = c.save(c.IPAM, ch)
		if err != nil {
			return err
		}

	}
	return nil
}

func (c *Client) load(ipam *IPAM, ch <-chan struct{}) error {
	kv, err := c.Store.Get(ipamDataKey)
	if err != nil {
		return err
	}
	parsedIPAM, err := parseIPAM(string(kv.Value))
	if err != nil {
		return err
	}
	*ipam = *parsedIPAM
	ipam.SetPrevKVPair(kv)
	return nil
}

// save implements the Saver interface of IPAM.
func (c *Client) save(ipam *IPAM, ch <-chan struct{}) error {
	c.savingMutex.Lock()
	defer c.savingMutex.Unlock()
	var err error
	log.Tracef(trace.Inside, "Entering save() from %d", getGID())
	select {
	case msg := <-ch:

		// Is it possible to actually "lose" a lock via this channel?
		// Examination of libkv code appears to point to the fact that
		// a message on this channel would only be sent to the owner.
		// That is, it only is sent here:
		// https://github.com/romana/libkv/blob/master/store/etcd/etcd.go#L589

		// Probably no need to reload the state at this point,
		// as it would be detected by the watch.
		//		err = common.NewError("Lost lock while saving in %d: %p", getGID(), &msg)
		log.Warn(fmt.Sprintf("Lost lock while saving in %d: %p", getGID(), &msg))
		return nil
	default:
		err = c.Store.AtomicPut(ipamDataKey, ipam)
		if err != nil {
			log.Errorf("Error saving IPAM: %s: %d", err, getGID())
			return err
		}
		log.Debugf("%d: Saved IPAM (Alloc rev: %d, Topo rev: %d): IPAM rev %d", getGID(), ipam.AllocationRevision, ipam.TopologyRevision, c.IPAM.GetPrevKVPair().LastIndex)
		return nil
	}
}

// watchIPAM watches the backing store, and if a new IPAM is detected, it will
// reinitialize itself with the new value.
func (c *Client) watchIPAM() error {
	log.Tracef(trace.Public, "Entering watchIPAM.")
	stopCh := make(<-chan struct{})
	ch, err := c.Store.ReconnectingWatch(ipamDataKey, stopCh)
	if err != nil {
		return err
	}

	go func() {
		log.Tracef(trace.Inside, "watchIPAM: Entering watchIPAM goroutine: %d", getGID())
		for {

			select {
			case kv := <-ch:
				c.savingMutex.RLock()
				prevKV := c.IPAM.GetPrevKVPair()
				if prevKV == nil || kv.LastIndex > prevKV.LastIndex {
					log.Debugf("Received IPAM with revision %d, current last revision %d", kv.LastIndex, prevKV.LastIndex)
					if err != nil {
						log.Error(err)
						// Nothing to do here, but since there is a new version,
						// IPAM will continue failing on save until we get another one and
						// try again
						c.savingMutex.RUnlock()
						continue
					}
					c.IPAM, err = parseIPAM(string(kv.Value))
					if err != nil {
						log.Error(err)
						c.savingMutex.RUnlock()
						continue
					}
					c.IPAM.save = c.save
					c.IPAM.load = c.load
					c.IPAM.SetPrevKVPair(kv)
					log.Debugf("Loaded IPAM with revision %d", kv.LastIndex)
				}
				c.savingMutex.RUnlock()
			}
		}
	}()
	return nil
}

// AddRomanaIP adds romanaIP information for service to the store.
func (c *Client) AddRomanaIP(serviceName string, e api.ExposedIPSpec) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return c.Store.PutObject(RomanaIPPrefix+"/"+serviceName, b)
}

// DeleteRomanaIP deletes romanaIP information for service from store.
func (c *Client) DeleteRomanaIP(serviceName string) error {
	_, err := c.Store.Delete(RomanaIPPrefix + "/" + serviceName)
	return err
}

// ListRomanaIP lists romanaIP information for services in the store.
func (c *Client) ListRomanaIPs() (map[string]api.ExposedIPSpec, error) {
	exposedIPs := make(map[string]api.ExposedIPSpec)

	kvpairs, err := c.Store.ListObjects(RomanaIPPrefix)
	if err != nil {
		return nil, err
	}
	if err == libkvStore.ErrKeyNotFound {
		return exposedIPs, nil
	}

	for i := range kvpairs {
		if kvpairs[i] == nil {
			continue
		}

		var eip api.ExposedIPSpec
		err := json.Unmarshal(kvpairs[i].Value, &eip)
		if err != nil {
			continue
		}

		serviceName := strings.TrimPrefix(kvpairs[i].Key, c.Store.getKey(RomanaIPPrefix+"/"))
		exposedIPs[serviceName] = eip
	}

	return exposedIPs, nil
}

// GetTopology returns the representation of latest topology in store.
func (c *Client) GetTopology() (interface{}, error) {
	ch, err := c.ipamLocker.Lock()
	if err != nil {
		return nil, fmt.Errorf("failed to get ipam lock: %s", err)
	}
	defer c.ipamLocker.Unlock()

	kv, err := c.Store.Get(ipamDataKey)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ipam information: %s", err)
	}

	select {
	case lockError := <-ch:
		return nil, fmt.Errorf("failed to hold on to ipam lock: %s", lockError)
	default:
	}

	ipamState := &IPAM{}
	err = json.Unmarshal(kv.Value, ipamState)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ipam information: %s", err)
	}

	select {
	case lockError := <-ch:
		return nil, fmt.Errorf("failed to hold on to ipam lock: %s", lockError)
	default:
	}

	return getTopologyFromIPAMState(ipamState), nil
}

func getTopologyFromIPAMState(ipamState *IPAM) interface{} {
	if ipamState == nil {
		return nil
	}

	topology := api.TopologyUpdateRequest{}

	for _, network := range ipamState.Networks {
		var tenants []string
		var networks []string

		for t, n := range ipamState.TenantToNetwork {
			for i := range n {
				if n[i] == network.Name {
					tenants = append(tenants, t)
					networks = append(networks, n[i])
				}
			}
		}

		topology.Networks = append(topology.Networks, api.NetworkDefinition{
			Name:      network.Name,
			CIDR:      network.CIDR.String(),
			BlockMask: network.BlockMask,
			Tenants:   tenants,
		})

		var maps []api.GroupOrHost
		if network.Group != nil {
			if network.Group.Hosts != nil && len(network.Group.Hosts) > 0 {
				for _, host := range addHosts(network.Group.Hosts) {
					maps = append(maps, host)
				}
			}
			if network.Group.Groups != nil && len(network.Group.Groups) > 0 {
				for _, group := range addGroups(network.Group.Groups, 0) {
					maps = append(maps, group)
				}
			}
		}

		topology.Topologies = append(topology.Topologies, api.TopologyDefinition{
			Networks: networks,
			Map:      maps,
		})
	}

	return &topology
}

// addHosts adds host information to topology map.
func addHosts(hosts []*Host) []api.GroupOrHost {
	var rHosts []api.GroupOrHost

	for _, host := range hosts {
		if host != nil {
			rHosts = append(rHosts, api.GroupOrHost{
				Name:       host.Name,
				IP:         host.IP,
				Assignment: host.Tags,
			})
		}
	}

	return rHosts
}

// addGroups recursively adds groups or hosts to topology map.
func addGroups(groups []*Group, level uint) []api.GroupOrHost {
	var rGroups []api.GroupOrHost

	// currently addGroups can recursively call itself as many times
	// as possible but we want prevent it here to about 20 levels to
	// maintain a balance between giving enough topology information
	// out to the user and not falling in loops.
	if level >= defaultTopologyLevels {
		return rGroups
	}

	for _, group := range groups {
		if group != nil && !group.Dummy {
			var subgroups []api.GroupOrHost

			if group.Hosts != nil && len(group.Hosts) > 0 {
				for _, host := range addHosts(group.Hosts) {
					subgroups = append(subgroups, host)
				}
			}

			if group.Groups != nil && len(group.Groups) > 0 {
				for _, group := range addGroups(group.Groups, level+1) {
					subgroups = append(subgroups, group)
				}
			}

			var cidr string
			if group.CIDR.IPNet != nil {
				cidr = group.CIDR.IPNet.String()
			}

			rGroups = append(rGroups, api.GroupOrHost{
				Name:       group.Name,
				Routing:    group.Routing,
				CIDR:       cidr,
				Assignment: group.Assignment,
				Groups:     subgroups,
			})
		}
	}

	return rGroups
}
