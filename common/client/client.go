package client

import (
	"sync"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"
)

const (
	DefaultEtcdPrefix    = "/romana"
	DefaultEtcdEndpoints = "localhost:2379"

	ipamKey        = "/ipam"
	ipamDataKey    = ipamKey + "/data"
	PoliciesPrefix = "/policies"
)

type Client struct {
	config     *common.Config
	Store      *Store
	ipamLocker sync.Locker
	IPAM       *IPAM
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
		config: config,
		Store:  store,
	}

	err = c.initIPAM()
	if err != nil {
		return nil, err
	}

	return c, nil

}

func NewClientTransaction(config *common.Config) (*Client, sync.Locker, error) {
	if config.EtcdPrefix == "" {
		config.EtcdPrefix = DefaultEtcdPrefix
	}
	store, err := NewStore(config.EtcdEndpoints, config.EtcdPrefix)
	if err != nil {
		return nil, nil, err
	}

	c := &Client{
		config: config,
		Store:  store,
	}

	locker, err := c.initIpamTransaction()
	if err != nil {
		return nil, nil, err
	}

	return c, locker, nil

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
			case val := <-ch:
				ipamJson := string(val)
				log.Tracef(trace.Inside, "WatchBlocks: got JSON [%s]", ipamJson)
				ipam, err := ParseIPAM(ipamJson, nil, nil)
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
			case val := <-ch:
				ipamJson := string(val)
				ipam, err := ParseIPAM(ipamJson, nil, nil)
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
	objs, err := c.Store.ListObjects(PoliciesPrefix, &api.Policy{})
	if err != nil {
		return nil, err
	}
	policies := make([]api.Policy, len(objs))
	for i, obj := range objs {
		policies[i] = *obj.(*api.Policy)
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
	return c.Store.PutObject(PoliciesPrefix+"/"+policy.ID, policy)
}

// DeletePolicy attempts to delete policy. If the policy does
// not exist, false is returned, instead of an error.
func (c *Client) DeletePolicy(id string) (bool, error) {
	return c.Store.Delete(PoliciesPrefix + id)
}

func (c *Client) initIPAM() error {
	locker, err := c.initIpamTransaction()
	if locker != nil {
		locker.Unlock()
	}

	return err
}

func (c *Client) initIpamTransaction() (sync.Locker, error) {
	c.ipamLocker, err = c.Store.NewLocker(ipamKey)
	if err != nil {
		return nil, err
	}
	log.Tracef(trace.Inside, "initIPAM(): Created locker %v", c.ipamLocker)

	c.ipamLocker.Lock()

	// Check if IPAM info exists in the store
	ipamExists, err := c.Store.Exists(ipamDataKey)
	if err != nil {
		return nil, err
	}
	if ipamExists {
		// Load if exists
		log.Infof("Loading IPAM data from %s", c.Store.getKey(ipamDataKey))
		kv, err := c.Store.Get(ipamDataKey)
		if err != nil {
			return nil, err
		}

		c.IPAM, err = ParseIPAM(string(kv.Value), c.save, c.ipamLocker)
		if err != nil {
			return nil, err
		}
	} else {
		// If does not exist, initialize and save
		log.Infof("No IPAM data found at %s, initializing", c.Store.getKey(ipamDataKey))
		c.IPAM, err = NewIPAM(c.save, c.ipamLocker)
		if err != nil {
			return nil, err
		}
		err = c.save(c.IPAM)
		if err != nil {
			return nil, err
		}
	}

	return c.ipamLocker, nil
}

// save implements the Saver interface of IPAM.
func (c *Client) save(ipam *IPAM) error {
	err = c.Store.PutObject(ipamDataKey, c.IPAM)
	if err != nil {
		return err
	}
	return nil
}
