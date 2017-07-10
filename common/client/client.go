package client

import (
	"encoding/json"
	"sync"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	log "github.com/romana/rlog"
)

const (
	ipamDataKey    = "/ipam/data"
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

func (c *Client) ListHosts() api.HostList {
	return c.IPAM.ListHosts()
}

func (c *Client) ListPolicies() ([]api.Policy, error) {
	objs, err := c.Store.ListObjects(PoliciesPrefix, &api.Policy{})
	if err != nil {
		return nil, err
	}
	policies := make([]api.Policy, len(objs))
	for i, obj := range objs {
		policies[i] = obj.(api.Policy)
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
	return c.Store.PutObject(PoliciesPrefix+policy.ID, policy)
}

// DeletePolicy attempts to delete policy. If the policy does
// not exist, false is returned, instead of an error.
func (c *Client) DeletePolicy(id string) (bool, error) {
	return c.Store.Delete(PoliciesPrefix + id)
}

func (c *Client) initIPAM() error {
	c.ipamLocker, err = c.Store.NewLocker(c.Store.prefix + "/ipam/lock")
	if err != nil {
		return err
	}

	c.ipamLocker.Lock()
	defer c.ipamLocker.Unlock()

	// Check if IPAM info exists in the store
	ipamExists, err := c.Store.Exists(ipamDataKey)
	if err != nil {
		return err
	}
	if ipamExists {
		// Load if exists
		log.Infof("Loading IPAM data from %s", ipamDataKey)
		kv, err := c.Store.Get(ipamDataKey)
		if err != nil {
			return err
		}

		c.IPAM, err = ParseIPAM(string(kv.Value), c.save, c.ipamLocker)
		if err != nil {
			return err
		}
	} else {
		// If does not exist, initialize and save
		log.Infof("No IPAM data found at %s, initializing", ipamDataKey)
		c.IPAM, err = NewIPAM(c.save, c.ipamLocker)
		if err != nil {
			return err
		}
		err = c.save(c.IPAM)
		if err != nil {
			return err
		}
	}

	return nil
}

// save implements the Saver interface of IPAM.
func (c *Client) save(ipam *IPAM) error {
	b, err := json.Marshal(c.IPAM)
	if err != nil {
		return err
	}
	err = c.Store.Put(ipamDataKey, b, nil)
	if err != nil {
		return err
	}
	return nil
}
