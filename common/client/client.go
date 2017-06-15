package client

import (
	"encoding/json"
	"sync"

	"github.com/romana/core/common"
)

type Client struct {
	config     *common.Config
	Store      *common.Store
	ipamLocker sync.Locker
	IPAM       *IPAM
}

// NewClient creates a new Client object based on provided config
func NewClient(config *Config) (*Client, error) {
	store, err := NewStore(config.EtcdEndpoints, config.EtcdPrefix)
	if err != nil {
		return nil, err
	}

	client := &Client{
		config: config,
		Store:  store,
	}

	err = c.initIPAM()
	if err != nil {
		return nil, err
	}

	return client, nil
}

const (
	ipamDataKey = "/ipam/data"
)

func (c *Client) initIPAM() error {
	c.ipamLocker, err = c.store.NewLocker(c.store.prefix + "/ipam/lock")
	if err != nil {
		return err
	}

	c.ipamLocker.Lock()
	defer r.ipamLocker.Unlock()

	// Check if IPAM info exists in the store
	ipamExists, err := c.store.Exists(ipamDataKey)
	if err != nil {
		return err
	}
	if ipamExists {
		// Load if exists
		log.Infof("Loading IPAM data from %s", ipamDataKey)
		kv, err := c.store.Get(ipamDataKey)
		if err != nil {
			return err
		}

		c.IPAM, err = ParseIPAM(string(kv.Value), c.save, c.ipamLocker)
		if err != nil {
			return err
		}
	} else {
		// If does not exist, initialize and save
		log.Infof("No IPAM data found at %s, initializing", key)
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
	err = c.store.Put(ipamDataKey, b, nil)
	if err != nil {
		return err
	}
	return nil
}
