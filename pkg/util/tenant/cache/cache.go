// Copyright (c) 2016 Pani Networks
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

package cache

import (
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	"github.com/romana/core/pkg/util/tenant/hasher"
	log "github.com/romana/rlog"
	"sync"
	"time"
)

// Interface defines tenant cache behavior.
type Interface interface {
	// Starts synchronization loop
	// which maintains the store.
	// Returns update channel.
	// Update channel receives notifications
	// when change in a store detected.
	Run(stop <-chan struct{}) <-chan string

	// Returns a list of objects in cache.
	List() []common.Tenant
}

// Config represents configuration for the tenant cache.
type Config struct {
	// CacheTickSeconds is a delay before attempts to refresh the cache.
	CacheTickSeconds int
}

// Cache implements tenant/cache.Interface.
type Cache struct {
	client *common.RestClient

	// Delay between main loop runs.
	ticker <-chan time.Time

	store []common.Tenant

	mu *sync.Mutex

	// Combined hash of all tenants in the store,
	// used to invalidate the store and to generate update notifications.
	hash string
}

// New creates new empty tenant cache.
func New(client *common.RestClient, config Config) Interface {
	t := time.Tick(time.Duration(config.CacheTickSeconds) * time.Second)
	return &Cache{client: client, ticker: t, mu: &sync.Mutex{}}
}

// Run implements cache.Interface.
func (c *Cache) Run(stop <-chan struct{}) <-chan string {
	log.Trace(trace.Public, "Tenant cache Run()")
	update := make(chan string)

	go func() {
		for {
			select {
			case <-stop:
				close(update)
				return
			case <-c.ticker:

				// Fetch all tenants from romana Tenant service,
				currentState, err := c.getNewState(c.client)
				if err != nil {
					log.Errorf("Tenant cache failed to sync with upstream, %s", err)
					continue
				}

				// and check if tenants from Tenant service are different
				// from the tenants in our cache.
				newHash := hasher.HashRomanaTenants(currentState)
				if c.hash != newHash {

					// Refresh the cache
					c.mu.Lock()
					c.store = currentState
					c.hash = newHash
					c.mu.Unlock()

					// and generate notification.
					log.Tracef(5, "Tenant cache detected changes in tenant backend, generating update event.")
					update <- c.hash
				}
			}
		}
	}()

	return update
}

// List implements Interface.
func (c *Cache) List() []common.Tenant {
	c.mu.Lock()
	defer c.mu.Unlock()

	tenants := c.store
	return tenants
}

// getNewState retrieves tenants from romana Tenant service.
func (c *Cache) getNewState(client *common.RestClient) ([]common.Tenant, error) {
	tenants := []common.Tenant{}

	tenantURL, err := client.GetServiceUrl("tenant")
	if err != nil {
		return tenants, err
	}
	tenantsURL := fmt.Sprintf("%s/tenants", tenantURL)

	err = client.Get(tenantsURL, &tenants)
	if err != nil {
		return tenants, err
	}

	for tenantNum, _ := range tenants {
		fullUrl := fmt.Sprintf("%s/tenants/%d/segments", tenantURL, tenants[tenantNum].ID)
		err = client.Get(fullUrl, &tenants[tenantNum].Segments)

		// ignore 404 error here which means no segments
		// considered to be a zero segments rather then
		// an error.
		if err != nil && !checkHttp404(err) {
			return tenants, err
		}
	}

	return tenants, nil
}

func checkHttp404(err error) (ret bool) {
	switch e := err.(type) {
	case common.HttpError:
		if e.StatusCode == 404 {
			ret = true
		}
	}

	return
}
