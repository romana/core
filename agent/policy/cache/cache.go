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

// Policy cache package maintains local a local copy of all romana policies
// and provides updates when a policy added/deleted/modified.
// Useful for the clients who lists entire policy storage often.
package cache

import (
	"sync"
	"time"

	"github.com/romana/core/agent/policy/hasher"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"
	"github.com/romana/core/common/log/trace"

	log "github.com/romana/rlog"
)

// Interface defines policy cache behavior.
type Interface interface {
	// Run starts main loop that synchronizes internal cache
	// with Policy service periodically and generates
	// notification if cache was updated.
	Run(stop <-chan struct{}) <-chan string

	// List returns a list of all romana policies in a cache.
	List() []api.Policy
}

// Config represents configuration for the policy cache.
type Config struct {
	// CacheTickSeconds is a delay before attempts to refresh the cache.
	CacheTickSeconds int
}

// New creates new policy cache.
func New(client *client.Client, config Config) Interface {
	t := time.Tick(time.Duration(config.CacheTickSeconds) * time.Second)
	return &Cache{client: client, ticker: t, mu: &sync.Mutex{}}
}

// Cache implements Interface.
type Cache struct {
	// Romana rest client to access romana policy storage.
	client *client.Client

	// Delay between main loop runs.
	ticker <-chan time.Time

	// Internal store for romana policies.
	store []api.Policy

	mu *sync.Mutex

	// Combined hash of all romana policies in the store,
	// used to invalidate the store and to generate update notifications.
	hash string
}

// Run implements Interface.
func (c *Cache) Run(stop <-chan struct{}) <-chan string {
	log.Trace(trace.Public, "Policy cache Run()")
	update := make(chan string)

	go func() {
		for {
			select {
			case <-stop:
				close(update)
				return
			case <-c.ticker:

				// Fetch all policies from romana Policy service,
				currentState, err := c.getNewState(c.client)
				if err != nil {
					log.Errorf("Policy cache failed to sync with upstream, %s", err)
					continue
				}

				// and check if policies from Policy service are different
				// from the policies in our cache.
				newHash := hasher.HashRomanaPolicies(currentState)
				if c.hash != newHash {

					// Refresh the cache
					c.mu.Lock()
					c.store = currentState
					c.hash = newHash
					c.mu.Unlock()

					// and generate notification.
					log.Tracef(5, "Policy cache detected changes in policy backend, generating update event.")
					update <- c.hash
				}
			}
		}
	}()

	return update
}

// List implements Interface.
func (c *Cache) List() []api.Policy {
	c.mu.Lock()
	defer c.mu.Unlock()

	policies := c.store
	return policies
}

// getNewState retrieves romana policies from romana Policy service.
func (c *Cache) getNewState(client *client.Client) ([]api.Policy, error) {
	return client.ListPolicies()
}
