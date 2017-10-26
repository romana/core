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

package policycache

import (
	"github.com/romana/core/agent/cache"
	"github.com/romana/core/common/api"
)

type Interface interface {
	Put(string, api.Policy)
	Get(string) (api.Policy, bool)
	Delete(string)
	List() []api.Policy
	Keys() []string
}

type PolicyStorage struct {
	store cache.Interface
}

func New() Interface {
	return &PolicyStorage{cache.New()}
}

func (p *PolicyStorage) Put(key string, policy api.Policy) {
	p.store.Put(key, policy)
}

func (p *PolicyStorage) Get(key string) (api.Policy, bool) {
	item, ok := p.store.Get(key)
	if !ok {
		return api.Policy{}, ok
	}

	policy, ok := item.(api.Policy)
	if !ok {
		return api.Policy{}, ok
	}

	return policy, ok
}

func (p *PolicyStorage) List() []api.Policy {
	var result []api.Policy
	items := p.store.List()
	for _, item := range items {
		policy, ok := item.(api.Policy)
		if !ok {
			continue
		}
		result = append(result, policy)
	}
	return result
}

func (p *PolicyStorage) Keys() []string {
	return p.store.Keys()
}

func (p *PolicyStorage) Delete(key string) {
	p.store.Delete(key)
}
